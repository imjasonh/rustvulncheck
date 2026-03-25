//! Extract modified Rust function symbols from GitHub commit diffs.
//!
//! Uses AST parsing via `syn` to precisely identify Added, Modified, and
//! Deleted function symbols. For each changed `.rs` file, fetches the full
//! before/after contents from GitHub, parses both with `syn::parse_file`,
//! and diffs the function sets.

use crate::github::PatchDiff;

/// A vulnerable symbol extracted from a patch diff.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct VulnerableSymbol {
    /// The file path in the repository
    pub file: String,
    /// The inferred fully-qualified function name (best effort)
    pub function: String,
    /// Whether this is a new function, modified function, or deleted function
    pub change_type: ChangeType,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum ChangeType {
    Modified,
    Added,
    Deleted,
}

/// Extract function signatures by fetching full file contents and AST-diffing.
///
/// For each changed `.rs` file in the diff, fetches the before (parent) and
/// after (commit) versions from GitHub, parses both with `syn`, and diffs
/// the function sets. Files that fail to parse are skipped with a warning.
pub fn extract_symbols(
    diff: &PatchDiff,
    gh: &crate::github::GithubClient,
) -> Vec<VulnerableSymbol> {
    let mut all_symbols = Vec::new();

    let parent_sha = match &diff.parent_sha {
        Some(sha) => sha,
        None => {
            eprintln!(
                "Warning: no parent SHA for commit {}, cannot diff files",
                &diff.commit_sha[..7.min(diff.commit_sha.len())]
            );
            return all_symbols;
        }
    };

    if diff.owner.is_empty() || diff.repo.is_empty() {
        eprintln!(
            "Warning: missing owner/repo metadata for commit {}, cannot fetch files",
            &diff.commit_sha[..7.min(diff.commit_sha.len())]
        );
        return all_symbols;
    }

    for file_patch in &diff.files {
        if is_test_file(&file_patch.filename) {
            continue;
        }

        let module_path = file_path_to_module(&file_patch.filename);

        let before = gh
            .fetch_file_contents(&diff.owner, &diff.repo, &file_patch.filename, parent_sha)
            .ok()
            .flatten();

        let after = gh
            .fetch_file_contents(
                &diff.owner,
                &diff.repo,
                &file_patch.filename,
                &diff.commit_sha,
            )
            .ok()
            .flatten();

        match crate::ast_differ::ast_diff_symbols(
            before.as_deref(),
            after.as_deref(),
            &module_path,
            &file_patch.filename,
        ) {
            Some(symbols) => {
                all_symbols.extend(symbols);
            }
            None => {
                eprintln!(
                    "  Warning: AST parsing failed for {}, skipping",
                    file_patch.filename
                );
            }
        }
    }

    all_symbols
}

/// Convert a file path like `src/http/request.rs` to a module path like `http::request`.
///
/// Handles workspace layouts like `crates/foo/src/bar.rs` → `foo::bar`
/// and top-level `src/bar.rs` → `bar`. Replaces hyphens with underscores
/// to match Rust crate naming conventions.
pub(crate) fn file_path_to_module(path: &str) -> String {
    // Split into components
    let parts: Vec<&str> = path.split('/').collect();

    // Find the `src` component — everything before it is the crate prefix,
    // everything after it is the module path.
    let (crate_parts, mod_parts) = if let Some(src_idx) = parts.iter().position(|&p| p == "src") {
        (&parts[..src_idx], &parts[src_idx + 1..])
    } else {
        // No src/ directory — use the whole path
        (&[][..], &parts[..])
    };

    // Build module path from the parts after src/
    let mut mod_path: Vec<&str> = mod_parts.to_vec();

    // Strip .rs extension from last component and handle mod.rs / lib.rs
    if let Some(last) = mod_path.last_mut() {
        *last = last.trim_end_matches(".rs");
    }
    // Remove trailing mod or lib (e.g. src/net/mod.rs → net)
    if mod_path.last() == Some(&"mod") || mod_path.last() == Some(&"lib") {
        mod_path.pop();
    }

    // For workspace crates, use the last crate directory as prefix
    // e.g. crates/algorithms/sha3/src/simd/avx2.rs → sha3::simd::avx2
    let crate_name = crate_parts.last().copied().unwrap_or("");

    let mut result_parts: Vec<&str> = Vec::new();
    if !crate_name.is_empty() {
        result_parts.push(crate_name);
    }
    result_parts.extend(mod_path);

    // Join and replace hyphens with underscores (Rust crate convention)
    result_parts.join("::").replace('-', "_")
}

/// Returns true if the file path looks like a non-library file
/// (tests, examples, benchmarks, build scripts) that downstream
/// code wouldn't call.
pub(crate) fn is_test_file(path: &str) -> bool {
    let parts: Vec<&str> = path.split('/').collect();
    // Any path component named tests, test, examples, benches, or fuzz
    if parts.iter().any(|&p| {
        matches!(p, "tests" | "test" | "examples" | "example" | "benches" | "fuzz")
    }) {
        return true;
    }
    // Files named *_test.rs or test_*.rs
    if let Some(filename) = parts.last() {
        if filename.ends_with("_test.rs") || filename.starts_with("test_") {
            return true;
        }
    }
    // Top-level perf/ directories (e.g. quinn's perf/src/server.rs)
    if parts.first() == Some(&"perf") {
        return true;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_file_path_to_module() {
        assert_eq!(file_path_to_module("src/http/request.rs"), "http::request");
        assert_eq!(file_path_to_module("src/lib.rs"), "");
        assert_eq!(file_path_to_module("src/net/tcp/mod.rs"), "net::tcp");
        assert_eq!(
            file_path_to_module("crates/algorithms/sha3/src/simd/avx2.rs"),
            "sha3::simd::avx2"
        );
        assert_eq!(
            file_path_to_module("pyo3-ffi/src/object.rs"),
            "pyo3_ffi::object"
        );
        assert_eq!(file_path_to_module("src/lib.rs"), "");
    }

    #[test]
    fn test_is_test_file() {
        assert!(is_test_file("tests/integration.rs"));
        assert!(is_test_file("crates/foo/tests/rfc7539.rs"));
        assert!(is_test_file("src/my_test.rs"));
        assert!(is_test_file("examples/server.rs"));
        assert!(is_test_file("quinn/examples/server.rs"));
        assert!(is_test_file("fuzz/fuzz_targets/params.rs"));
        assert!(is_test_file("perf/src/server.rs"));
        assert!(is_test_file("benches/bench.rs"));
        assert!(!is_test_file("src/lib.rs"));
        assert!(!is_test_file("src/http/request.rs"));
    }
}
