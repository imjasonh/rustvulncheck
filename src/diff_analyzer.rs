//! Extract modified Rust function symbols from GitHub commit diffs.
//!
//! Uses AST parsing via `syn` to precisely identify Added, Modified, and
//! Deleted function symbols. For each changed `.rs` file, fetches the full
//! before/after contents from GitHub, parses both with `syn::parse_file`,
//! and diffs the function sets.

use std::collections::HashMap;

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

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
pub enum ChangeType {
    Added,
    Deleted,
    Modified,
}

/// Extract function signatures by fetching full file contents and AST-diffing.
///
/// For each changed `.rs` file in the diff, fetches the before (parent) and
/// after (commit) versions from GitHub, parses both with `syn`, and diffs
/// the function sets. Files that fail to parse are skipped with a warning.
///
/// `package_name` is used to:
/// - Prepend the crate name to symbols from non-workspace repos (e.g. `src/lib.rs`)
/// - Filter out files belonging to sibling crates in workspace repos
pub fn extract_symbols(
    diff: &PatchDiff,
    gh: &crate::github::GithubClient,
    package_name: &str,
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

        if !file_belongs_to_crate(&file_patch.filename, package_name) {
            continue;
        }

        let mut module_path = file_path_to_module(&file_patch.filename);

        // For non-workspace repos (files directly under src/), prepend the
        // package name so symbols get properly qualified crate prefixes.
        if needs_crate_prefix(&file_patch.filename) && !package_name.is_empty() {
            let crate_name = package_name.replace('-', "_");
            if module_path.is_empty() {
                module_path = crate_name;
            } else {
                module_path = format!("{}::{}", crate_name, module_path);
            }
        }

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

    dedup_symbols(all_symbols)
}

/// Returns true when the file path has no workspace crate directory before `src/`,
/// meaning the package name must be prepended to get a fully qualified module path.
///
/// Examples:
/// - `src/lib.rs` → true (no crate dir prefix)
/// - `src/parser.rs` → true
/// - `crates/hyper/src/lib.rs` → false (workspace crate dir `hyper` provides prefix)
/// - `pyo3-ffi/src/object.rs` → false
pub(crate) fn needs_crate_prefix(path: &str) -> bool {
    let parts: Vec<&str> = path.split('/').collect();
    match parts.iter().position(|&p| p == "src") {
        Some(0) => true,  // src/ is the first component
        Some(_) => false, // there are directories before src/
        None => true,     // no src/ at all — can't determine, include prefix
    }
}

/// Returns true if the file at `path` belongs to the crate named `package_name`.
///
/// For single-crate repos (files directly under `src/`), always returns true.
/// For workspace repos, checks that the directory immediately before `src/`
/// matches the package name (with hyphens normalized to underscores).
pub(crate) fn file_belongs_to_crate(path: &str, package_name: &str) -> bool {
    let parts: Vec<&str> = path.split('/').collect();
    let src_idx = match parts.iter().position(|&p| p == "src") {
        Some(idx) => idx,
        None => return true, // no src/ — can't determine, include it
    };
    if src_idx == 0 {
        return true; // src/... at top level — single crate repo, always include
    }
    // The directory immediately before src/ is the crate directory
    let crate_dir = parts[src_idx - 1].replace('-', "_");
    let target = package_name.replace('-', "_");
    crate_dir == target
}

/// Deduplicate symbols by function name, keeping the highest-priority change type.
///
/// Priority: Deleted > Modified > Added. When multiple trait impls produce the
/// same qualified name (e.g., `Value::from` from multiple `impl From<T>`), we
/// keep only one entry with the most significant change type.
pub(crate) fn dedup_symbols(symbols: Vec<VulnerableSymbol>) -> Vec<VulnerableSymbol> {
    fn change_priority(ct: &ChangeType) -> u8 {
        match ct {
            ChangeType::Deleted => 0,
            ChangeType::Modified => 1,
            ChangeType::Added => 2,
        }
    }

    let mut best: HashMap<String, VulnerableSymbol> = HashMap::new();
    for sym in symbols {
        best.entry(sym.function.clone())
            .and_modify(|existing| {
                if change_priority(&sym.change_type) < change_priority(&existing.change_type) {
                    *existing = sym.clone();
                }
            })
            .or_insert(sym);
    }
    let mut result: Vec<_> = best.into_values().collect();
    result.sort_by(|a, b| a.file.cmp(&b.file).then(a.function.cmp(&b.function)));
    result
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
    // Files named *_test.rs, test_*.rs, or *_tests.rs, or proptests.rs
    if let Some(filename) = parts.last() {
        if filename.ends_with("_test.rs")
            || filename.ends_with("_tests.rs")
            || filename.starts_with("test_")
            || *filename == "proptests.rs"
        {
            return true;
        }
    }
    // Path components ending in -tests (e.g. lucet-runtime-tests/src/...)
    if parts.iter().any(|p| p.ends_with("-tests") || p.ends_with("_tests")) {
        return true;
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
        assert!(is_test_file("src/btreemap/proptests.rs"));
        assert!(is_test_file("lucet-runtime/lucet-runtime-tests/src/guest_fault.rs"));
        assert!(is_test_file("crate/foo_tests/src/bar.rs"));
        assert!(is_test_file("src/integration_tests.rs"));
        assert!(!is_test_file("src/lib.rs"));
        assert!(!is_test_file("src/http/request.rs"));
        assert!(!is_test_file("src/testing/trace.rs"));
    }

    // ── needs_crate_prefix tests ─────────────────────────────────────

    #[test]
    fn test_needs_crate_prefix() {
        // Single-crate repos: src/ is at top level, needs prefix
        assert!(needs_crate_prefix("src/lib.rs"));
        assert!(needs_crate_prefix("src/parser.rs"));
        assert!(needs_crate_prefix("src/proto/h1.rs"));

        // Workspace repos: directory before src/ provides the crate name
        assert!(!needs_crate_prefix("crates/hyper/src/lib.rs"));
        assert!(!needs_crate_prefix("pyo3-ffi/src/object.rs"));
        assert!(!needs_crate_prefix("crates/algorithms/sha3/src/simd/avx2.rs"));

        // No src/ in path — needs prefix as fallback
        assert!(needs_crate_prefix("build.rs"));
    }

    // ── file_belongs_to_crate tests ──────────────────────────────────

    #[test]
    fn test_file_belongs_to_crate_single_crate_repo() {
        // Single-crate repos always match (src/ at top level)
        assert!(file_belongs_to_crate("src/lib.rs", "hyper"));
        assert!(file_belongs_to_crate("src/parser.rs", "serde_yaml"));
    }

    #[test]
    fn test_file_belongs_to_crate_workspace_match() {
        // File's crate dir matches the package name
        assert!(file_belongs_to_crate("crates/hyper/src/lib.rs", "hyper"));
        assert!(file_belongs_to_crate("tokio/src/net.rs", "tokio"));
        assert!(file_belongs_to_crate("crates/algorithms/sha3/src/simd.rs", "sha3"));
    }

    #[test]
    fn test_file_belongs_to_crate_workspace_mismatch() {
        // File belongs to a sibling crate, not the target
        assert!(!file_belongs_to_crate("tokio-util/src/codec.rs", "tokio"));
        assert!(!file_belongs_to_crate("crates/hyper-util/src/lib.rs", "hyper"));
        assert!(!file_belongs_to_crate("opentelemetry-sdk/src/testing/trace.rs", "opentelemetry_api"));
    }

    #[test]
    fn test_file_belongs_to_crate_hyphen_normalization() {
        // Hyphens and underscores are interchangeable
        assert!(file_belongs_to_crate("pyo3-ffi/src/object.rs", "pyo3-ffi"));
        assert!(file_belongs_to_crate("pyo3-ffi/src/object.rs", "pyo3_ffi"));
        assert!(file_belongs_to_crate("foo_bar/src/lib.rs", "foo-bar"));
    }

    #[test]
    fn test_file_belongs_to_crate_no_src() {
        // Files without src/ are always included (can't determine crate)
        assert!(file_belongs_to_crate("build.rs", "hyper"));
        assert!(file_belongs_to_crate("Cargo.toml", "hyper"));
    }

    // ── dedup_symbols tests ──────────────────────────────────────────

    #[test]
    fn test_dedup_symbols_keeps_highest_priority() {
        let symbols = vec![
            VulnerableSymbol {
                file: "src/lib.rs".into(),
                function: "Value::from".into(),
                change_type: ChangeType::Added,
            },
            VulnerableSymbol {
                file: "src/lib.rs".into(),
                function: "Value::from".into(),
                change_type: ChangeType::Modified,
            },
            VulnerableSymbol {
                file: "src/lib.rs".into(),
                function: "Value::from".into(),
                change_type: ChangeType::Deleted,
            },
        ];

        let result = dedup_symbols(symbols);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].function, "Value::from");
        assert_eq!(result[0].change_type, ChangeType::Deleted);
    }

    #[test]
    fn test_dedup_symbols_modified_over_added() {
        let symbols = vec![
            VulnerableSymbol {
                file: "src/common.rs".into(),
                function: "Key::from".into(),
                change_type: ChangeType::Added,
            },
            VulnerableSymbol {
                file: "src/common.rs".into(),
                function: "Key::from".into(),
                change_type: ChangeType::Modified,
            },
        ];

        let result = dedup_symbols(symbols);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].change_type, ChangeType::Modified);
    }

    #[test]
    fn test_dedup_symbols_preserves_distinct_functions() {
        let symbols = vec![
            VulnerableSymbol {
                file: "src/lib.rs".into(),
                function: "foo".into(),
                change_type: ChangeType::Added,
            },
            VulnerableSymbol {
                file: "src/lib.rs".into(),
                function: "bar".into(),
                change_type: ChangeType::Modified,
            },
            VulnerableSymbol {
                file: "src/other.rs".into(),
                function: "baz".into(),
                change_type: ChangeType::Deleted,
            },
        ];

        let result = dedup_symbols(symbols);
        assert_eq!(result.len(), 3);
    }

    #[test]
    fn test_dedup_symbols_across_files() {
        // Same function name from different files (e.g., re-exports or identical trait impls)
        let symbols = vec![
            VulnerableSymbol {
                file: "src/v1.rs".into(),
                function: "api::time::now".into(),
                change_type: ChangeType::Added,
            },
            VulnerableSymbol {
                file: "src/v2.rs".into(),
                function: "api::time::now".into(),
                change_type: ChangeType::Deleted,
            },
        ];

        let result = dedup_symbols(symbols);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].change_type, ChangeType::Deleted);
    }

    #[test]
    fn test_dedup_symbols_empty_input() {
        let result = dedup_symbols(Vec::new());
        assert!(result.is_empty());
    }
}
