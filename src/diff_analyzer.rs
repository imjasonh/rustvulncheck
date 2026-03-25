//! Analyze unified diffs to extract modified Rust function signatures.

use regex::Regex;

use crate::github::PatchDiff;

/// A vulnerable symbol extracted from a patch diff.
#[derive(Debug, Clone, serde::Serialize)]
pub struct VulnerableSymbol {
    /// The file path in the repository
    pub file: String,
    /// The inferred fully-qualified function name (best effort)
    pub function: String,
    /// Whether this is a new function, modified function, or deleted function
    pub change_type: ChangeType,
}

#[derive(Debug, Clone, serde::Serialize)]
pub enum ChangeType {
    Modified,
    Added,
    Deleted,
}

/// Extract function signatures from a patch diff.
///
/// Strategy:
/// 1. Look at unified diff hunk headers (`@@ ... @@ fn ...`) which often contain
///    the enclosing function name.
/// 2. Look at added/removed lines containing `fn ` declarations.
/// 3. Infer module path from the file path.
pub fn extract_symbols(diff: &PatchDiff) -> Vec<VulnerableSymbol> {
    let mut symbols = Vec::new();
    let fn_decl_re = Regex::new(
        r"(?:pub\s+(?:\(crate\)\s+)?)?(?:unsafe\s+)?(?:async\s+)?fn\s+([a-zA-Z_][a-zA-Z0-9_]*)",
    )
    .unwrap();
    let hunk_header_re = Regex::new(r"^@@.*@@\s*(.*)$").unwrap();
    // Match impl blocks, allowing nested generics (e.g. impl<T: Foo<Bar>> Type<T>)
    // We match `impl` then skip everything up to the last `>>` or `>` before the type name.
    let impl_re =
        Regex::new(r"impl\b(?:<.*>)?\s+(?:([a-zA-Z_][a-zA-Z0-9_:]*)\s+for\s+)?([a-zA-Z_][a-zA-Z0-9_:<>, ]*)").unwrap();

    for file_patch in &diff.files {
        // Skip test files — they aren't callable library code
        if is_test_file(&file_patch.filename) {
            continue;
        }
        let module_path = file_path_to_module(&file_patch.filename);

        let mut current_context_fn: Option<String> = None;
        let mut current_impl_type: Option<String> = None;

        for line in file_patch.patch.lines() {
            // Track hunk headers - they often show the enclosing function
            if let Some(caps) = hunk_header_re.captures(line) {
                let context = &caps[1];
                let has_fn = fn_decl_re.captures(context);
                let has_impl = impl_re.captures(context);

                if let Some(icaps) = has_impl {
                    current_impl_type = Some(icaps[2].trim().to_string());
                }

                if let Some(fcaps) = has_fn {
                    // Hunk header explicitly names a fn — use it
                    current_context_fn = Some(fcaps[1].to_string());
                }
                // If the hunk header shows only `impl` (no fn), do NOT clear
                // current_context_fn. Git picks the nearest enclosing scope
                // line for hunk headers, and consecutive hunks in the same
                // long method can alternate between showing `fn foo` and
                // `impl Foo`. Clearing would silently drop body-only changes.
                // current_context_fn will be properly reset when we encounter
                // an actual fn declaration in context/changed lines.
                continue;
            }

            // Track impl blocks in context lines
            if line.starts_with(' ') || line.starts_with('+') || line.starts_with('-') {
                let content = &line[1..];
                if let Some(icaps) = impl_re.captures(content) {
                    if !content.trim_start().starts_with("//") {
                        current_impl_type = Some(icaps[2].trim().to_string());
                        // In a context/changed line showing impl, we're entering
                        // a new impl block — clear the fn context.
                        current_context_fn = None;
                    }
                }
            }

            // Look for fn declarations in changed lines
            let is_added = line.starts_with('+') && !line.starts_with("+++");
            let is_removed = line.starts_with('-') && !line.starts_with("---");

            if (is_added || is_removed) && line.contains("fn ") {
                let content = &line[1..];
                // Skip comments
                if content.trim_start().starts_with("//") || content.trim_start().starts_with("*")
                {
                    continue;
                }
                if let Some(caps) = fn_decl_re.captures(content) {
                    let fn_name = &caps[1];
                    let qualified = qualify_fn_name(&module_path, &current_impl_type, fn_name);
                    let change_type = if is_added {
                        ChangeType::Added
                    } else {
                        ChangeType::Deleted
                    };
                    symbols.push(VulnerableSymbol {
                        file: file_patch.filename.clone(),
                        function: qualified,
                        change_type,
                    });
                }
            } else if is_added || is_removed {
                // Changed line inside a function body
                let content = &line[1..];
                if content.trim().is_empty() || content.trim_start().starts_with("//") {
                    continue;
                }
                if let Some(ref ctx_fn) = current_context_fn {
                    let qualified =
                        qualify_fn_name(&module_path, &current_impl_type, ctx_fn);
                    if !symbols.iter().any(|s| s.function == qualified) {
                        symbols.push(VulnerableSymbol {
                            file: file_patch.filename.clone(),
                            function: qualified,
                            change_type: ChangeType::Modified,
                        });
                    }
                } else if current_impl_type.is_some() {
                    // We have code changes inside an impl block but the fn
                    // declaration is too far above for git to include it in
                    // the hunk header or context. Still record the change at
                    // the impl-type level rather than silently dropping it.
                    let qualified =
                        qualify_fn_name(&module_path, &current_impl_type, "<method>");
                    if !symbols.iter().any(|s| s.function == qualified) {
                        symbols.push(VulnerableSymbol {
                            file: file_patch.filename.clone(),
                            function: qualified,
                            change_type: ChangeType::Modified,
                        });
                    }
                }
            }

            // Update current function context from context/added lines
            if !line.starts_with('-') {
                let content = if line.starts_with('+') || line.starts_with(' ') {
                    &line[1..]
                } else {
                    line
                };
                if content.contains("fn ") && !content.trim_start().starts_with("//") {
                    if let Some(caps) = fn_decl_re.captures(content) {
                        current_context_fn = Some(caps[1].to_string());
                    }
                }
            }
        }
    }

    symbols
}

/// Convert a file path like `src/http/request.rs` to a module path like `http::request`.
///
/// Handles workspace layouts like `crates/foo/src/bar.rs` → `foo::bar`
/// and top-level `src/bar.rs` → `bar`. Replaces hyphens with underscores
/// to match Rust crate naming conventions.
fn file_path_to_module(path: &str) -> String {
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
fn is_test_file(path: &str) -> bool {
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

/// Build a qualified function name from module path, optional impl type, and fn name.
fn qualify_fn_name(module: &str, impl_type: &Option<String>, fn_name: &str) -> String {
    let type_part = impl_type.as_ref().map(|ty| {
        // Clean up generic parameters for the type name
        ty.split('<').next().unwrap_or(ty).trim().to_string()
    });

    // Build path parts, skipping empty segments to avoid leading `::`
    let parts: Vec<&str> = [Some(module), type_part.as_deref(), Some(fn_name)]
        .into_iter()
        .flatten()
        .filter(|s| !s.is_empty())
        .collect();

    parts.join("::")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_file_path_to_module() {
        assert_eq!(file_path_to_module("src/http/request.rs"), "http::request");
        assert_eq!(file_path_to_module("src/lib.rs"), "");
        assert_eq!(file_path_to_module("src/net/tcp/mod.rs"), "net::tcp");
        // Workspace crate paths
        assert_eq!(
            file_path_to_module("crates/algorithms/sha3/src/simd/avx2.rs"),
            "sha3::simd::avx2"
        );
        // Hyphens become underscores
        assert_eq!(
            file_path_to_module("pyo3-ffi/src/object.rs"),
            "pyo3_ffi::object"
        );
        // src/lib.rs should produce empty module path
        assert_eq!(file_path_to_module("src/lib.rs"), "");
    }

    #[test]
    fn test_qualify_fn_name_empty_module() {
        // When module is empty (src/lib.rs), no leading ::
        let empty = "".to_string();
        let impl_ty = Some("Context".to_string());
        assert_eq!(qualify_fn_name(&empty, &impl_ty, "seal"), "Context::seal");
        assert_eq!(qualify_fn_name(&empty, &None, "main"), "main");
        assert_eq!(
            qualify_fn_name("foo::bar", &impl_ty, "baz"),
            "foo::bar::Context::baz"
        );
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

    #[test]
    fn test_consecutive_hunks_preserve_fn_context() {
        // When consecutive hunks are in the same function and hunk 1 header
        // shows `fn foo`, hunk 2 (with `impl` header) should preserve context.
        let diff = PatchDiff {
            commit_sha: "abc123".to_string(),
            files: vec![crate::github::FilePatch {
                filename: "src/keccak/xof.rs".to_string(),
                patch: concat!(
                    "@@ -100,6 +100,8 @@ pub(crate) fn squeeze(out: &mut [u8]) {\n",
                    "     let x = 1;\n",
                    "+    let y = 2;\n",
                    " }\n",
                    "@@ -200,10 +202,12 @@ impl<const RATE: usize> KeccakXofState<RATE> {\n",
                    "     let blocks = out_len / RATE;\n",
                    "-        for i in 0..blocks {\n",
                    "+        for i in 1..blocks {\n",
                    "         }\n",
                )
                .to_string(),
            }],
        };

        let symbols = extract_symbols(&diff);
        assert!(
            symbols.iter().any(|s| s.function.contains("squeeze")),
            "Expected squeeze to be found, got: {:?}",
            symbols
        );
    }

    #[test]
    fn test_impl_body_changes_without_fn_context() {
        // Reproduces the real xof.rs scenario: BOTH hunk headers show `impl`,
        // fn declaration is too far above for git to include. Changes should
        // still be captured at the impl-type level.
        let diff = PatchDiff {
            commit_sha: "6bbe15ec".to_string(),
            files: vec![crate::github::FilePatch {
                filename: "crates/algorithms/sha3/src/generic_keccak/xof.rs".to_string(),
                patch: concat!(
                    "@@ -290,6 +290,12 @@ impl<const PARALLEL_LANES: usize, const RATE: usize> KeccakState<PARALLEL_LANES>\n",
                    " /// Squeeze\n",
                    "+/// Note that calling squeeze multiple times will only give correct\n",
                    "+/// output if all sqeezed chunks are RATE bytes long.\n",
                    " #[hax_lib::attributes]\n",
                    "@@ -316,42 +322,38 @@ impl<const RATE: usize, STATE: KeccakItem<1>> KeccakXofState<1, RATE, STATE> {\n",
                    "             self.inner.keccakf1600();\n",
                    "         }\n",
                    " \n",
                    "-        if out_len <= RATE {\n",
                    "-            self.inner.squeeze::<RATE>(out, 0, out_len);\n",
                    "+        if out_len > 0 {\n",
                    "+            let blocks = out_len / RATE;\n",
                    "+            self.inner.squeeze::<RATE>(out, 0, RATE);\n",
                    "+            for i in 1..blocks {\n",
                    "         }\n",
                )
                .to_string(),
            }],
        };

        let symbols = extract_symbols(&diff);
        assert!(
            !symbols.is_empty(),
            "Expected symbols from impl body changes, got none"
        );
        assert!(
            symbols.iter().any(|s| s.function.contains("KeccakXofState")),
            "Expected KeccakXofState in symbol, got: {:?}",
            symbols
        );
    }

    #[test]
    fn test_extract_fn_from_diff() {
        let diff = PatchDiff {
            commit_sha: "abc123".to_string(),
            files: vec![crate::github::FilePatch {
                filename: "src/http/request.rs".to_string(),
                patch: r#"@@ -10,6 +10,8 @@ impl Request {
     pub fn parse(buf: &[u8]) -> Result<Self> {
-        let old_code = true;
+        let new_code = true;
+        let extra = false;
     }
"#
                .to_string(),
            }],
        };

        let symbols = extract_symbols(&diff);
        assert!(!symbols.is_empty());
        assert!(symbols.iter().any(|s| s.function.contains("parse")));
    }
}
