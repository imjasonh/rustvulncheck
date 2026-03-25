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
    let impl_re =
        Regex::new(r"impl(?:<[^>]*>)?\s+(?:([a-zA-Z_][a-zA-Z0-9_:]*)\s+for\s+)?([a-zA-Z_][a-zA-Z0-9_:<>, ]*)").unwrap();

    for file_patch in &diff.files {
        let module_path = file_path_to_module(&file_patch.filename);

        let mut current_context_fn: Option<String> = None;
        let mut current_impl_type: Option<String> = None;

        for line in file_patch.patch.lines() {
            // Track hunk headers - they often show the enclosing function
            if let Some(caps) = hunk_header_re.captures(line) {
                let context = &caps[1];
                // Check if the hunk header contains an impl block
                if let Some(icaps) = impl_re.captures(context) {
                    current_impl_type = Some(icaps[2].trim().to_string());
                    current_context_fn = None;
                }
                // Check if hunk header mentions a fn
                if let Some(fcaps) = fn_decl_re.captures(context) {
                    current_context_fn = Some(fcaps[1].to_string());
                }
                continue;
            }

            // Track impl blocks in context lines
            if line.starts_with(' ') || line.starts_with('+') || line.starts_with('-') {
                let content = &line[1..];
                if let Some(icaps) = impl_re.captures(content) {
                    if !content.trim_start().starts_with("//") {
                        current_impl_type = Some(icaps[2].trim().to_string());
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
                // Changed line inside a known function context
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
fn file_path_to_module(path: &str) -> String {
    let path = path
        .trim_start_matches("src/")
        .trim_end_matches(".rs")
        .trim_end_matches("/mod")
        .trim_end_matches("/lib");

    path.replace('/', "::")
}

/// Build a qualified function name from module path, optional impl type, and fn name.
fn qualify_fn_name(module: &str, impl_type: &Option<String>, fn_name: &str) -> String {
    match impl_type {
        Some(ty) => {
            // Clean up generic parameters for the type name
            let clean_ty = ty
                .split('<')
                .next()
                .unwrap_or(ty)
                .trim()
                .to_string();
            format!("{}::{}::{}", module, clean_ty, fn_name)
        }
        None => format!("{}::{}", module, fn_name),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_file_path_to_module() {
        assert_eq!(file_path_to_module("src/http/request.rs"), "http::request");
        assert_eq!(file_path_to_module("src/lib.rs"), "lib");
        assert_eq!(
            file_path_to_module("src/net/tcp/mod.rs"),
            "net::tcp"
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
