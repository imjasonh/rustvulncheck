//! Scan Rust source files for references to vulnerable symbols.
//!
//! This module implements a lightweight static analysis that:
//! 1. Parses `use` statements to build an import map
//! 2. Searches for call patterns matching vulnerable function names
//! 3. Reports call sites with confidence levels

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use regex::Regex;

/// Confidence that a call site actually invokes the vulnerable symbol.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Confidence {
    /// Fully qualified path or unambiguous associated-function call after `use`.
    High,
    /// Method call `.foo()` where `foo` matches, but we can't confirm the receiver type.
    Medium,
}

/// A location in source code where a vulnerable symbol appears to be called.
#[derive(Debug, Clone)]
pub struct CallSite {
    /// Path to the source file (relative to project root).
    pub file: PathBuf,
    /// 1-based line number.
    pub line: usize,
    /// The line of source code (trimmed).
    pub snippet: String,
    /// The vulnerable symbol that was matched.
    pub symbol: String,
    /// How confident we are this is a real call.
    pub confidence: Confidence,
}

/// An import extracted from a `use` statement.
#[derive(Debug, Clone)]
struct Import {
    /// The full path being imported (e.g., `hyper::http::Request`).
    full_path: String,
    /// The local name it's imported as (e.g., `Request`, or a renamed alias).
    local_name: String,
}

/// Scan all `.rs` files under `project_root/src` for calls to any of the given
/// vulnerable symbols. Each symbol is a fully-qualified path like
/// `hyper::http::Request::parse`.
pub fn scan_for_symbols(project_root: &Path, symbols: &[&str]) -> Vec<CallSite> {
    let src_dir = project_root.join("src");
    if !src_dir.exists() {
        return Vec::new();
    }

    // Collect all .rs files
    let rs_files: Vec<PathBuf> = walkdir::WalkDir::new(&src_dir)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.path()
                .extension()
                .map_or(false, |ext| ext == "rs")
        })
        .map(|e| e.path().to_path_buf())
        .collect();

    let mut all_sites = Vec::new();

    for rs_file in &rs_files {
        let content = match std::fs::read_to_string(rs_file) {
            Ok(c) => c,
            Err(_) => continue,
        };

        let rel_path = rs_file
            .strip_prefix(project_root)
            .unwrap_or(rs_file)
            .to_path_buf();

        let imports = extract_imports(&content);
        let sites = find_call_sites(&rel_path, &content, &imports, symbols);
        all_sites.extend(sites);
    }

    all_sites
}

/// Extract `use` statements from Rust source code.
///
/// Handles common patterns:
/// - `use hyper::http::Request;`            → Request -> hyper::http::Request
/// - `use hyper::http::Request as Req;`     → Req -> hyper::http::Request
/// - `use hyper::http::{Request, Response};` → Request -> hyper::http::Request, etc.
/// - `use hyper::http::*;`                  → wildcard import of hyper::http
fn extract_imports(source: &str) -> Vec<Import> {
    let mut imports = Vec::new();

    // Simple use: `use foo::bar::Baz;` or `use foo::bar::Baz as Alias;`
    let simple_use_re = Regex::new(
        r"(?m)^\s*use\s+((?:[a-zA-Z_][a-zA-Z0-9_]*::)*[a-zA-Z_][a-zA-Z0-9_]*)(?:\s+as\s+([a-zA-Z_][a-zA-Z0-9_]*))?\s*;"
    ).unwrap();

    for caps in simple_use_re.captures_iter(source) {
        let full_path = caps[1].to_string();
        let local_name = caps
            .get(2)
            .map(|m| m.as_str().to_string())
            .unwrap_or_else(|| {
                full_path
                    .rsplit("::")
                    .next()
                    .unwrap_or(&full_path)
                    .to_string()
            });
        imports.push(Import {
            full_path,
            local_name,
        });
    }

    // Grouped use: `use foo::bar::{Baz, Qux as Q};`
    let group_use_re = Regex::new(
        r"(?m)^\s*use\s+((?:[a-zA-Z_][a-zA-Z0-9_]*::)*[a-zA-Z_][a-zA-Z0-9_]*)(?:::)?\{([^}]+)\}\s*;"
    ).unwrap();

    for caps in group_use_re.captures_iter(source) {
        let prefix = &caps[1];
        let items = &caps[2];
        for item in items.split(',') {
            let item = item.trim();
            if item.is_empty() || item == "*" || item == "self" {
                continue;
            }
            // Handle `Foo as Bar`
            let parts: Vec<&str> = item.splitn(2, " as ").collect();
            let name = parts[0].trim();
            let alias = if parts.len() > 1 {
                parts[1].trim()
            } else {
                name
            };
            // Handle nested paths like `sub::Item`
            let full = format!("{}::{}", prefix, name);
            let local = alias
                .rsplit("::")
                .next()
                .unwrap_or(alias)
                .to_string();
            imports.push(Import {
                full_path: full,
                local_name: local,
            });
        }
    }

    // Wildcard use: `use foo::bar::*;`
    let wildcard_re = Regex::new(
        r"(?m)^\s*use\s+((?:[a-zA-Z_][a-zA-Z0-9_]*::)*[a-zA-Z_][a-zA-Z0-9_]*)::\*\s*;"
    ).unwrap();

    for caps in wildcard_re.captures_iter(source) {
        imports.push(Import {
            full_path: format!("{}::*", &caps[1]),
            local_name: "*".to_string(),
        });
    }

    imports
}

/// Search source code for call patterns matching vulnerable symbols.
fn find_call_sites(
    file_path: &Path,
    source: &str,
    imports: &[Import],
    symbols: &[&str],
) -> Vec<CallSite> {
    let mut sites = Vec::new();

    // Build a lookup from local names to full paths via imports
    let import_map: HashMap<&str, &str> = imports
        .iter()
        .map(|i| (i.local_name.as_str(), i.full_path.as_str()))
        .collect();

    // Collect wildcard import prefixes
    let wildcard_prefixes: Vec<&str> = imports
        .iter()
        .filter(|i| i.local_name == "*")
        .map(|i| i.full_path.trim_end_matches("::*"))
        .collect();

    for &symbol in symbols {
        // Parse the symbol: e.g. "hyper::http::Request::parse"
        let parts: Vec<&str> = symbol.rsplitn(2, "::").collect();
        if parts.len() < 2 {
            continue;
        }
        let fn_name = parts[0]; // "parse"
        let parent_path = parts[1]; // "hyper::http::Request"

        // The type/module name is the last segment of parent_path
        let type_name = parent_path.rsplit("::").next().unwrap_or(parent_path);

        // Determine what local names could refer to this symbol
        let mut local_callers: Vec<String> = Vec::new();

        // 1. Fully qualified call: hyper::http::Request::parse(...)
        local_callers.push(symbol.to_string());

        // 2. After `use hyper::http::Request;` → Request::parse(...)
        for (local, full) in &import_map {
            if *full == parent_path {
                local_callers.push(format!("{}::{}", local, fn_name));
            }
        }

        // 3. After `use hyper::http::*;` → Request::parse(...)
        //    The parent of parent_path might be a wildcard import
        if let Some(grandparent) = parent_path.rsplit_once("::").map(|(p, _)| p) {
            if wildcard_prefixes.contains(&grandparent) {
                local_callers.push(format!("{}::{}", type_name, fn_name));
            }
        }

        // 4. After `use hyper::http::Request;` and calling as method: foo.parse(...)
        //    This is lower confidence since we can't verify the receiver type.
        let method_pattern = format!(".{}(", fn_name);

        // Check if the type is imported (needed for method call confidence)
        let type_is_imported = import_map.values().any(|&v| v == parent_path)
            || wildcard_prefixes.iter().any(|&wp| {
                parent_path
                    .rsplit_once("::")
                    .map(|(p, _)| p == wp)
                    .unwrap_or(false)
            });

        for (line_num, line) in source.lines().enumerate() {
            let trimmed = line.trim();

            // Skip comments
            if trimmed.starts_with("//") || trimmed.starts_with("/*") || trimmed.starts_with('*')
            {
                continue;
            }

            // Check for direct/qualified calls (High confidence)
            let found_high = local_callers.iter().any(|caller| {
                line.contains(caller.as_str())
            });

            if found_high {
                sites.push(CallSite {
                    file: file_path.to_path_buf(),
                    line: line_num + 1,
                    snippet: trimmed.to_string(),
                    symbol: symbol.to_string(),
                    confidence: Confidence::High,
                });
                continue;
            }

            // Check for method-style calls (Medium confidence)
            // Only flag if the type is imported in this file
            if type_is_imported && line.contains(&method_pattern) {
                sites.push(CallSite {
                    file: file_path.to_path_buf(),
                    line: line_num + 1,
                    snippet: trimmed.to_string(),
                    symbol: symbol.to_string(),
                    confidence: Confidence::Medium,
                });
            }
        }
    }

    // Deduplicate: same file+line should only appear once per symbol
    sites.sort_by(|a, b| {
        a.file
            .cmp(&b.file)
            .then(a.line.cmp(&b.line))
            .then(a.symbol.cmp(&b.symbol))
    });
    sites.dedup_by(|a, b| a.file == b.file && a.line == b.line && a.symbol == b.symbol);

    sites
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_simple_imports() {
        let source = r#"
use hyper::http::Request;
use tokio::sync::Mutex as TokioMutex;
use std::io;
"#;
        let imports = extract_imports(source);
        assert_eq!(imports.len(), 3);
        assert_eq!(imports[0].full_path, "hyper::http::Request");
        assert_eq!(imports[0].local_name, "Request");
        assert_eq!(imports[1].full_path, "tokio::sync::Mutex");
        assert_eq!(imports[1].local_name, "TokioMutex");
    }

    #[test]
    fn test_extract_grouped_imports() {
        let source = r#"
use hyper::http::{Request, Response};
"#;
        let imports = extract_imports(source);
        assert!(imports.iter().any(|i| i.full_path == "hyper::http::Request"
            && i.local_name == "Request"));
        assert!(imports.iter().any(|i| i.full_path == "hyper::http::Response"
            && i.local_name == "Response"));
    }

    #[test]
    fn test_extract_wildcard_imports() {
        let source = "use hyper::http::*;\n";
        let imports = extract_imports(source);
        assert!(imports.iter().any(|i| i.full_path == "hyper::http::*"
            && i.local_name == "*"));
    }

    #[test]
    fn test_find_high_confidence_qualified_call() {
        let source = r#"
use hyper::http::Request;

fn handler() {
    let req = Request::parse(buf);
}
"#;
        let imports = extract_imports(source);
        let sites = find_call_sites(
            Path::new("src/main.rs"),
            source,
            &imports,
            &["hyper::http::Request::parse"],
        );
        assert_eq!(sites.len(), 1);
        assert_eq!(sites[0].confidence, Confidence::High);
        assert_eq!(sites[0].line, 5);
        assert!(sites[0].snippet.contains("Request::parse"));
    }

    #[test]
    fn test_find_fully_qualified_call() {
        let source = r#"
fn handler() {
    let req = hyper::http::Request::parse(buf);
}
"#;
        let imports = extract_imports(source);
        let sites = find_call_sites(
            Path::new("src/main.rs"),
            source,
            &imports,
            &["hyper::http::Request::parse"],
        );
        assert_eq!(sites.len(), 1);
        assert_eq!(sites[0].confidence, Confidence::High);
    }

    #[test]
    fn test_find_method_call_medium_confidence() {
        let source = r#"
use hyper::http::Request;

fn handler(req: Request) {
    let result = req.parse(data);
}
"#;
        let imports = extract_imports(source);
        let sites = find_call_sites(
            Path::new("src/main.rs"),
            source,
            &imports,
            &["hyper::http::Request::parse"],
        );
        assert_eq!(sites.len(), 1);
        assert_eq!(sites[0].confidence, Confidence::Medium);
    }

    #[test]
    fn test_no_match_without_import() {
        // Method call `.parse()` without importing the type → no match
        let source = r#"
fn handler(s: String) {
    let n = s.parse(data);
}
"#;
        let imports = extract_imports(source);
        let sites = find_call_sites(
            Path::new("src/main.rs"),
            source,
            &imports,
            &["hyper::http::Request::parse"],
        );
        assert!(sites.is_empty());
    }

    #[test]
    fn test_wildcard_import_enables_type_call() {
        let source = r#"
use hyper::http::*;

fn handler() {
    let req = Request::parse(buf);
}
"#;
        let imports = extract_imports(source);
        let sites = find_call_sites(
            Path::new("src/main.rs"),
            source,
            &imports,
            &["hyper::http::Request::parse"],
        );
        assert_eq!(sites.len(), 1);
        assert_eq!(sites[0].confidence, Confidence::High);
    }

    #[test]
    fn test_skips_comments() {
        let source = r#"
use hyper::http::Request;

// Request::parse(buf) is vulnerable
fn handler() {
    // let req = Request::parse(buf);
}
"#;
        let imports = extract_imports(source);
        let sites = find_call_sites(
            Path::new("src/main.rs"),
            source,
            &imports,
            &["hyper::http::Request::parse"],
        );
        assert!(sites.is_empty());
    }
}
