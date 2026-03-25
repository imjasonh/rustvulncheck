//! AST-based symbol extraction using `syn`.
//!
//! Instead of regex-matching unified diff lines, this module parses
//! the before/after Rust source files into ASTs and diffs the function
//! sets to precisely identify Added, Modified, and Deleted symbols.

use std::collections::{HashMap, HashSet};

use syn::visit::Visit;
use syn::{ItemFn, ItemImpl, ItemMod, ImplItemFn};

use crate::diff_analyzer::{ChangeType, VulnerableSymbol};

/// A function symbol extracted from a parsed AST.
#[derive(Debug, Clone)]
pub struct FnSymbol {
    /// Fully qualified name: `module::Type::method` or `module::free_fn`
    qualified_name: String,
    /// Hash of the function body tokens for detecting modifications
    body_hash: u64,
}

/// Extract all function symbols from a Rust source string.
///
/// Parses the source with `syn::parse_file` and walks the AST to find
/// all `fn` items, including methods inside `impl` blocks. Returns
/// `None` if parsing fails.
pub fn extract_fn_symbols(source: &str, module_path: &str) -> Option<Vec<FnSymbol>> {
    let file = syn::parse_file(source).ok()?;
    let mut visitor = SymbolVisitor {
        module_path: module_path.to_string(),
        impl_type_stack: Vec::new(),
        in_test: false,
        symbols: Vec::new(),
    };
    visitor.visit_file(&file);
    Some(visitor.symbols)
}

/// Diff two sets of function symbols to produce VulnerableSymbol entries.
///
/// - Functions in `after` but not `before`: Added
/// - Functions in `before` but not `after`: Deleted
/// - Functions in both but with different body hashes: Modified
/// - Functions unchanged: omitted
pub fn diff_symbols(
    before: &[FnSymbol],
    after: &[FnSymbol],
    file_path: &str,
) -> Vec<VulnerableSymbol> {
    let before_map: HashMap<&str, &FnSymbol> = before
        .iter()
        .map(|s| (s.qualified_name.as_str(), s))
        .collect();
    let after_map: HashMap<&str, &FnSymbol> = after
        .iter()
        .map(|s| (s.qualified_name.as_str(), s))
        .collect();

    let before_names: HashSet<&str> = before_map.keys().copied().collect();
    let after_names: HashSet<&str> = after_map.keys().copied().collect();

    let mut results = Vec::new();

    // Added: in after but not before
    for name in after_names.difference(&before_names) {
        results.push(VulnerableSymbol {
            file: file_path.to_string(),
            function: name.to_string(),
            change_type: ChangeType::Added,
        });
    }

    // Deleted: in before but not after
    for name in before_names.difference(&after_names) {
        results.push(VulnerableSymbol {
            file: file_path.to_string(),
            function: name.to_string(),
            change_type: ChangeType::Deleted,
        });
    }

    // Modified: in both but with different body hash
    for name in before_names.intersection(&after_names) {
        let b = before_map[name];
        let a = after_map[name];
        if b.body_hash != a.body_hash {
            results.push(VulnerableSymbol {
                file: file_path.to_string(),
                function: name.to_string(),
                change_type: ChangeType::Modified,
            });
        }
    }

    // Sort for deterministic output: by file, then function, then change_type
    results.sort_by(|a, b| {
        a.file
            .cmp(&b.file)
            .then(a.function.cmp(&b.function))
            .then(a.change_type.cmp(&b.change_type))
    });

    results
}

/// Extract symbols from before/after source and diff them.
/// Returns `None` if either file fails to parse.
pub fn ast_diff_symbols(
    before_source: Option<&str>,
    after_source: Option<&str>,
    module_path: &str,
    file_path: &str,
) -> Option<Vec<VulnerableSymbol>> {
    match (before_source, after_source) {
        (Some(before), Some(after)) => {
            let before_syms = extract_fn_symbols(before, module_path)?;
            let after_syms = extract_fn_symbols(after, module_path)?;
            Some(diff_symbols(&before_syms, &after_syms, file_path))
        }
        (None, Some(after)) => {
            // New file — all functions are Added
            let after_syms = extract_fn_symbols(after, module_path)?;
            Some(
                after_syms
                    .into_iter()
                    .map(|s| VulnerableSymbol {
                        file: file_path.to_string(),
                        function: s.qualified_name,
                        change_type: ChangeType::Added,
                    })
                    .collect(),
            )
        }
        (Some(before), None) => {
            // Deleted file — all functions are Deleted
            let before_syms = extract_fn_symbols(before, module_path)?;
            Some(
                before_syms
                    .into_iter()
                    .map(|s| VulnerableSymbol {
                        file: file_path.to_string(),
                        function: s.qualified_name,
                        change_type: ChangeType::Deleted,
                    })
                    .collect(),
            )
        }
        (None, None) => Some(Vec::new()),
    }
}

// ── AST Visitor ──────────────────────────────────────────────────────

struct SymbolVisitor {
    module_path: String,
    /// Stack of impl type names (for nested impls, though rare in practice)
    impl_type_stack: Vec<String>,
    /// Whether we're inside a #[cfg(test)] module
    in_test: bool,
    symbols: Vec<FnSymbol>,
}

impl SymbolVisitor {
    /// Build the fully qualified name for a function.
    fn qualify(&self, fn_name: &str) -> String {
        let mut parts: Vec<&str> = Vec::new();
        if !self.module_path.is_empty() {
            parts.push(&self.module_path);
        }
        if let Some(impl_type) = self.impl_type_stack.last() {
            parts.push(impl_type);
        }
        parts.push(fn_name);
        parts.join("::")
    }

    /// Check if an item has #[test] or #[cfg(test)] attributes.
    fn has_test_attr(attrs: &[syn::Attribute]) -> bool {
        for attr in attrs {
            if attr.path().is_ident("test") {
                return true;
            }
            if attr.path().is_ident("cfg") {
                // Check for #[cfg(test)]
                let tokens = attr.meta.to_token_stream().to_string();
                if tokens.contains("test") {
                    return true;
                }
            }
        }
        false
    }

    /// Extract a simple type name from a syn::Type, stripping generics.
    fn type_name(ty: &syn::Type) -> Option<String> {
        match ty {
            syn::Type::Path(type_path) => {
                // Use the last segment's ident (e.g., for `std::convert::From<T>` → `From`,
                // but for `MyStruct<T>` → `MyStruct`)
                let last = type_path.path.segments.last()?;
                Some(last.ident.to_string())
            }
            syn::Type::Reference(type_ref) => Self::type_name(&type_ref.elem),
            _ => None,
        }
    }

    /// Hash function body tokens for modification detection.
    fn hash_body(block: &syn::Block) -> u64 {
        use std::hash::{Hash, Hasher};
        // Use the token stream string as the hash input.
        // This normalizes whitespace but preserves semantics.
        let tokens = block.to_token_stream().to_string();
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        tokens.hash(&mut hasher);
        hasher.finish()
    }

    fn record_fn(&mut self, name: &str, attrs: &[syn::Attribute], body: &syn::Block) {
        // Skip test functions
        if Self::has_test_attr(attrs) || name.starts_with("test_") {
            return;
        }
        if self.in_test {
            return;
        }

        self.symbols.push(FnSymbol {
            qualified_name: self.qualify(name),
            body_hash: Self::hash_body(body),
        });
    }
}

impl<'ast> Visit<'ast> for SymbolVisitor {
    fn visit_item_fn(&mut self, node: &'ast ItemFn) {
        let name = node.sig.ident.to_string();
        self.record_fn(&name, &node.attrs, &node.block);
        // Don't recurse into nested items — we handle those at the top level
    }

    fn visit_item_impl(&mut self, node: &'ast ItemImpl) {
        // For `impl Trait for Type`, use Type (self_ty), not Trait.
        // For `impl Type`, also use self_ty. syn gives us exactly the right field.
        if let Some(type_name) = Self::type_name(&node.self_ty) {
            self.impl_type_stack.push(type_name);

            // Visit each method in the impl block
            for item in &node.items {
                if let syn::ImplItem::Fn(method) = item {
                    self.visit_impl_item_fn(method);
                }
            }

            self.impl_type_stack.pop();
        }
        // Don't call the default visit — we manually visited methods above
    }

    fn visit_impl_item_fn(&mut self, node: &'ast ImplItemFn) {
        let name = node.sig.ident.to_string();
        self.record_fn(&name, &node.attrs, &node.block);
    }

    fn visit_item_mod(&mut self, node: &'ast ItemMod) {
        // Skip #[cfg(test)] modules entirely
        if Self::has_test_attr(&node.attrs) {
            return;
        }

        // Recurse into inline modules (those with `mod foo { ... }`)
        if let Some((_, items)) = &node.content {
            let old_module = self.module_path.clone();
            let mod_name = node.ident.to_string();
            self.module_path = if self.module_path.is_empty() {
                mod_name
            } else {
                format!("{}::{}", self.module_path, mod_name)
            };

            for item in items {
                self.visit_item(item);
            }

            self.module_path = old_module;
        }
    }
}

use quote::ToTokens;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_simple_fn() {
        let source = r#"
            pub fn hello() {
                println!("hello");
            }
        "#;
        let symbols = extract_fn_symbols(source, "mymod").unwrap();
        assert_eq!(symbols.len(), 1);
        assert_eq!(symbols[0].qualified_name, "mymod::hello");
    }

    #[test]
    fn test_extract_impl_methods() {
        let source = r#"
            struct Request;
            impl Request {
                pub fn parse(buf: &[u8]) -> Self { Request }
                fn internal() {}
            }
        "#;
        let symbols = extract_fn_symbols(source, "http::request").unwrap();
        assert_eq!(symbols.len(), 2);
        let names: Vec<&str> = symbols.iter().map(|s| s.qualified_name.as_str()).collect();
        assert!(names.contains(&"http::request::Request::parse"));
        assert!(names.contains(&"http::request::Request::internal"));
    }

    #[test]
    fn test_trait_impl_uses_type_not_trait() {
        // This is the key test — impl Trait for Type should use Type
        let source = r#"
            struct PyObject;
            impl<T> From<T> for PyObject {
                fn from(val: T) -> Self { PyObject }
            }
        "#;
        let symbols = extract_fn_symbols(source, "instance").unwrap();
        assert_eq!(symbols.len(), 1);
        assert_eq!(
            symbols[0].qualified_name, "instance::PyObject::from",
            "Should use implementing type (PyObject), not trait (From)"
        );
    }

    #[test]
    fn test_complex_generics_no_leak() {
        // impl<T> From<Py<T>> for PyObject where T: AsRef<PyAny>
        let source = r#"
            struct PyObject;
            struct Py<T>(T);
            trait AsRef<T> {}
            impl<T> From<Py<T>> for PyObject where T: AsRef<PyObject> {
                fn from(val: Py<T>) -> Self { PyObject }
            }
        "#;
        let symbols = extract_fn_symbols(source, "instance").unwrap();
        assert_eq!(symbols.len(), 1);
        let name = &symbols[0].qualified_name;
        assert!(
            !name.contains("for "),
            "No 'for' leak: got '{}'", name
        );
        assert!(
            !name.contains("where"),
            "No 'where' leak: got '{}'", name
        );
        assert_eq!(name, "instance::PyObject::from");
    }

    #[test]
    fn test_test_functions_skipped() {
        let source = r#"
            pub fn real_function() {}

            #[test]
            fn test_something() {}

            fn test_other_thing() {}
        "#;
        let symbols = extract_fn_symbols(source, "").unwrap();
        assert_eq!(symbols.len(), 1);
        assert_eq!(symbols[0].qualified_name, "real_function");
    }

    #[test]
    fn test_cfg_test_module_skipped() {
        let source = r#"
            pub fn real_function() {}

            #[cfg(test)]
            mod tests {
                fn helper() {}
                #[test]
                fn test_it() {}
            }
        "#;
        let symbols = extract_fn_symbols(source, "mymod").unwrap();
        assert_eq!(symbols.len(), 1);
        assert_eq!(symbols[0].qualified_name, "mymod::real_function");
    }

    #[test]
    fn test_diff_added_deleted_modified() {
        let before = vec![
            FnSymbol { qualified_name: "foo".into(), body_hash: 100 },
            FnSymbol { qualified_name: "bar".into(), body_hash: 200 },
            FnSymbol { qualified_name: "old_fn".into(), body_hash: 300 },
        ];
        let after = vec![
            FnSymbol { qualified_name: "foo".into(), body_hash: 100 }, // unchanged
            FnSymbol { qualified_name: "bar".into(), body_hash: 999 }, // modified
            FnSymbol { qualified_name: "new_fn".into(), body_hash: 400 }, // added
        ];

        let result = diff_symbols(&before, &after, "src/lib.rs");

        let added: Vec<_> = result.iter().filter(|s| matches!(s.change_type, ChangeType::Added)).collect();
        let deleted: Vec<_> = result.iter().filter(|s| matches!(s.change_type, ChangeType::Deleted)).collect();
        let modified: Vec<_> = result.iter().filter(|s| matches!(s.change_type, ChangeType::Modified)).collect();

        assert_eq!(added.len(), 1);
        assert_eq!(added[0].function, "new_fn");

        assert_eq!(deleted.len(), 1);
        assert_eq!(deleted[0].function, "old_fn");

        assert_eq!(modified.len(), 1);
        assert_eq!(modified[0].function, "bar");

        // foo is unchanged — should NOT appear
        assert!(!result.iter().any(|s| s.function == "foo"));
    }

    #[test]
    fn test_ast_diff_end_to_end() {
        let before_src = r#"
            struct Decoder;
            impl Decoder {
                pub fn decode(buf: &[u8]) -> Self { Decoder }
                fn old_helper() {}
            }
        "#;
        let after_src = r#"
            struct Decoder;
            impl Decoder {
                pub fn decode(buf: &[u8]) -> Self {
                    let x = 1;
                    Decoder
                }
                fn new_helper() {}
            }
        "#;

        let result = ast_diff_symbols(
            Some(before_src),
            Some(after_src),
            "proto::h1",
            "src/proto/h1/decode.rs",
        )
        .unwrap();

        let names: Vec<(&str, &ChangeType)> = result
            .iter()
            .map(|s| (s.function.as_str(), &s.change_type))
            .collect();

        assert!(names.iter().any(|(n, t)| *n == "proto::h1::Decoder::decode" && matches!(t, ChangeType::Modified)));
        assert!(names.iter().any(|(n, t)| *n == "proto::h1::Decoder::old_helper" && matches!(t, ChangeType::Deleted)));
        assert!(names.iter().any(|(n, t)| *n == "proto::h1::Decoder::new_helper" && matches!(t, ChangeType::Added)));
    }
}
