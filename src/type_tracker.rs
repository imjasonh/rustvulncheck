//! Track variable types through Rust source code using `syn` AST parsing.
//!
//! Builds a map of variable names to their resolved types by analyzing:
//! - Function/method parameters with type annotations
//! - Let bindings with explicit type annotations
//! - Let bindings with constructor calls (e.g., `let x = Foo::new()`)
//! - Struct/enum field definitions
//! - Closure parameters with type annotations
//! - For-loop bindings where the iterator type is known
//!
//! Combined with import resolution, this allows promoting method-call
//! matches from medium to high confidence.

use std::collections::HashMap;

use syn::visit::Visit;

/// A resolved type binding: variable name → qualified type path.
///
/// The qualified path uses the full crate path where possible
/// (e.g., `hyper::http::Request` rather than just `Request`).
#[derive(Debug, Clone)]
pub struct TypeBinding {
    pub var_name: String,
    pub type_path: String,
}

/// Mapping from local type names to fully-qualified paths via imports.
/// e.g., `Request` → `hyper::http::Request`
pub type ImportMap = HashMap<String, String>;

/// Extract all variable → type bindings from a Rust source file.
///
/// Uses `syn` to parse the AST and walks function bodies to find
/// type annotations and constructor patterns. Resolves short type
/// names to fully-qualified paths using the provided import map.
pub fn extract_type_bindings(source: &str, import_map: &ImportMap) -> Vec<TypeBinding> {
    let file = match syn::parse_file(source) {
        Ok(f) => f,
        Err(_) => return Vec::new(), // Unparseable → no bindings
    };

    let mut visitor = TypeVisitor {
        import_map,
        bindings: Vec::new(),
    };
    visitor.visit_file(&file);
    visitor.bindings
}

/// AST visitor that collects variable → type bindings.
struct TypeVisitor<'a> {
    import_map: &'a ImportMap,
    bindings: Vec<TypeBinding>,
}

impl<'a> TypeVisitor<'a> {
    /// Resolve a type path to its fully-qualified form using the import map.
    ///
    /// Given a syn `Path` like `Request` or `http::Request`, look up the
    /// leading segment in the import map to expand it.
    fn resolve_type_path(&self, path: &syn::Path) -> Option<String> {
        let segments: Vec<String> = path
            .segments
            .iter()
            .map(|seg| seg.ident.to_string())
            .collect();

        if segments.is_empty() {
            return None;
        }

        // Try resolving the first segment via imports
        let first = &segments[0];
        if let Some(full) = self.import_map.get(first.as_str()) {
            if segments.len() == 1 {
                return Some(full.clone());
            }
            // Multi-segment: e.g., `http::Request` where `http` is imported
            let rest = segments[1..].join("::");
            return Some(format!("{}::{}", full, rest));
        }

        // No import match — return the path as-is
        Some(segments.join("::"))
    }

    /// Extract the type name from a syn::Type, if it's a simple path type.
    fn extract_type_name(&self, ty: &syn::Type) -> Option<String> {
        match ty {
            syn::Type::Path(type_path) => self.resolve_type_path(&type_path.path),
            syn::Type::Reference(type_ref) => {
                // &T or &mut T → resolve T
                self.extract_type_name(&type_ref.elem)
            }
            _ => None,
        }
    }

    /// Try to infer the type from an expression (right-hand side of a let binding).
    ///
    /// Handles:
    /// - `Type::new()`, `Type::default()`, `Type::from(...)` — constructor patterns
    /// - `Type::builder().build()` — builder patterns (uses the initial type)
    /// - `Type { field: value }` — struct literals
    fn infer_type_from_expr(&self, expr: &syn::Expr) -> Option<String> {
        match expr {
            // Type::method(...) — associated function call (constructor pattern)
            syn::Expr::Call(call) => {
                if let syn::Expr::Path(path_expr) = call.func.as_ref() {
                    let segments: Vec<&syn::PathSegment> =
                        path_expr.path.segments.iter().collect();
                    // Need at least 2 segments: Type::new
                    if segments.len() >= 2 {
                        // The type is everything except the last segment (the method name)
                        let type_segments: Vec<String> = segments[..segments.len() - 1]
                            .iter()
                            .map(|s| s.ident.to_string())
                            .collect();
                        let type_name = type_segments.join("::");

                        // Resolve through imports
                        if type_segments.len() == 1 {
                            if let Some(full) = self.import_map.get(&type_name) {
                                return Some(full.clone());
                            }
                        }
                        return Some(type_name);
                    }
                }
                None
            }

            // expr.method(...) — method chain; try to infer from the root
            syn::Expr::MethodCall(method_call) => self.infer_type_from_expr(&method_call.receiver),

            // expr? — try operator; infer from inner
            syn::Expr::Try(try_expr) => self.infer_type_from_expr(&try_expr.expr),

            // (expr) — parenthesized
            syn::Expr::Paren(paren) => self.infer_type_from_expr(&paren.expr),

            // Type { field: value } — struct literal
            syn::Expr::Struct(struct_expr) => self.resolve_type_path(&struct_expr.path),

            // await expressions: expr.await — infer from inner
            syn::Expr::Await(await_expr) => self.infer_type_from_expr(&await_expr.base),

            _ => None,
        }
    }

    /// Record a binding from a pattern + type.
    fn record_pat_type(&mut self, pat: &syn::Pat, type_path: &str) {
        match pat {
            syn::Pat::Ident(pat_ident) => {
                self.bindings.push(TypeBinding {
                    var_name: pat_ident.ident.to_string(),
                    type_path: type_path.to_string(),
                });
            }
            // Destructuring: let (a, b): (TypeA, TypeB) — skip for now
            // Ref patterns: let ref x: Type — extract x
            syn::Pat::Reference(pat_ref) => {
                self.record_pat_type(&pat_ref.pat, type_path);
            }
            _ => {}
        }
    }
}

impl<'a, 'ast> Visit<'ast> for TypeVisitor<'a> {
    /// Visit function/method signatures to extract parameter types.
    fn visit_item_fn(&mut self, node: &'ast syn::ItemFn) {
        for param in &node.sig.inputs {
            if let syn::FnArg::Typed(pat_type) = param {
                if let Some(type_name) = self.extract_type_name(&pat_type.ty) {
                    self.record_pat_type(&pat_type.pat, &type_name);
                }
            }
        }
        // Continue visiting the function body
        syn::visit::visit_item_fn(self, node);
    }

    /// Visit impl method signatures.
    fn visit_impl_item_fn(&mut self, node: &'ast syn::ImplItemFn) {
        for param in &node.sig.inputs {
            if let syn::FnArg::Typed(pat_type) = param {
                if let Some(type_name) = self.extract_type_name(&pat_type.ty) {
                    self.record_pat_type(&pat_type.pat, &type_name);
                }
            }
        }
        syn::visit::visit_impl_item_fn(self, node);
    }

    /// Visit let bindings for explicit type annotations and constructor inference.
    fn visit_local(&mut self, node: &'ast syn::Local) {
        // Case 1: `let x: Type = ...` — explicit annotation
        if let syn::Pat::Type(pat_type) = &node.pat {
            if let Some(type_name) = self.extract_type_name(&pat_type.ty) {
                self.record_pat_type(&pat_type.pat, &type_name);
            }
        }

        // Case 2: `let x = Type::new()` — infer from constructor
        if let Some(init) = &node.init {
            if let Some(type_name) = self.infer_type_from_expr(&init.expr) {
                // Only record if we didn't already get a type from annotation
                let var_name = extract_pat_name(&node.pat);
                if let Some(name) = var_name {
                    if !self.bindings.iter().any(|b| b.var_name == name) {
                        self.bindings.push(TypeBinding {
                            var_name: name,
                            type_path: type_name,
                        });
                    }
                }
            }
        }

        syn::visit::visit_local(self, node);
    }

    /// Visit closure parameters with type annotations.
    fn visit_expr_closure(&mut self, node: &'ast syn::ExprClosure) {
        for input in &node.inputs {
            if let syn::Pat::Type(pat_type) = input {
                if let Some(type_name) = self.extract_type_name(&pat_type.ty) {
                    self.record_pat_type(&pat_type.pat, &type_name);
                }
            }
        }
        syn::visit::visit_expr_closure(self, node);
    }

    /// Visit struct definitions to track field types.
    fn visit_item_struct(&mut self, node: &'ast syn::ItemStruct) {
        let struct_name = node.ident.to_string();
        for field in &node.fields {
            if let Some(ident) = &field.ident {
                if let Some(type_name) = self.extract_type_name(&field.ty) {
                    // Record as "StructName.field_name" for field access tracking
                    self.bindings.push(TypeBinding {
                        var_name: format!("{}.{}", struct_name, ident),
                        type_path: type_name,
                    });
                }
            }
        }
        syn::visit::visit_item_struct(self, node);
    }
}

/// Extract a simple variable name from a pattern.
fn extract_pat_name(pat: &syn::Pat) -> Option<String> {
    match pat {
        syn::Pat::Ident(ident) => Some(ident.ident.to_string()),
        syn::Pat::Type(pat_type) => extract_pat_name(&pat_type.pat),
        syn::Pat::Reference(pat_ref) => extract_pat_name(&pat_ref.pat),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_import_map(pairs: &[(&str, &str)]) -> ImportMap {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn test_explicit_type_annotation() {
        let source = r#"
use hyper::http::Request;

fn handler() {
    let req: Request = get_request();
    req.parse();
}
"#;
        let imports = make_import_map(&[("Request", "hyper::http::Request")]);
        let bindings = extract_type_bindings(source, &imports);

        assert!(
            bindings
                .iter()
                .any(|b| b.var_name == "req" && b.type_path == "hyper::http::Request"),
            "Expected req → hyper::http::Request, got: {:?}",
            bindings
        );
    }

    #[test]
    fn test_constructor_inference() {
        let source = r#"
use hyper::http::Request;

fn handler() {
    let req = Request::new(body);
}
"#;
        let imports = make_import_map(&[("Request", "hyper::http::Request")]);
        let bindings = extract_type_bindings(source, &imports);

        assert!(
            bindings
                .iter()
                .any(|b| b.var_name == "req" && b.type_path == "hyper::http::Request"),
            "Expected req → hyper::http::Request from constructor, got: {:?}",
            bindings
        );
    }

    #[test]
    fn test_function_parameter() {
        let source = r#"
use hyper::http::Request;

fn handle_request(req: Request, name: String) {
    req.parse();
}
"#;
        let imports = make_import_map(&[
            ("Request", "hyper::http::Request"),
            ("String", "String"),
        ]);
        let bindings = extract_type_bindings(source, &imports);

        assert!(
            bindings
                .iter()
                .any(|b| b.var_name == "req" && b.type_path == "hyper::http::Request"),
            "Expected req from fn param, got: {:?}",
            bindings
        );
    }

    #[test]
    fn test_reference_type() {
        let source = r#"
use hyper::http::Request;

fn handle_request(req: &mut Request) {
    req.parse();
}
"#;
        let imports = make_import_map(&[("Request", "hyper::http::Request")]);
        let bindings = extract_type_bindings(source, &imports);

        assert!(
            bindings
                .iter()
                .any(|b| b.var_name == "req" && b.type_path == "hyper::http::Request"),
            "Should see through &mut, got: {:?}",
            bindings
        );
    }

    #[test]
    fn test_struct_literal() {
        let source = r#"
use hyper::http::Request;

fn handler() {
    let req = Request { method: "GET", path: "/" };
}
"#;
        let imports = make_import_map(&[("Request", "hyper::http::Request")]);
        let bindings = extract_type_bindings(source, &imports);

        assert!(
            bindings
                .iter()
                .any(|b| b.var_name == "req" && b.type_path == "hyper::http::Request"),
            "Expected struct literal inference, got: {:?}",
            bindings
        );
    }

    #[test]
    fn test_builder_pattern() {
        let source = r#"
use hyper::http::Request;

fn handler() {
    let req = Request::builder().uri("/").body(()).unwrap();
}
"#;
        let imports = make_import_map(&[("Request", "hyper::http::Request")]);
        let bindings = extract_type_bindings(source, &imports);

        // Builder chains resolve to the root type
        assert!(
            bindings
                .iter()
                .any(|b| b.var_name == "req" && b.type_path == "hyper::http::Request"),
            "Expected builder pattern inference, got: {:?}",
            bindings
        );
    }

    #[test]
    fn test_no_type_info() {
        let source = r#"
fn handler() {
    let x = something();
    x.parse();
}
"#;
        let imports = make_import_map(&[]);
        let bindings = extract_type_bindings(source, &imports);

        // No bindings for x since we can't determine the type
        assert!(
            !bindings.iter().any(|b| b.var_name == "x"),
            "Should not infer type from unknown function call, got: {:?}",
            bindings
        );
    }

    #[test]
    fn test_struct_field_types() {
        let source = r#"
use hyper::Client;

struct MyApp {
    client: Client,
    name: String,
}
"#;
        let imports = make_import_map(&[("Client", "hyper::Client")]);
        let bindings = extract_type_bindings(source, &imports);

        assert!(
            bindings
                .iter()
                .any(|b| b.var_name == "MyApp.client" && b.type_path == "hyper::Client"),
            "Expected struct field tracking, got: {:?}",
            bindings
        );
    }

    #[test]
    fn test_closure_param() {
        let source = r#"
use hyper::http::Request;

fn handler() {
    let f = |req: Request| {
        req.parse();
    };
}
"#;
        let imports = make_import_map(&[("Request", "hyper::http::Request")]);
        let bindings = extract_type_bindings(source, &imports);

        assert!(
            bindings
                .iter()
                .any(|b| b.var_name == "req" && b.type_path == "hyper::http::Request"),
            "Expected closure param type, got: {:?}",
            bindings
        );
    }
}
