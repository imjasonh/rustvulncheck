Here is a clean, self-contained architecture prompt you can copy and paste directly to your coding agent to kick off the project.
Context for Coding Agent
Project Goal: Build cargo deep-audit, a deterministic, reachability-based vulnerability scanner for Rust. It aims to achieve parity with Go's govulncheck by identifying if a known vulnerable function in a dependency is actually reachable from the user's code.
Constraints: No live LLM calls at runtime. The tool must be fast, deterministic, and run locally. Accept standard static analysis trade-offs (e.g., Rapid Type Analysis for dyn Trait, blind spots at FFI boundaries).
Architecture & Pipeline Overview
The system consists of three distinct phases. We are currently focusing on MVP execution starting with Phase 1.
Phase 1: Offline Database Enrichment (The Target for MVP)
Objective: Translate crate-level vulnerability data into function-level signatures.
 * Input: The official RustSec Advisory Database (github.com/RustSec/advisory-db), which stores vulnerabilities as TOML files with crate names, patched versions, and PR/Issue URLs.
 * Process:
   * Parse the TOML files to extract the crate, patched version/commit, and vulnerability ID.
   * Query the GitHub API or local git diffs to isolate the exact commit that patched the vulnerability.
   * Analyze the diff to extract the fully qualified signatures of the modified functions (e.g., hyper::http::Request::parse).
 * Output: A lightweight JSON or SQLite database mapping CVE IDs to specific crate::module::function signatures.
Phase 2: Static Analysis Engine (Call Graph Extractor)
Objective: Deterministically map the execution paths of a target Rust codebase.
 * Tech Stack: Use the rust-analyzer API crates (e.g., ra_ap_hir, ra_ap_ide) to parse the target codebase without requiring a full rustc compilation step.
 * Process:
   * Ingest the user's Rust project and expand all macros.
   * Build a comprehensive call graph from the entry points (main, public library functions) down through the dependency tree.
   * Implement Rapid Type Analysis (RTA) for dynamic dispatch: if a method on dyn Trait is called, draw edges to all concrete types in the binary that implement that trait.
Phase 3: CLI Orchestrator (cargo deep-audit)
Objective: The user-facing tool that glues the DB and Engine together.
 * Tech Stack: Rust (clap for CLI, cargo_metadata for dependency resolution).
 * Execution Flow:
   * Parse the user's Cargo.lock to find the exact dependency tree.
   * Download/load the Enriched Vulnerability Database (from Phase 1).
   * Filter the DB for crates that exist in the user's lockfile.
   * Run the Static Analysis Engine (Phase 2) to search the call graph for paths terminating at the vulnerable_symbols identified in the DB.
   * Print the full execution path to stdout if a match is found.
First Task for Agent
Begin building the Phase 1 Offline Database Enrichment pipeline. Write a script that clones the RustSec/advisory-db repository, parses the TOML files, and successfully pulls the associated git patch diffs via the GitHub API for a test batch of 10 recent advisories.
Would you like me to write the initial starter code for that first Phase 1 script (either in Python or Rust) so you have a solid foundation to hand over along with the prompt?
