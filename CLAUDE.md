# CLAUDE.md

## What is this?

`rustvulncheck` (binary: `cargo-deep-audit`) is a reachability-based vulnerability scanner for Rust, inspired by Go's `govulncheck`. Instead of just flagging vulnerable dependencies, it identifies the specific vulnerable *functions* and checks whether your code actually calls them.

## Architecture

Three-phase pipeline:

1. **Enrich** (`cargo-deep-audit enrich`): Parses RustSec advisory TOML files, fetches the fixing commit from GitHub, extracts modified function symbols from the diff, and writes an enriched `vuln_db.json`.
2. **Analyze** (`cargo-deep-audit analyze`): Parses a project's `Cargo.lock`, cross-references locked versions against `vuln_db.json`, then scans source files for calls to vulnerable symbols.
3. **CLI**: Orchestrates the above via `clap` subcommands.

## Key files

- `src/main.rs` — CLI entry point, `enrich` and `analyze` subcommands
- `src/advisory.rs` — RustSec TOML parser
- `src/diff_analyzer.rs` — Extracts function symbols from unified diffs
- `src/scanner.rs` — Finds call sites of vulnerable symbols in source code
- `src/type_tracker.rs` — Variable type inference (using `syn`) to improve call-site confidence
- `src/analyzer.rs` — Phase 2 orchestrator: version matching + symbol scanning
- `src/github.rs` — GitHub API client for fetching patch diffs
- `src/lockfile.rs` — `Cargo.lock` parser
- `src/db.rs` — `VulnDb` serialization/deserialization
- `vuln_db.json` — The enriched vulnerability database (642 entries)

## Commands

```bash
# Build
cargo build

# Run tests
cargo test

# Phase 1: Enrich database from RustSec advisory-db
cargo-deep-audit enrich \
  --advisory-db /path/to/advisory-db \
  --output vuln_db.json \
  --github-token <token> \
  [--limit N] [--include-all] [--existing-db existing.json] \
  [--re-enrich] [--timeout-secs N]

# Phase 2: Analyze a project
cargo-deep-audit analyze \
  --project /path/to/rust/project \
  --db vuln_db.json
```

## Test fixtures

- `tests/fixtures/vulnerable_project/` — Golden test, expects 4 reachable vulns
- `tests/fixtures/safe_project/` — Expects 0 reachable vulns
- `tests/fixtures/edge_cases_project/` — Tests false positives, comments, aliasing
- `tests/fixtures/test_project/` — Basic integration test

## vuln_db.json structure

```json
{
  "generated_at": "unix:<timestamp>",
  "entries": [{
    "advisory_id": "RUSTSEC-2026-XXXX",
    "package": "crate-name",
    "title": "...",
    "date": "YYYY-MM-DD",
    "patched_versions": [">= X.Y.Z"],
    "commit_sha": "abc123...",
    "vulnerable_symbols": [{
      "file": "src/module/file.rs",
      "function": "crate::module::Type::method",
      "change_type": "Modified|Added|Deleted"
    }]
  }]
}
```

## Known issues with symbol extraction

The diff-based symbol extraction in `diff_analyzer.rs` has several known limitations:

- **`<method>` placeholders** (~90 entries): When the fn declaration is too far from the diff hunk for git to include in the header, the tool falls back to `Type::<method>` which loses precision.
- **`for` keyword leaking** (~14 entries): The `impl_re` regex's greedy `<.*>` can over-match nested generics in `impl<T> Trait for Type`, causing `for Type` to appear in the symbol (e.g., `instance::for PyObject::from`).
- **`where` clause leaking** (~5 entries): Similar regex issue where `where` bounds bleed into the type capture.
- **Test functions included** (~39 entries): `#[cfg(test)]` functions inside library source files pass the `is_test_file` check (which only filters by file path, not attributes).
- **Missing crate name prefix**: For non-workspace repos, `src/foo/bar.rs` becomes `foo::bar` instead of `crate_name::foo::bar` since the crate name isn't in the file path.
- **Empty symbol lists** (~495 of 642 entries): Many advisories lack GitHub commit references or the diffs don't yield extractable symbols.
