# Lessons Learned from Spot-Checking vuln_db.json

## Summary

A spot-check of the enriched vulnerability database (642 entries, 147 with symbols) uncovered three classes of bugs in `diff_analyzer.rs`, all now fixed with regression tests.

## Bug 1: `for` keyword leaking into symbol names (~14 entries)

**Symptom:** Symbols like `instance::for PyObject::from` instead of `instance::PyObject::from`.

**Root cause:** The `impl_re` regex used `(?:<.*>)?` to skip generic params after `impl`. The greedy `.*` matched across nested `<>` brackets. For `impl<T> From<Py<T>> for PyObject`, the `<.*>` consumed `<T> From<Py<T>>` (everything up to the *last* `>`), leaving ` for PyObject` as the "type" capture.

**Fix:** Replaced the regex-based impl parser with `parse_impl_type()`, which uses bracket-counting (`skip_balanced_angles`) to correctly handle nested generics, then finds ` for ` only at the top level (not inside `<>`).

**Lesson:** Greedy regex quantifiers inside delimiter pairs (`<.*>`) are a classic source of over-matching when the delimiters can nest. Use iterative bracket-counting instead.

## Bug 2: `where` clause leaking into symbol names (~5 entries)

**Symptom:** Symbols like `lock_api::mutex::where::<method>` or `array::where T: HasAfEnum::get_backend`.

**Root cause:** Same as Bug 1 — the regex type capture `([a-zA-Z_][a-zA-Z0-9_:<>, ]*)` included spaces and continued matching through `where` clauses. Even after generics were (incorrectly) consumed, the remaining text was slurped into the type name.

**Fix:** The new `parse_impl_type()` uses `find_top_level_keyword(type_str, " where ")` to stop the type capture at `where` clauses, again only at the top bracket-nesting level.

**Lesson:** When parsing structured syntax, stop-conditions matter as much as start-conditions. The type name capture needed explicit terminators (` where `, `{`, newline).

## Bug 3: Test functions included in symbols (~39 entries)

**Symptom:** Symbols like `pycell::impl_::test_inherited_size` or `fyrox_core::test_combine_uuids` appearing as "vulnerable symbols" even though they're test functions.

**Root cause:** The `is_test_file()` filter only checked file paths (`tests/`, `*_test.rs`, etc.). Functions marked with `#[test]` or `#[cfg(test)]` inside library source files (`src/lib.rs`, `src/pycell/impl_.rs`, etc.) were not caught.

**Fix:** Added two filters in `extract_symbols()`:
1. Track `#[test]` and `#[cfg(test)]` attributes in diff lines; skip the next fn declaration when seen.
2. Skip any function whose name starts with `test_` (standard Rust convention).

**Lesson:** Path-based test detection is necessary but not sufficient. Rust commonly has `#[cfg(test)] mod tests { ... }` inside library files. Attribute-level and naming-convention filters are needed too.

## Verified Good Entries

Not everything was broken. Several entries verified correctly against their actual GitHub commits:

- **RUSTSEC-2026-0076 (libcrux-ml-dsa):** `libcrux_ml_dsa::encoding::signature::deserialize` — correct crate name conversion from hyphenated path, correct function extraction, test files properly filtered.
- **RUSTSEC-2022-0022 (hyper):** `Client::record_header_indices` — correctly identified from `MaybeUninit` safety fix. Impl types `Server`/`Client` properly tracked.
- **RUSTSEC-2023-0001 (tokio):** Named pipe functions (`pipe_mode`, `opts_default_pipe_mode`) plausible for `reject_remote_clients` fix.

## Remaining Known Limitations

These are documented in CLAUDE.md but not yet fixed:

- **`<method>` placeholders (~90 entries):** When git hunk headers don't include the fn declaration, the tool records `Type::<method>`. This is a fundamental limitation of diff-based analysis — the fn context depends on git's hunk header generation, which uses a limited window.
- **Missing crate name prefix:** For non-workspace repos, `src/foo/bar.rs` → `foo::bar` instead of `crate_name::foo::bar`. The crate name isn't available from the file path alone; fixing this would require reading `Cargo.toml` from the repo.
- **Empty symbol lists (495/642):** Many advisories lack GitHub commit references, or the referenced commits don't contain extractable Rust function changes (version bumps only, C code, etc.).

## Testing Strategy

Each fix has targeted regression tests using synthetic diffs that reproduce the exact patterns found in the real vuln_db:
- `test_for_keyword_no_longer_leaks_into_symbol` — reproduces pyo3's `impl<T> From<Py<T>> for PyObject`
- `test_where_clause_no_longer_leaks_into_symbol` — reproduces lock_api's `impl ... where R: Send`
- `test_test_functions_filtered_by_attribute` — `#[test]` fn inside library source
- `test_test_functions_filtered_by_name_prefix` — `test_*` naming convention
- `test_cfg_test_functions_filtered` — `#[cfg(test)]` attribute
- `test_parse_impl_type_*` — unit tests for the new bracket-counting parser
