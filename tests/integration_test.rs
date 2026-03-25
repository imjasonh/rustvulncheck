use std::path::PathBuf;
use std::process::Command;

fn fixtures() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

fn run_analyze(project: &str, db: &str) -> std::process::Output {
    let f = fixtures();
    Command::new(env!("CARGO_BIN_EXE_cargo-deep-audit"))
        .args([
            "analyze",
            "--project",
            f.join(project).to_str().unwrap(),
            "--db",
            f.join(db).to_str().unwrap(),
        ])
        .output()
        .expect("failed to run binary")
}

/// Parse structured fields from the report output.
struct Report {
    stdout: String,
}

impl Report {
    fn new(output: &std::process::Output) -> Self {
        Self {
            stdout: String::from_utf8_lossy(&output.stdout).to_string(),
        }
    }

    /// Extract the integer after a label like "Found 4 vulnerable dependencies".
    fn extract_count(&self, label: &str) -> usize {
        for line in self.stdout.lines() {
            if line.contains(label) {
                for word in line.split_whitespace() {
                    if let Ok(n) = word.parse::<usize>() {
                        return n;
                    }
                }
            }
        }
        panic!("Could not find '{}' in output:\n{}", label, self.stdout);
    }

    fn vulnerable_dep_count(&self) -> usize {
        self.extract_count("vulnerable dependencies")
    }

    fn reachable_symbol_count(&self) -> usize {
        self.extract_count("reachable vulnerable symbols")
    }

    fn files_scanned(&self) -> usize {
        self.extract_count("Scanned")
    }

    /// Return all `[HIGH] file:line → snippet` entries from the reachable section.
    fn high_findings(&self) -> Vec<String> {
        self.findings_with_tag("[HIGH]")
    }

    /// Return all `[MEDIUM] file:line → snippet` entries from the reachable section.
    fn medium_findings(&self) -> Vec<String> {
        self.findings_with_tag("[MEDIUM]")
    }

    fn findings_with_tag(&self, tag: &str) -> Vec<String> {
        self.stdout
            .lines()
            .filter(|l| l.contains(tag))
            .map(|l| l.trim().to_string())
            .collect()
    }

    /// Return advisory IDs listed in the "Vulnerable Dependencies" section.
    fn listed_advisories(&self) -> Vec<String> {
        let dep_section = self
            .stdout
            .split("--- Vulnerable Dependencies ---")
            .nth(1)
            .unwrap_or("")
            .split("---")
            .next()
            .unwrap_or("");
        dep_section
            .lines()
            .filter_map(|l| {
                let trimmed = l.trim();
                if trimmed.starts_with("RUSTSEC-") {
                    Some(trimmed.split_whitespace().next().unwrap().to_string())
                } else {
                    None
                }
            })
            .collect()
    }

    /// Return advisory IDs that appear in the "Reachable Vulnerable Symbols" section.
    fn reachable_advisories(&self) -> Vec<String> {
        let reachable = self
            .stdout
            .split("Reachable Vulnerable Symbols")
            .nth(1)
            .unwrap_or("");
        reachable
            .lines()
            .filter_map(|l| {
                let trimmed = l.trim();
                if trimmed.starts_with("RUSTSEC-") {
                    Some(
                        trimmed
                            .split_whitespace()
                            .next()
                            .unwrap()
                            .to_string(),
                    )
                } else {
                    None
                }
            })
            .collect()
    }

    fn result_line(&self) -> &str {
        self.stdout
            .lines()
            .find(|l| l.starts_with("RESULT:"))
            .unwrap_or("RESULT: not found")
    }
}

// =============================================================================
// Phase 1: Enrichment pipeline
// =============================================================================

#[test]
fn test_parse_fixture_advisories() {
    let f = fixtures();
    let output = Command::new(env!("CARGO_BIN_EXE_cargo-deep-audit"))
        .args([
            "enrich",
            "--advisory-db",
            f.to_str().unwrap(),
            "--limit",
            "10",
            "--include-all",
            "--output",
            "/tmp/test_vuln_db.json",
        ])
        .output()
        .expect("failed to run binary");

    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(
        stdout.contains("Found 3 total advisories"),
        "Expected 3 advisories:\n{stdout}"
    );
    assert!(stdout.contains("RUSTSEC-2024-0001"));
    assert!(stdout.contains("RUSTSEC-2024-0002"));
    assert!(stdout.contains("RUSTSEC-2024-0003"));
    assert!(stdout.contains("Wrote enriched database to /tmp/test_vuln_db.json"));

    let json_content = std::fs::read_to_string("/tmp/test_vuln_db.json").unwrap();
    let db: serde_json::Value = serde_json::from_str(&json_content).unwrap();
    assert!(!db["entries"].as_array().unwrap().is_empty());
}

// =============================================================================
// Golden: vulnerable_project
//
// Fixture layout:
//   Cargo.lock: hyper 0.14.27, smallvec 1.10.0, tokio 1.37.0, regex 1.9.6,
//               serde_json 1.0.120 (patched)
//   src/main.rs:    module declarations only
//   src/server.rs:  Client::encode (qualified), decoder.decode (typed method)
//   src/utils.rs:   vec.insert_many (constructor-inferred), handle.abort (typed param)
//
// Expected vulnerable deps: 4 (hyper, smallvec, tokio, regex)
// Expected reachable: 4 (Client::encode, Decoder::decode, SmallVec::insert_many,
//                         JoinHandle::abort)
// Expected NOT reachable: regex::compile::Compiler::compile (internal, never called)
// Expected NOT listed: serde_json (version 1.0.120 >= 1.0.100 → patched)
// =============================================================================

#[test]
fn golden_vulnerable_project() {
    let output = run_analyze("vulnerable_project", "golden_vuln_db.json");
    let r = Report::new(&output);
    println!("{}", r.stdout);

    // Exit non-zero
    assert!(!output.status.success());
    assert!(r.result_line().contains("VULNERABLE"));

    // Counts
    assert_eq!(r.files_scanned(), 3, "3 .rs files in src/");
    assert_eq!(r.vulnerable_dep_count(), 4, "hyper + smallvec + tokio + regex");
    assert_eq!(r.reachable_symbol_count(), 4, "4 symbols reachable");

    // Vulnerable deps listed (order may vary)
    let listed = r.listed_advisories();
    assert!(listed.contains(&"RUSTSEC-2024-0001".to_string()), "hyper");
    assert!(listed.contains(&"RUSTSEC-2024-0010".to_string()), "smallvec");
    assert!(listed.contains(&"RUSTSEC-2024-0020".to_string()), "tokio");
    assert!(listed.contains(&"RUSTSEC-2024-0030".to_string()), "regex");
    assert_eq!(listed.len(), 4);

    // serde_json 1.0.120 is patched — should NOT be listed
    assert!(
        !r.stdout.contains("RUSTSEC-2024-0040"),
        "serde_json is patched, should not appear"
    );

    // Reachable findings: exact set
    let reachable = r.reachable_advisories();
    assert!(reachable.contains(&"RUSTSEC-2024-0001".to_string()), "hyper reachable");
    assert!(reachable.contains(&"RUSTSEC-2024-0010".to_string()), "smallvec reachable");
    assert!(reachable.contains(&"RUSTSEC-2024-0020".to_string()), "tokio reachable");
    // regex Compiler::compile is NOT reachable (internal symbol, user only calls Regex::new)
    assert!(
        !reachable.contains(&"RUSTSEC-2024-0030".to_string()),
        "regex Compiler::compile should NOT be reachable"
    );

    // All findings are HIGH confidence
    let highs = r.high_findings();
    assert_eq!(highs.len(), 4, "all 4 findings should be HIGH");
    assert_eq!(r.medium_findings().len(), 0, "no MEDIUM findings");

    // Verify specific call sites
    assert!(
        highs.iter().any(|h| h.contains("src/server.rs:8") && h.contains("Client::encode")),
        "Client::encode at server.rs:8:\n{:?}",
        highs
    );
    assert!(
        highs.iter().any(|h| h.contains("src/server.rs:12") && h.contains("decoder.decode")),
        "Decoder::decode at server.rs:12:\n{:?}",
        highs
    );
    assert!(
        highs.iter().any(|h| h.contains("src/utils.rs:9") && h.contains("insert_many")),
        "SmallVec::insert_many at utils.rs:9:\n{:?}",
        highs
    );
    assert!(
        highs.iter().any(|h| h.contains("src/utils.rs:16") && h.contains("handle.abort")),
        "JoinHandle::abort at utils.rs:16:\n{:?}",
        highs
    );
}

// =============================================================================
// Golden: safe_project
//
// Fixture layout:
//   Cargo.lock: hyper 1.2.0 (patched), smallvec 1.11.0 (patched),
//               tokio 1.37.0 (vulnerable), regex 1.9.6 (vulnerable)
//   src/main.rs:    module declaration
//   src/handler.rs: uses Regex::new (not Compiler::compile),
//                   references JoinHandle but never calls .abort()
//
// Expected vulnerable deps: 2 (tokio, regex)
// Expected reachable: 0 (neither abort() nor Compiler::compile is called)
// Expected NOT listed: hyper (patched), smallvec (patched)
// =============================================================================

#[test]
fn golden_safe_project() {
    let output = run_analyze("safe_project", "golden_vuln_db.json");
    let r = Report::new(&output);
    println!("{}", r.stdout);

    // Exit zero
    assert!(output.status.success());
    assert!(r.result_line().contains("POSSIBLY SAFE"));

    // Counts
    assert_eq!(r.files_scanned(), 2, "2 .rs files in src/");
    assert_eq!(r.vulnerable_dep_count(), 2, "tokio + regex");
    assert_eq!(r.reachable_symbol_count(), 0, "nothing reachable");

    // Only tokio and regex listed (both vulnerable versions)
    let listed = r.listed_advisories();
    assert!(listed.contains(&"RUSTSEC-2024-0020".to_string()), "tokio listed");
    assert!(listed.contains(&"RUSTSEC-2024-0030".to_string()), "regex listed");
    assert_eq!(listed.len(), 2);

    // Patched deps NOT listed
    assert!(!r.stdout.contains("RUSTSEC-2024-0001"), "hyper is patched");
    assert!(!r.stdout.contains("RUSTSEC-2024-0010"), "smallvec is patched");

    // No findings at all
    assert!(r.high_findings().is_empty(), "no HIGH findings");
    assert!(r.medium_findings().is_empty(), "no MEDIUM findings");
    assert!(r.reachable_advisories().is_empty(), "no reachable advisories");
}

// =============================================================================
// Golden: edge_cases_project
//
// Fixture layout:
//   Cargo.lock: hyper 0.14.27, serde_json 1.0.90, cookie 0.17.0, tokio 1.37.0
//   src/main.rs:           module declarations only
//   src/aliased.rs:        `use Decoder as HyperDecoder` → dec.decode(data)
//   src/grouped.rs:        `use cookie::parse::parse_cookie` (free fn), jar.add(c) (typed method)
//   src/commented.rs:      Client::encode & Deserializer::parse inside comments
//   src/false_positive.rs: .abort() on MyHandle (wrong type), .parse() on String
//
// Expected vulnerable deps: 4 (hyper, tokio, serde_json, cookie)
// Expected reachable: 3 findings from 2 advisories
//   - hyper::Decoder::decode via aliased import (HIGH)
//   - cookie::parse_cookie free function call (HIGH)
//   - cookie::CookieJar::add typed method call (HIGH)
// Expected NOT reachable:
//   - hyper::Client::encode (commented out)
//   - serde_json::Deserializer::parse (commented out)
//   - tokio::JoinHandle::abort (only called on MyHandle, wrong type → suppressed)
// =============================================================================

#[test]
fn golden_edge_cases() {
    let output = run_analyze("edge_cases_project", "golden_vuln_db.json");
    let r = Report::new(&output);
    println!("{}", r.stdout);

    // Exit non-zero (some reachable findings exist)
    assert!(!output.status.success());
    assert!(r.result_line().contains("VULNERABLE"));

    // Counts
    assert_eq!(r.files_scanned(), 5, "5 .rs files in src/");
    assert_eq!(r.vulnerable_dep_count(), 4, "hyper + tokio + serde_json + cookie");
    assert_eq!(r.reachable_symbol_count(), 3, "3 symbols reachable");

    // All 4 vulnerable deps listed
    let listed = r.listed_advisories();
    assert!(listed.contains(&"RUSTSEC-2024-0001".to_string()), "hyper listed");
    assert!(listed.contains(&"RUSTSEC-2024-0020".to_string()), "tokio listed");
    assert!(listed.contains(&"RUSTSEC-2024-0040".to_string()), "serde_json listed");
    assert!(listed.contains(&"RUSTSEC-2024-0050".to_string()), "cookie listed");
    assert_eq!(listed.len(), 4);

    // Reachable: hyper (Decoder::decode only) and cookie (both symbols)
    let reachable = r.reachable_advisories();
    assert!(reachable.contains(&"RUSTSEC-2024-0001".to_string()), "hyper Decoder::decode reachable");
    assert!(reachable.contains(&"RUSTSEC-2024-0050".to_string()), "cookie symbols reachable");

    // NOT reachable: tokio and serde_json
    assert!(
        !reachable.contains(&"RUSTSEC-2024-0020".to_string()),
        "tokio abort() should be suppressed (called on wrong type MyHandle)"
    );
    assert!(
        !reachable.contains(&"RUSTSEC-2024-0040".to_string()),
        "serde_json Deserializer::parse should be suppressed (inside comments)"
    );

    // All findings are HIGH (type tracker resolved all receivers)
    let highs = r.high_findings();
    assert_eq!(highs.len(), 3, "exactly 3 HIGH findings");
    assert_eq!(r.medium_findings().len(), 0, "no MEDIUM findings");

    // Verify: aliased import → Decoder::decode detected
    assert!(
        highs.iter().any(|h| h.contains("src/aliased.rs:10") && h.contains("dec.decode")),
        "Aliased import Decoder::decode at aliased.rs:10:\n{:?}",
        highs
    );

    // Verify: free function parse_cookie detected
    assert!(
        highs.iter().any(|h| h.contains("src/grouped.rs:11") && h.contains("parse_cookie")),
        "Free function parse_cookie at grouped.rs:11:\n{:?}",
        highs
    );

    // Verify: typed method CookieJar::add detected
    assert!(
        highs.iter().any(|h| h.contains("src/grouped.rs:15") && h.contains("jar.add")),
        "CookieJar::add at grouped.rs:15:\n{:?}",
        highs
    );

    // Verify: Client::encode NOT found (commented out in commented.rs)
    assert!(
        !highs.iter().any(|h| h.contains("Client::encode")),
        "Client::encode should not appear (it's in a comment)"
    );

    // Verify: Deserializer::parse NOT found (commented out)
    assert!(
        !highs.iter().any(|h| h.contains("Deserializer::parse")),
        "Deserializer::parse should not appear (it's in a comment)"
    );

    // Verify: JoinHandle::abort NOT found (called on wrong type)
    assert!(
        !highs.iter().any(|h| h.contains("abort")),
        "abort() should not appear (called on MyHandle, not JoinHandle)"
    );
}

// =============================================================================
// Golden: clean project (no vulnerable deps at all)
// =============================================================================

#[test]
fn golden_clean_project() {
    let tmp = tempfile::tempdir().unwrap();
    let src_dir = tmp.path().join("src");
    std::fs::create_dir_all(&src_dir).unwrap();

    std::fs::write(
        tmp.path().join("Cargo.lock"),
        r#"version = 3

[[package]]
name = "clean-app"
version = "0.1.0"

[[package]]
name = "serde"
version = "1.0.200"
source = "registry+https://github.com/rust-lang/crates.io-index"
"#,
    )
    .unwrap();

    std::fs::write(
        src_dir.join("main.rs"),
        "fn main() { println!(\"Hello\"); }\n",
    )
    .unwrap();

    let f = fixtures();
    let output = Command::new(env!("CARGO_BIN_EXE_cargo-deep-audit"))
        .args([
            "analyze",
            "--project",
            tmp.path().to_str().unwrap(),
            "--db",
            f.join("golden_vuln_db.json").to_str().unwrap(),
        ])
        .output()
        .expect("failed to run binary");

    let r = Report::new(&output);
    println!("{}", r.stdout);

    assert!(output.status.success());
    assert!(r.result_line().contains("CLEAN"));
    assert_eq!(r.vulnerable_dep_count(), 0);
    assert!(r.high_findings().is_empty());
    assert!(r.medium_findings().is_empty());
}
