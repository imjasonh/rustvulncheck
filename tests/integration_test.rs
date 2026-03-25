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

// =============================================================================
// Phase 1: Enrichment pipeline tests
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
    let stderr = String::from_utf8_lossy(&output.stderr);
    println!("STDOUT:\n{stdout}");
    println!("STDERR:\n{stderr}");

    assert!(
        stdout.contains("Found 3 total advisories"),
        "Expected 3 advisories, got: {stdout}"
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
// Phase 2: Golden codebase integration tests
// =============================================================================

/// Golden test: vulnerable project with multiple call patterns.
///
/// The vulnerable_project fixture has:
/// - hyper 0.14.27 (vulnerable, patched >= 1.0.0) with calls to Client::encode and Decoder::decode
/// - smallvec 1.10.0 (vulnerable, patched >= 1.11.0) with calls to SmallVec::insert_many
/// - tokio 1.37.0 (vulnerable, patched >= 1.38.0) with calls to JoinHandle::abort
/// - regex 1.9.6 (vulnerable, patched >= 1.10.0) — present but Compiler::compile is NOT called
#[test]
fn golden_vulnerable_project() {
    let output = run_analyze("vulnerable_project", "golden_vuln_db.json");
    let stdout = String::from_utf8_lossy(&output.stdout);
    println!("STDOUT:\n{stdout}");

    // --- Should exit non-zero (vulnerable) ---
    assert!(
        !output.status.success(),
        "Should exit with non-zero when vulnerabilities found"
    );
    assert!(
        stdout.contains("VULNERABLE"),
        "Should report VULNERABLE status:\n{stdout}"
    );

    // --- Should detect all four vulnerable dependencies ---
    assert!(stdout.contains("RUSTSEC-2024-0001"), "hyper advisory missing:\n{stdout}");
    assert!(stdout.contains("RUSTSEC-2024-0010"), "smallvec advisory missing:\n{stdout}");
    assert!(stdout.contains("RUSTSEC-2024-0020"), "tokio advisory missing:\n{stdout}");
    assert!(stdout.contains("RUSTSEC-2024-0030"), "regex advisory missing:\n{stdout}");

    // --- Should find reachable calls for hyper, smallvec, and tokio ---
    assert!(
        stdout.contains("Client::encode"),
        "Should find Client::encode call:\n{stdout}"
    );
    assert!(
        stdout.contains("insert_many"),
        "Should find SmallVec::insert_many call:\n{stdout}"
    );
    assert!(
        stdout.contains("abort"),
        "Should find JoinHandle::abort call:\n{stdout}"
    );

    // --- regex Compiler::compile is NOT called in user code ---
    // It's an internal symbol; user code only calls Regex::new.
    // It should appear in "Vulnerable Dependencies" but NOT in "Reachable" findings.
    let reachable_section = stdout
        .split("Reachable Vulnerable Symbols")
        .nth(1)
        .unwrap_or("");
    assert!(
        !reachable_section.contains("Compiler::compile"),
        "Compiler::compile should NOT appear as reachable:\n{stdout}"
    );

    // --- Should scan multiple source files ---
    assert!(
        stdout.contains("3 source files"),
        "Should scan all 3 .rs files:\n{stdout}"
    );
}

/// Golden test: safe project where vulnerabilities exist in deps but aren't reachable.
///
/// The safe_project fixture has:
/// - hyper 1.2.0 (PATCHED — version >= 1.0.0) → should not appear at all
/// - smallvec 1.11.0 (PATCHED — version >= 1.11.0) → should not appear at all
/// - tokio 1.37.0 (vulnerable) but abort() is NEVER called → dep listed, no findings
/// - regex 1.9.6 (vulnerable) but Compiler::compile is NEVER called → dep listed, no findings
#[test]
fn golden_safe_project() {
    let output = run_analyze("safe_project", "golden_vuln_db.json");
    let stdout = String::from_utf8_lossy(&output.stdout);
    println!("STDOUT:\n{stdout}");

    // --- Should exit zero (safe / not reachable) ---
    assert!(
        output.status.success(),
        "Should exit successfully when no reachable vulns:\n{stdout}"
    );

    // --- Patched deps should NOT appear ---
    assert!(
        !stdout.contains("RUSTSEC-2024-0001"),
        "hyper is patched (1.2.0), should not appear:\n{stdout}"
    );
    assert!(
        !stdout.contains("RUSTSEC-2024-0010"),
        "smallvec is patched (1.11.0), should not appear:\n{stdout}"
    );

    // --- Vulnerable but unreachable deps SHOULD appear in dep list ---
    assert!(
        stdout.contains("RUSTSEC-2024-0020"),
        "tokio advisory should be listed (vulnerable version):\n{stdout}"
    );
    assert!(
        stdout.contains("RUSTSEC-2024-0030"),
        "regex advisory should be listed (vulnerable version):\n{stdout}"
    );

    // --- But no reachable findings ---
    assert!(
        stdout.contains("POSSIBLY SAFE"),
        "Should report POSSIBLY SAFE (deps present but not reachable):\n{stdout}"
    );
    assert!(
        !stdout.contains("Reachable Vulnerable Symbols"),
        "Should NOT have reachable symbols section:\n{stdout}"
    );
}

/// Minimal test: project with zero vulnerable dependencies.
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

    let stdout = String::from_utf8_lossy(&output.stdout);
    println!("STDOUT:\n{stdout}");

    assert!(
        stdout.contains("CLEAN"),
        "Should report CLEAN:\n{stdout}"
    );
    assert!(
        output.status.success(),
        "Should exit successfully when clean"
    );
}
