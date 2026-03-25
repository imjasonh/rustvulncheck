use std::path::PathBuf;
use std::process::Command;

#[test]
fn test_parse_fixture_advisories() {
    let fixtures = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");

    let output = Command::new(env!("CARGO_BIN_EXE_cargo-deep-audit"))
        .args([
            "enrich",
            "--advisory-db",
            fixtures.to_str().unwrap(),
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
    println!("STDOUT:\n{}", stdout);
    println!("STDERR:\n{}", stderr);

    // Should find all 3 fixture advisories
    assert!(
        stdout.contains("Found 3 total advisories"),
        "Expected 3 advisories, got: {}",
        stdout
    );

    // Should identify hyper and tokio as having GitHub refs
    assert!(stdout.contains("RUSTSEC-2024-0001"));
    assert!(stdout.contains("RUSTSEC-2024-0002"));
    assert!(stdout.contains("RUSTSEC-2024-0003"));

    // Should write output file
    assert!(stdout.contains("Wrote enriched database to /tmp/test_vuln_db.json"));

    // Verify JSON output is valid
    let json_content = std::fs::read_to_string("/tmp/test_vuln_db.json").unwrap();
    let db: serde_json::Value = serde_json::from_str(&json_content).unwrap();
    assert!(db["entries"].as_array().unwrap().len() > 0);
}

#[test]
fn test_analyze_detects_vulnerable_call() {
    let fixtures = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let test_project = fixtures.join("test_project");
    let vuln_db = fixtures.join("test_vuln_db.json");

    let output = Command::new(env!("CARGO_BIN_EXE_cargo-deep-audit"))
        .args([
            "analyze",
            "--project",
            test_project.to_str().unwrap(),
            "--db",
            vuln_db.to_str().unwrap(),
        ])
        .output()
        .expect("failed to run binary");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    println!("STDOUT:\n{}", stdout);
    println!("STDERR:\n{}", stderr);

    // Should find hyper and tokio as vulnerable deps (both below patched versions)
    assert!(
        stdout.contains("RUSTSEC-2024-0001"),
        "Should detect hyper advisory"
    );
    assert!(
        stdout.contains("RUSTSEC-2024-0002"),
        "Should detect tokio advisory"
    );

    // serde 1.0.190 is above patched version >= 1.0.180, should NOT appear
    assert!(
        !stdout.contains("RUSTSEC-2024-0099"),
        "serde should not be flagged as vulnerable (version is patched)"
    );

    // Should detect the Request::parse call in the test project
    assert!(
        stdout.contains("Request::parse"),
        "Should find the vulnerable call site: {}",
        stdout
    );

    // Should report as VULNERABLE since a reachable symbol was found
    assert!(
        stdout.contains("VULNERABLE"),
        "Should report vulnerable status: {}",
        stdout
    );

    // Exit code should be 1 (vulnerable)
    assert!(
        !output.status.success(),
        "Should exit with non-zero when vulnerabilities found"
    );
}

#[test]
fn test_analyze_clean_project() {
    // Create a temporary project with no vulnerable calls
    let tmp = tempfile::tempdir().unwrap();
    let src_dir = tmp.path().join("src");
    std::fs::create_dir_all(&src_dir).unwrap();

    std::fs::write(
        tmp.path().join("Cargo.lock"),
        r#"version = 3

[[package]]
name = "safe-app"
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

    let fixtures = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let vuln_db = fixtures.join("test_vuln_db.json");

    let output = Command::new(env!("CARGO_BIN_EXE_cargo-deep-audit"))
        .args([
            "analyze",
            "--project",
            tmp.path().to_str().unwrap(),
            "--db",
            vuln_db.to_str().unwrap(),
        ])
        .output()
        .expect("failed to run binary");

    let stdout = String::from_utf8_lossy(&output.stdout);
    println!("STDOUT:\n{}", stdout);

    // Should report clean
    assert!(
        stdout.contains("CLEAN"),
        "Should report clean status: {}",
        stdout
    );

    // Exit code should be 0
    assert!(output.status.success(), "Should exit successfully when clean");
}
