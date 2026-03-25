use std::path::PathBuf;
use std::process::Command;

#[test]
fn test_parse_fixture_advisories() {
    let fixtures = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");

    let output = Command::new(env!("CARGO_BIN_EXE_cargo-deep-audit"))
        .args([
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
