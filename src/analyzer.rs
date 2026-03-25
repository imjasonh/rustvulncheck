//! Analyze a Rust project for reachable vulnerable symbols.
//!
//! Orchestrates the full analysis pipeline:
//! 1. Parse Cargo.lock to identify dependencies and versions
//! 2. Load the enriched vulnerability database
//! 3. Match vulnerable crates against the lockfile (version-aware)
//! 4. Scan source files for references to vulnerable symbols
//! 5. Produce a structured report

use std::path::Path;

use anyhow::{Context, Result};

use crate::db::{VulnDb, VulnEntry};
use crate::lockfile::{parse_lockfile, LockedPackage};
use crate::scanner::{scan_for_symbols, CallSite, Confidence};

/// A vulnerability that is present in the dependency tree.
#[derive(Debug)]
pub struct AffectedDependency {
    pub advisory_id: String,
    pub package: String,
    pub locked_version: String,
    pub title: String,
    pub patched_versions: Vec<String>,
    pub vulnerable_symbols: Vec<String>,
}

/// A finding: a vulnerable symbol that appears to be called in user code.
#[derive(Debug)]
pub struct Finding {
    pub advisory_id: String,
    pub package: String,
    pub symbol: String,
    pub call_sites: Vec<CallSite>,
}

/// Full analysis result for a project.
#[derive(Debug)]
pub struct AnalysisReport {
    /// Vulnerabilities present in dependencies (regardless of reachability).
    pub affected_deps: Vec<AffectedDependency>,
    /// Vulnerable symbols that appear to be called from user code.
    pub findings: Vec<Finding>,
    /// Total number of source files scanned.
    pub files_scanned: usize,
}

/// Run the full analysis on a Rust project.
///
/// `project_root` should contain `Cargo.lock` and `src/`.
/// `vuln_db_path` is the path to the enriched JSON database from Phase 1.
pub fn analyze(project_root: &Path, vuln_db_path: &Path) -> Result<AnalysisReport> {
    // Step 1: Load the vulnerability database
    let vuln_db =
        VulnDb::load(vuln_db_path).with_context(|| format!("loading {}", vuln_db_path.display()))?;
    println!(
        "Loaded vulnerability database ({} entries)",
        vuln_db.entries.len()
    );

    // Step 2: Parse Cargo.lock
    let lockfile_path = project_root.join("Cargo.lock");
    let locked_packages = parse_lockfile(&lockfile_path)?;
    println!(
        "Parsed Cargo.lock ({} packages)",
        locked_packages.len()
    );

    // Step 3: Find affected dependencies
    let affected = find_affected_deps(&vuln_db.entries, &locked_packages);
    println!(
        "Found {} vulnerabilities affecting locked dependencies",
        affected.len()
    );

    if affected.is_empty() {
        return Ok(AnalysisReport {
            affected_deps: affected,
            findings: Vec::new(),
            files_scanned: 0,
        });
    }

    // Step 4: Collect all vulnerable symbols to search for
    let all_symbols: Vec<&str> = affected
        .iter()
        .flat_map(|a| a.vulnerable_symbols.iter().map(|s| s.as_str()))
        .collect();

    if all_symbols.is_empty() {
        println!("No function-level symbols to scan for (crate-level vulnerabilities only)");
        return Ok(AnalysisReport {
            affected_deps: affected,
            findings: Vec::new(),
            files_scanned: 0,
        });
    }

    println!(
        "Scanning source files for {} vulnerable symbols...",
        all_symbols.len()
    );

    // Step 5: Scan source files
    let call_sites = scan_for_symbols(project_root, &all_symbols);

    // Count files scanned
    let files_scanned = count_rs_files(project_root);

    // Step 6: Group call sites into findings
    let findings = group_into_findings(&affected, call_sites);

    Ok(AnalysisReport {
        affected_deps: affected,
        findings,
        files_scanned,
    })
}

/// Match vulnerability entries against locked packages, checking version ranges.
fn find_affected_deps(entries: &[VulnEntry], packages: &[LockedPackage]) -> Vec<AffectedDependency> {
    let mut affected = Vec::new();

    for entry in entries {
        // Find matching packages by name
        for pkg in packages {
            if pkg.name != entry.package {
                continue;
            }

            // Check if the locked version is vulnerable (i.e., NOT in a patched range)
            if is_vulnerable(&pkg.version, &entry.patched_versions) {
                let symbols: Vec<String> = entry
                    .vulnerable_symbols
                    .iter()
                    .map(|s| s.function.clone())
                    .collect();

                affected.push(AffectedDependency {
                    advisory_id: entry.advisory_id.clone(),
                    package: entry.package.clone(),
                    locked_version: pkg.version.clone(),
                    title: entry.title.clone(),
                    patched_versions: entry.patched_versions.clone(),
                    vulnerable_symbols: symbols,
                });
            }
        }
    }

    affected
}

/// Check if a version is vulnerable given the patched version requirements.
///
/// Patched versions are typically in the format `">= 1.2.0"` or `"^1.2.3"`.
/// A version is vulnerable if it does NOT satisfy any of the patched requirements.
fn is_vulnerable(version_str: &str, patched_versions: &[String]) -> bool {
    let version = match semver::Version::parse(version_str) {
        Ok(v) => v,
        Err(_) => return false, // Can't parse → assume not vulnerable
    };

    if patched_versions.is_empty() {
        // No patched version listed → advisory applies to all versions
        return true;
    }

    // A version is vulnerable if it does NOT match ANY patched version requirement.
    // Each patched_versions entry is a semver requirement like ">= 1.2.0".
    for req_str in patched_versions {
        if let Ok(req) = semver::VersionReq::parse(req_str) {
            if req.matches(&version) {
                // This version IS patched
                return false;
            }
        }
    }

    // Didn't match any patched requirement → vulnerable
    true
}

/// Group call sites by advisory+symbol into findings.
fn group_into_findings(affected: &[AffectedDependency], call_sites: Vec<CallSite>) -> Vec<Finding> {
    let mut findings: Vec<Finding> = Vec::new();

    for dep in affected {
        for symbol in &dep.vulnerable_symbols {
            let sites: Vec<CallSite> = call_sites
                .iter()
                .filter(|cs| cs.symbol == *symbol)
                .cloned()
                .collect();

            if !sites.is_empty() {
                findings.push(Finding {
                    advisory_id: dep.advisory_id.clone(),
                    package: dep.package.clone(),
                    symbol: symbol.clone(),
                    call_sites: sites,
                });
            }
        }
    }

    findings
}

/// Count .rs files in the src/ directory.
fn count_rs_files(project_root: &Path) -> usize {
    let src_dir = project_root.join("src");
    if !src_dir.exists() {
        return 0;
    }
    walkdir::WalkDir::new(src_dir)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.path()
                .extension()
                .map_or(false, |ext| ext == "rs")
        })
        .count()
}

/// Print a human-readable analysis report to stdout.
pub fn print_report(report: &AnalysisReport) {
    println!("\n{}", "=".repeat(70));
    println!("  VULNERABILITY ANALYSIS REPORT");
    println!("{}\n", "=".repeat(70));

    // Summary
    println!(
        "Scanned {} source files",
        report.files_scanned
    );
    println!(
        "Found {} vulnerable dependencies",
        report.affected_deps.len()
    );
    println!(
        "Found {} reachable vulnerable symbols\n",
        report.findings.len()
    );

    // Section 1: Affected dependencies
    if !report.affected_deps.is_empty() {
        println!("--- Vulnerable Dependencies ---\n");
        for dep in &report.affected_deps {
            println!(
                "  {} {} @ {}",
                dep.advisory_id, dep.package, dep.locked_version
            );
            println!("  {}", dep.title);
            if !dep.patched_versions.is_empty() {
                println!(
                    "  Fix: upgrade to {}",
                    dep.patched_versions.join(" or ")
                );
            }
            if dep.vulnerable_symbols.is_empty() {
                println!("  Symbols: (none extracted - crate-level advisory)");
            } else {
                println!("  Vulnerable symbols:");
                for sym in &dep.vulnerable_symbols {
                    println!("    - {}", sym);
                }
            }
            println!();
        }
    }

    // Section 2: Reachable findings
    if report.findings.is_empty() {
        if report.affected_deps.is_empty() {
            println!("No known vulnerabilities found in dependencies.");
        } else {
            println!("--- Reachability Analysis ---\n");
            println!(
                "  None of the {} vulnerable symbols appear to be called from your code.",
                report
                    .affected_deps
                    .iter()
                    .map(|d| d.vulnerable_symbols.len())
                    .sum::<usize>()
            );
            println!("  The vulnerabilities exist in your dependency tree but may not be reachable.\n");
        }
    } else {
        println!("--- Reachable Vulnerable Symbols ---\n");
        for finding in &report.findings {
            let high_count = finding
                .call_sites
                .iter()
                .filter(|cs| cs.confidence == Confidence::High)
                .count();
            let medium_count = finding.call_sites.len() - high_count;

            println!(
                "  {} ({}) :: {}",
                finding.advisory_id, finding.package, finding.symbol
            );
            println!(
                "  {} call site(s) ({} high confidence, {} medium confidence)",
                finding.call_sites.len(),
                high_count,
                medium_count
            );

            for site in &finding.call_sites {
                let conf_tag = match site.confidence {
                    Confidence::High => "HIGH",
                    Confidence::Medium => "MEDIUM",
                };
                println!(
                    "    [{}] {}:{} → {}",
                    conf_tag,
                    site.file.display(),
                    site.line,
                    site.snippet
                );
            }
            println!();
        }
    }

    // Exit code guidance
    if !report.findings.is_empty() {
        println!("RESULT: VULNERABLE - reachable vulnerable symbols detected");
    } else if !report.affected_deps.is_empty() {
        println!("RESULT: POSSIBLY SAFE - vulnerable dependencies present but symbols not detected in source");
    } else {
        println!("RESULT: CLEAN - no known vulnerabilities in dependencies");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_vulnerable_basic() {
        // Version 0.14.27 is below >= 1.0.0 → vulnerable
        assert!(is_vulnerable("0.14.27", &[">= 1.0.0".to_string()]));

        // Version 1.2.0 satisfies >= 1.0.0 → NOT vulnerable
        assert!(!is_vulnerable("1.2.0", &[">= 1.0.0".to_string()]));

        // Version 1.0.0 satisfies >= 1.0.0 → NOT vulnerable
        assert!(!is_vulnerable("1.0.0", &[">= 1.0.0".to_string()]));
    }

    #[test]
    fn test_is_vulnerable_multiple_ranges() {
        // Multiple patched version ranges (common for backports)
        let patched = vec![">= 2.0.0".to_string(), ">= 1.5.3, < 2.0.0".to_string()];

        assert!(is_vulnerable("1.4.0", &patched)); // below both ranges
        assert!(!is_vulnerable("1.5.3", &patched)); // in backport range
        assert!(!is_vulnerable("2.0.0", &patched)); // in main range
        assert!(is_vulnerable("1.5.2", &patched)); // just below backport
    }

    #[test]
    fn test_is_vulnerable_no_patched() {
        // No patched version → all versions vulnerable
        assert!(is_vulnerable("1.0.0", &[]));
    }

    #[test]
    fn test_is_vulnerable_unparseable() {
        // Unparseable version → assume not vulnerable (conservative)
        assert!(!is_vulnerable("not-a-version", &[">= 1.0.0".to_string()]));
    }

    #[test]
    fn test_find_affected_deps() {
        let entries = vec![VulnEntry {
            advisory_id: "RUSTSEC-2024-0001".to_string(),
            package: "hyper".to_string(),
            title: "Test vuln".to_string(),
            date: "2024-01-01".to_string(),
            patched_versions: vec![">= 1.0.0".to_string()],
            commit_sha: None,
            vulnerable_symbols: vec![crate::diff_analyzer::VulnerableSymbol {
                file: "src/http.rs".to_string(),
                function: "hyper::http::Request::parse".to_string(),
                change_type: crate::diff_analyzer::ChangeType::Modified,
            }],
        }];

        let packages = vec![
            LockedPackage {
                name: "hyper".to_string(),
                version: "0.14.27".to_string(),
            },
            LockedPackage {
                name: "tokio".to_string(),
                version: "1.32.0".to_string(),
            },
        ];

        let affected = find_affected_deps(&entries, &packages);
        assert_eq!(affected.len(), 1);
        assert_eq!(affected[0].package, "hyper");
        assert_eq!(affected[0].locked_version, "0.14.27");
        assert_eq!(affected[0].vulnerable_symbols, vec!["hyper::http::Request::parse"]);
    }
}
