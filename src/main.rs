mod advisory;
mod analyzer;
mod ast_differ;
mod db;
mod diff_analyzer;
mod github;
mod lockfile;
mod scanner;
mod type_tracker;

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::process;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

use advisory::{parse_advisory_db, Advisory};
use db::{VulnDb, VulnEntry};
use diff_analyzer::extract_symbols;
use github::GithubClient;

/// cargo deep-audit: reachability-based vulnerability scanner for Rust
#[derive(Parser, Debug)]
#[command(name = "cargo-deep-audit", version, about)]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Enrich the RustSec advisory database with function-level symbols (Phase 1).
    Enrich(EnrichArgs),

    /// Analyze a Rust project for reachable vulnerable symbols (Phase 2).
    Analyze(AnalyzeArgs),
}

/// Arguments for the `enrich` subcommand.
#[derive(Parser, Debug)]
struct EnrichArgs {
    /// Path to a local clone of the RustSec advisory-db.
    /// If not provided, the repo will be cloned to a temp directory.
    #[arg(long)]
    advisory_db: Option<PathBuf>,

    /// Maximum number of enriched entries to collect (most recent first).
    #[arg(long, default_value = "10")]
    limit: usize,

    /// Output JSON file path.
    #[arg(long, default_value = "vuln_db.json")]
    output: PathBuf,

    /// GitHub API token (can also be set via GITHUB_TOKEN env var).
    #[arg(long, env = "GITHUB_TOKEN")]
    github_token: Option<String>,

    /// Include all advisories, even those without GitHub references.
    #[arg(long)]
    include_all: bool,

    /// Path to an existing enriched DB to resume from (skips already-enriched advisories).
    #[arg(long)]
    existing_db: Option<PathBuf>,

    /// Re-enrich existing entries by re-fetching diffs and re-extracting symbols
    /// with the current code. Requires --existing-db. Processes up to --limit entries
    /// that have a commit_sha.
    #[arg(long)]
    re_enrich: bool,

    /// Stop processing after this many seconds (for CI time-boxing).
    #[arg(long)]
    timeout_secs: Option<u64>,
}

/// Arguments for the `analyze` subcommand.
#[derive(Parser, Debug)]
struct AnalyzeArgs {
    /// Path to the Rust project to analyze (must contain Cargo.lock and src/).
    #[arg(long, default_value = ".")]
    project: PathBuf,

    /// Path to the enriched vulnerability database JSON.
    #[arg(long, default_value = "vuln_db.json")]
    db: PathBuf,
}

fn main() -> Result<()> {
    let args = Args::parse();

    match args.command {
        Command::Enrich(enrich_args) => run_enrich(enrich_args),
        Command::Analyze(analyze_args) => run_analyze(analyze_args),
    }
}

fn run_analyze(args: AnalyzeArgs) -> Result<()> {
    let project = args.project.canonicalize().with_context(|| {
        format!("project path '{}' does not exist", args.project.display())
    })?;

    // Verify the project has the expected structure
    if !project.join("Cargo.lock").exists() {
        anyhow::bail!(
            "No Cargo.lock found in {}. Run `cargo generate-lockfile` first.",
            project.display()
        );
    }
    if !project.join("src").exists() {
        anyhow::bail!(
            "No src/ directory found in {}. Is this a Rust project?",
            project.display()
        );
    }

    let report = analyzer::analyze(&project, &args.db)?;
    analyzer::print_report(&report);

    // Exit with appropriate code
    if !report.findings.is_empty() {
        process::exit(1); // Vulnerable
    }

    Ok(())
}

fn run_enrich(args: EnrichArgs) -> Result<()> {
    let start_time = Instant::now();
    let timeout = args.timeout_secs.map(Duration::from_secs);

    // Step 1: Get the advisory-db
    let db_path = match &args.advisory_db {
        Some(path) => {
            println!("Using local advisory-db at {}", path.display());
            path.clone()
        }
        None => {
            let tmp = PathBuf::from("/tmp/advisory-db");
            clone_advisory_db(&tmp)?;
            tmp
        }
    };

    // Step 2: Load existing DB if resuming
    let mut vuln_db = match &args.existing_db {
        Some(path) if path.exists() => {
            let existing = VulnDb::load(path)
                .with_context(|| format!("loading existing DB from {}", path.display()))?;
            println!(
                "Loaded existing DB with {} entries from {}",
                existing.entries.len(),
                path.display()
            );
            existing
        }
        _ => VulnDb::new(),
    };

    // Step 3: Parse advisories
    println!("Parsing advisory database...");
    let all_advisories = parse_advisory_db(&db_path)?;
    println!("Found {} total advisories", all_advisories.len());

    // Build advisory lookup by ID for re-enrichment
    let advisory_by_id: std::collections::HashMap<&str, &Advisory> = all_advisories
        .iter()
        .map(|a| (a.id.as_str(), a))
        .collect();

    let gh = GithubClient::new(args.github_token);

    // Helper closure to check timeout
    let timed_out = |start: &Instant, t: &Option<Duration>| -> bool {
        if let Some(t) = t {
            if start.elapsed() >= *t {
                println!(
                    "Timeout reached after {} seconds, stopping.",
                    start.elapsed().as_secs()
                );
                return true;
            }
        }
        false
    };

    // Step 4: Re-enrich existing entries if --re-enrich is set
    let mut re_enriched_count = 0usize;

    if args.re_enrich {
        // Find existing entries that have commit SHAs and matching advisories
        let re_enrich_indices: Vec<usize> = vuln_db
            .entries
            .iter()
            .enumerate()
            .filter(|(_, e)| {
                e.commit_sha.is_some() && advisory_by_id.contains_key(e.advisory_id.as_str())
            })
            .map(|(i, _)| i)
            .collect();

        let re_enrich_target = args.limit.min(re_enrich_indices.len());
        println!(
            "Re-enriching up to {} of {} existing entries...\n",
            re_enrich_target,
            re_enrich_indices.len()
        );

        for &idx in &re_enrich_indices {
            if re_enriched_count >= args.limit {
                println!(
                    "Reached --limit of {} re-enriched entries, stopping.",
                    args.limit
                );
                break;
            }
            if timed_out(&start_time, &timeout) {
                break;
            }

            let entry = &vuln_db.entries[idx];
            let adv = advisory_by_id[entry.advisory_id.as_str()];
            let old_symbol_count = entry.vulnerable_symbols.len();

            println!(
                "[{}/{}] Re-enriching {} ({})",
                re_enriched_count + 1,
                re_enrich_target,
                entry.advisory_id,
                entry.package,
            );

            let gh_refs = adv.github_refs();
            let mut new_symbols = Vec::new();
            let mut new_sha = entry.commit_sha.clone();

            for gh_ref in &gh_refs {
                match gh.fetch_diff(gh_ref) {
                    Ok(Some(diff)) => {
                        println!(
                            "  Fetched commit {} ({} .rs files)",
                            &diff.commit_sha[..7.min(diff.commit_sha.len())],
                            diff.files.len()
                        );
                        new_sha = Some(diff.commit_sha.clone());
                        new_symbols = extract_symbols(&diff, &gh);
                        break;
                    }
                    Ok(None) => {
                        println!("  Ref returned no diff, trying next...");
                    }
                    Err(e) => {
                        eprintln!("  Error fetching diff: {}", e);
                    }
                }
            }

            let new_symbol_count = new_symbols.len();
            if new_symbol_count != old_symbol_count {
                println!(
                    "  Symbols: {} -> {} (changed)",
                    old_symbol_count, new_symbol_count
                );
            } else {
                println!("  Symbols: {} (unchanged)", new_symbol_count);
            }
            for sym in &new_symbols {
                println!("    - {} ({:?})", sym.function, sym.change_type);
            }

            // Update the entry in-place
            let entry_mut = &mut vuln_db.entries[idx];
            entry_mut.commit_sha = new_sha;
            entry_mut.vulnerable_symbols = new_symbols;
            re_enriched_count += 1;
            println!();
        }
    }

    // Step 5: Process new (unenriched) advisories
    let already_enriched: HashSet<String> = vuln_db
        .entries
        .iter()
        .map(|e| e.advisory_id.clone())
        .collect();

    // Filter to advisories with GitHub refs unless --include-all
    let candidates: Vec<&Advisory> = if args.include_all {
        all_advisories.iter().collect()
    } else {
        all_advisories
            .iter()
            .filter(|a| !a.github_urls.is_empty())
            .collect()
    };
    println!(
        "{} advisories have GitHub references",
        candidates.len()
    );

    // Filter out already-enriched advisories
    let unenriched: Vec<&Advisory> = candidates
        .into_iter()
        .filter(|a| !already_enriched.contains(&a.id))
        .collect();
    println!(
        "{} advisories still need enrichment",
        unenriched.len()
    );

    let new_limit = if args.re_enrich {
        // When re-enriching, don't also add new entries (separate concerns)
        0
    } else {
        args.limit
    };
    let target = new_limit.min(unenriched.len());
    if target > 0 {
        println!(
            "Processing advisories (collecting up to {} new enriched entries)...\n",
            target
        );
    }

    let mut new_count = 0usize;

    for adv in &unenriched {
        if new_count >= new_limit {
            break;
        }
        if timed_out(&start_time, &timeout) {
            break;
        }

        let gh_refs = adv.github_refs();
        if gh_refs.is_empty() {
            continue;
        }

        println!(
            "[{}/{}] {} ({}) - {}",
            new_count + 1,
            target,
            adv.id,
            adv.package,
            adv.title
        );

        let mut entry = VulnEntry {
            advisory_id: adv.id.clone(),
            package: adv.package.clone(),
            title: adv.title.clone(),
            date: adv.date.clone(),
            patched_versions: adv.patched_versions.clone(),
            commit_sha: None,
            vulnerable_symbols: Vec::new(),
        };

        // Try each ref until we get a diff
        for gh_ref in &gh_refs {
            match gh.fetch_diff(gh_ref) {
                Ok(Some(diff)) => {
                    println!(
                        "  Fetched commit {} ({} .rs files)",
                        &diff.commit_sha[..7.min(diff.commit_sha.len())],
                        diff.files.len()
                    );
                    entry.commit_sha = Some(diff.commit_sha.clone());
                    let symbols = extract_symbols(&diff, &gh);
                    if symbols.is_empty() {
                        println!("  No function signatures extracted from diff");
                    } else {
                        println!("  Extracted {} symbols:", symbols.len());
                        for sym in &symbols {
                            println!("    - {} ({:?})", sym.function, sym.change_type);
                        }
                    }
                    entry.vulnerable_symbols = symbols;
                    break;
                }
                Ok(None) => {
                    println!("  Ref returned no diff, trying next...");
                }
                Err(e) => {
                    eprintln!("  Error fetching diff: {}", e);
                }
            }
        }

        vuln_db.entries.push(entry);
        new_count += 1;
        println!();
    }

    // Only update timestamp if we actually changed something
    if new_count > 0 || re_enriched_count > 0 {
        vuln_db.update_timestamp();
    }

    // Step 6: Write output
    let entries_with_symbols = vuln_db
        .entries
        .iter()
        .filter(|e| !e.vulnerable_symbols.is_empty())
        .count();
    if args.re_enrich {
        println!(
            "Done! Re-enriched {} entries ({} total, {} with symbols).",
            re_enriched_count,
            vuln_db.entries.len(),
            entries_with_symbols,
        );
    } else {
        println!(
            "Done! Added {} new entries ({} total, {} with symbols).",
            new_count,
            vuln_db.entries.len(),
            entries_with_symbols,
        );
    }

    vuln_db.write_json(&args.output)?;
    println!("Wrote enriched database to {}", args.output.display());

    Ok(())
}

fn clone_advisory_db(dest: &Path) -> Result<()> {
    if dest.exists() {
        println!(
            "Advisory-db already cached at {}, pulling updates...",
            dest.display()
        );
        let repo = git2::Repository::open(dest).context("opening cached advisory-db")?;
        // Fetch origin/main
        let mut remote = repo.find_remote("origin")?;
        remote.fetch(&["main"], None, None)?;
        // Fast-forward to origin/main
        let fetch_head = repo.find_reference("refs/remotes/origin/main")?;
        let commit = repo.reference_to_annotated_commit(&fetch_head)?;
        let (analysis, _) = repo.merge_analysis(&[&commit])?;
        if analysis.is_fast_forward() {
            let mut reference = repo.find_reference("refs/heads/main")?;
            reference.set_target(commit.id(), "fast-forward")?;
            repo.set_head("refs/heads/main")?;
            repo.checkout_head(Some(git2::build::CheckoutBuilder::new().force()))?;
            println!("Fast-forwarded to latest.");
        } else {
            println!("Already up to date.");
        }
        return Ok(());
    }

    println!("Cloning RustSec advisory-db to {}...", dest.display());
    git2::Repository::clone("https://github.com/rustsec/advisory-db.git", dest)
        .context("cloning advisory-db")?;
    println!("Clone complete.");
    Ok(())
}
