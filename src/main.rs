mod advisory;
mod analyzer;
mod db;
mod diff_analyzer;
mod github;
mod lockfile;
mod scanner;

use std::path::{Path, PathBuf};
use std::process;

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

    // Step 2: Parse advisories
    println!("Parsing advisory database...");
    let all_advisories = parse_advisory_db(&db_path)?;
    println!("Found {} total advisories", all_advisories.len());

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

    println!(
        "Processing advisories (collecting up to {} enriched entries)...\n",
        args.limit
    );

    // Step 3: Fetch diffs and extract symbols
    let gh = GithubClient::new(args.github_token);
    let mut vuln_db = VulnDb::new();

    for adv in &candidates {
        if vuln_db.entries.len() >= args.limit {
            break;
        }

        let gh_refs = adv.github_refs();
        if gh_refs.is_empty() {
            continue;
        }

        println!(
            "[{}/{}] {} ({}) - {}",
            vuln_db.entries.len() + 1,
            args.limit,
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
                    let symbols = extract_symbols(&diff);
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
        println!();
    }

    // Step 4: Write output
    let entries_with_symbols = vuln_db
        .entries
        .iter()
        .filter(|e| !e.vulnerable_symbols.is_empty())
        .count();
    println!(
        "Done! {} of {} entries have extracted symbols.",
        entries_with_symbols,
        vuln_db.entries.len()
    );

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
