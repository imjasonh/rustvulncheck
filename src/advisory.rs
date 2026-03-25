//! Parser for RustSec advisory-db TOML files.

use anyhow::{Context, Result};
use serde::Deserialize;
use std::path::Path;
use walkdir::WalkDir;

/// Raw TOML structure of a RustSec advisory file.
#[derive(Debug, Deserialize)]
pub struct AdvisoryFile {
    pub advisory: AdvisoryMeta,
    #[serde(default)]
    pub versions: VersionInfo,
}

#[derive(Debug, Deserialize)]
pub struct AdvisoryMeta {
    pub id: String,
    #[serde(default)]
    pub package: String,
    #[serde(default)]
    pub date: String,
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub references: Vec<String>,
    #[serde(default)]
    pub title: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
pub struct VersionInfo {
    #[serde(default)]
    pub patched: Vec<String>,
    #[serde(default)]
    pub unaffected: Vec<String>,
}

/// Parsed advisory with extracted GitHub references.
#[derive(Debug, Clone)]
pub struct Advisory {
    pub id: String,
    pub package: String,
    pub date: String,
    pub title: String,
    pub patched_versions: Vec<String>,
    pub github_urls: Vec<String>,
}

impl Advisory {
    /// Extract GitHub PR/issue/commit URLs from advisory references and URL fields.
    pub fn github_refs(&self) -> Vec<GithubRef> {
        let mut refs = Vec::new();
        for url in &self.github_urls {
            if let Some(r) = GithubRef::parse(url) {
                refs.push(r);
            }
        }
        refs
    }
}

/// A parsed GitHub reference (PR, issue, or commit).
#[derive(Debug, Clone)]
pub enum GithubRef {
    PullRequest {
        owner: String,
        repo: String,
        number: u64,
    },
    Issue {
        owner: String,
        repo: String,
        number: u64,
    },
    Commit {
        owner: String,
        repo: String,
        sha: String,
    },
}

impl GithubRef {
    pub fn parse(url: &str) -> Option<Self> {
        let url = url.trim_end_matches('/');

        // Match: github.com/owner/repo/pull/123
        if let Some(caps) = regex::Regex::new(
            r"github\.com/([^/]+)/([^/]+)/pull/(\d+)",
        )
        .ok()?
        .captures(url)
        {
            return Some(GithubRef::PullRequest {
                owner: caps[1].to_string(),
                repo: caps[2].to_string(),
                number: caps[3].parse().ok()?,
            });
        }

        // Match: github.com/owner/repo/issues/123
        if let Some(caps) = regex::Regex::new(
            r"github\.com/([^/]+)/([^/]+)/issues/(\d+)",
        )
        .ok()?
        .captures(url)
        {
            return Some(GithubRef::Issue {
                owner: caps[1].to_string(),
                repo: caps[2].to_string(),
                number: caps[3].parse().ok()?,
            });
        }

        // Match: github.com/owner/repo/commit/<sha>
        if let Some(caps) = regex::Regex::new(
            r"github\.com/([^/]+)/([^/]+)/commit/([0-9a-f]+)",
        )
        .ok()?
        .captures(url)
        {
            return Some(GithubRef::Commit {
                owner: caps[1].to_string(),
                repo: caps[2].to_string(),
                sha: caps[3].to_string(),
            });
        }

        None
    }
}

/// Scan a directory of RustSec advisory TOML files and parse them.
pub fn parse_advisory_db(db_path: &Path) -> Result<Vec<Advisory>> {
    let crates_dir = db_path.join("crates");
    if !crates_dir.exists() {
        anyhow::bail!(
            "advisory-db 'crates' directory not found at {}",
            crates_dir.display()
        );
    }

    let mut advisories = Vec::new();

    for entry in WalkDir::new(&crates_dir)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        let path = entry.path();
        if path.extension().map_or(true, |ext| ext != "toml") {
            continue;
        }

        match parse_advisory_file(path) {
            Ok(adv) => advisories.push(adv),
            Err(e) => {
                eprintln!("Warning: skipping {}: {}", path.display(), e);
            }
        }
    }

    // Sort by date descending (most recent first)
    advisories.sort_by(|a, b| b.date.cmp(&a.date));

    Ok(advisories)
}

fn parse_advisory_file(path: &Path) -> Result<Advisory> {
    let content =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;

    let file: AdvisoryFile =
        toml::from_str(&content).with_context(|| format!("parsing {}", path.display()))?;

    let mut github_urls = Vec::new();

    // Collect URLs from the `url` field
    if let Some(ref url) = file.advisory.url {
        if url.contains("github.com") {
            github_urls.push(url.clone());
        }
    }

    // Collect URLs from `references`
    for r in &file.advisory.references {
        if r.contains("github.com") {
            github_urls.push(r.clone());
        }
    }

    Ok(Advisory {
        id: file.advisory.id,
        package: file.advisory.package,
        date: file.advisory.date,
        title: file
            .advisory
            .title
            .unwrap_or_else(|| "(no title)".to_string()),
        patched_versions: file.versions.patched,
        github_urls,
    })
}
