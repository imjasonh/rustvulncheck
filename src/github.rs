//! GitHub API client for fetching patch diffs.

use anyhow::{Context, Result};
use reqwest::blocking::Client;
use reqwest::header::{ACCEPT, AUTHORIZATION, USER_AGENT};
use serde::Deserialize;

use crate::advisory::GithubRef;

pub struct GithubClient {
    client: Client,
    token: Option<String>,
}

#[derive(Debug, Deserialize)]
struct PrResponse {
    merge_commit_sha: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CommitFile {
    filename: String,
    patch: Option<String>,
}

/// A fetched diff from GitHub, containing per-file patches.
#[derive(Debug, Clone)]
pub struct PatchDiff {
    pub commit_sha: String,
    pub files: Vec<FilePatch>,
}

#[derive(Debug, Clone)]
pub struct FilePatch {
    pub filename: String,
    pub patch: String,
}

impl GithubClient {
    pub fn new(token: Option<String>) -> Self {
        Self {
            client: Client::new(),
            token,
        }
    }

    fn get(&self, url: &str) -> reqwest::blocking::RequestBuilder {
        let mut req = self
            .client
            .get(url)
            .header(USER_AGENT, "cargo-deep-audit/0.1")
            .header(ACCEPT, "application/vnd.github.v3+json");

        if let Some(ref token) = self.token {
            req = req.header(AUTHORIZATION, format!("Bearer {}", token));
        }

        req
    }

    /// Fetch the diff for a GitHub reference (PR, commit, or issue).
    /// For PRs, resolves the merge commit first. For issues, returns None.
    pub fn fetch_diff(&self, gh_ref: &GithubRef) -> Result<Option<PatchDiff>> {
        match gh_ref {
            GithubRef::Commit { owner, repo, sha } => {
                let diff = self.fetch_commit_diff(owner, repo, sha)?;
                Ok(Some(diff))
            }
            GithubRef::PullRequest {
                owner,
                repo,
                number,
            } => {
                // Get the merge commit SHA from the PR
                let url = format!(
                    "https://api.github.com/repos/{}/{}/pulls/{}",
                    owner, repo, number
                );
                let resp: PrResponse = self
                    .get(&url)
                    .send()
                    .context("fetching PR metadata")?
                    .error_for_status()
                    .context("PR API error")?
                    .json()
                    .context("parsing PR response")?;

                if let Some(sha) = resp.merge_commit_sha {
                    let diff = self.fetch_commit_diff(owner, repo, &sha)?;
                    Ok(Some(diff))
                } else {
                    eprintln!("  PR {}/{}/pull/{} has no merge commit", owner, repo, number);
                    Ok(None)
                }
            }
            GithubRef::Issue { .. } => {
                // Issues don't have diffs directly; skip.
                Ok(None)
            }
        }
    }

    fn fetch_commit_diff(&self, owner: &str, repo: &str, sha: &str) -> Result<PatchDiff> {
        let url = format!(
            "https://api.github.com/repos/{}/{}/commits/{}",
            owner, repo, sha
        );

        let resp = self
            .get(&url)
            .send()
            .context("fetching commit")?
            .error_for_status()
            .context("commit API error")?;

        #[derive(Deserialize)]
        struct CommitResponse {
            sha: String,
            files: Option<Vec<CommitFile>>,
        }

        let commit: CommitResponse = resp.json().context("parsing commit response")?;

        let files = commit
            .files
            .unwrap_or_default()
            .into_iter()
            .filter(|f| f.filename.ends_with(".rs"))
            .filter_map(|f| {
                f.patch.map(|patch| FilePatch {
                    filename: f.filename,
                    patch,
                })
            })
            .collect();

        Ok(PatchDiff {
            commit_sha: commit.sha,
            files,
        })
    }
}
