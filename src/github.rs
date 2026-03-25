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
struct PrDetailResponse {
    merge_commit_sha: Option<String>,
    base: Option<PrBranch>,
}

#[derive(Debug, Deserialize)]
struct PrBranch {
    sha: String,
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
    /// Owner/repo needed for fetching full file contents for AST parsing.
    pub owner: String,
    pub repo: String,
    /// Parent commit SHA, used to fetch the "before" version of files.
    pub parent_sha: Option<String>,
    pub files: Vec<FilePatch>,
}

#[derive(Debug, Clone)]
pub struct FilePatch {
    pub filename: String,
    /// The unified diff patch text from the GitHub API.
    #[allow(dead_code)]
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
                // Use the PR files endpoint to get all changes across the PR,
                // rather than a single commit which may miss changes (e.g. if
                // the merge commit is a version bump, or changes span multiple
                // commits).
                let diff = self.fetch_pr_diff(owner, repo, *number)?;
                Ok(Some(diff))
            }
            GithubRef::Issue { .. } => {
                // Issues don't have diffs directly; skip.
                Ok(None)
            }
        }
    }

    /// Fetch all .rs file changes from a PR using the PR files endpoint.
    /// This captures all changes across the PR, not just a single commit.
    fn fetch_pr_diff(&self, owner: &str, repo: &str, number: u64) -> Result<PatchDiff> {
        // Get merge commit SHA and base ref for the entry metadata
        let pr_url = format!(
            "https://api.github.com/repos/{}/{}/pulls/{}",
            owner, repo, number
        );
        let pr_resp: PrDetailResponse = self
            .get(&pr_url)
            .send()
            .context("fetching PR metadata")?
            .error_for_status()
            .context("PR API error")?
            .json()
            .context("parsing PR response")?;

        let commit_sha = pr_resp
            .merge_commit_sha
            .unwrap_or_else(|| format!("pr-{}", number));

        let parent_sha = pr_resp.base.map(|b| b.sha);

        // Fetch all files changed in the PR (paginated, up to 300 files)
        let files_url = format!(
            "https://api.github.com/repos/{}/{}/pulls/{}/files?per_page=100",
            owner, repo, number
        );
        let resp = self
            .get(&files_url)
            .send()
            .context("fetching PR files")?
            .error_for_status()
            .context("PR files API error")?;

        let pr_files: Vec<CommitFile> = resp.json().context("parsing PR files response")?;

        let files = pr_files
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
            commit_sha,
            owner: owner.to_string(),
            repo: repo.to_string(),
            parent_sha,
            files,
        })
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
            parents: Option<Vec<CommitParent>>,
            files: Option<Vec<CommitFile>>,
        }

        #[derive(Deserialize)]
        struct CommitParent {
            sha: String,
        }

        let commit: CommitResponse = resp.json().context("parsing commit response")?;

        let parent_sha = commit
            .parents
            .as_ref()
            .and_then(|p| p.first())
            .map(|p| p.sha.clone());

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
            owner: owner.to_string(),
            repo: repo.to_string(),
            parent_sha,
            files,
        })
    }

    /// Fetch the raw contents of a file at a specific ref (commit SHA, branch, tag).
    /// Returns `Ok(None)` if the file doesn't exist at that ref (404).
    pub fn fetch_file_contents(
        &self,
        owner: &str,
        repo: &str,
        path: &str,
        ref_: &str,
    ) -> Result<Option<String>> {
        let url = format!(
            "https://api.github.com/repos/{}/{}/contents/{}?ref={}",
            owner, repo, path, ref_
        );

        let resp = self
            .client
            .get(&url)
            .header(USER_AGENT, "cargo-deep-audit/0.1")
            .header(ACCEPT, "application/vnd.github.v3.raw");

        let resp = if let Some(ref token) = self.token {
            resp.header(AUTHORIZATION, format!("Bearer {}", token))
        } else {
            resp
        };

        let resp = resp.send().context("fetching file contents")?;

        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }

        let body = resp
            .error_for_status()
            .context("file contents API error")?
            .text()
            .context("reading file contents")?;

        Ok(Some(body))
    }
}
