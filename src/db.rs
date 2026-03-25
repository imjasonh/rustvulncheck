//! Output database: maps advisory IDs to vulnerable function signatures.

use serde::Serialize;
use std::path::Path;

/// The enriched vulnerability database.
#[derive(Debug, Serialize)]
pub struct VulnDb {
    pub generated_at: String,
    pub entries: Vec<VulnEntry>,
}

/// A single vulnerability entry with function-level detail.
#[derive(Debug, Serialize)]
pub struct VulnEntry {
    pub advisory_id: String,
    pub package: String,
    pub title: String,
    pub date: String,
    pub patched_versions: Vec<String>,
    pub commit_sha: Option<String>,
    pub vulnerable_symbols: Vec<crate::diff_analyzer::VulnerableSymbol>,
}

impl VulnDb {
    pub fn new() -> Self {
        let now = chrono_lite_now();
        Self {
            generated_at: now,
            entries: Vec::new(),
        }
    }

    pub fn write_json(&self, path: &Path) -> anyhow::Result<()> {
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(path, json)?;
        Ok(())
    }
}

/// Simple timestamp without pulling in chrono.
fn chrono_lite_now() -> String {
    use std::time::SystemTime;
    let duration = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    format!("unix:{}", duration.as_secs())
}
