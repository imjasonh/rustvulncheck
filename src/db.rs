//! Output database: maps advisory IDs to vulnerable function signatures.

use serde::{Deserialize, Serialize};
use std::path::Path;

/// The enriched vulnerability database.
#[derive(Debug, Serialize, Deserialize)]
pub struct VulnDb {
    pub generated_at: String,
    pub entries: Vec<VulnEntry>,
}

/// A single vulnerability entry with function-level detail.
#[derive(Debug, Clone, Serialize, Deserialize)]
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

    pub fn update_timestamp(&mut self) {
        self.generated_at = chrono_lite_now();
    }

    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let data = std::fs::read_to_string(path)?;
        let db: VulnDb = serde_json::from_str(&data)?;
        Ok(db)
    }

    pub fn write_json(&self, path: &Path) -> anyhow::Result<()> {
        // Sort for deterministic output to minimize diff noise
        let mut sorted = self.entries.clone();
        sorted.sort_by(|a, b| a.advisory_id.cmp(&b.advisory_id));
        for entry in &mut sorted {
            entry.vulnerable_symbols.sort_by(|a, b| {
                a.file
                    .cmp(&b.file)
                    .then(a.function.cmp(&b.function))
                    .then(a.change_type.cmp(&b.change_type))
            });
        }

        let sorted_db = VulnDb {
            generated_at: self.generated_at.clone(),
            entries: sorted,
        };
        let mut json = serde_json::to_string_pretty(&sorted_db)?;
        json.push('\n');
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
