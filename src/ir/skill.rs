use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NormalizedSkill {
    pub id: String,
    pub display_name: String,
    pub description: String,
    pub source_path: PathBuf,
    /// Content captured from the validated file handle during compilation.
    /// Emitters must consume this snapshot instead of reopening `source_path`.
    pub content: String,
}

impl NormalizedSkill {
    /// Returns the provider-facing, flat skill name used for paths and frontmatter.
    pub fn canonical_name(&self) -> String {
        self.id.replace('_', "-").to_ascii_lowercase()
    }

    /// Returns the immutable content captured while loading the project.
    pub fn read_content(&self) -> Result<&str> {
        Ok(&self.content)
    }
}
