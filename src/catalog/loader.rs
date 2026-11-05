use anyhow::{Context, Result, bail};
use std::fs;
use std::path::Path;

use crate::manifest::schema::AliasesManifest;

/// Loads and validates the AliasesManifest from a given path.
pub fn load_aliases<P: AsRef<Path>>(path: P) -> Result<AliasesManifest> {
    let aliases_path = path.as_ref();

    if !aliases_path.exists() {
        bail!("The aliases file does not exist at: {:?}", aliases_path);
    }

    let content = fs::read_to_string(aliases_path)
        .with_context(|| format!("Failed to read aliases file at: {:?}", aliases_path))?;

    let aliases: AliasesManifest = yaml_serde::from_str(&content)
        .with_context(|| format!("Failed to parse aliases YAML at: {:?}", aliases_path))?;

    if aliases.schema != "1.0" {
        bail!(
            "Unsupported schema version '{}' in {:?}. Expected '1.0'",
            aliases.schema,
            aliases_path
        );
    }

    Ok(aliases)
}
