use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};

pub fn default_state_database_path() -> Result<PathBuf> {
    if let Some(override_dir) = std::env::var_os("ARC_STATE_DIR") {
        if override_dir.is_empty() {
            bail!("ARC_STATE_DIR cannot be empty");
        }
        return Ok(PathBuf::from(override_dir).join("runtime-state.sqlite3"));
    }

    #[cfg(windows)]
    if let Some(local_app_data) = std::env::var_os("LOCALAPPDATA") {
        return Ok(PathBuf::from(local_app_data)
            .join("Arc")
            .join("runtime")
            .join("runtime-state.sqlite3"));
    }

    #[cfg(not(windows))]
    {
        if let Some(xdg_state_home) = std::env::var_os("XDG_STATE_HOME") {
            return Ok(PathBuf::from(xdg_state_home)
                .join("arc")
                .join("runtime-state.sqlite3"));
        }
        if let Some(user_home) = std::env::var_os("HOME") {
            return Ok(PathBuf::from(user_home)
                .join(".local")
                .join("state")
                .join("arc")
                .join("runtime-state.sqlite3"));
        }
    }

    bail!("unable to resolve an Arc runtime state directory")
}

pub fn canonical_workspace_root(ir_path: &Path) -> Result<PathBuf> {
    let ir_parent = ir_path.parent().context("BehaviorIR path has no parent")?;
    let ir_parent = if ir_parent.as_os_str().is_empty() {
        Path::new(".")
    } else {
        ir_parent
    };
    let is_provider_integration_dir = ir_parent
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| matches!(name, ".codex" | ".agents"));
    let workspace = if is_provider_integration_dir {
        let parent = ir_parent
            .parent()
            .context("BehaviorIR integration directory has no workspace parent")?;
        if parent.as_os_str().is_empty() {
            Path::new(".")
        } else {
            parent
        }
    } else {
        ir_parent
    };
    workspace
        .canonicalize()
        .with_context(|| format!("failed canonicalizing Arc workspace root {workspace:?}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn workspace_root_is_parent_of_integration_directory() {
        let root = std::env::temp_dir().join(format!(
            "arc_workspace_path_{}_{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        let integration = root.join(".codex");
        std::fs::create_dir_all(&integration).unwrap();
        let actual = canonical_workspace_root(&integration.join("arc_ir.json")).unwrap();
        assert_eq!(actual, root.canonicalize().unwrap());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn explicit_ir_uses_its_containing_directory_as_workspace() {
        let root = std::env::temp_dir().join(format!(
            "arc_explicit_ir_path_{}_{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let actual = canonical_workspace_root(&root.join("custom-ir.json")).unwrap();
        assert_eq!(actual, root.canonicalize().unwrap());
        let _ = std::fs::remove_dir_all(root);
    }
}
