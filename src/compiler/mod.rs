pub mod flattener;
pub mod linker;
pub mod validator;

use anyhow::{Context, Result};
use std::collections::BTreeMap;

use crate::ir::{BehaviorIR, BoundRole, WorkspaceContext};
use crate::manifest::loader::LoadedArcProject;

pub use flattener::SkillFlattener;

pub use linker::GuardLinker;
pub use validator::SemanticValidator;

/// Lowers a LoadedArcProject into a unified BehaviorIR for the specified target OSes.
pub fn lower(project: &LoadedArcProject, target_os_list: &[String]) -> Result<BehaviorIR> {
    // 1. Run comprehensive semantic validation on the project
    SemanticValidator::validate_project(project).context("Failed semantic validation")?;

    // 2. Resolve WorkspaceContext
    let workdir = project.workdir.clone();
    let instructions_path = project.instructions_path.clone();
    let instructions_content = project.instructions_content.clone();

    let mut roles = BTreeMap::new();
    for (role_name, role_config) in &project.roles {
        let (src_path, content) = if role_config.src.is_some() {
            let source = project.role_sources.get(role_name).ok_or_else(|| {
                anyhow::anyhow!(
                    "Role '{}' has a source declaration but no validated source snapshot",
                    role_name
                )
            })?;
            (Some(source.path.clone()), Some(source.content.clone()))
        } else {
            (None, None)
        };

        roles.insert(
            role_name.clone(),
            BoundRole {
                description: role_config.description.clone(),
                src_path,
                content,
            },
        );
    }

    let context = WorkspaceContext {
        workdir: workdir.clone(),
        instructions_path,
        instructions_content,
        roles,
    };

    // 3. Flatten Skills & validate normalization collision
    let skills = SkillFlattener::flatten_skills(&workdir, &project.skills)
        .context("Failed during skill flattening stage")?;
    SemanticValidator::validate_skills_normalization(&skills)
        .context("Failed skill normalization validation")?;

    // 4. Link guards & rules for target OSes
    let (lifecycle_guards, tool_guards, rules) = GuardLinker::link_project(project, target_os_list)
        .with_context(|| {
            format!(
                "Failed linking guards and rules for target OS list: {:?}",
                target_os_list
            )
        })?;

    let mut ir = BehaviorIR {
        schema: "1.0".to_string(),
        compiler_version: env!("CARGO_PKG_VERSION").to_string(),
        build_id: Some(uuid::Uuid::new_v4().to_string()),
        content_hash: None,
        runtime: project.manifest.runtime.clone(),
        context,
        skills,
        lifecycle_guards,
        tool_guards,
        rules,
    };
    ir.content_hash = Some(ir.compute_content_hash());
    ir.validate_integrity()
        .context("Generated IR failed runtime invariant validation")?;

    Ok(ir)
}
