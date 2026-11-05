use anyhow::Result;
use std::path::PathBuf;

use crate::emitters::skill_document::render_skill_document;
use crate::emitters::traits::GeneratedArtifact;
use crate::ir::NormalizedSkill;
use crate::target::{OsTarget, ProviderTarget};

pub struct SkillsEmitter;

impl SkillsEmitter {
    /// Emits all NormalizedSkills as AGY Progressive Skills in `.agents/skills/<id>/SKILL.md`.
    pub fn emit_skills(
        skills: &[NormalizedSkill],
        target_os: &OsTarget,
    ) -> Result<Vec<GeneratedArtifact>> {
        let mut artifacts = Vec::new();

        for skill in skills {
            let canonical_name = skill.canonical_name();
            let raw_content = skill.read_content()?;

            let formatted =
                render_skill_document(&canonical_name, &skill.description, raw_content)?;

            let relative_path = PathBuf::from(format!(".agents/skills/{canonical_name}/SKILL.md"));

            artifacts.push(GeneratedArtifact {
                provider: ProviderTarget::Gemini,
                target_os: target_os.clone(),
                relative_path,
                content: formatted,
                is_executable: false,
            });
        }

        Ok(artifacts)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_skills_emission() {
        let temp_dir = std::env::temp_dir();
        let dummy_skill_file = temp_dir.join("test_emit_skill.md");
        fs::write(&dummy_skill_file, "# Skill Body\nInstructions here.").unwrap();

        let skills = vec![NormalizedSkill {
            id: "rust_dev_testing".into(),
            display_name: "rust_dev.testing".into(),
            description: "Rust testing skill".into(),
            source_path: dummy_skill_file.clone(),
            content: "# Skill Body\nInstructions here.".into(),
        }];

        let artifacts = SkillsEmitter::emit_skills(
            &skills,
            &OsTarget::new("windows").expect("windows is a valid test OS"),
        )
        .unwrap();
        assert_eq!(artifacts.len(), 1);
        assert_eq!(
            artifacts[0].relative_path,
            PathBuf::from(".agents/skills/rust-dev-testing/SKILL.md")
        );
        assert!(artifacts[0].content.contains("name: rust-dev-testing"));
        assert!(
            artifacts[0]
                .content
                .contains("description: Rust testing skill")
        );
        assert!(artifacts[0].content.contains("# Skill Body"));

        let _ = fs::remove_file(dummy_skill_file);
    }
}
