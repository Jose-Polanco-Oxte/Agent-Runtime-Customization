use anyhow::Result;
use std::path::PathBuf;

use crate::emitters::skill_document::render_skill_document;
use crate::emitters::traits::GeneratedArtifact;
use crate::ir::NormalizedSkill;
use crate::target::{OsTarget, ProviderTarget};

pub struct SkillsEmitter;

impl SkillsEmitter {
    /// Emits all NormalizedSkills as Codex Skills in `.codex/skills/<id>/SKILL.md`.
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

            let codex_path = PathBuf::from(format!(".codex/skills/{canonical_name}/SKILL.md"));
            artifacts.push(GeneratedArtifact {
                provider: ProviderTarget::Codex,
                target_os: target_os.clone(),
                relative_path: codex_path,
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
    fn test_codex_skills_emission() {
        let temp_dir = std::env::temp_dir().join("arc_test_codex_skills_single");
        let _ = fs::remove_dir_all(&temp_dir);
        fs::create_dir_all(&temp_dir).unwrap();

        let dummy_skill_file = temp_dir.join("skill.md");
        fs::write(&dummy_skill_file, "# Codex Skill Body\nInstructions here.").unwrap();

        let skill = NormalizedSkill {
            id: "git_rebase".into(),
            display_name: "git.rebase".into(),
            description: "Rebase instructions".into(),
            source_path: dummy_skill_file.clone(),
            content: "# Codex Skill Body\nInstructions here.".into(),
        };

        let target_os = OsTarget::new("linux").expect("linux is a valid test OS");
        let artifacts = SkillsEmitter::emit_skills(&[skill], &target_os).unwrap();

        assert_eq!(artifacts.len(), 1);
        assert_eq!(
            artifacts[0].relative_path,
            PathBuf::from(".codex/skills/git-rebase/SKILL.md")
        );
        assert!(artifacts[0].content.contains("name: git-rebase"));
        assert!(artifacts[0].content.contains("# Codex Skill Body"));

        let _ = fs::remove_file(dummy_skill_file);
        let _ = fs::remove_dir_all(temp_dir);
    }
}
