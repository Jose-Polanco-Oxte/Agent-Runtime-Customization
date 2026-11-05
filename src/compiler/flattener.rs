use anyhow::{Result, bail};
use std::collections::BTreeMap;
use std::path::Path;

use crate::ir::NormalizedSkill;
use crate::manifest::loader::{read_contained_file, resolve_relative_path, validate_containment};
use crate::manifest::schema::{SkillDeclaration, SkillItem};

pub struct SkillFlattener;

impl SkillFlattener {
    /// Iteratively flattens the hierarchical map of skills into a linear collection of NormalizedSkill (M6).
    pub fn flatten_skills(
        workdir: &Path,
        declarations: &BTreeMap<String, SkillDeclaration>,
    ) -> Result<Vec<NormalizedSkill>> {
        struct FlattenFrame<'a> {
            prefix_id: String,
            prefix_display: String,
            declarations: &'a BTreeMap<String, SkillDeclaration>,
        }

        let mut flattened = Vec::new();
        let mut stack = vec![FlattenFrame {
            prefix_id: String::new(),
            prefix_display: "skills".into(),
            declarations,
        }];

        while let Some(frame) = stack.pop() {
            // Process entries in reverse to maintain original map order on the stack
            for (name, declaration) in frame.declarations.iter().rev() {
                if name.contains('/')
                    || name.contains('\\')
                    || name.contains("..")
                    || name.starts_with('.')
                {
                    bail!(
                        "Invalid skill declaration name '{}': contains path traversal or forbidden characters",
                        name
                    );
                }

                let canonical_segment = name.replace('_', "-").to_ascii_lowercase();
                let id = if frame.prefix_id.is_empty() {
                    canonical_segment
                } else {
                    format!("{}-{}", frame.prefix_id, canonical_segment)
                };

                let display_name = format!("{}.{}", frame.prefix_display, name);

                match declaration {
                    SkillDeclaration::Single(item) => {
                        let skill = Self::process_skill_item(workdir, &id, &display_name, item)?;
                        flattened.push(skill);
                    }
                    SkillDeclaration::Group {
                        description: _,
                        members,
                    } => {
                        stack.push(FlattenFrame {
                            prefix_id: id,
                            prefix_display: format!("{display_name}.members"),
                            declarations: members,
                        });
                    }
                }
            }
        }

        // Reverse to ensure deterministic forward order from top to bottom
        flattened.reverse();
        Ok(flattened)
    }

    fn process_skill_item(
        workdir: &Path,
        id: &str,
        display_name: &str,
        item: &SkillItem,
    ) -> Result<NormalizedSkill> {
        let raw_source_path = resolve_relative_path(workdir, &item.src)?;
        let source_path = validate_containment(
            workdir,
            &raw_source_path,
            &format!("Skill '{}'", display_name),
        )?;

        let (_content_path, content) = if source_path.is_file() {
            read_contained_file(workdir, &source_path, &format!("skill '{}'", display_name))?
        } else if source_path.is_dir() {
            let skill_md = source_path.join("SKILL.md");
            let readme_md = source_path.join("README.md");
            let content_path = if skill_md.is_file() {
                skill_md
            } else if readme_md.is_file() {
                readme_md
            } else {
                bail!(
                    "Skill '{}' source path {:?} is a directory, but does not contain a 'SKILL.md' or 'README.md' file",
                    display_name,
                    source_path
                );
            };
            read_contained_file(
                workdir,
                &content_path,
                &format!("skill '{}' content", display_name),
            )?
        } else {
            bail!(
                "Skill '{}' refers to a non-regular path: {:?}",
                display_name,
                source_path
            );
        };

        Ok(NormalizedSkill {
            id: id.to_string(),
            display_name: display_name.to_string(),
            description: item.description.clone(),
            source_path,
            content,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_flatten_recursive_skills() {
        let temp_dir = std::env::temp_dir();
        let dummy_skill_file = temp_dir.join("test_skill_rec.md");
        std::fs::write(&dummy_skill_file, "# Skill Content").unwrap();

        let mut declarations = BTreeMap::new();
        declarations.insert(
            "python".to_string(),
            SkillDeclaration::Single(SkillItem {
                description: "Python skill".to_string(),
                src: PathBuf::from("test_skill_rec.md"),
            }),
        );

        let mut sub_members = BTreeMap::new();
        sub_members.insert(
            "struct".to_string(),
            SkillDeclaration::Single(SkillItem {
                description: "Struct anti-pattern".to_string(),
                src: PathBuf::from("test_skill_rec.md"),
            }),
        );

        let mut rust_members = BTreeMap::new();
        rust_members.insert(
            "testing".to_string(),
            SkillDeclaration::Single(SkillItem {
                description: "Rust testing".to_string(),
                src: PathBuf::from("test_skill_rec.md"),
            }),
        );
        rust_members.insert(
            "anti_patterns".to_string(),
            SkillDeclaration::Group {
                description: None,
                members: sub_members,
            },
        );

        declarations.insert(
            "rust_dev".to_string(),
            SkillDeclaration::Group {
                description: Some("Rust Suite".to_string()),
                members: rust_members,
            },
        );

        let flattened = SkillFlattener::flatten_skills(&temp_dir, &declarations).unwrap();
        assert_eq!(flattened.len(), 3);
        assert!(
            flattened
                .iter()
                .any(|s| s.id == "python" && s.display_name == "skills.python")
        );
        assert!(
            flattened.iter().any(|s| s.id == "rust-dev-testing"
                && s.display_name == "skills.rust_dev.members.testing")
        );
        assert!(
            flattened
                .iter()
                .any(|s| s.id == "rust-dev-anti-patterns-struct"
                    && s.display_name == "skills.rust_dev.members.anti_patterns.members.struct")
        );

        let _ = std::fs::remove_file(dummy_skill_file);
    }
}
