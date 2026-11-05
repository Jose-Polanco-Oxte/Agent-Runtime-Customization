use arc::emitters::targets::{codex, gemini};
use arc::ir::NormalizedSkill;
use arc::{GeneratedArtifact, OsTarget, ProviderTarget};
use serde::Deserialize;
use std::path::PathBuf;

#[derive(Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct Metadata {
    name: String,
    description: String,
}

fn emit(
    provider: ProviderTarget,
    os: &str,
    name: &str,
    description: &str,
    body: &str,
) -> GeneratedArtifact {
    let skill = NormalizedSkill {
        id: name.into(),
        display_name: name.into(),
        description: description.into(),
        source_path: PathBuf::from("snapshot-only-does-not-exist.md"),
        content: body.into(),
    };
    let target_os = OsTarget::new(os).unwrap();
    let mut artifacts = match provider {
        ProviderTarget::Codex => {
            codex::skills_emitter::SkillsEmitter::emit_skills(&[skill], &target_os)
        }
        ProviderTarget::Gemini => {
            gemini::skills_emitter::SkillsEmitter::emit_skills(&[skill], &target_os)
        }
        ProviderTarget::Claude | ProviderTarget::OpenCode => panic!("unsupported test provider"),
    }
    .unwrap();
    assert_eq!(artifacts.len(), 1);
    let artifact = artifacts.remove(0);
    assert_eq!(artifact.provider, provider);
    assert_eq!(artifact.target_os, target_os);
    assert!(!artifact.is_executable);
    let root = if provider == ProviderTarget::Codex {
        ".codex"
    } else {
        ".agents"
    };
    assert_eq!(
        artifact.relative_path,
        PathBuf::from(format!("{root}/skills/{name}/SKILL.md"))
    );
    artifact
}

fn unpack(content: &str) -> (Metadata, &str) {
    let (yaml, body) = content
        .strip_prefix("---\n")
        .expect("opening delimiter")
        .split_once("\n---\n\n")
        .expect("closing delimiter");
    // Keep the newline before the delimiter: it belongs to a YAML block scalar.
    let yaml = format!("{yaml}\n");
    let value: yaml_serde::Value = yaml_serde::from_str(&yaml).expect("valid YAML metadata");
    assert!(
        value["name"].is_string(),
        "name must be a YAML string: {yaml}"
    );
    assert!(
        value["description"].is_string(),
        "description must be a YAML string: {yaml}"
    );
    (
        yaml_serde::from_str(&yaml).expect("valid string metadata"),
        body,
    )
}

#[test]
fn both_providers_round_trip_yaml_string_metadata() {
    let descriptions = [
        "Revisar: comandos",
        "true",
        "false",
        "null",
        "123",
        "# literal",
        "comillas 'simples' y \"dobles\"",
        "primera\nsegunda\n",
        "---\n: # 🦀",
        "",
        "  espacios iniciales y finales  ",
        "uno\r\ndos\r\n",
        "[a, b]",
        "a---b",
    ];
    for provider in [ProviderTarget::Codex, ProviderTarget::Gemini] {
        for os in ["windows", "linux"] {
            for name in ["true", "123", "test-skill"] {
                for description in descriptions {
                    let artifact = emit(provider, os, name, description, "# Body\n");
                    let (metadata, body) = unpack(&artifact.content);
                    assert_eq!(
                        metadata,
                        Metadata {
                            name: name.into(),
                            description: description.into()
                        },
                        "document={:?}",
                        artifact.content
                    );
                    assert_eq!(body, "# Body\n");
                }
            }
        }
    }
}

#[test]
fn both_providers_strip_only_the_complete_initial_frontmatter_block() {
    let cases = [
        ("---\ndescription: 'a---b'\n---\n# Body\n", "# Body\n"),
        (
            "---\r\ndescription: 'a---b'\r\n---\r\n\r\n# Body\r\n",
            "\r\n# Body\r\n",
        ),
        (
            "---\ndescription: |\n  ---\n---\n  # Indented\n\n",
            "  # Indented\n\n",
        ),
        ("---\n---\n", ""),
        ("---\ndescription: old\n---", ""),
        (
            "---\nname: old\n---\n# Body\n---\nkeep",
            "# Body\n---\nkeep",
        ),
    ];
    for provider in [ProviderTarget::Codex, ProviderTarget::Gemini] {
        for (source, expected) in cases {
            let artifact = emit(provider, "windows", "test-skill", "new", source);
            let (metadata, body) = unpack(&artifact.content);
            assert_eq!(metadata.description, "new");
            assert_eq!(body, expected, "source={source:?}");
        }
    }
}

#[test]
fn both_providers_preserve_content_without_a_complete_initial_block() {
    let cases = [
        "---\ndescription: old\n# Keep this\n--- inline body\n",
        "---inline\nold\n---\n# Keep this\n",
        "---\nold\n----\n# Keep this\n",
        "# Heading\n---\nbody\n---\n",
        "\n---\nname: body\n---\n",
        "---",
        "",
        "  # Indented\n\n",
        "  \r\n# CRLF\r\n\r\n",
    ];
    for provider in [ProviderTarget::Codex, ProviderTarget::Gemini] {
        for source in cases {
            let artifact = emit(provider, "linux", "test-skill", "new", source);
            let (_, body) = unpack(&artifact.content);
            assert_eq!(body, source, "source={source:?}");
        }
    }
}

#[test]
fn loaded_project_emits_valid_skills_for_both_provider_targets() {
    struct Workspace(PathBuf);
    impl Drop for Workspace {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.0).expect("remove isolated project");
        }
    }
    let workspace =
        Workspace(std::env::temp_dir().join(format!("arc-skill-{}", uuid::Uuid::new_v4())));
    std::fs::create_dir_all(workspace.0.join("skills/review")).unwrap();
    let body = "\r\n  # Review 🦀\r\n\r\n";
    std::fs::write(
        workspace.0.join("skills/review/SKILL.md"),
        format!("---\r\ndescription: 'a---b'\r\n---\r\n{body}"),
    )
    .unwrap();
    std::fs::write(workspace.0.join("arc.yaml"), "schema: '1.0'\nroot: {workdir: '.'}\nskills:\n  code_review:\n    src: skills/review\n    description: 'Revisar: comandos # literal'\n").unwrap();
    let project = arc::load_project(&workspace.0.join("arc.yaml")).unwrap();
    let registry = arc::EmitterRegistry::new();
    for provider in [ProviderTarget::Codex, ProviderTarget::Gemini] {
        for os in ["windows", "linux"] {
            let ir = arc::lower(&project, &[os.to_string()]).unwrap();
            let context = arc::EmissionContext {
                provider,
                target_os: OsTarget::new(os).unwrap(),
                environment: arc::ProviderEnvironment::Cli,
                decision_ui: arc::DecisionUiMode::Auto,
                decision_environment: if provider == ProviderTarget::Codex {
                    arc::DecisionEnvironment::codex_hook_with_embedded_ui()
                } else {
                    arc::DecisionEnvironment::hook_with_embedded_ui()
                },
                base_output_path: workspace.0.clone(),
                is_multi_target: false,
                arc_bin: Some("arc".into()),
            };
            let artifacts = registry.get(provider).unwrap().emit(&ir, &context).unwrap();
            let root = if provider == ProviderTarget::Codex {
                ".codex"
            } else {
                ".agents"
            };
            let path = PathBuf::from(format!("{root}/skills/code-review/SKILL.md"));
            let skill = artifacts
                .iter()
                .find(|artifact| artifact.relative_path == path)
                .expect("compiled skill artifact");
            let (metadata, actual_body) = unpack(&skill.content);
            assert_eq!(metadata.name, "code-review");
            assert_eq!(metadata.description, "Revisar: comandos # literal");
            assert_eq!(actual_body, body);
        }
    }
}
