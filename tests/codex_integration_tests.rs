#[path = "guard_evaluation_support.rs"]
mod guard_evaluation_support;
use guard_evaluation_support::evaluate_session_event;

use arc::compiler::validator::SemanticValidator;
use arc::{
    ArcRuntimeSession, CodexAdapter, CodexEmitter, CodexPreToolUseInput, EmissionContext,
    EmitterRegistry, OsTarget, ProviderTarget, TargetEmitter, check_project_compatibility,
    generate_capabilities_table, load_project, lower, write_artifacts,
};
use std::fs;

#[test]
fn test_codex_end_to_end_build() {
    let temp_dir = std::env::temp_dir().join(format!("arc_codex_test_{}", std::process::id()));
    let _ = fs::remove_dir_all(&temp_dir);
    fs::create_dir_all(&temp_dir).unwrap();

    let arc_yaml = r#"
schema: "1.0"
root:
  workdir: "."
  instructions: "directives.md"
skills:
  git_flow:
    src: "skills/git_flow.md"
    description: "Standard git branching workflow"
roles:
  reviewer:
    description: "Code reviewer"
    src: "roles/reviewer.md"
guards:
  tools:
    protected_push:
      matches:
        alias: git.push.force
      require:
        probe:
          use:
            alias: git.branch.current
          in:
            - feature
      on_failure:
        action: deny
        feedback: "Force push is only permitted on feature branches"
  lifecycle:
    clean_exit:
      trigger: end
      require:
        decide:
          prompt: "Are all git changes committed or stashed?"
      on_failure:
        action: deny
        feedback: "Uncommitted changes remain before session end"
"#;

    let aliases_yaml = r#"
schema: "1.0"
matchers:
  git.push.force:
    windows:
      exact: "git push --force origin main"
      regex: '(?i)git\s+push\s+.*--force'
    linux:
      regex: 'git\s+push\s+.*--force'
operations:
  git.branch.current:
    windows: "git branch --show-current"
    linux: "git branch --show-current"
"#;

    let directives_md = "# Workspace Directives\nAlways follow test-driven development.";
    let skill_md = "# Git Flow\nStep 1: Check out a dedicated branch.";
    let role_md = "# Reviewer Role\nReview all pull requests for cleanliness.";

    fs::write(temp_dir.join("arc.yaml"), arc_yaml).unwrap();
    fs::write(temp_dir.join("aliases.yaml"), aliases_yaml).unwrap();
    fs::write(temp_dir.join("directives.md"), directives_md).unwrap();
    fs::create_dir_all(temp_dir.join("skills")).unwrap();
    fs::write(temp_dir.join("skills/git_flow.md"), skill_md).unwrap();
    fs::create_dir_all(temp_dir.join("roles")).unwrap();
    fs::write(temp_dir.join("roles/reviewer.md"), role_md).unwrap();

    // 1. Load project
    let project = load_project(&temp_dir.join("arc.yaml")).unwrap();

    // 2. Validate capability compatibility for Codex
    let val_res = SemanticValidator::validate_project_for_provider(&project, ProviderTarget::Codex);
    assert!(
        val_res.is_ok(),
        "Validation should succeed for compliant Codex project"
    );

    // 3. Lower project into BehaviorIR
    let ir = lower(&project, &["windows".to_string()]).unwrap();

    // 4. Emit artifacts using CodexEmitter
    let emitter = CodexEmitter;
    fs::create_dir_all(temp_dir.join(".codex")).unwrap();
    let existing_config = "model = \"custom-model\"\n[sandbox]\nmode = \"strict\"\n";
    fs::write(temp_dir.join(".codex/config.toml"), existing_config).unwrap();
    let emission_ctx = EmissionContext {
        provider: ProviderTarget::Codex,
        target_os: OsTarget::new("windows").expect("windows is a valid test OS"),
        environment: arc::ProviderEnvironment::Cli,
        decision_ui: arc::DecisionUiMode::Auto,
        decision_environment: arc::DecisionEnvironment::codex_hook_with_embedded_ui(),
        base_output_path: temp_dir.clone(),
        is_multi_target: false,
        arc_bin: Some("arc".into()),
    };

    let artifacts = emitter.emit(&ir, &emission_ctx).unwrap();
    write_artifacts(&temp_dir, &artifacts).unwrap();

    // 5. Verify generated artifacts
    assert!(temp_dir.join(".codex/arc_ir.json").exists());
    assert!(temp_dir.join("AGENTS.md").exists());
    assert!(temp_dir.join(".codex/skills/git-flow/SKILL.md").exists());
    assert!(temp_dir.join(".codex/hooks.json").exists());
    assert_eq!(
        fs::read_to_string(temp_dir.join(".codex/config.toml")).unwrap(),
        existing_config
    );

    // Check AGENTS.md content (includes project guidelines and simulated role personas)
    let agents_md_content = fs::read_to_string(temp_dir.join("AGENTS.md")).unwrap();
    assert!(agents_md_content.contains("Always follow test-driven development."));
    assert!(agents_md_content.contains("### Role: `reviewer`"));
    assert!(agents_md_content.contains("Review all pull requests for cleanliness."));

    // Check canonical flat skill path and frontmatter.
    let skill_content =
        fs::read_to_string(temp_dir.join(".codex/skills/git-flow/SKILL.md")).unwrap();
    assert!(skill_content.contains("name: git-flow"));
    assert!(skill_content.contains("# Git Flow"));

    // Check .codex/hooks.json content
    let hooks_json = fs::read_to_string(temp_dir.join(".codex/hooks.json")).unwrap();
    let hooks: serde_json::Value = serde_json::from_str(&hooks_json).unwrap();
    for event in ["PreToolUse", "Stop"] {
        let groups = hooks["hooks"][event].as_array().unwrap();
        assert!(groups[0]["hooks"].is_array());
    }

    // 6. Test runtime hook simulation with CodexAdapter
    let hook_raw_json = r#"{
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {
            "command": "git push --force origin main"
        },
        "session_id": "codex-test-session-001",
        "cwd": "C:/fake_repo"
    }"#;

    let hook_input: CodexPreToolUseInput = serde_json::from_str(hook_raw_json).unwrap();
    let arc_event = CodexAdapter::pre_tool_use_to_event(&hook_input, 1);

    let mut session = ArcRuntimeSession::new("test-session", ir.clone())
        .with_trusted_anchor(
            arc::SqliteStateStore::open_in_memory()
                .unwrap()
                .trust_and_anchor_ir(std::path::Path::new("canonical/arc_ir.json"), &ir)
                .unwrap(),
        )
        .unwrap();
    let eval_result = evaluate_session_event(&mut session, arc_event).unwrap();
    let output = CodexAdapter::evaluation_result_to_pre_tool_use_output(&eval_result).unwrap();

    // In session evaluation, probe runner runs. Since C:/fake_repo is not on 'feature', it denies!
    assert_eq!(
        output
            .hook_specific_output
            .as_ref()
            .unwrap()
            .permission_decision,
        "deny"
    );
    assert!(
        output
            .hook_specific_output
            .unwrap()
            .permission_decision_reason
            .unwrap()
            .contains("Force push is only permitted on feature branches")
    );

    let _ = fs::remove_dir_all(temp_dir);
}

#[test]
fn test_gemini_rejection_of_start_deny() {
    let temp_dir = std::env::temp_dir().join(format!("arc_gemini_incompat_{}", std::process::id()));
    let _ = fs::remove_dir_all(&temp_dir);
    fs::create_dir_all(&temp_dir).unwrap();

    let arc_yaml = r#"
schema: "1.0"
root:
  workdir: "."
guards:
  lifecycle:
    guard_start:
      trigger: start
      require:
        decide:
          prompt: "Is start safe?"
      on_failure:
        action: deny
"#;

    fs::write(temp_dir.join("arc.yaml"), arc_yaml).unwrap();
    let project = load_project(&temp_dir.join("arc.yaml")).unwrap();

    // Check compatibility diagnostics
    let diagnostics = check_project_compatibility(&project, ProviderTarget::Gemini);
    assert_eq!(diagnostics.len(), 1);
    assert_eq!(diagnostics[0].guard_id, "guard_start");

    // Validation must fail
    let val_res =
        SemanticValidator::validate_project_for_provider(&project, ProviderTarget::Gemini);
    assert!(val_res.is_err());
    let err_str = val_res.unwrap_err().to_string();
    assert!(err_str.contains("Provider capability validation failed for target 'gemini'"));
    assert!(err_str.contains("PreInvocation"));

    let _ = fs::remove_dir_all(temp_dir);
}

#[test]
fn test_capabilities_matrix_output() {
    let registry = EmitterRegistry::new();
    let table = generate_capabilities_table(&registry.providers());
    assert!(table.contains("Gemini (AGY)"));
    assert!(table.contains("Codex"));
    assert!(!table.contains("Claude"));
    assert!(!table.contains("OpenCode"));
    assert!(table.contains("PreToolUse (Tool Guards)"));
    assert!(table.contains("Lifecycle: Start"));
    assert!(table.contains("Lifecycle: End"));
    assert!(table.contains("User Approval Dialog"));
}

#[test]
fn test_codex_accepts_regex_ask_matcher_for_arc_owned_dialog() {
    let temp_dir =
        std::env::temp_dir().join(format!("arc_codex_ask_incompat_{}", std::process::id()));
    let _ = fs::remove_dir_all(&temp_dir);
    fs::create_dir_all(&temp_dir).unwrap();
    fs::write(
        temp_dir.join("arc.yaml"),
        r#"
schema: "1.0"
root:
  workdir: "."
guards:
  tools:
    approve_dynamic_push:
      matches:
        regex: "git push .*"
      require:
        decide:
          prompt: "Approve push?"
      on_failure:
        action: ask
"#,
    )
    .unwrap();

    let project = load_project(&temp_dir.join("arc.yaml")).unwrap();
    SemanticValidator::validate_project_for_provider(&project, ProviderTarget::Codex).unwrap();
    let _ = fs::remove_dir_all(&temp_dir);
}
