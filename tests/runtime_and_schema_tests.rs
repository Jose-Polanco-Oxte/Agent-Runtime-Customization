#[path = "guard_evaluation_support.rs"]
mod guard_evaluation_support;
use guard_evaluation_support::evaluate_session_event;

use std::fs;
use std::path::Path;
use std::sync::Arc;

use arc::{
    ActionType, ActivationCacheSummary, ArcEvaluationResult, ArcEvent, ArcEventType,
    ArcRuntimeSession, BehaviorIR, EVENT_EVALUATION_REPORT_SCHEMA, EffectiveDisposition,
    EvaluationCompleteness, EvaluationFault, EventEvaluationReport, GuardResult, GuardResultState,
    MockDecisionProvider, MockProbeRunner, OsTarget, ProviderTarget, discover_arc_root,
    fingerprint, load_project, lower,
};

fn canonical_test_result(
    provider: ProviderTarget,
    event_type: ArcEventType,
    action: ActionType,
    satisfied: bool,
) -> ArcEvaluationResult {
    let guard_results = vec![GuardResult::test_result(
        "test_guard",
        0,
        0,
        action,
        satisfied,
    )];
    let report_fingerprint = fingerprint(&serde_json::to_vec(&guard_results).unwrap());
    ArcEvaluationResult::from_report(EventEvaluationReport {
        schema: EVENT_EVALUATION_REPORT_SCHEMA.into(),
        invocation_id: "test-invocation".into(),
        provider,
        event_id: "test-event".into(),
        event_type,
        input_fingerprint: fingerprint(b"test-input"),
        effective_disposition: arc::reduce_effective_disposition(&guard_results),
        authorization_requirements: Vec::new(),
        activation_cache_summary: ActivationCacheSummary {
            logical_occurrences: 0,
            unique_probe_evaluations: 0,
            unique_decision_evaluations: 0,
            coalesced_in_flight: 0,
            reused_completed: 0,
            physical_faults: 0,
        },
        report_fingerprint,
        started_unix_ms: 1,
        completed_unix_ms: 2,
        guard_results,
    })
    .unwrap()
}

fn canonical_fault_result(
    provider: ProviderTarget,
    event_type: ArcEventType,
) -> ArcEvaluationResult {
    let mut guard = GuardResult::test_result("fault_guard", 0, 0, ActionType::Deny, false);
    guard.state = GuardResultState::Faulted {
        faults: vec![EvaluationFault::Probe {
            summary: "probe execution failed".into(),
        }],
        causes: Vec::new(),
    };
    guard.completeness = EvaluationCompleteness::IncompleteDueToFault;
    let guard_results = vec![guard];
    let report_fingerprint = fingerprint(&serde_json::to_vec(&guard_results).unwrap());
    ArcEvaluationResult::from_report(EventEvaluationReport {
        schema: EVENT_EVALUATION_REPORT_SCHEMA.into(),
        invocation_id: "fault-invocation".into(),
        provider,
        event_id: "fault-event".into(),
        event_type,
        input_fingerprint: fingerprint(b"fault-input"),
        effective_disposition: EffectiveDisposition::RuntimeFault,
        authorization_requirements: Vec::new(),
        activation_cache_summary: ActivationCacheSummary {
            logical_occurrences: 0,
            unique_probe_evaluations: 0,
            unique_decision_evaluations: 0,
            coalesced_in_flight: 0,
            reused_completed: 0,
            physical_faults: 1,
        },
        report_fingerprint,
        started_unix_ms: 1,
        completed_unix_ms: 2,
        guard_results,
    })
    .unwrap()
}

fn canonical_authorization_result(provider: ProviderTarget) -> ArcEvaluationResult {
    let guard_results = vec![GuardResult::test_result(
        "guard-review",
        0,
        0,
        ActionType::Message,
        true,
    )];
    let report_fingerprint = fingerprint(&serde_json::to_vec(&guard_results).unwrap());
    ArcEvaluationResult::from_report(EventEvaluationReport {
        schema: EVENT_EVALUATION_REPORT_SCHEMA.into(),
        invocation_id: "authorization-invocation".into(),
        provider,
        event_id: "authorization-event".into(),
        event_type: ArcEventType::ToolCall,
        input_fingerprint: fingerprint(b"authorization-input"),
        effective_disposition: EffectiveDisposition::Continue,
        authorization_requirements: vec![arc::ExactOperationAuthorization {
            guard_id: "guard-review".into(),
            event_id: "authorization-event".into(),
            tool: "bash".into(),
            operation_fingerprint: "op-fp-1".into(),
            normalized_arguments_fingerprint: "norm-fp-1".into(),
        }],
        activation_cache_summary: ActivationCacheSummary {
            logical_occurrences: 0,
            unique_probe_evaluations: 0,
            unique_decision_evaluations: 0,
            coalesced_in_flight: 0,
            reused_completed: 0,
            physical_faults: 0,
        },
        report_fingerprint,
        started_unix_ms: 1,
        completed_unix_ms: 2,
        guard_results,
    })
    .unwrap()
}

#[test]
fn test_end_to_end_project_load_and_lowering() {
    let temp_dir = std::env::temp_dir().join("arc_test_project_e2e");
    let _ = fs::remove_dir_all(&temp_dir);
    fs::create_dir_all(&temp_dir).unwrap();

    let workdir = temp_dir.join("workspace");
    fs::create_dir_all(&workdir).unwrap();
    fs::create_dir_all(workdir.join("skills/python")).unwrap();
    fs::write(workdir.join("skills/python/README.md"), "# Python skill").unwrap();
    fs::write(workdir.join("instructions.md"), "# Project Instructions").unwrap();

    // 1. arc.yaml
    let arc_yaml = r#"
schema: '1.0'
root:
  workdir: 'workspace'
  instructions: 'instructions.md'

modules:
  guards: 'guards.yaml'

skills:
  python:
    description: 'Python Dev'
    src: 'skills/python'

roles:
  backend:
    description: 'Backend Developer'
"#;
    fs::write(temp_dir.join("arc.yaml"), arc_yaml).unwrap();

    // 2. guards.yaml
    let guards_yaml = r#"
schema: '1.0'
guards:
  lifecycle:
    safe_start:
      trigger: start
      require:
        rule: valid.branch
      on_failure:
        action: deny
        feedback: "Cannot start on main"
      order: 10

  tools:
    protect_push:
      matches:
        alias: git.push.force
      require:
        all:
          - rule: valid.branch
          - decide:
              prompt: "Authorize force push?"
      on_failure:
        action: deny
        feedback: "Force push not authorized"
      order: 5
"#;
    fs::write(workdir.join("guards.yaml"), guards_yaml).unwrap();

    // 3. rules.yaml
    let rules_yaml = r#"
schema: '1.0'
rules:
  valid.branch:
    not:
      probe:
        use:
          alias: git.branch.current
        in:
          - main
"#;
    fs::write(workdir.join("rules.yaml"), rules_yaml).unwrap();

    // 4. aliases.yaml
    let aliases_yaml = r#"
schema: '1.0'
matchers:
  git.push.force:
    default:
      regex: '^git push .*--force.*$'

operations:
  git.branch.current:
    default: 'git rev-parse --abbrev-ref HEAD'
"#;
    fs::write(workdir.join("aliases.yaml"), aliases_yaml).unwrap();

    // Test discovery
    let discovered = discover_arc_root(&temp_dir).unwrap();
    assert_eq!(discovered, temp_dir.join("arc.yaml"));

    // Test load_project
    let project = load_project(&discovered).unwrap();
    assert_eq!(project.skills.len(), 1);
    assert_eq!(project.roles.len(), 1);
    assert_eq!(project.guards.lifecycle.len(), 1);
    assert_eq!(project.guards.tools.len(), 1);
    assert!(project.rules.is_some());
    assert!(project.aliases.is_some());

    // Test lower to BehaviorIR for windows
    let os_targets = vec!["windows".to_string()];
    let ir = lower(&project, &os_targets).unwrap();

    assert_eq!(ir.skills.len(), 1);
    assert_eq!(ir.lifecycle_guards.len(), 1);
    assert_eq!(ir.tool_guards.len(), 1);
    assert_eq!(ir.rules.len(), 1);

    // Test runtime with the generated IR
    // Scenario A: git branch is main -> start denied
    let probe_main =
        Arc::new(MockProbeRunner::new().with_output("git rev-parse --abbrev-ref HEAD", "main"));
    let store = arc::SqliteStateStore::open_in_memory().unwrap();
    let anchor = store
        .trust_and_anchor_ir(Path::new("test_ir.json"), &ir)
        .unwrap();
    let mut session = ArcRuntimeSession::new("test-sess", ir.clone())
        .with_trusted_anchor(anchor)
        .unwrap()
        .with_probe_runner(probe_main);

    let start_ev = ArcEvent::lifecycle("test-sess", "ev-1", ArcEventType::Start, 1);
    let eval_result = evaluate_session_event(&mut session, start_ev).unwrap();
    assert_eq!(
        eval_result.effective_disposition,
        arc::EffectiveDisposition::Deny
    );
    assert_eq!(
        eval_result.failure_bundle.failed_guards[0]
            .configured_feedback
            .as_deref(),
        Some("Cannot start on main")
    );

    // Scenario B: git branch is dev -> start allowed
    let probe_dev =
        Arc::new(MockProbeRunner::new().with_output("git rev-parse --abbrev-ref HEAD", "dev"));
    let provider =
        Arc::new(MockDecisionProvider::new().with_decision("Authorize force push?", true));
    let mut session_dev = ArcRuntimeSession::new("test-sess-2", ir)
        .with_probe_runner(probe_dev)
        .with_decision_provider(provider);

    let start_ev2 = ArcEvent::lifecycle("test-sess-2", "ev-1", ArcEventType::Start, 1);
    let eval_result2 = evaluate_session_event(&mut session_dev, start_ev2).unwrap();
    assert_eq!(
        eval_result2.effective_disposition,
        arc::EffectiveDisposition::Continue
    );

    // Tool call force push on dev -> triggers exact operation authorization
    let push_ev = ArcEvent::tool_call(
        "test-sess-2",
        "ev-2",
        2,
        "bash",
        "git push --force origin dev",
    );
    let eval_push = evaluate_session_event(&mut session_dev, push_ev).unwrap();
    assert_eq!(eval_push.authorization_requirements.len(), 1);
    assert_eq!(
        eval_push.authorization_requirements[0].guard_id,
        "protect_push"
    );
    assert_eq!(eval_push.authorization_requirements[0].tool, "bash");

    // Cleanup
    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_containment_violation_rejection() {
    let temp_dir = std::env::temp_dir().join("arc_test_containment");
    let _ = fs::remove_dir_all(&temp_dir);
    fs::create_dir_all(&temp_dir).unwrap();

    let workdir = temp_dir.join("workspace");
    fs::create_dir_all(&workdir).unwrap();

    let outside = temp_dir.join("outside");
    fs::create_dir_all(&outside).unwrap();
    fs::write(outside.join("secret.md"), "secret").unwrap();

    let arc_yaml = r#"
schema: '1.0'
root:
  workdir: 'workspace'
  instructions: '../outside/secret.md'
"#;
    let arc_yaml_path = temp_dir.join("arc.yaml");
    fs::write(&arc_yaml_path, arc_yaml).unwrap();

    let result = load_project(&arc_yaml_path);
    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("Workspace containment violation")
    );

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_duplicate_inline_and_module_rejection() {
    let temp_dir = std::env::temp_dir().join("arc_test_duplicate");
    let _ = fs::remove_dir_all(&temp_dir);
    fs::create_dir_all(&temp_dir).unwrap();

    let workdir = temp_dir.join("workspace");
    fs::create_dir_all(&workdir).unwrap();
    fs::write(
        workdir.join("skills.yaml"),
        "schema: '1.0'\nskills:\n  s1:\n    description: d\n    src: '.'",
    )
    .unwrap();

    let arc_yaml = r#"
schema: '1.0'
root:
  workdir: 'workspace'

modules:
  skills: 'skills.yaml'

skills:
  inline_skill:
    description: inline
    src: '.'
"#;
    let arc_yaml_path = temp_dir.join("arc.yaml");
    fs::write(&arc_yaml_path, arc_yaml).unwrap();

    let result = load_project(&arc_yaml_path);
    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("Duplicate section definition")
    );

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_gemini_emitter_and_agy_hook_simulation() {
    use arc::{
        AgyAdapter, AgyPreToolUseInput, AgyToolCallDetail, EmissionContext, EmitterRegistry,
        ProviderTarget, write_artifacts,
    };

    let temp_dir = std::env::temp_dir().join("arc_test_gemini_emitter");
    let _ = fs::remove_dir_all(&temp_dir);
    fs::create_dir_all(&temp_dir).unwrap();

    let workdir = temp_dir.join("workspace");
    fs::create_dir_all(&workdir).unwrap();
    fs::create_dir_all(workdir.join("skills/testing")).unwrap();
    fs::write(
        workdir.join("skills/testing/SKILL.md"),
        "# Testing Skill\nRun cargo test",
    )
    .unwrap();
    fs::write(
        workdir.join("guidelines.md"),
        "# Team Guidelines\nFollow clean code",
    )
    .unwrap();

    let arc_yaml = r#"
schema: '1.0'
root:
  workdir: 'workspace'
  instructions: 'guidelines.md'

runtime:
  decision_timeout_seconds: 37

skills:
  testing:
    description: 'Testing guidelines'
    src: 'skills/testing/SKILL.md'

roles:
  qa:
    description: 'QA Engineer'

guards:
  tools:
    block_rm:
      matches:
        exact:
          - 'rm -rf /'
      require:
        decide:
          prompt: 'Is this safe?'
      on_failure:
        action: deny
        feedback: 'Dangerous deletion blocked'
"#;
    let arc_yaml_path = temp_dir.join("arc.yaml");
    fs::write(&arc_yaml_path, arc_yaml).unwrap();

    // 1. Load project
    let project = load_project(&arc_yaml_path).unwrap();

    // 2. Lower project to BehaviorIR for Windows
    let os_target = OsTarget::new("windows").expect("windows is a valid test OS");
    let os_targets = vec!["windows".to_string()];
    let ir = lower(&project, &os_targets).unwrap();
    assert_eq!(ir.runtime.decision_timeout_seconds, 37);

    // 3. Emit using GeminiEmitter
    let registry = EmitterRegistry::new();
    let emitter = registry.get(ProviderTarget::Gemini).unwrap();
    let emission_ctx = EmissionContext {
        provider: ProviderTarget::Gemini,
        target_os: os_target.clone(),
        environment: arc::ProviderEnvironment::Cli,
        decision_ui: arc::DecisionUiMode::Auto,
        decision_environment: arc::DecisionEnvironment {
            provider_native: true,
            arc_embedded_ui: true,
            arc_owns_app_server_session: false,
            direct_mcp_channel: false,
        },
        base_output_path: workdir.clone(),
        is_multi_target: false,
        arc_bin: None,
    };

    let artifacts = emitter.emit(&ir, &emission_ctx).unwrap();
    assert_eq!(artifacts.len(), 4); // AGENTS.md, skills/testing, hooks.json, arc_ir.json

    // 4. Write artifacts to disk
    write_artifacts(&workdir, &artifacts).unwrap();

    assert!(workdir.join(".agents/AGENTS.md").exists());
    assert!(workdir.join(".agents/skills/testing/SKILL.md").exists());
    assert!(workdir.join(".agents/hooks.json").exists());
    assert!(workdir.join(".agents/arc_ir.json").exists());

    // 5. Verify AGENTS.md content
    let agents_md = fs::read_to_string(workdir.join(".agents/AGENTS.md")).unwrap();
    assert!(agents_md.contains("Follow clean code"));
    assert!(agents_md.contains("### Role: `qa`"));

    // 6. Verify hooks.json content
    let hooks_json = fs::read_to_string(workdir.join(".agents/hooks.json")).unwrap();
    assert!(hooks_json.contains("PreToolUse"));
    assert!(hooks_json.contains("arc hook run --event-type pre-tool-use"));
    // Hook timeout = decision timeout + HOOK_TIMEOUT_MARGIN_SECONDS (schema.rs).
    let expected_hook_timeout = ir.runtime.hook_timeout_seconds();
    assert_eq!(
        expected_hook_timeout,
        37 + arc::manifest::schema::HOOK_TIMEOUT_MARGIN_SECONDS
    );
    assert!(
        hooks_json.contains(&format!("\"timeout\": {expected_hook_timeout}")),
        "hooks.json={hooks_json}"
    );

    // 7. Simulate AGY PreToolUse hook execution using AgyAdapter
    let loaded_ir: BehaviorIR =
        serde_json::from_str(&fs::read_to_string(workdir.join(".agents/arc_ir.json")).unwrap())
            .unwrap();

    let allow_provider = Arc::new(MockDecisionProvider::new().with_decision("Is this safe?", true));
    let mut session = ArcRuntimeSession::new("test-agy-session", loaded_ir)
        .with_decision_provider(allow_provider);

    // Scenario A: dangerous command 'rm -rf /' -> triggers decide or denial
    let agy_input_danger = AgyPreToolUseInput {
        tool_call: AgyToolCallDetail {
            name: "run_command".into(),
            args: serde_json::json!({ "CommandLine": "rm -rf /" }),
        },
        step_idx: Some(1),
        conversation_id: Some("conv-test".into()),
        model_name: Some("gemini-2.5-pro".into()),
        transcript_path: None,
    };
    let event_danger = AgyAdapter::pre_tool_use_to_event(&agy_input_danger, 1);
    let eval_danger = evaluate_session_event(&mut session, event_danger).unwrap();
    // Auto uses Arc's stable Allow/Deny embedded UI for Gemini too. Simulate a
    // resolved Deny without manufacturing a provider-native force_ask.
    let resolution = arc::resolve_capability(arc::CapabilityContext::cli(
        arc::ProviderTarget::Gemini,
        OsTarget::host().unwrap(),
        arc::CapabilityEvent::ToolCall,
        arc::ActionType::Ask,
        arc::DecisionUiMode::Auto,
    ));
    assert_eq!(eval_danger.authorization_requirements.len(), 1);
    assert_eq!(
        eval_danger.authorization_requirements[0].guard_id,
        "block_rm"
    );
    let agy_output = AgyAdapter::embedded_decision_to_pre_tool_use_output(
        &resolution,
        arc::decision_ui::PortableDecision::Deny,
        "Denied in Arc embedded UI".into(),
    )
    .unwrap();
    assert_eq!(agy_output.decision, "deny");

    // Scenario B: safe command 'cargo test' -> allowed immediately
    let agy_input_safe = AgyPreToolUseInput {
        tool_call: AgyToolCallDetail {
            name: "run_command".into(),
            args: serde_json::json!({ "CommandLine": "cargo test" }),
        },
        step_idx: Some(2),
        conversation_id: Some("conv-test".into()),
        model_name: Some("gemini-2.5-pro".into()),
        transcript_path: None,
    };
    let event_safe = AgyAdapter::pre_tool_use_to_event(&agy_input_safe, 2);
    let eval_safe = evaluate_session_event(&mut session, event_safe).unwrap();
    let agy_output_safe = AgyAdapter::evaluation_result_to_pre_tool_use_output(&eval_safe).unwrap();
    assert_eq!(agy_output_safe.decision, "allow");

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_probe_error_interception_in_agy_simulation() {
    use arc::{
        AgyAdapter, AgyPreToolUseInput, AgyStopInput, AgyToolCallDetail, BoundLifecycleGuard,
        BoundRuleExpression, BoundToolGuard, WorkspaceContext,
        manifest::schema::{ActionType, LifecycleTrigger, OnFailureConfig},
    };
    use std::collections::BTreeMap;

    // Create IR with a guard that runs an invalid probe command
    let ir = BehaviorIR {
        schema: "1.0".into(),
        compiler_version: env!("CARGO_PKG_VERSION").into(),
        build_id: None,
        content_hash: None,
        runtime: Default::default(),
        context: WorkspaceContext {
            workdir: ".".into(),
            instructions_path: None,
            instructions_content: None,
            roles: BTreeMap::new(),
        },
        skills: Vec::new(),
        lifecycle_guards: vec![BoundLifecycleGuard {
            id: "ensure_valid_exit".into(),
            triggers: vec![LifecycleTrigger::End],
            require: BoundRuleExpression::Probe {
                command: if cfg!(target_os = "windows") {
                    "cmd /c \"echo ARC_SECRET_STOP=hidden 1>&2 & exit /b 1\"".into()
                } else {
                    "sh -c 'echo ARC_SECRET_STOP=hidden >&2; exit 1'".into()
                },
                expected_in: vec!["clean".into()],
            },
            on_failure: OnFailureConfig {
                action: ActionType::Deny,
                feedback: Some(
                    "This business feedback should NOT show on technical probe failure".into(),
                ),
            },
            order: 10,
            declaration_order: 0,
        }],
        tool_guards: vec![BoundToolGuard {
            id: "check_branch_probe".into(),
            matcher: arc::BoundMatcher {
                exact_patterns: vec!["git push".into()],
                regex_patterns: vec![],
            },
            require: BoundRuleExpression::Probe {
                command: if cfg!(target_os = "windows") {
                    "cmd /c \"echo ARC_SECRET_TOOL=hidden 1>&2 & exit /b 127\"".into()
                } else {
                    "sh -c 'echo ARC_SECRET_TOOL=hidden >&2; exit 127'".into()
                },
                expected_in: vec!["main".into()],
            },
            on_failure: OnFailureConfig {
                action: ActionType::Deny,
                feedback: Some("Push denied feedback".into()),
            },
            order: 10,
            declaration_order: 0,
        }],
        rules: BTreeMap::new(),
    };

    let mut session = ArcRuntimeSession::new("test-error-session", ir);

    // 1. Tool Call probe failure
    let tool_input = AgyPreToolUseInput {
        tool_call: AgyToolCallDetail {
            name: "run_command".into(),
            args: serde_json::json!({ "CommandLine": "git push" }),
        },
        step_idx: Some(1),
        conversation_id: Some("conv-err".into()),
        model_name: None,
        transcript_path: None,
    };
    let tool_event = AgyAdapter::pre_tool_use_to_event(&tool_input, 1);
    let eval_tool = evaluate_session_event(&mut session, tool_event).unwrap();
    let agy_out = AgyAdapter::evaluation_result_to_pre_tool_use_output(&eval_tool).unwrap();
    assert_eq!(agy_out.decision, "deny");
    assert!(
        agy_out
            .reason
            .as_ref()
            .unwrap()
            .contains("[ARC PROBE ERROR]")
    );
    assert!(
        !agy_out
            .reason
            .as_ref()
            .unwrap()
            .contains("Push denied feedback")
    );
    assert!(
        !agy_out
            .reason
            .as_deref()
            .unwrap()
            .contains("ARC_SECRET_TOOL")
    );

    // 2. Stop Lifecycle probe failure
    let stop_input = AgyStopInput {
        transcript_path: None,
        execution_num: Some(1),
        termination_reason: Some("model_stop".into()),
        error: None,
        fully_idle: Some(true),
        conversation_id: Some("conv-err".into()),
    };
    let stop_event = AgyAdapter::stop_to_event(&stop_input, 2);
    let eval_stop = evaluate_session_event(&mut session, stop_event).unwrap();
    let agy_stop_out = AgyAdapter::evaluation_result_to_stop_output(&eval_stop).unwrap();
    assert_eq!(agy_stop_out.decision, "stop");
    assert!(
        agy_stop_out
            .reason
            .as_ref()
            .unwrap()
            .contains("[ARC PROBE ERROR]")
    );
    assert!(
        !agy_stop_out
            .reason
            .as_ref()
            .unwrap()
            .contains("This business feedback should NOT show")
    );
    assert!(
        !agy_stop_out
            .reason
            .as_deref()
            .unwrap()
            .contains("ARC_SECRET_STOP")
    );
}

#[test]
fn test_action_ask_and_cli_decision_in_agy_simulation() {
    use arc::{
        AgyAdapter, AgyPreToolUseInput, AgyToolCallDetail, BehaviorIR, BoundMatcher,
        BoundRuleExpression, BoundToolGuard, CliDecisionProvider, MockProbeRunner,
        WorkspaceContext,
        manifest::schema::{ActionType, OnFailureConfig},
    };
    use std::collections::BTreeMap;
    use std::sync::Arc;

    let mut ir = BehaviorIR {
        schema: "1.0".into(),
        compiler_version: env!("CARGO_PKG_VERSION").into(),
        build_id: None,
        content_hash: None,
        runtime: Default::default(),
        context: WorkspaceContext {
            workdir: ".".into(),
            instructions_path: None,
            instructions_content: None,
            roles: BTreeMap::new(),
        },
        skills: Vec::new(),
        lifecycle_guards: Vec::new(),
        tool_guards: vec![
            BoundToolGuard {
                id: "confirm_delete_prueba".into(),
                matcher: BoundMatcher {
                    exact_patterns: vec!["rm prueba.txt".into()],
                    regex_patterns: vec![],
                },
                require: BoundRuleExpression::Probe {
                    command: "check_authorized".into(),
                    expected_in: vec!["authorized".into()],
                },
                on_failure: OnFailureConfig {
                    action: ActionType::Ask,
                    feedback: Some("Are you sure you want to delete prueba.txt?".into()),
                },
                order: 10,
                declaration_order: 0,
            },
            BoundToolGuard {
                id: "decide_publish".into(),
                matcher: BoundMatcher {
                    exact_patterns: vec!["publish pkg".into()],
                    regex_patterns: vec![],
                },
                require: BoundRuleExpression::Decide {
                    prompt: "Did user confirm publishing?".into(),
                },
                on_failure: OnFailureConfig {
                    action: ActionType::Deny,
                    feedback: Some("Publish blocked".into()),
                },
                order: 20,
                declaration_order: 1,
            },
        ],
        rules: BTreeMap::new(),
    };
    ir.content_hash = Some(ir.compute_content_hash());

    // 1. Test ActionType::Ask uses the Arc-owned binary dialog in auto mode.
    let probe_runner =
        Arc::new(MockProbeRunner::new().with_output("check_authorized", "unauthorized"));
    let store = arc::SqliteStateStore::open_in_memory().unwrap();
    let anchor = store
        .trust_and_anchor_ir(Path::new("test_ir.json"), &ir)
        .unwrap();
    let mut session = ArcRuntimeSession::new("test-ask-session", ir.clone())
        .with_trusted_anchor(anchor.clone())
        .unwrap()
        .with_probe_runner(probe_runner);

    let tool_input = AgyPreToolUseInput {
        tool_call: AgyToolCallDetail {
            name: "run_command".into(),
            args: serde_json::json!({ "CommandLine": "rm prueba.txt" }),
        },
        step_idx: Some(1),
        conversation_id: Some("conv-ask".into()),
        model_name: None,
        transcript_path: None,
    };
    let tool_event = AgyAdapter::pre_tool_use_to_event(&tool_input, 1);
    let eval_tool = evaluate_session_event(&mut session, tool_event).unwrap();
    assert_eq!(
        eval_tool.effective_disposition,
        arc::EffectiveDisposition::Ask
    );
    assert_eq!(eval_tool.failure_bundle.failed_guards.len(), 1);
    let resolution = arc::resolve_capability(arc::CapabilityContext::cli(
        arc::ProviderTarget::Gemini,
        OsTarget::host().unwrap(),
        arc::CapabilityEvent::ToolCall,
        ActionType::Ask,
        arc::DecisionUiMode::Auto,
    ));
    let agy_out = AgyAdapter::embedded_decision_to_pre_tool_use_output(
        &resolution,
        arc::decision_ui::PortableDecision::Allow,
        "Allowed in Arc embedded UI".into(),
    )
    .unwrap();
    assert_eq!(agy_out.decision, "allow");

    // 2. A model-backed positive decision still requires the user's Arc-owned
    // confirmation for the exact tool call.
    let allow_decision = Arc::new(
        arc::MockDecisionProvider::new().with_decision("Did user confirm publishing?", true),
    );
    let mut session_decide = ArcRuntimeSession::new("test-decide-session", ir.clone())
        .with_trusted_anchor(anchor.clone())
        .unwrap()
        .with_decision_provider(allow_decision);

    let pub_input = AgyPreToolUseInput {
        tool_call: AgyToolCallDetail {
            name: "run_command".into(),
            args: serde_json::json!({ "CommandLine": "publish pkg" }),
        },
        step_idx: Some(2),
        conversation_id: Some("conv-ask".into()),
        model_name: None,
        transcript_path: None,
    };
    let pub_event = AgyAdapter::pre_tool_use_to_event(&pub_input, 2);
    let eval_pub = evaluate_session_event(&mut session_decide, pub_event.clone()).unwrap();
    assert_eq!(eval_pub.authorization_requirements.len(), 1);
    let pub_agy_out = AgyAdapter::embedded_decision_to_pre_tool_use_output(
        &resolution,
        arc::decision_ui::PortableDecision::Allow,
        "Allowed in Arc embedded UI".into(),
    )
    .unwrap();
    assert_eq!(pub_agy_out.decision, "allow");

    // 3. A missing session intent is a runtime fault, so a guard configured as
    // Ask cannot turn the invalid evaluation into a human authorization flow.
    let mut ask_on_missing_intent_ir = ir.clone();
    let decide_publish_guard = ask_on_missing_intent_ir
        .tool_guards
        .iter_mut()
        .find(|guard| guard.id == "decide_publish")
        .expect("decide_publish guard exists");
    decide_publish_guard.on_failure.action = ActionType::Ask;
    decide_publish_guard.on_failure.feedback = Some("Confirm publishing?".into());
    ask_on_missing_intent_ir.content_hash = Some(ask_on_missing_intent_ir.compute_content_hash());
    let ask_on_missing_intent_anchor = store
        .trust_and_anchor_ir(Path::new("test_ir.json"), &ask_on_missing_intent_ir)
        .unwrap();
    let failing_cmd = if cfg!(target_os = "windows") {
        "cmd /c exit 1"
    } else {
        "sh -c 'exit 1'"
    };
    let failing_decision =
        Arc::new(CliDecisionProvider::for_gemini().with_custom_command(failing_cmd));
    let mut session_failing = ArcRuntimeSession::new("test-fail-decide", ask_on_missing_intent_ir)
        .with_trusted_anchor(ask_on_missing_intent_anchor)
        .unwrap()
        .with_decision_provider(failing_decision);

    let eval_fail = evaluate_session_event(&mut session_failing, pub_event.clone()).unwrap();
    assert_eq!(
        eval_fail.effective_disposition,
        arc::EffectiveDisposition::RuntimeFault,
        "missing intent must fault before the configured Ask action is reduced"
    );
    let ui_request = arc::interactive_decision_request_from_evaluation_result(
        &eval_fail,
        arc::ProviderTarget::Gemini,
        arc::ArcEventType::ToolCall,
        "event-session-intent-missing",
        "invocation-session-intent-missing",
        None,
        None,
        "workspace",
    )
    .unwrap();
    assert!(ui_request.is_none(), "RuntimeFault must suppress Ask UI");
    let fail_output = AgyAdapter::evaluation_result_to_pre_tool_use_output(&eval_fail).unwrap();
    assert_eq!(fail_output.decision, "deny");

    // 4. Test DecisionProvider non-compliance returns formatted findings for remediation
    let findings_decision = Arc::new(arc::MockDecisionProvider::new().with_verdict(
        "Did user confirm publishing?",
        arc::DecisionVerdict::deny("Missing required security check"),
    ));
    let mut session_findings = ArcRuntimeSession::new("test-findings-decide", ir)
        .with_trusted_anchor(anchor)
        .unwrap()
        .with_decision_provider(findings_decision);

    let eval_findings = evaluate_session_event(&mut session_findings, pub_event).unwrap();
    let findings_agy_out =
        AgyAdapter::evaluation_result_to_pre_tool_use_output(&eval_findings).unwrap();
    assert_eq!(findings_agy_out.decision, "deny");
    let reason = findings_agy_out.reason.unwrap();
    assert!(reason.contains("Auditor findings:"));
    assert!(!reason.contains("auditor_findings:"));
    assert!(reason.contains("Missing required security check"));
}

#[test]
fn test_ir_integrity_validation_fails_on_tampering() {
    let mut ir = BehaviorIR {
        schema: "1.0".to_string(),
        compiler_version: "1.0.0".to_string(),
        build_id: Some("build-123".to_string()),
        content_hash: None,
        runtime: Default::default(),
        context: arc::WorkspaceContext {
            workdir: std::path::PathBuf::from("."),
            instructions_path: None,
            instructions_content: None,
            roles: std::collections::BTreeMap::new(),
        },
        skills: Vec::new(),
        lifecycle_guards: Vec::new(),
        tool_guards: Vec::new(),
        rules: std::collections::BTreeMap::new(),
    };
    ir.content_hash = Some(ir.compute_content_hash());

    // Valid IR passes integrity check
    assert!(ir.validate_integrity().is_ok());

    // Tampered content hash fails
    let mut tampered_hash_ir = ir.clone();
    tampered_hash_ir.content_hash = Some("invalid-sha256-hash".to_string());
    assert!(tampered_hash_ir.validate_integrity().is_err());

    // Tampered rules without recomputed hash fails
    let mut tampered_rules_ir = ir.clone();
    tampered_rules_ir
        .lifecycle_guards
        .push(arc::BoundLifecycleGuard {
            id: "injected_guard".into(),
            triggers: vec![arc::LifecycleTrigger::Start],
            require: arc::BoundRuleExpression::Decide {
                prompt: "evil?".into(),
            },
            on_failure: arc::OnFailureConfig {
                action: arc::ActionType::Deny,
                feedback: None,
            },
            order: 0,
            declaration_order: 0,
        });
    assert!(tampered_rules_ir.validate_integrity().is_err());
}

#[test]
fn test_bounded_command_execution_timeout() {
    use std::process::Command;
    use std::time::Duration;

    let cmd = if cfg!(target_os = "windows") {
        let mut c = Command::new("powershell");
        c.args(["-Command", "Start-Sleep -Seconds 5"]);
        c
    } else {
        let mut c = Command::new("sleep");
        c.arg("5");
        c
    };

    // Execute with a 100ms timeout
    let res = arc::run_command_bounded(cmd, Duration::from_millis(100), 65536);
    assert!(res.is_err());
    let err = res.unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);
}

#[test]
fn test_bounded_command_caps_output_without_deadlock() {
    use std::process::Command;
    use std::time::Duration;

    let command = if cfg!(target_os = "windows") {
        let mut command = Command::new("powershell");
        command.args([
            "-NoProfile",
            "-Command",
            "$chunk='x'*4096; 1..64 | ForEach-Object {[Console]::Out.Write($chunk)}",
        ]);
        command
    } else {
        let mut command = Command::new("sh");
        command.args(["-c", "yes x | head -c 262144"]);
        command
    };

    let output = arc::run_command_bounded(command, Duration::from_secs(10), 1024).unwrap();
    assert!(output.status.success());
    assert_eq!(output.stdout.len(), 1024);
    assert!(output.stderr.len() <= 1024);
}

#[test]
fn test_bounded_command_timeout_terminates_descendants() {
    use std::process::Command;
    use std::time::Duration;

    let root = std::env::temp_dir().join(format!(
        "arc_process_tree_{}_{}",
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    std::fs::create_dir_all(&root).unwrap();
    let marker = root.join("descendant-survived.txt");

    let command = if cfg!(target_os = "windows") {
        let child_script = root.join("child.ps1");
        let parent_script = root.join("parent.ps1");
        std::fs::write(
            &child_script,
            format!(
                "Start-Sleep -Milliseconds 900; Set-Content -LiteralPath '{}' -Value survived",
                marker.display()
            ),
        )
        .unwrap();
        std::fs::write(
            &parent_script,
            format!(
                "Start-Process -FilePath powershell.exe -ArgumentList @('-NoProfile','-File','{}'); Start-Sleep -Seconds 30",
                child_script.display()
            ),
        )
        .unwrap();
        let mut command = Command::new("powershell");
        command.args(["-NoProfile", "-File", &parent_script.to_string_lossy()]);
        command
    } else {
        let parent_script = root.join("parent.sh");
        std::fs::write(
            &parent_script,
            format!("(sleep 0.9; touch '{}') & wait\n", marker.display()),
        )
        .unwrap();
        let mut command = Command::new("sh");
        command.arg(parent_script);
        command
    };

    let result = arc::run_command_bounded(command, Duration::from_millis(200), 1024);
    assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::TimedOut);
    std::thread::sleep(Duration::from_millis(1200));
    assert!(!marker.exists(), "a timed-out descendant remained alive");
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn test_sanitized_probe_error_does_not_leak_details_to_provider() {
    use arc::{AgyAdapter, CodexAdapter};

    let evaluation = canonical_fault_result(ProviderTarget::Gemini, ArcEventType::ToolCall);

    // AGY adapter test
    let agy_out = AgyAdapter::evaluation_result_to_pre_tool_use_output(&evaluation).unwrap();
    assert_eq!(agy_out.decision, "deny");
    let agy_reason = agy_out.reason.unwrap();
    assert!(agy_reason.contains("[ARC PROBE ERROR]"));
    assert!(agy_reason.contains("Guard evaluation failed"));

    // Codex adapter test
    let codex_out = CodexAdapter::evaluation_result_to_pre_tool_use_output(&evaluation).unwrap();
    let specific = codex_out.hook_specific_output.unwrap();
    assert_eq!(specific.permission_decision, "deny");
    let codex_reason = specific.permission_decision_reason.unwrap();
    assert!(codex_reason.contains("[ARC PROBE ERROR]"));
    assert!(codex_reason.contains("Guard evaluation failed"));
}

#[test]
fn test_h3_recursion_marker_semantics() {
    use std::io::Write;
    use std::process::{Command, Stdio};

    let root = std::env::temp_dir().join(format!("arc_h3_test_{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(root.join(".gemini")).unwrap();
    fs::create_dir_all(root.join(".arc-test-state")).unwrap();

    let arc_yaml = r#"
schema: '1.0'
root:
  workdir: '.'

guards:
  tools:
    block_force_push:
      matches:
        exact: 'git push --force'
      require:
        probe:
          use: 'git rev-parse --abbrev-ref HEAD'
          in: ['non_existent_branch']
      on_failure:
        action: deny
        feedback: 'Force push is strictly blocked'
  lifecycle:
    block_stop:
      trigger: end
      require:
        probe:
          use: 'git rev-parse --abbrev-ref HEAD'
          in: ['non_existent_branch']
      on_failure:
        action: deny
        feedback: 'Stop is blocked'
"#;
    fs::write(root.join("arc.yaml"), arc_yaml).unwrap();

    // Compile IR
    let project = arc::load_project(root.join("arc.yaml")).unwrap();
    let ir = arc::lower(
        &project,
        &["windows".into(), "linux".into(), "macos".into()],
    )
    .unwrap();
    let ir_json = serde_json::to_string(&ir).unwrap();
    let ir_path = root.join(".agents/arc_ir.json");
    fs::create_dir_all(root.join(".agents")).unwrap();
    fs::write(&ir_path, &ir_json).unwrap();

    let state_db = root.join(".arc-test-state/runtime-state.sqlite3");
    let state_store = arc::SqliteStateStore::open(&state_db).unwrap();
    state_store.trust_ir_file(&ir_path).unwrap();

    let tool_payload = r#"{
        "toolCall": {
            "name": "run_command",
            "args": {
                "CommandLine": "git push --force"
            }
        },
        "stepIdx": 1,
        "conversationId": "h3-session"
    }"#;

    let run_hook = |env_var: Option<&str>, event_arg: &str, payload: &str| -> serde_json::Value {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_arc"));
        cmd.current_dir(&root)
            .args([
                "hook",
                "run",
                "--event-type",
                event_arg,
                "--provider",
                "gemini",
                "--ir-path",
                ir_path.to_str().unwrap(),
            ])
            .env("ARC_STATE_DIR", root.join(".arc-test-state"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        match env_var {
            Some(val) => {
                cmd.env("ARC_HOOK_ACTIVE", val);
            }
            None => {
                cmd.env_remove("ARC_HOOK_ACTIVE");
            }
        }

        let mut child = cmd.spawn().unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(payload.as_bytes())
            .unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice(&output.stdout).unwrap()
    };

    // 1. Without variable -> blocks normally (deny)
    let res_no_env = run_hook(None, "pre-tool-use", tool_payload);
    assert_eq!(res_no_env["decision"], "deny");

    // 2. Variable empty -> blocks normally (deny)
    let res_empty_env = run_hook(Some(""), "pre-tool-use", tool_payload);
    assert_eq!(res_empty_env["decision"], "deny");

    // 3. Variable incorrect/arbitrary value -> blocks normally (deny)
    let res_wrong_env = run_hook(Some("1"), "pre-tool-use", tool_payload);
    assert_eq!(res_wrong_env["decision"], "deny");

    let res_wrong_env2 = run_hook(Some("true"), "pre-tool-use", tool_payload);
    assert_eq!(res_wrong_env2["decision"], "deny");

    // 4. Exact internal token for PreToolUse -> allows (bypasses recursion) and logs to journal
    let res_exact_env = run_hook(
        Some("ARC_INTERNAL_RECURSION_V1"),
        "pre-tool-use",
        tool_payload,
    );
    assert_eq!(res_exact_env["decision"], "allow");

    // Verify observability journal recorded the recursion bypass event
    let journal = arc::ObservabilityJournal::open(&state_db).unwrap();
    let events = journal
        .query(&arc::EventQuery {
            event_types: vec!["recursionbypass".into()],
            ..Default::default()
        })
        .unwrap();
    assert!(
        !events.is_empty(),
        "Expected RecursionBypass event in journal"
    );
    assert_eq!(events[0].event_type, "RecursionBypass");
    assert_eq!(
        events[0].reason_code.as_deref(),
        Some("internal_recursion_marker_match")
    );

    // 5. Exact internal token with DIFFERENT event (e.g. stop) -> does NOT bypass, evaluates normally and blocks (continue loop)
    let stop_payload = r#"{
        "executionNum": 1,
        "terminationReason": "model_stop",
        "conversationId": "h3-session"
    }"#;
    let res_stop = run_hook(Some("ARC_INTERNAL_RECURSION_V1"), "stop", stop_payload);
    assert_eq!(res_stop["decision"], "stop"); // Blocked by guard (terminal stop, never continue loop)

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn test_agy_cli_and_ide_session_intent_and_auditor_recursion_bypass() {
    use std::io::Write;
    use std::process::{Command, Stdio};

    let root = std::env::temp_dir().join(format!(
        "arc_agy_cli_defect2_{}_{}",
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(root.join(".agents")).unwrap();
    fs::create_dir_all(root.join(".arc-test-state")).unwrap();

    let script_path = if cfg!(windows) {
        let p = root.join("mock_auditor.bat");
        fs::write(
            &p,
            "@echo {\"decision\": true, \"findings\": null, \"error\": null}\r\n",
        )
        .unwrap();
        p
    } else {
        let p = root.join("mock_auditor.sh");
        fs::write(
            &p,
            "#!/bin/sh\necho '{\"decision\": true, \"findings\": null, \"error\": null}'\n",
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(&p).unwrap().permissions();
            perms.set_mode(0o755);
            fs::set_permissions(&p, perms).unwrap();
        }
        p
    };

    let arc_yaml = r#"
schema: '1.0'
root:
  workdir: '.'

guards:
  lifecycle:
    ensure_clean_completion:
      trigger: end
      require:
        decide:
          prompt: 'Verify whether the agent has fully addressed the user request.'
      on_failure:
        action: deny
        feedback: 'Completion rejected by auditor.'
"#;
    fs::write(root.join("arc.yaml"), arc_yaml).unwrap();

    let project = arc::load_project(root.join("arc.yaml")).unwrap();
    let mut ir = arc::lower(
        &project,
        &["windows".into(), "linux".into(), "macos".into()],
    )
    .unwrap();
    ir.content_hash = Some(ir.compute_content_hash());
    let ir_bytes = serde_json::to_vec_pretty(&ir).unwrap();
    let ir_path = root.join(".agents/arc_ir.json");
    fs::write(&ir_path, &ir_bytes).unwrap();

    let state_db = root.join(".arc-test-state/runtime-state.sqlite3");
    let state_store = arc::SqliteStateStore::open(&state_db).unwrap();
    state_store.trust_ir_file(&ir_path).unwrap();

    for product_dir in ["antigravity-cli", "antigravity-ide"] {
        let session_id = format!("session-{product_dir}");
        let logs_dir = root
            .join(".gemini")
            .join(product_dir)
            .join("brain")
            .join(&session_id)
            .join(".system_generated")
            .join("logs");
        fs::create_dir_all(&logs_dir).unwrap();
        let transcript_full = logs_dir.join("transcript_full.jsonl");
        fs::write(
            &transcript_full,
            "{\"step_index\":0,\"source\":\"USER_EXPLICIT\",\"type\":\"USER_INPUT\",\"content\":\"<USER_REQUEST>\\nCalcula 3 + 4\\n</USER_REQUEST>\"}\n\
             {\"step_index\":1,\"source\":\"MODEL\",\"type\":\"PLANNER_RESPONSE\",\"content\":\"7\"}\n",
        )
        .unwrap();

        let stop_payload = serde_json::json!({
            "conversationId": session_id,
            "executionNum": 0,
            "fullyIdle": true,
            "terminationReason": "NO_TOOL_CALL",
            "transcriptPath": transcript_full.to_string_lossy(),
        });

        let mut cmd = Command::new(env!("CARGO_BIN_EXE_arc"));
        cmd.current_dir(&root)
            .args([
                "hook",
                "run",
                "--event-type",
                "stop",
                "--provider",
                "gemini",
                "--ir-path",
                ir_path.to_str().unwrap(),
            ])
            .env("ARC_STATE_DIR", root.join(".arc-test-state"))
            .env("USERPROFILE", &root)
            .env("HOME", &root)
            .env("ARC_LLM_CLI", &script_path)
            .env_remove("ARC_HOOK_ACTIVE")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let mut child = cmd.spawn().unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(stop_payload.to_string().as_bytes())
            .unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let parsed: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        let journal = arc::ObservabilityJournal::open(&state_db).unwrap();
        let events = journal.query(&arc::EventQuery::default()).unwrap();
        assert_eq!(parsed["decision"], "stop");
        assert!(
            parsed.get("reason").is_none() || parsed["reason"].is_null(),
            "Satisfied decide guard on {product_dir} must not emit fault reason: {parsed}; events={events:#?}"
        );
    }

    // Verify internal auditor session with ARC_HOOK_ACTIVE bypasses Stop without evaluating guards
    let auditor_session_id = "586ad623-8a67-4489-bb79-8b78a946275d";
    let auditor_logs_dir = root
        .join(".gemini")
        .join("antigravity-cli")
        .join("brain")
        .join(auditor_session_id)
        .join(".system_generated")
        .join("logs");
    fs::create_dir_all(&auditor_logs_dir).unwrap();
    let auditor_transcript = auditor_logs_dir.join("transcript_full.jsonl");
    fs::write(
        &auditor_transcript,
        "{\"step_index\":0,\"source\":\"USER_EXPLICIT\",\"type\":\"USER_INPUT\",\"content\":\"<USER_REQUEST>\\nSystem: You are an automated, strictly read-only compliance auditor and security evaluator. Audit Payload: {\\\"audit_request\\\":{\\\"role\\\":\\\"read_only_compliance_auditor\\\"}}\\n</USER_REQUEST>\"}\n",
    )
    .unwrap();

    let auditor_stop_payload = serde_json::json!({
        "conversationId": auditor_session_id,
        "executionNum": 0,
        "fullyIdle": true,
        "terminationReason": "NO_TOOL_CALL",
        "transcriptPath": auditor_transcript.to_string_lossy(),
    });

    let mut cmd = Command::new(env!("CARGO_BIN_EXE_arc"));
    cmd.current_dir(&root)
        .args([
            "hook",
            "run",
            "--event-type",
            "stop",
            "--provider",
            "gemini",
            "--ir-path",
            ir_path.to_str().unwrap(),
        ])
        .env("ARC_STATE_DIR", root.join(".arc-test-state"))
        .env("USERPROFILE", &root)
        .env("HOME", &root)
        .env("ARC_HOOK_ACTIVE", "ARC_INTERNAL_RECURSION_V1")
        .env("ARC_LLM_CLI", "command-that-must-not-run")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = cmd.spawn().unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(auditor_stop_payload.to_string().as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    let parsed: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(parsed["decision"], "stop");
    assert!(parsed.get("reason").is_none() || parsed["reason"].is_null());

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn test_h1_tool_argument_normalization_and_fail_closed() {
    use arc::{
        ActionType, AgyAdapter, AgyPreToolUseInput, AgyToolCallDetail, ArcRuntimeSession,
        BehaviorIR, BoundMatcher, BoundRuleExpression, BoundToolGuard, CodexAdapter,
        CodexPreToolUseInput, OnFailureConfig, WorkspaceContext,
    };
    use std::collections::BTreeMap;

    let ir = BehaviorIR {
        schema: "1.0".into(),
        compiler_version: "1.0.0".into(),
        build_id: None,
        content_hash: None,
        runtime: Default::default(),
        context: WorkspaceContext {
            workdir: ".".into(),
            instructions_path: None,
            instructions_content: None,
            roles: BTreeMap::new(),
        },
        skills: Vec::new(),
        lifecycle_guards: Vec::new(),
        tool_guards: vec![BoundToolGuard {
            id: "block_force_push".into(),
            matcher: BoundMatcher {
                exact_patterns: vec!["git push --force".into()],
                regex_patterns: vec![],
            },
            require: BoundRuleExpression::Probe {
                command: "check_allowed".into(),
                expected_in: vec!["allow".into()],
            },
            on_failure: OnFailureConfig {
                action: ActionType::Deny,
                feedback: Some("Force push is denied".into()),
            },
            order: 0,
            declaration_order: 0,
        }],
        rules: BTreeMap::new(),
    };

    // 1. Parameterized test of all recognized command formats: all must be normalized and denied
    let recognized_payloads = vec![
        serde_json::json!({ "CommandLine": "git push --force" }),
        serde_json::json!({ "command": "git push --force" }),
        serde_json::json!({ "cmd": "git push --force" }),
        serde_json::json!({ "script": "git push --force" }),
        serde_json::json!({ "exec": "git push --force" }),
        serde_json::json!({ "query": "git push --force" }),
        serde_json::json!({ "args": ["git", "push", "--force"] }),
        serde_json::json!(["git", "push", "--force"]),
        serde_json::json!("{\"command\": \"git push --force\"}"),
        serde_json::json!("git push --force"),
    ];

    for payload in recognized_payloads {
        // Test AGY adapter
        let agy_input = AgyPreToolUseInput {
            tool_call: AgyToolCallDetail {
                name: "run_command".into(),
                args: payload.clone(),
            },
            step_idx: Some(1),
            conversation_id: Some("s1".into()),
            model_name: None,
            transcript_path: None,
        };
        let agy_event = AgyAdapter::pre_tool_use_to_event(&agy_input, 1);
        let mut session_agy = ArcRuntimeSession::new("s1", ir.clone());
        let eval_agy = evaluate_session_event(&mut session_agy, agy_event).unwrap();
        let agy_out = AgyAdapter::evaluation_result_to_pre_tool_use_output(&eval_agy).unwrap();
        assert_eq!(
            agy_out.decision, "deny",
            "Failed for payload: {:?}",
            payload
        );

        // Test Codex adapter
        let codex_input = CodexPreToolUseInput {
            hook_event_name: Some("PreToolUse".into()),
            tool_name: "Bash".into(),
            tool_input: payload.clone(),
            turn_id: None,
            session_id: Some("s1".into()),
            tool_use_id: None,
            cwd: None,
            model: None,
            transcript_path: None,
        };
        let codex_event = CodexAdapter::pre_tool_use_to_event(&codex_input, 1);
        let mut session_codex = ArcRuntimeSession::new("s1", ir.clone());
        let eval_codex = evaluate_session_event(&mut session_codex, codex_event).unwrap();
        let codex_out =
            CodexAdapter::evaluation_result_to_pre_tool_use_output(&eval_codex).unwrap();
        assert_eq!(
            codex_out
                .hook_specific_output
                .as_ref()
                .unwrap()
                .permission_decision,
            "deny",
            "Failed for payload: {:?}",
            payload
        );
    }

    // 2. Unrecognized / malformed format for a protected command tool: must FAIL CLOSED (never allow)
    let unrecognized_payloads = vec![
        serde_json::json!({ "unexpected_field": 12345 }),
        serde_json::json!({ "foo": "bar", "unknown": true }),
        serde_json::json!({ "args": { "nested_unknown": 99 } }),
    ];

    for unrec in unrecognized_payloads {
        // AGY
        let agy_input = AgyPreToolUseInput {
            tool_call: AgyToolCallDetail {
                name: "run_command".into(),
                args: unrec.clone(),
            },
            step_idx: Some(1),
            conversation_id: Some("s1".into()),
            model_name: None,
            transcript_path: None,
        };
        let agy_event = AgyAdapter::pre_tool_use_to_event(&agy_input, 1);
        let mut session_agy = ArcRuntimeSession::new("s1", ir.clone());
        let res_agy = evaluate_session_event(&mut session_agy, agy_event);
        assert!(
            matches!(res_agy, Err(arc::ArcEvaluationError::RuntimeFault(_))),
            "Unrecognized payload must fail closed with RuntimeFault on AGY, got {:?}",
            res_agy
        );

        // Codex
        let codex_input = CodexPreToolUseInput {
            hook_event_name: Some("PreToolUse".into()),
            tool_name: "Bash".into(),
            tool_input: unrec.clone(),
            turn_id: None,
            session_id: Some("s1".into()),
            tool_use_id: None,
            cwd: None,
            model: None,
            transcript_path: None,
        };
        let codex_event = CodexAdapter::pre_tool_use_to_event(&codex_input, 1);
        let mut session_codex = ArcRuntimeSession::new("s1", ir.clone());
        let res_codex = evaluate_session_event(&mut session_codex, codex_event);
        assert!(
            matches!(res_codex, Err(arc::ArcEvaluationError::RuntimeFault(_))),
            "Unrecognized payload must fail closed with RuntimeFault on Codex, got {:?}",
            res_codex
        );
    }

    // 3. Non-command tool: should NOT be blocked without an applicable guard
    let non_cmd_input = AgyPreToolUseInput {
        tool_call: AgyToolCallDetail {
            name: "view_file".into(),
            args: serde_json::json!({ "AbsolutePath": "/path/to/file.rs" }),
        },
        step_idx: Some(1),
        conversation_id: Some("s1".into()),
        model_name: None,
        transcript_path: None,
    };
    let non_cmd_event = AgyAdapter::pre_tool_use_to_event(&non_cmd_input, 1);
    let mut session_non_cmd = ArcRuntimeSession::new("s1", ir);
    let eval_non_cmd = evaluate_session_event(&mut session_non_cmd, non_cmd_event).unwrap();
    let non_cmd_out = AgyAdapter::evaluation_result_to_pre_tool_use_output(&eval_non_cmd).unwrap();
    assert_eq!(non_cmd_out.decision, "allow");
}

#[test]
fn test_h5_strict_union_deserialization_rejects_ambiguity_and_unknown_fields() {
    use arc::manifest::schema::{
        AliasVariant, InlineMatcher, MatcherConfig, ProbeUse, SkillDeclaration,
    };

    // 1. SkillDeclaration
    let valid_single = "description: 'A single skill'\nsrc: 'skills/s1'";
    assert!(yaml_serde::from_str::<SkillDeclaration>(valid_single).is_ok());

    let valid_group =
        "description: 'A group'\nmembers:\n  sub:\n    description: 'Sub'\n    src: 'skills/sub'";
    assert!(yaml_serde::from_str::<SkillDeclaration>(valid_group).is_ok());

    let ambiguous_skill = "description: 'Ambiguous'\nsrc: 'skills/s1'\nmembers:\n  sub:\n    description: 'Sub'\n    src: 'skills/sub'";
    assert!(
        yaml_serde::from_str::<SkillDeclaration>(ambiguous_skill).is_err(),
        "Skill with both src and members must fail"
    );

    let unknown_field_skill = "description: 'Single'\nsrc: 'skills/s1'\nextra_unknown: 123";
    assert!(
        yaml_serde::from_str::<SkillDeclaration>(unknown_field_skill).is_err(),
        "Skill with unknown fields must fail"
    );

    let empty_skill = "{}";
    assert!(
        yaml_serde::from_str::<SkillDeclaration>(empty_skill).is_err(),
        "Empty skill must fail"
    );

    // 2. MatcherConfig
    let valid_alias = "alias: 'git_commands'";
    assert!(yaml_serde::from_str::<MatcherConfig>(valid_alias).is_ok());

    let valid_inline = "exact: 'git push'";
    assert!(yaml_serde::from_str::<MatcherConfig>(valid_inline).is_ok());

    let ambiguous_matcher = "alias: 'git_commands'\nexact: 'git push'";
    assert!(
        yaml_serde::from_str::<MatcherConfig>(ambiguous_matcher).is_err(),
        "Matcher with both alias and inline exact must fail"
    );

    let unknown_field_matcher = "exact: 'git push'\nextra_key: 'not allowed'";
    assert!(
        yaml_serde::from_str::<MatcherConfig>(unknown_field_matcher).is_err(),
        "Matcher with unknown fields must fail"
    );

    let empty_matcher = "{}";
    assert!(
        yaml_serde::from_str::<MatcherConfig>(empty_matcher).is_err(),
        "Empty matcher must fail"
    );

    // 3. ProbeUse
    let valid_probe_cmd = "'git rev-parse HEAD'";
    assert!(yaml_serde::from_str::<ProbeUse>(valid_probe_cmd).is_ok());

    let valid_probe_alias = "alias: 'git_rev'";
    assert!(yaml_serde::from_str::<ProbeUse>(valid_probe_alias).is_ok());

    let unknown_probe_alias = "alias: 'git_rev'\nextra: 123";
    assert!(
        yaml_serde::from_str::<ProbeUse>(unknown_probe_alias).is_err(),
        "ProbeUse with extra fields must fail"
    );

    let invalid_probe_mapping = "invalid_key: 'foo'";
    assert!(
        yaml_serde::from_str::<ProbeUse>(invalid_probe_mapping).is_err(),
        "ProbeUse with invalid key must fail"
    );

    // 4. AliasVariant
    let valid_set = "set: 'windows'";
    assert!(yaml_serde::from_str::<AliasVariant<InlineMatcher>>(valid_set).is_ok());

    let valid_concrete = "exact: 'git push'";
    assert!(yaml_serde::from_str::<AliasVariant<InlineMatcher>>(valid_concrete).is_ok());

    let unknown_set = "set: 'windows'\nextra_key: 123";
    assert!(
        yaml_serde::from_str::<AliasVariant<InlineMatcher>>(unknown_set).is_err(),
        "AliasVariant with extra field in set must fail"
    );

    let ambiguous_variant = "set: 'windows'\nexact: 'git push'";
    assert!(
        yaml_serde::from_str::<AliasVariant<InlineMatcher>>(ambiguous_variant).is_err(),
        "AliasVariant with both set and exact must fail"
    );

    // 5. StringList rejection of empty/whitespace elements in single and mixed lists (H5)
    use arc::manifest::schema::StringList;
    assert!(yaml_serde::from_str::<StringList>("'git push'").is_ok());
    assert!(yaml_serde::from_str::<StringList>("['git push', 'git pull']").is_ok());

    assert!(
        yaml_serde::from_str::<StringList>("''").is_err(),
        "Empty string must fail"
    );
    assert!(
        yaml_serde::from_str::<StringList>("'   '").is_err(),
        "Whitespace string must fail"
    );
    assert!(
        yaml_serde::from_str::<StringList>("[]").is_err(),
        "Empty list must fail"
    );
    assert!(
        yaml_serde::from_str::<StringList>("['git push', '']").is_err(),
        "Mixed list with empty string must fail"
    );
    assert!(
        yaml_serde::from_str::<StringList>("['git push', '   ']").is_err(),
        "Mixed list with whitespace string must fail"
    );
}

#[test]
fn test_h6_strict_auditor_response_parsing() {
    use arc::{
        ArcEventType, CliDecisionProvider, CurrentOperation, DecisionError, DecisionProvider,
        DecisionVerdict, SessionContext,
    };

    let temp_dir = std::env::temp_dir();
    let _unique_id = uuid::Uuid::new_v4();

    // Helper to test custom script output through CliDecisionProvider
    let test_script_output = |output_content: &str| -> Result<DecisionVerdict, DecisionError> {
        let script_path = if cfg!(target_os = "windows") {
            let p = temp_dir.join(format!("test_h6_{}.bat", uuid::Uuid::new_v4()));
            std::fs::write(&p, format!("@echo off\r\necho {}\r\n", output_content)).unwrap();
            p
        } else {
            let p = temp_dir.join(format!("test_h6_{}.sh", uuid::Uuid::new_v4()));
            std::fs::write(&p, format!("#!/bin/sh\necho '{}'\n", output_content)).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mut perms = std::fs::metadata(&p).unwrap().permissions();
                perms.set_mode(0o755);
                std::fs::set_permissions(&p, perms).unwrap();
            }
            p
        };
        let custom_cmd = script_path.to_string_lossy().to_string();
        let provider = CliDecisionProvider::for_gemini().with_custom_command(custom_cmd);
        let ctx = SessionContext {
            user_intent: "test intent".into(),
            ..Default::default()
        };
        let op = CurrentOperation {
            event_type: ArcEventType::ToolCall,
            tool: Some("run_command".into()),
            input: Some(serde_json::json!({"CommandLine": "cargo test"})),
            command_text: Some("cargo test".into()),
        };
        let res = provider.decide(
            "Is this command safe?",
            Some(&ctx),
            Some(&op),
            &arc::runtime::GuardDecisionEvidence::default(),
        );
        let _ = std::fs::remove_file(&script_path);
        res
    };

    // 1. Valid JSON object -> Ok
    let valid_res = test_script_output(r#"{"decision": true, "findings": null}"#).unwrap();
    assert!(valid_res.decision);

    // 2. Bare booleans -> Err
    assert!(
        test_script_output("true").is_err(),
        "Bare boolean 'true' must be rejected"
    );
    assert!(
        test_script_output("false").is_err(),
        "Bare boolean 'false' must be rejected"
    );

    // 3. Conversational / free text -> Err
    assert!(
        test_script_output("The command is safe to execute").is_err(),
        "Free text must be rejected"
    );

    // 4. Markdown block -> Err
    assert!(
        test_script_output("```json\n{\"decision\": true}\n```").is_err(),
        "Markdown block must be rejected"
    );

    // 5. Embedded JSON in text -> Err
    assert!(
        test_script_output("Analysis: {\"decision\": true}").is_err(),
        "Embedded JSON must be rejected"
    );

    // 6. Unknown fields -> Err
    assert!(
        test_script_output(r#"{"decision": true, "extra_field": 123}"#).is_err(),
        "JSON with unknown fields must be rejected"
    );

    // 7. Missing decision field -> Err
    assert!(
        test_script_output(r#"{"findings": "all clean"}"#).is_err(),
        "JSON missing decision must be rejected"
    );

    // 8. Contradictory payload: decision=true with error -> Err (H6)
    assert!(
        test_script_output(r#"{"decision": true, "error": "policy violated"}"#).is_err(),
        "Contradictory decision=true with error must be rejected"
    );

    // 9. Invalid confidence out of range -> Err (H6)
    assert!(
        test_script_output(r#"{"decision": true, "confidence": 1.5}"#).is_err(),
        "Confidence > 1.0 must be rejected"
    );
    assert!(
        test_script_output(r#"{"decision": true, "confidence": -0.1}"#).is_err(),
        "Confidence < 0.0 must be rejected"
    );
}

#[test]
fn test_m3_build_manifest_generation_and_integrity() {
    use arc::emitters::{BuildManifest, GeneratedArtifact, write_artifacts};
    use sha2::{Digest, Sha256};
    use std::fs;
    use std::path::PathBuf;

    let temp_dir = std::env::temp_dir().join(format!("arc_m3_test_{}", uuid::Uuid::new_v4()));
    fs::create_dir_all(&temp_dir).unwrap();

    let artifacts = vec![
        GeneratedArtifact {
            provider: arc::target::ProviderTarget::Codex,
            target_os: arc::target::OsTarget::new("linux").expect("linux is a valid test OS"),
            relative_path: PathBuf::from(".codex/hooks.json"),
            content: "{\n  \"description\": \"Auto-generated by Arc\",\n  \"hooks\": []\n}\n"
                .into(),
            is_executable: false,
        },
        GeneratedArtifact {
            provider: arc::target::ProviderTarget::Gemini,
            target_os: arc::target::OsTarget::new("linux").expect("linux is a valid test OS"),
            relative_path: PathBuf::from("scripts/check.sh"),
            content: "#!/bin/sh\necho 'ok'\n".into(),
            is_executable: true,
        },
    ];

    let manifest = write_artifacts(&temp_dir, &artifacts).unwrap();

    // Verify manifest was written to disk
    let manifest_file_path = temp_dir.join(".arc").join("build_manifest.json");
    assert!(
        manifest_file_path.exists(),
        ".arc/build_manifest.json must exist in output directory"
    );

    let disk_manifest_str = fs::read_to_string(&manifest_file_path).unwrap();
    let disk_manifest: BuildManifest = serde_json::from_str(&disk_manifest_str).unwrap();
    assert_eq!(manifest, disk_manifest);

    // Verify all artifacts are listed
    assert_eq!(disk_manifest.artifacts.len(), 2);
    assert_eq!(disk_manifest.arc_version, env!("CARGO_PKG_VERSION"));

    // Verify byte-by-byte SHA256 integrity of all artifacts on disk
    for record in &disk_manifest.artifacts {
        let file_path = temp_dir.join(&record.relative_path);
        assert!(
            file_path.exists(),
            "Artifact file {:?} must exist",
            file_path
        );

        let bytes = fs::read(&file_path).unwrap();
        let mut hasher = Sha256::new();
        hasher.update(&bytes);
        let calculated_hash = hex::encode(hasher.finalize());

        assert_eq!(
            record.sha256, calculated_hash,
            "SHA256 hash must match disk content for {}",
            record.relative_path
        );
        assert_eq!(
            record.size_bytes,
            bytes.len() as u64,
            "Size must match disk content for {}",
            record.relative_path
        );
    }

    // Rebuilding with updated artifact should update manifest consistently
    let updated_artifacts = vec![GeneratedArtifact {
        provider: arc::target::ProviderTarget::Gemini,
        target_os: arc::target::OsTarget::new("linux").expect("linux is a valid test OS"),
        relative_path: PathBuf::from("scripts/check.sh"),
        content: "#!/bin/sh\necho 'updated'\n".into(),
        is_executable: true,
    }];
    let updated_manifest = write_artifacts(&temp_dir, &updated_artifacts).unwrap();
    let updated_disk_manifest: BuildManifest =
        serde_json::from_str(&fs::read_to_string(&manifest_file_path).unwrap()).unwrap();
    assert_eq!(updated_manifest, updated_disk_manifest);
    assert_eq!(
        updated_disk_manifest.artifacts.len(),
        2,
        "Merged manifest must contain both artifacts"
    );

    let check_record = updated_disk_manifest
        .artifacts
        .iter()
        .find(|a| a.relative_path == "scripts/check.sh")
        .unwrap();
    let check_bytes = fs::read(temp_dir.join("scripts/check.sh")).unwrap();
    let mut check_hasher = Sha256::new();
    check_hasher.update(&check_bytes);
    assert_eq!(check_record.sha256, hex::encode(check_hasher.finalize()));

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_m5_toctou_prevention_and_contained_handles() {
    use arc::manifest::{load_project, read_contained_file};
    use std::fs;
    use std::path::PathBuf;

    let temp_root = std::env::temp_dir().join(format!("arc_m5_test_{}", uuid::Uuid::new_v4()));
    let workdir = temp_root.join("work");
    let outside_dir = temp_root.join("outside");
    fs::create_dir_all(&workdir).unwrap();
    fs::create_dir_all(&outside_dir).unwrap();

    let inside_file = workdir.join("skills.yaml");
    fs::write(
        &inside_file,
        "schema: '1.0'\nskills:\n  s1:\n    description: 's1'\n    src: 's1'\n",
    )
    .unwrap();

    let outside_file = outside_dir.join("secret.yaml");
    fs::write(&outside_file, "schema: '1.0'\nskills: {}\n").unwrap();

    // 1. Contained file read via open handle succeeds
    let (canonical, content) =
        read_contained_file(&workdir, &inside_file, "skills module").unwrap();
    let clean_workdir = {
        let cw = workdir.canonicalize().unwrap();
        let mut s = cw.to_string_lossy().to_string();
        if s.starts_with(r"\\?\") {
            s = s[4..].to_string();
        }
        PathBuf::from(s)
    };
    assert!(canonical.starts_with(&clean_workdir));
    assert!(content.contains("description: 's1'"));

    // 2. Reading outside file directly must fail containment
    assert!(read_contained_file(&workdir, &outside_file, "outside file").is_err());

    // 3. Testing load_project with uncontained module
    let manifest_path = workdir.join("arc.yaml");
    let manifest_content = r#"
schema: '1.0'
root:
  workdir: '.'
modules:
  skills: '../outside/secret.yaml'
"#;
    fs::write(&manifest_path, manifest_content).unwrap();

    let err = load_project(&manifest_path).unwrap_err();
    assert!(
        err.to_string().contains("Workspace containment violation")
            || err.to_string().contains("escapes workdir"),
        "Uncontained module must be rejected, got: {}",
        err
    );

    let _ = fs::remove_dir_all(&temp_root);
}

#[test]
fn test_m8_atomic_write_rollback_on_failure() {
    use arc::emitters::{GeneratedArtifact, write_artifacts};
    use std::fs;
    use std::path::PathBuf;

    let temp_root = std::env::temp_dir().join(format!("arc_m8_test_{}", uuid::Uuid::new_v4()));
    fs::create_dir_all(&temp_root).unwrap();

    let initial_file1 = temp_root.join("file1.txt");
    fs::write(&initial_file1, "v1_original").unwrap();

    let initial_file2 = temp_root.join("file2.txt");
    fs::write(&initial_file2, "v2_original").unwrap();

    // 1. Test mid-commit failure and rollback
    let batch = vec![
        GeneratedArtifact {
            provider: arc::target::ProviderTarget::Gemini,
            target_os: arc::target::OsTarget::new("linux").expect("linux is a valid test OS"),
            relative_path: PathBuf::from("file1.txt"),
            content: "v1_new_staged".into(),
            is_executable: false,
        },
        GeneratedArtifact {
            provider: arc::target::ProviderTarget::Gemini,
            target_os: arc::target::OsTarget::new("linux").expect("linux is a valid test OS"),
            relative_path: PathBuf::from("nonexistent_dir/uncreatable/file2.txt"),
            content: "v2_new_staged".into(),
            is_executable: false,
        },
    ];

    // Make parent dir of file2 a blocking file so directory creation / commit fails
    let bad_dir = temp_root.join("nonexistent_dir");
    fs::write(&bad_dir, "blocking file that prevents directory creation").unwrap();

    let result = write_artifacts(&temp_root, &batch);
    assert!(result.is_err(), "Batch with mid-commit failure must fail");

    // Verify rollback: file1.txt MUST remain "v1_original"
    assert_eq!(
        fs::read_to_string(&initial_file1).unwrap(),
        "v1_original",
        "Rollback must restore file1.txt to its original content"
    );

    // Verify no stray .tmp files left anywhere in temp_root
    for entry in fs::read_dir(&temp_root).unwrap().flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        assert!(
            !name.starts_with(".tmp_arc_") && !name.starts_with(".tmp_backup_"),
            "No temporary or backup files should remain after rollback: {}",
            name
        );
    }

    // 2. Test successful atomic commit of entire batch
    fs::remove_file(&bad_dir).unwrap();
    let valid_batch = vec![
        GeneratedArtifact {
            provider: arc::target::ProviderTarget::Gemini,
            target_os: arc::target::OsTarget::new("linux").expect("linux is a valid test OS"),
            relative_path: PathBuf::from("file1.txt"),
            content: "v1_committed".into(),
            is_executable: false,
        },
        GeneratedArtifact {
            provider: arc::target::ProviderTarget::Gemini,
            target_os: arc::target::OsTarget::new("linux").expect("linux is a valid test OS"),
            relative_path: PathBuf::from("file2.txt"),
            content: "v2_committed".into(),
            is_executable: false,
        },
    ];

    let manifest = write_artifacts(&temp_root, &valid_batch).unwrap();
    assert_eq!(manifest.artifacts.len(), 2);
    assert_eq!(fs::read_to_string(&initial_file1).unwrap(), "v1_committed");
    assert_eq!(fs::read_to_string(&initial_file2).unwrap(), "v2_committed");

    let _ = fs::remove_dir_all(&temp_root);
}

#[test]
fn test_l3_state_store_requested_and_completed_timestamps() {
    use arc::runtime::execution::{
        GuardActivation, GuardExecutionKey, GuardExecutionRecord, GuardExecutionState,
    };
    use arc::runtime::state_store::{GuardExecutionStateStore, SqliteStateStore};
    use std::fs;

    let temp_db_dir = std::env::temp_dir().join(format!("arc_l3_test_{}", uuid::Uuid::new_v4()));
    fs::create_dir_all(&temp_db_dir).unwrap();
    let db_path = temp_db_dir.join("state.sqlite");

    let store = SqliteStateStore::open(&db_path).unwrap();

    let key = GuardExecutionKey {
        workspace_id: "ws-1".into(),
        session_id: "sess-1".into(),
        turn_id: Some("turn-1".into()),
        guard_id: "guard-1".into(),
        activation: GuardActivation::SessionStart,
        subject_id: None,
    };

    // 1. Requested state has requested_at and NO completed_at
    let mut record = GuardExecutionRecord::new("exec-1".into(), key.clone(), 1000);
    record.state = GuardExecutionState::RemediationRequested;
    record.mark_requested("2026-08-22T18:00:00Z");
    record.revision = 1;

    let outcome = store.compare_and_swap(None, &record).unwrap();
    assert_eq!(outcome, arc::runtime::state_store::WriteOutcome::Written);

    let loaded = store.load(&key).unwrap().expect("Record must exist");
    assert_eq!(
        loaded.requested_at,
        Some("2026-08-22T18:00:00Z".to_string())
    );
    assert_eq!(
        loaded.completed_at, None,
        "Requested guard must not have completed_at"
    );

    // 2. Completed state has both requested_at and completed_at
    let mut completed_record = loaded;
    completed_record.state = GuardExecutionState::Satisfied;
    completed_record.mark_completed("2026-08-22T18:05:00Z");
    completed_record.revision = 2;

    let outcome2 = store.compare_and_swap(Some(1), &completed_record).unwrap();
    assert_eq!(outcome2, arc::runtime::state_store::WriteOutcome::Written);

    let loaded_completed = store.load(&key).unwrap().expect("Record must exist");
    assert_eq!(
        loaded_completed.requested_at,
        Some("2026-08-22T18:00:00Z".to_string())
    );
    assert_eq!(
        loaded_completed.completed_at,
        Some("2026-08-22T18:05:00Z".to_string())
    );
    assert!(
        loaded_completed.completed_at.unwrap() >= loaded_completed.requested_at.unwrap(),
        "completed_at must be >= requested_at"
    );

    let _ = fs::remove_dir_all(&temp_db_dir);
}

#[test]
fn test_l3_observability_retention_and_guard_preservation() {
    use arc::runtime::execution::{
        GuardActivation, GuardExecutionKey, GuardExecutionRecord, GuardExecutionState,
    };
    use arc::runtime::observability::{EventQuery, NewObservabilityEvent, ObservabilityJournal};
    use arc::runtime::state_store::{GuardExecutionStateStore, SqliteStateStore};
    use std::fs;
    use std::time::Duration;

    let temp_dir = std::env::temp_dir().join(format!("arc_l3_retention_{}", uuid::Uuid::new_v4()));
    fs::create_dir_all(&temp_dir).unwrap();
    let db_path = temp_dir.join("runtime.sqlite3");

    // 1. Initialize DB and StateStore, populate trusted IR and guard execution record
    let store = SqliteStateStore::open(&db_path).unwrap();
    let dummy_ir_file = temp_dir.join("arc_ir.json");
    fs::write(&dummy_ir_file, r#"{"schema":"1.0","version":"1.0.0"}"#).unwrap();
    store.trust_ir_file(&dummy_ir_file).unwrap();

    let guard_key = GuardExecutionKey {
        workspace_id: "ws-retention-test".into(),
        session_id: "sess-retention-test".into(),
        turn_id: Some("turn-1".into()),
        guard_id: "guard-active".into(),
        activation: GuardActivation::ToolCall,
        subject_id: None,
    };
    let mut guard_record = GuardExecutionRecord::new("exec-100".into(), guard_key.clone(), 5000);
    guard_record.state = GuardExecutionState::Satisfied;
    store.compare_and_swap(None, &guard_record).unwrap();

    // 2. Open ObservabilityJournal on same DB and append events (one recent, one old)
    let journal = ObservabilityJournal::open(&db_path).unwrap();
    journal
        .append(NewObservabilityEvent {
            event_type: "RecentEvent".into(),
            level: "info".into(),
            session_id: Some("sess-recent".into()),
            details: serde_json::json!({"status": "ok"}),
            ..Default::default()
        })
        .unwrap();

    // Insert an old event (simulate 10 days ago by direct SQL or appending)
    {
        let conn = rusqlite::Connection::open(&db_path).unwrap();
        let ten_days_ago_ms = (std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64)
            - (10 * 24 * 3600 * 1000);

        conn.execute(
            "INSERT INTO observability_events (
                timestamp_unix_ms, event_type, level, session_id, process_id, details_json
            ) VALUES (?1, 'OldEvent', 'info', 'sess-old', 1, '{}')",
            rusqlite::params![ten_days_ago_ms],
        )
        .unwrap();
    }

    let all_events = journal.query(&EventQuery::default()).unwrap();
    assert_eq!(all_events.len(), 2);

    // 3. Purge observability events older than 1 day (max_age = 24h)
    let purged = journal
        .purge_expired(Duration::from_secs(24 * 3600))
        .unwrap();
    assert_eq!(
        purged, 1,
        "Exactly 1 expired observability event should be purged"
    );

    // 4. Verify only the recent event remains in observability_events
    let remaining_events = journal.query(&EventQuery::default()).unwrap();
    assert_eq!(remaining_events.len(), 1);
    assert_eq!(remaining_events[0].event_type, "RecentEvent");

    // 5. Verify guard_executions and trusted_irs were NOT touched
    let loaded_guard = store.load(&guard_key).unwrap();
    assert!(
        loaded_guard.is_some(),
        "Active guard execution record must NOT be deleted by observability retention"
    );

    let trusted_verification = store.verify_trusted_ir_file(&dummy_ir_file);
    assert!(
        trusted_verification.is_ok(),
        "Trusted IR must NOT be deleted or altered by observability retention"
    );

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_h2_two_phase_lifecycle_start_and_end_contract() {
    use arc::runtime::adapter::agy::{AgyAdapter, AgyPreInvocationInput, AgyStopInput};
    use arc::runtime::adapter::codex::{CodexAdapter, CodexSessionStartInput, CodexStopInput};
    use arc::runtime::events::ArcEventType;

    // AGY: PreInvocation on turn 1 produces Start event
    let agy_start_input = AgyPreInvocationInput {
        invocation_num: Some(1),
        conversation_id: Some("conv-1".into()),
        transcript_path: None,
    };
    let start_event = AgyAdapter::pre_invocation_to_event(&agy_start_input, 1);
    assert!(start_event.is_some());
    assert_eq!(start_event.unwrap().event_type, ArcEventType::Start);

    // AGY: PreInvocation on turn > 1 produces NONE (Invariant 2)
    let agy_later_input = AgyPreInvocationInput {
        invocation_num: Some(2),
        conversation_id: Some("conv-1".into()),
        transcript_path: None,
    };
    let later_event = AgyAdapter::pre_invocation_to_event(&agy_later_input, 2);
    assert!(
        later_event.is_none(),
        "PreInvocation for turn > 1 must never trigger Start"
    );

    // AGY: Stop produces End event
    let agy_stop_input = AgyStopInput {
        transcript_path: None,
        execution_num: Some(1),
        termination_reason: None,
        error: None,
        fully_idle: Some(true),
        conversation_id: Some("conv-1".into()),
    };
    let stop_event = AgyAdapter::stop_to_event(&agy_stop_input, 3);
    assert_eq!(stop_event.event_type, ArcEventType::End);

    // Codex: SessionStart produces Start event
    let codex_start_input = CodexSessionStartInput {
        hook_event_name: Some("SessionStart".into()),
        session_id: Some("codex-1".into()),
        cwd: None,
        transcript_path: None,
    };
    let codex_start = CodexAdapter::session_start_to_event(&codex_start_input, 1);
    assert_eq!(codex_start.event_type, ArcEventType::Start);

    // Codex: Stop produces End event
    let codex_stop_input = CodexStopInput {
        hook_event_name: Some("Stop".into()),
        session_id: Some("codex-1".into()),
        turn_id: Some("turn-1".into()),
        cwd: None,
        model: None,
        transcript_path: None,
        stop_hook_active: false,
    };
    let codex_stop = CodexAdapter::stop_to_event(&codex_stop_input, 2);
    assert_eq!(codex_stop.event_type, ArcEventType::End);
}

#[test]
fn test_h9_multidimensional_capability_and_degradation_reporting() {
    use arc::manifest::LoadedArcProject;
    use arc::manifest::schema::{
        ActionType, ArcManifest, GuardsConfig, LifecycleGuardConfig, LifecycleTrigger,
        OnFailureConfig, RootConfig, RuleExpression, ToolGuardConfig, TriggerSelector,
    };
    use arc::target::ProviderTarget;
    use arc::target::capabilities::{
        CapabilityContext, CapabilityLevel, generate_degradation_report, resolve_capability,
    };
    use arc::target::{DecisionEnvironment, ProviderEnvironment};
    use std::collections::BTreeMap;

    let mut lifecycle = BTreeMap::new();
    lifecycle.insert(
        "start_msg".to_string(),
        LifecycleGuardConfig {
            trigger: TriggerSelector::Single(LifecycleTrigger::Start),
            require: RuleExpression::Decide {
                decide: arc::manifest::schema::DecideConfig {
                    prompt: "welcome".into(),
                },
            },
            on_failure: OnFailureConfig {
                action: ActionType::Message,
                feedback: Some("welcome".into()),
            },
            order: None,
            declaration_order: 0,
        },
    );
    lifecycle.insert(
        "end_ask".to_string(),
        LifecycleGuardConfig {
            trigger: TriggerSelector::Single(LifecycleTrigger::End),
            require: RuleExpression::Decide {
                decide: arc::manifest::schema::DecideConfig {
                    prompt: "confirm exit".into(),
                },
            },
            on_failure: OnFailureConfig {
                action: ActionType::Ask,
                feedback: Some("confirm exit".into()),
            },
            order: None,
            declaration_order: 1,
        },
    );

    let mut tools = BTreeMap::new();
    tools.insert(
        "cmd_guard".to_string(),
        ToolGuardConfig {
            matches: arc::manifest::schema::MatcherConfig::Alias {
                alias: "git.push".into(),
            },
            require: RuleExpression::Decide {
                decide: arc::manifest::schema::DecideConfig {
                    prompt: "allow push?".into(),
                },
            },
            on_failure: OnFailureConfig {
                action: ActionType::Deny,
                feedback: Some("denied".into()),
            },
            order: None,
            declaration_order: 0,
        },
    );
    tools.insert(
        "ask_guard".to_string(),
        ToolGuardConfig {
            matches: arc::manifest::schema::MatcherConfig::Alias {
                alias: "git.force".into(),
            },
            require: RuleExpression::Decide {
                decide: arc::manifest::schema::DecideConfig {
                    prompt: "allow force?".into(),
                },
            },
            on_failure: OnFailureConfig {
                action: ActionType::Ask,
                feedback: Some("confirm tool".into()),
            },
            order: None,
            declaration_order: 1,
        },
    );

    let project = LoadedArcProject {
        manifest_path: std::path::PathBuf::from("arc.yaml"),
        manifest: ArcManifest {
            schema: "1.0".into(),
            root: RootConfig {
                workdir: std::path::PathBuf::from("."),
                instructions: None,
            },
            runtime: Default::default(),
            modules: None,
            skills: None,
            roles: None,
            guards: None,
        },
        workdir: std::path::PathBuf::from("."),
        instructions_path: None,
        instructions_content: None,
        skills: BTreeMap::new(),
        roles: BTreeMap::new(),
        role_sources: BTreeMap::new(),
        guards: GuardsConfig { lifecycle, tools },
        rules: None,
        aliases: None,
    };

    // 1. Degradation report for Gemini (AGY)
    let agy_report = generate_degradation_report(&project, ProviderTarget::Gemini);
    let start_msg = agy_report
        .iter()
        .find(|r| r.guard_id == "start_msg")
        .unwrap();
    assert_eq!(start_msg.provider, ProviderTarget::Gemini);
    assert_eq!(start_msg.environment, ProviderEnvironment::Cli);
    assert_eq!(start_msg.target_os, OsTarget::host().unwrap());
    assert_eq!(start_msg.capability, CapabilityLevel::Supported);
    assert_eq!(start_msg.guarantee, "Advisory");

    let end_ask = agy_report.iter().find(|r| r.guard_id == "end_ask").unwrap();
    assert_eq!(end_ask.capability, CapabilityLevel::Emulated);
    assert_eq!(end_ask.guarantee, "Interactive");

    let cmd_guard = agy_report
        .iter()
        .find(|r| r.guard_id == "cmd_guard")
        .unwrap();
    assert_eq!(cmd_guard.capability, CapabilityLevel::Supported);
    assert_eq!(cmd_guard.guarantee, "Preventive");
    assert_eq!(
        agy_report
            .iter()
            .find(|r| r.guard_id == "start_msg")
            .unwrap()
            .provider,
        ProviderTarget::Gemini
    );

    let ask_guard = agy_report
        .iter()
        .find(|r| r.guard_id == "ask_guard")
        .unwrap();
    assert_eq!(ask_guard.capability, CapabilityLevel::Emulated);
    assert_eq!(ask_guard.guarantee, "Interactive");

    // 2. Degradation report for Codex
    let codex_report = generate_degradation_report(&project, ProviderTarget::Codex);
    let codex_start_msg = codex_report
        .iter()
        .find(|r| r.guard_id == "start_msg")
        .unwrap();
    assert_eq!(codex_start_msg.capability, CapabilityLevel::Partial);
    assert_eq!(codex_start_msg.guarantee, "Advisory");

    let codex_end_ask = codex_report
        .iter()
        .find(|r| r.guard_id == "end_ask")
        .unwrap();
    assert_eq!(codex_end_ask.capability, CapabilityLevel::Emulated);
    assert_eq!(codex_end_ask.guarantee, "Interactive");

    let codex_cmd_guard = codex_report
        .iter()
        .find(|r| r.guard_id == "cmd_guard")
        .unwrap();
    assert_eq!(codex_cmd_guard.capability, CapabilityLevel::Partial);
    assert_eq!(codex_cmd_guard.guarantee, "Preventive");

    let codex_ask_guard = codex_report
        .iter()
        .find(|r| r.guard_id == "ask_guard")
        .unwrap();
    assert_eq!(codex_ask_guard.capability, CapabilityLevel::Emulated);
    assert_eq!(codex_ask_guard.guarantee, "Interactive");

    // Every report row must be the same provider/event/action resolution that
    // the capability registry exposes; this prevents a report from claiming a
    // stronger surface than the generated runtime can provide (H9).
    for (provider, report) in [
        (ProviderTarget::Gemini, &agy_report),
        (ProviderTarget::Codex, &codex_report),
    ] {
        for row in report {
            let decision_environment = match provider {
                ProviderTarget::Gemini => DecisionEnvironment {
                    provider_native: true,
                    arc_embedded_ui: true,
                    arc_owns_app_server_session: false,
                    direct_mcp_channel: false,
                },
                ProviderTarget::Codex => DecisionEnvironment::codex_hook_with_embedded_ui(),
                _ => unreachable!(),
            };
            let resolution = resolve_capability(CapabilityContext {
                provider,
                environment: row.environment,
                target_os: row.target_os.clone(),
                event: row.event,
                requested_action: row.requested_action,
                decision_ui: row.decision_ui,
                decision_environment,
            });
            assert_eq!(row.capability, resolution.capability);
            assert_eq!(row.effective_action, resolution.effective_action);
            assert_eq!(row.guarantee, resolution.guarantee);
            assert_eq!(row.mechanism, resolution.mechanism);
            assert_eq!(row.decision_transport, resolution.decision_transport);
            assert_eq!(row.coverage_surface, resolution.coverage_surface);
        }
    }
}

#[test]
fn h9_environment_and_missing_transport_change_the_real_codex_contract() {
    use arc::manifest::LoadedArcProject;
    use arc::manifest::schema::{
        ActionType, ArcManifest, GuardsConfig, MatcherConfig, OnFailureConfig, RootConfig,
        RuleExpression, ToolGuardConfig,
    };
    use arc::runtime::adapter::codex::CodexAdapter;
    use arc::target::ProviderTarget;
    use arc::target::capabilities::{CapabilityLevel, generate_degradation_report_for_environment};
    use std::collections::BTreeMap;

    let mut tools = BTreeMap::new();
    tools.insert(
        "ask_guard".to_string(),
        ToolGuardConfig {
            matches: MatcherConfig::Alias {
                alias: "git.push".into(),
            },
            require: RuleExpression::Decide {
                decide: arc::manifest::schema::DecideConfig {
                    prompt: "allow?".into(),
                },
            },
            on_failure: OnFailureConfig {
                action: ActionType::Ask,
                feedback: None,
            },
            order: None,
            declaration_order: 0,
        },
    );
    let project = LoadedArcProject {
        manifest_path: "arc.yaml".into(),
        manifest: ArcManifest {
            schema: "1.0".into(),
            root: RootConfig {
                workdir: ".".into(),
                instructions: None,
            },
            runtime: Default::default(),
            modules: None,
            skills: None,
            roles: None,
            guards: None,
        },
        workdir: ".".into(),
        instructions_path: None,
        instructions_content: None,
        skills: BTreeMap::new(),
        roles: BTreeMap::new(),
        role_sources: BTreeMap::new(),
        guards: GuardsConfig {
            lifecycle: BTreeMap::new(),
            tools,
        },
        rules: None,
        aliases: None,
    };

    let desktop =
        generate_degradation_report_for_environment(&project, ProviderTarget::Codex, "desktop");
    assert_eq!(desktop[0].capability, CapabilityLevel::Unsupported);

    let evaluation = canonical_test_result(
        ProviderTarget::Codex,
        ArcEventType::ToolCall,
        ActionType::Ask,
        false,
    );
    let payload = CodexAdapter::evaluation_result_to_pre_tool_use_output(&evaluation).unwrap();
    let provider = payload
        .hook_specific_output
        .expect("an unresolved ask must emit an explicit fail-closed payload");
    assert_eq!(provider.permission_decision, "deny");
}

#[test]
fn h9_resolution_drives_emitter_adapter_and_final_payload_for_every_transport_mode() {
    use arc::decision_ui::PortableDecision;
    use arc::emitters::{CodexEmitter, EmissionContext, GeminiEmitter, TargetEmitter};
    use arc::manifest::schema::{ActionType, LifecycleTrigger, OnFailureConfig};
    use arc::target::{
        CapabilityContext, CapabilityEvent, CapabilityLevel, DecisionEnvironment,
        DecisionTransport, DecisionUiMode, ProviderEnvironment, ProviderTarget, resolve_capability,
    };
    use arc::{
        BoundLifecycleGuard, BoundMatcher, BoundRuleExpression, BoundToolGuard, WorkspaceContext,
    };
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    fn ir_with_action(action: ActionType) -> BehaviorIR {
        BehaviorIR {
            schema: "1.0".into(),
            compiler_version: env!("CARGO_PKG_VERSION").into(),
            build_id: None,
            content_hash: None,
            runtime: Default::default(),
            context: WorkspaceContext {
                workdir: ".".into(),
                instructions_path: None,
                instructions_content: None,
                roles: BTreeMap::new(),
            },
            skills: Vec::new(),
            lifecycle_guards: Vec::new(),
            tool_guards: vec![BoundToolGuard {
                id: "tool_guard".into(),
                matcher: BoundMatcher {
                    exact_patterns: vec!["git push".into()],
                    regex_patterns: Vec::new(),
                },
                require: BoundRuleExpression::Decide {
                    prompt: "allow?".into(),
                },
                on_failure: OnFailureConfig {
                    action,
                    feedback: Some("policy".into()),
                },
                order: 0,
                declaration_order: 0,
            }],
            rules: BTreeMap::new(),
        }
    }

    fn emission_context(
        provider: ProviderTarget,
        environment: ProviderEnvironment,
        decision_ui: DecisionUiMode,
    ) -> EmissionContext {
        EmissionContext {
            provider,
            target_os: OsTarget::new("windows").unwrap(),
            environment,
            decision_ui,
            decision_environment: match provider {
                ProviderTarget::Gemini => DecisionEnvironment {
                    provider_native: true,
                    arc_embedded_ui: true,
                    arc_owns_app_server_session: false,
                    direct_mcp_channel: false,
                },
                ProviderTarget::Codex => DecisionEnvironment::codex_hook_with_embedded_ui(),
                _ => unreachable!(),
            },
            base_output_path: PathBuf::from("."),
            is_multi_target: false,
            arc_bin: Some("arc".into()),
        }
    }

    let ask_evaluation = canonical_test_result(
        ProviderTarget::Gemini,
        ArcEventType::ToolCall,
        ActionType::Ask,
        false,
    );

    {
        let mode = DecisionUiMode::Provider;
        let ctx = emission_context(ProviderTarget::Gemini, ProviderEnvironment::Cli, mode);
        let resolution = resolve_capability(CapabilityContext {
            provider: ctx.provider,
            environment: ctx.environment,
            target_os: ctx.target_os.clone(),
            event: CapabilityEvent::ToolCall,
            requested_action: ActionType::Ask,
            decision_ui: ctx.decision_ui,
            decision_environment: ctx.decision_environment.clone(),
        });
        assert_eq!(resolution.capability, CapabilityLevel::Supported);
        assert_eq!(
            resolution.decision_transport,
            Some(DecisionTransport::ProviderNative)
        );
        let artifacts = GeminiEmitter
            .emit(&ir_with_action(ActionType::Ask), &ctx)
            .unwrap();
        let hooks = artifacts
            .iter()
            .find(|artifact| artifact.relative_path == PathBuf::from(".agents/hooks.json"))
            .unwrap();
        assert!(hooks.content.contains(&format!("--decision-ui {mode}")));
        let payload = arc::AgyAdapter::evaluation_result_to_pre_tool_use_output_with_resolution(
            &ask_evaluation,
            &resolution,
        )
        .unwrap();
        assert_eq!(payload.decision, "force_ask");
    }

    for mode in [DecisionUiMode::Auto, DecisionUiMode::Native] {
        let gemini_native =
            emission_context(ProviderTarget::Gemini, ProviderEnvironment::Cli, mode);
        let gemini_native_resolution = resolve_capability(CapabilityContext {
            provider: ProviderTarget::Gemini,
            environment: ProviderEnvironment::Cli,
            target_os: gemini_native.target_os.clone(),
            event: CapabilityEvent::ToolCall,
            requested_action: ActionType::Ask,
            decision_ui: mode,
            decision_environment: gemini_native.decision_environment.clone(),
        });
        assert_eq!(
            gemini_native_resolution.capability,
            CapabilityLevel::Emulated
        );
        assert_eq!(
            gemini_native_resolution.decision_transport,
            Some(DecisionTransport::ArcEmbeddedUi)
        );
        GeminiEmitter
            .emit(&ir_with_action(ActionType::Ask), &gemini_native)
            .unwrap();
        let gemini_payload = arc::AgyAdapter::embedded_decision_to_pre_tool_use_output(
            &gemini_native_resolution,
            PortableDecision::Allow,
            "allowed by Arc embedded UI".into(),
        )
        .unwrap();
        assert_eq!(gemini_payload.decision, "allow");
    }

    for mode in [DecisionUiMode::Auto, DecisionUiMode::Native] {
        let ctx = emission_context(ProviderTarget::Codex, ProviderEnvironment::Cli, mode);
        let resolution = resolve_capability(CapabilityContext {
            provider: ctx.provider,
            environment: ctx.environment,
            target_os: ctx.target_os.clone(),
            event: CapabilityEvent::ToolCall,
            requested_action: ActionType::Ask,
            decision_ui: ctx.decision_ui,
            decision_environment: ctx.decision_environment.clone(),
        });
        assert_eq!(resolution.capability, CapabilityLevel::Emulated);
        assert_eq!(
            resolution.decision_transport,
            Some(DecisionTransport::ArcEmbeddedUi)
        );
        let artifacts = CodexEmitter
            .emit(&ir_with_action(ActionType::Ask), &ctx)
            .unwrap();
        let hooks = artifacts
            .iter()
            .find(|artifact| artifact.relative_path == PathBuf::from(".codex/hooks.json"))
            .unwrap();
        assert!(hooks.content.contains(&format!("--decision-ui {mode}")));
        let payload = arc::CodexAdapter::embedded_decision_to_pre_tool_use_output(
            &resolution,
            PortableDecision::Allow,
            "allowed by Arc embedded UI".into(),
            "denied".into(),
        )
        .unwrap();
        let payload_json = serde_json::to_value(payload).unwrap();
        assert_eq!(
            payload_json["hookSpecificOutput"]["permissionDecision"],
            "allow"
        );
        assert!(payload_json["hookSpecificOutput"]["additionalContext"].is_string());
    }

    let provider_only = emission_context(
        ProviderTarget::Codex,
        ProviderEnvironment::Cli,
        DecisionUiMode::Provider,
    );
    let provider_resolution = resolve_capability(CapabilityContext {
        provider: ProviderTarget::Codex,
        environment: ProviderEnvironment::Cli,
        target_os: provider_only.target_os.clone(),
        event: CapabilityEvent::ToolCall,
        requested_action: ActionType::Ask,
        decision_ui: DecisionUiMode::Provider,
        decision_environment: provider_only.decision_environment.clone(),
    });
    assert_eq!(provider_resolution.capability, CapabilityLevel::Unsupported);
    assert!(
        CodexEmitter
            .emit(&ir_with_action(ActionType::Ask), &provider_only)
            .is_err()
    );
    let codex_ask_evaluation = canonical_test_result(
        ProviderTarget::Codex,
        ArcEventType::ToolCall,
        ActionType::Ask,
        false,
    );
    let denied = arc::CodexAdapter::evaluation_result_to_pre_tool_use_output_with_resolution(
        &codex_ask_evaluation,
        &provider_resolution,
    )
    .unwrap();
    assert_eq!(
        denied.hook_specific_output.unwrap().permission_decision,
        "deny"
    );

    let desktop = emission_context(
        ProviderTarget::Codex,
        ProviderEnvironment::Desktop,
        DecisionUiMode::Auto,
    );
    assert!(
        CodexEmitter
            .emit(&ir_with_action(ActionType::Deny), &desktop)
            .is_err()
    );

    let codex_deny_ctx = emission_context(
        ProviderTarget::Codex,
        ProviderEnvironment::Cli,
        DecisionUiMode::Auto,
    );
    let codex_deny_resolution = resolve_capability(CapabilityContext {
        provider: ProviderTarget::Codex,
        environment: ProviderEnvironment::Cli,
        target_os: codex_deny_ctx.target_os.clone(),
        event: CapabilityEvent::ToolCall,
        requested_action: ActionType::Deny,
        decision_ui: DecisionUiMode::Auto,
        decision_environment: codex_deny_ctx.decision_environment.clone(),
    });
    assert_eq!(codex_deny_resolution.capability, CapabilityLevel::Partial);
    CodexEmitter
        .emit(&ir_with_action(ActionType::Deny), &codex_deny_ctx)
        .unwrap();
    let codex_deny_evaluation = canonical_test_result(
        ProviderTarget::Codex,
        ArcEventType::ToolCall,
        ActionType::Deny,
        false,
    );
    let deny_payload = arc::CodexAdapter::evaluation_result_to_pre_tool_use_output_with_resolution(
        &codex_deny_evaluation,
        &codex_deny_resolution,
    )
    .unwrap();
    assert_eq!(
        deny_payload
            .hook_specific_output
            .unwrap()
            .permission_decision,
        "deny"
    );

    let mut gemini_start_ir = ir_with_action(ActionType::Deny);
    gemini_start_ir.tool_guards.clear();
    gemini_start_ir.lifecycle_guards.push(BoundLifecycleGuard {
        id: "start_guard".into(),
        triggers: vec![LifecycleTrigger::Start],
        require: BoundRuleExpression::Decide {
            prompt: "start?".into(),
        },
        on_failure: OnFailureConfig {
            action: ActionType::Deny,
            feedback: Some("cannot start".into()),
        },
        order: 0,
        declaration_order: 0,
    });
    let gemini_start_ctx = emission_context(
        ProviderTarget::Gemini,
        ProviderEnvironment::Cli,
        DecisionUiMode::Auto,
    );
    let gemini_start_resolution = resolve_capability(CapabilityContext {
        provider: ProviderTarget::Gemini,
        environment: ProviderEnvironment::Cli,
        target_os: gemini_start_ctx.target_os.clone(),
        event: CapabilityEvent::Start,
        requested_action: ActionType::Deny,
        decision_ui: DecisionUiMode::Auto,
        decision_environment: gemini_start_ctx.decision_environment.clone(),
    });
    assert_eq!(
        gemini_start_resolution.capability,
        CapabilityLevel::Unsupported
    );
    assert!(
        GeminiEmitter
            .emit(&gemini_start_ir, &gemini_start_ctx)
            .is_err()
    );
    let gemini_start_evaluation = canonical_test_result(
        ProviderTarget::Gemini,
        ArcEventType::Start,
        ActionType::Deny,
        false,
    );
    let advisory_only =
        arc::AgyAdapter::evaluation_result_to_pre_invocation_output_with_resolution(
            &gemini_start_evaluation,
            &gemini_start_resolution,
        )
        .unwrap();
    let advisory_json = serde_json::to_value(advisory_only).unwrap();
    assert_eq!(advisory_json["decision"], "abort");
    assert!(
        advisory_json["reason"]
            .as_str()
            .unwrap()
            .contains("Arc policy denied session start.")
    );
    assert_eq!(
        advisory_json["injectSteps"][0]["ephemeralMessage"],
        advisory_json["reason"]
    );
}

#[test]
fn test_m2_codex_rollout_and_decision_fail_closed() {
    use arc::runtime::adapter::codex::CodexAdapter;
    use arc::target::ProviderTarget;
    use arc::target::decision_strategy::{DecisionEnvironment, resolve_decision_transport};

    // 1. When no transport is available, resolve_decision_transport returns None and specifies operation is denied
    let empty_env = DecisionEnvironment {
        provider_native: false,
        arc_embedded_ui: false,
        arc_owns_app_server_session: false,
        direct_mcp_channel: false,
    };
    let resolution = resolve_decision_transport(ProviderTarget::Codex, &empty_env);
    assert_eq!(resolution.selected, None);
    assert!(
        resolution
            .compatibility_message
            .unwrap()
            .contains("operation was denied")
    );

    // 2. Continue with exact authorization requirements must fail closed when
    // called without the preceding interactive Ask/Allow/Deny round-trip.
    let need_auth = canonical_authorization_result(ProviderTarget::Codex);
    let tool_out = CodexAdapter::evaluation_result_to_pre_tool_use_output(&need_auth).unwrap();
    let codex_specific = tool_out
        .hook_specific_output
        .expect("unresolved exact authorization must not allow the call");
    assert_eq!(codex_specific.permission_decision, "deny");
    assert!(
        codex_specific
            .permission_decision_reason
            .unwrap()
            .contains("without user confirmation")
    );
    let agy_need_auth = canonical_authorization_result(ProviderTarget::Gemini);
    let agy_out = arc::runtime::adapter::agy::AgyAdapter::evaluation_result_to_pre_tool_use_output(
        &agy_need_auth,
    )
    .unwrap();
    assert_eq!(agy_out.decision, "deny");
    assert!(
        agy_out
            .reason
            .unwrap()
            .contains("without user confirmation")
    );

    // 3. A lifecycle Deny is terminal and cannot be converted into a loop continuation.
    let denied_lifecycle = canonical_test_result(
        ProviderTarget::Codex,
        ArcEventType::End,
        ActionType::Deny,
        false,
    );
    let stop_out = CodexAdapter::evaluation_result_to_stop_output(&denied_lifecycle).unwrap();
    assert_eq!(stop_out.r#continue, Some(false));
    assert!(stop_out.stop_reason.is_some());

    // 4. SessionStart NeedAuthorization aborts startup
    let denied_start = canonical_test_result(
        ProviderTarget::Codex,
        ArcEventType::Start,
        ActionType::Deny,
        false,
    );
    let start_out = CodexAdapter::evaluation_result_to_session_start_output(&denied_start).unwrap();
    assert!(!start_out.r#continue);
    // The session-start stop reason is the bundle feedback (AC-003.1: the provider
    // feedback envelope was removed). A denied guard with no configured feedback or
    // causes renders the Deny fallback of `evaluation_result_to_session_start_output`.
    let stop_reason = start_out.stop_reason.unwrap();
    assert!(
        stop_reason.starts_with("Arc guard feedback:"),
        "stop_reason={stop_reason}"
    );
    assert!(
        stop_reason.contains("Arc policy denied session start."),
        "stop_reason={stop_reason}"
    );
}

#[test]
fn test_m4_rigorous_source_validation_and_host_compatibility() {
    use arc::manifest::load_project;
    use std::fs;

    let temp_root = std::env::temp_dir().join(format!("arc_m4_test_{}", uuid::Uuid::new_v4()));
    let workdir = temp_root.join("work");
    fs::create_dir_all(&workdir).unwrap();

    // 1. Nonexistent skill source fails load_project
    let manifest_path = workdir.join("arc.yaml");
    let manifest_missing_skill = r#"
schema: '1.0'
root:
  workdir: '.'
skills:
  missing_skill:
    description: 'missing'
    src: 'skills/nonexistent_folder'
"#;
    fs::write(&manifest_path, manifest_missing_skill).unwrap();
    let err = load_project(&manifest_path).unwrap_err();
    assert!(
        err.to_string().contains("does not exist"),
        "Missing skill source must fail with does not exist error: {}",
        err
    );

    // 2. Uncontained skill source escaping workdir fails load_project
    let manifest_escaping_skill = r#"
schema: '1.0'
root:
  workdir: '.'
skills:
  escaped_skill:
    description: 'escaped'
    src: '../outside/folder'
"#;
    fs::write(&manifest_path, manifest_escaping_skill).unwrap();
    let err_escape = load_project(&manifest_path).unwrap_err();
    assert!(
        err_escape.to_string().contains("does not exist")
            || err_escape
                .to_string()
                .contains("Workspace containment violation")
            || err_escape.to_string().contains("escapes workdir"),
        "Escaping skill source must be rejected: {}",
        err_escape
    );

    // 3. Valid skill source directory succeeds
    let valid_skill_dir = workdir.join("skills").join("valid_skill");
    fs::create_dir_all(&valid_skill_dir).unwrap();
    let manifest_valid = r#"
schema: '1.0'
root:
  workdir: '.'
skills:
  valid_skill:
    description: 'valid'
    src: 'skills/valid_skill'
"#;
    fs::write(&manifest_path, manifest_valid).unwrap();
    let loaded = load_project(&manifest_path).unwrap();
    assert_eq!(loaded.skills.len(), 1);

    let _ = fs::remove_dir_all(&temp_root);
}

#[test]
fn test_m7_discover_arc_root_ancestor_and_cycle_prevention() {
    use arc::manifest::discover_arc_root;
    use std::fs;

    let temp_root = std::env::temp_dir().join(format!("arc_m7_test_{}", uuid::Uuid::new_v4()));
    let project_root = temp_root.join("project");
    let deep_nested = project_root.join("src").join("sub").join("deep");
    fs::create_dir_all(&deep_nested).unwrap();

    let arc_yaml = project_root.join("arc.yaml");
    fs::write(&arc_yaml, "schema: '1.0'\nroot:\n  workdir: '.'\n").unwrap();

    // 1. Discover from deeply nested subdirectory finds project_root/arc.yaml
    let discovered = discover_arc_root(&deep_nested).unwrap();
    assert_eq!(discovered, arc_yaml);

    // 2. Discover from direct file path
    let discovered_direct = discover_arc_root(&arc_yaml).unwrap();
    assert_eq!(discovered_direct, arc_yaml);

    // 3. Discover from explicit non-existent path fails immediately
    let non_existent_explicit = project_root.join("nonexistent_arc.yaml");
    let err_explicit = discover_arc_root(&non_existent_explicit).unwrap_err();
    assert!(
        err_explicit
            .to_string()
            .contains("Explicit Arc manifest file not found")
            || err_explicit.to_string().contains("not found"),
        "Explicit non-existent path must fail without ancestor fallback: {}",
        err_explicit
    );

    // 4. Discover in directory tree with no arc.yaml fails cleanly
    let empty_dir = temp_root.join("empty_hierarchy").join("a").join("b");
    fs::create_dir_all(&empty_dir).unwrap();
    let err = discover_arc_root(&empty_dir).unwrap_err();
    assert!(err.to_string().contains("No 'arc.yaml' found"));

    let _ = fs::remove_dir_all(&temp_root);
}

#[test]
fn test_l4_strict_ostarget_validation_and_universal_probes() {
    use arc::manifest::schema::{
        AliasVariant, AliasesManifest, OperationAliasEntry, ProbeConfig, ProbeUse, RuleExpression,
    };
    use arc::target::OsTarget;
    use arc::{
        ArcEvent, ArcEventType, ArcRuntimeSession, BoundProbeCommand, BoundRuleExpression,
        ProbeCommandError, ProbeRunner,
    };
    use std::collections::BTreeMap;
    use std::sync::atomic::{AtomicUsize, Ordering};

    // 1. Valid OsTarget deserialization
    let win: OsTarget = serde_json::from_str(r#""windows""#).unwrap();
    assert_eq!(win.as_str(), "windows");
    let lin: OsTarget = serde_json::from_str(r#""linux""#).unwrap();
    assert_eq!(lin.as_str(), "linux");
    let mac: OsTarget = serde_json::from_str(r#""macos""#).unwrap();
    assert_eq!(mac.as_str(), "macos");

    // 2. Invalid OsTarget deserialization fails
    assert!(serde_json::from_str::<OsTarget>(r#""freebsd""#).is_err());
    assert!(serde_json::from_str::<OsTarget>(r#""""#).is_err());

    // 3. Pure universal operation alias compiles for any OS
    let mut operations = BTreeMap::new();
    operations.insert(
        "universal.probe".to_string(),
        OperationAliasEntry {
            default: Some(AliasVariant::Concrete("echo universal".into())),
            windows: None,
            linux: None,
            macos: None,
        },
    );
    let aliases = AliasesManifest {
        schema: "1.0".into(),
        matchers: None,
        operations: Some(operations),
    };

    let probe_expr = RuleExpression::Probe {
        probe: ProbeConfig {
            use_op: ProbeUse::Alias {
                alias: "universal.probe".into(),
            },
            in_values: vec!["success".into()],
        },
    };

    let os_targets = vec!["windows".to_string(), "linux".to_string()];
    let bound = arc::compiler::linker::GuardLinker::link_rule_expression(
        &probe_expr,
        Some(&aliases),
        &os_targets,
    )
    .unwrap();
    match bound {
        arc::ir::BoundRuleExpression::Probe {
            command,
            expected_in,
        } => {
            assert_eq!(expected_in, vec!["success"]);
            match command {
                arc::ir::BoundProbeCommand::Single(cmd) => assert_eq!(cmd, "echo universal"),
                _ => panic!("Expected single universal command"),
            }
        }
        _ => panic!("Expected bound probe"),
    }

    // 4. Raw IR command maps reject unknown OS names, fallback placeholders,
    // and empty/whitespace commands before runtime evaluation.
    for raw in [
        r#"{"freebsd":"check"}"#,
        r#"{"default":"check"}"#,
        r#"{"host":"check"}"#,
        r#"{}"#,
        r#"{"windows":""}"#,
        r#"{"linux":"   "}"#,
    ] {
        assert!(
            serde_json::from_str::<BoundProbeCommand>(raw).is_err(),
            "invalid raw MultiOs command must be rejected: {raw}"
        );
    }

    let valid_multi_os: BoundProbeCommand =
        serde_json::from_str(r#"{"linux":"echo linux"}"#).unwrap();
    assert_eq!(valid_multi_os.resolve_for_os("linux"), Ok("echo linux"));
    let universal: BoundProbeCommand = serde_json::from_str(r#""echo universal""#).unwrap();
    assert_eq!(universal.resolve_for_os("windows"), Ok("echo universal"));

    // 5. A programmatically constructed invalid command is rejected by the
    // runtime IR boundary even if it bypasses serde deserialization.
    let invalid_ir = BehaviorIR {
        schema: "1.0".to_string(),
        compiler_version: "test".to_string(),
        build_id: None,
        content_hash: None,
        runtime: Default::default(),
        context: arc::WorkspaceContext {
            workdir: std::path::PathBuf::from("."),
            instructions_path: None,
            instructions_content: None,
            roles: BTreeMap::new(),
        },
        skills: Vec::new(),
        lifecycle_guards: Vec::new(),
        tool_guards: Vec::new(),
        rules: BTreeMap::from([(
            "invalid_probe".to_string(),
            BoundRuleExpression::Probe {
                command: BoundProbeCommand::MultiOs(BTreeMap::from([(
                    "default".to_string(),
                    "echo fallback".to_string(),
                )])),
                expected_in: vec!["ok".to_string()],
            },
        )]),
    };
    let raw_invalid_ir = serde_json::to_string(&invalid_ir).unwrap();
    assert!(
        serde_json::from_str::<BehaviorIR>(&raw_invalid_ir).is_err(),
        "deserializing an IR with an invalid OS key must fail before session creation"
    );
    assert!(
        invalid_ir.validate_integrity().is_err(),
        "invalid OS keys must be rejected before creating a runtime session"
    );

    // 6. A MultiOs command without the current host has no fallback and must
    // fail before invoking the probe runner.
    let host_os = match std::env::consts::OS {
        "windows" => "windows",
        "linux" => "linux",
        "macos" => "macos",
        other => panic!("test host must be a supported OS, got {other}"),
    };
    let other_os = if host_os == "windows" {
        "linux"
    } else {
        "windows"
    };
    let missing_host = BoundProbeCommand::MultiOs(BTreeMap::from([(
        other_os.to_string(),
        "echo other".to_string(),
    )]));
    assert_eq!(
        missing_host.resolve_for_host(),
        Err(ProbeCommandError::MissingForOs {
            os: host_os.to_string()
        })
    );

    struct CountingProbeRunner(AtomicUsize);
    impl ProbeRunner for CountingProbeRunner {
        fn run_probe(&self, _command: &str) -> anyhow::Result<String> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok("ok".to_string())
        }
    }

    let probe_runner = Arc::new(CountingProbeRunner(AtomicUsize::new(0)));
    let missing_host_expression = BoundRuleExpression::Probe {
        command: missing_host,
        expected_in: vec!["ok".to_string()],
    };
    let ir = arc::ir::BehaviorIR {
        schema: "1.0".into(),
        compiler_version: env!("CARGO_PKG_VERSION").into(),
        build_id: None,
        content_hash: None,
        runtime: Default::default(),
        context: arc::ir::WorkspaceContext {
            workdir: ".".into(),
            instructions_path: None,
            instructions_content: None,
            roles: BTreeMap::new(),
        },
        skills: Vec::new(),
        lifecycle_guards: vec![arc::ir::BoundLifecycleGuard {
            id: "guard-missing-host".into(),
            triggers: vec![arc::manifest::schema::LifecycleTrigger::Start],
            require: missing_host_expression,
            on_failure: arc::manifest::schema::OnFailureConfig {
                action: arc::manifest::schema::ActionType::Deny,
                feedback: None,
            },
            order: 1,
            declaration_order: 0,
        }],
        tool_guards: Vec::new(),
        rules: BTreeMap::new(),
    };
    let mut session = ArcRuntimeSession::new("test-session-missing-host", ir)
        .with_probe_runner(probe_runner.clone());
    let event = ArcEvent::lifecycle("test-session-missing-host", "ev-1", ArcEventType::Start, 1);
    let eval_result = evaluate_session_event(&mut session, event).unwrap();
    assert!(
        matches!(
            eval_result.report.guard_results.first().map(|guard| &guard.state),
            Some(GuardResultState::Faulted { faults, .. })
                if faults.iter().any(|fault| matches!(
                    fault,
                    EvaluationFault::Probe { summary } if summary.contains("cannot be resolved")
                ))
        ),
        "missing host command must be represented as a canonical evaluation fault"
    );
    assert_eq!(
        probe_runner.0.load(Ordering::SeqCst),
        0,
        "a missing host command must never invoke a fallback probe"
    );
}

#[test]
fn test_m6_deeply_nested_rule_traversal_without_stack_overflow() {
    use arc::compiler::flattener::SkillFlattener;
    use arc::compiler::linker::GuardLinker;
    use arc::compiler::validator::SemanticValidator;
    use arc::manifest::schema::{
        ProbeConfig, ProbeUse, RuleExpression, SkillDeclaration, SkillItem,
    };
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    // 1. Construct a deeply nested expression with 2000 levels of Not wrapping a leaf Probe
    let leaf = RuleExpression::Probe {
        probe: ProbeConfig {
            use_op: ProbeUse::Command("echo deep".into()),
            in_values: vec!["deep".into()],
        },
    };

    let mut current = leaf;
    for _ in 0..2000 {
        current = RuleExpression::Not {
            not: Box::new(current),
        };
    }

    // Iterative validation passes without stack overflow
    let val_res =
        SemanticValidator::validate_rule_expression_refs(&current, "deep_nesting_test", None, None);
    assert!(val_res.is_ok(), "Validation failed: {:?}", val_res.err());

    // Linking passes without stack overflow
    let os_list = vec!["windows".to_string()];
    let link_res = GuardLinker::link_rule_expression(&current, None, &os_list);
    assert!(link_res.is_ok(), "Linking failed: {:?}", link_res.err());

    // 2. Test deeply nested skills flattening without call recursion
    let temp_root = std::env::temp_dir().join(format!("arc_m6_skills_{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&temp_root).unwrap();
    let dummy_skill_file = temp_root.join("skill.md");
    std::fs::write(&dummy_skill_file, "skill instructions").unwrap();

    let mut nested_skills = BTreeMap::new();
    nested_skills.insert(
        "leaf_skill".to_string(),
        SkillDeclaration::Single(SkillItem {
            description: "deep leaf".into(),
            src: PathBuf::from("skill.md"),
        }),
    );

    for i in 0..100 {
        let mut group = BTreeMap::new();
        group.insert(
            format!("layer_{}", i),
            SkillDeclaration::Group {
                description: Some(format!("group {}", i)),
                members: nested_skills,
            },
        );
        nested_skills = group;
    }

    let flattened = SkillFlattener::flatten_skills(&temp_root, &nested_skills).unwrap();
    assert_eq!(flattened.len(), 1);
    assert!(flattened[0].id.contains("leaf-skill"));

    let _ = std::fs::remove_dir_all(&temp_root);
}

#[test]
fn test_m9_interleaved_mcp_requests_and_one_time_dispatch() {
    use serde_json::{Value, json};
    use std::io::{BufReader, Cursor};

    let wire_messages = [
        json!({
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": {"elicitation": {"form": {}}},
                "clientInfo": {"name": "test_interleaved", "version": "1"}
            }
        }),
        json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
        // Main tool call waiting for elicitation
        json!({
            "jsonrpc": "2.0", "id": 2, "method": "tools/call",
            "params": {"name": "arc_request_decision", "arguments": {
                "event_type": "PreToolUse", "message": "Deploy changes?", "guard_id": "deploy"
            }}
        }),
        // Interleaved ping during elicitation
        json!({"jsonrpc": "2.0", "id": 3, "method": "ping"}),
        // Interleaved tools/list during elicitation
        json!({"jsonrpc": "2.0", "id": 4, "method": "tools/list"}),
        // Orphaned response
        json!({"jsonrpc": "2.0", "id": "orphan-999", "result": {}}),
        // Elicitation resolution
        json!({
            "jsonrpc": "2.0", "id": "arc-elicitation-1",
            "result": {"action": "accept", "content": {"decision": "allow", "note": "approved"}}
        }),
    ];

    let wire = wire_messages
        .iter()
        .map(|value| serde_json::to_string(value).unwrap())
        .collect::<Vec<_>>()
        .join("\n")
        + "\n";

    let mut output = Vec::new();
    arc::mcp::serve(BufReader::new(Cursor::new(wire)), &mut output).unwrap();

    let responses: Vec<Value> = String::from_utf8(output)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();

    // 1. initialize response (id: 1)
    assert_eq!(responses[0]["id"], 1);
    assert!(responses[0]["result"]["serverInfo"]["name"].is_string());

    // 2. elicitation/create request emitted to client
    assert_eq!(responses[1]["method"], "elicitation/create");
    assert_eq!(responses[1]["id"], "arc-elicitation-1");

    // 3. interleaved ping response (id: 3)
    let ping_resp = responses.iter().find(|r| r["id"] == 3).unwrap();
    assert_eq!(ping_resp["result"], json!({}));

    // 4. tools/call response (id: 2) with decision "allow"
    let tool_resp = responses.iter().find(|r| r["id"] == 2).unwrap();
    assert_eq!(
        tool_resp["result"]["structuredContent"]["decision"],
        "allow"
    );

    // 5. buffered tools/list response (id: 4) dispatched after elicitation
    let list_resp = responses.iter().find(|r| r["id"] == 4).unwrap();
    assert!(list_resp["result"]["tools"].as_array().unwrap().len() >= 1);
}

#[test]
fn test_l1_hostile_id_table_and_collision_prevention() {
    use arc::compiler::validator::SemanticValidator;
    use arc::ir::NormalizedSkill;
    use std::path::PathBuf;

    let hostile_cases = [
        "../escaped",
        "..\\escaped",
        "sub/nested",
        "sub\\nested",
        ".hidden",
        "id with spaces",
        "id$special",
        "id*wildcard",
        "id:colon",
    ];

    for hostile in hostile_cases {
        let skill = NormalizedSkill {
            id: hostile.to_string(),
            display_name: hostile.to_string(),
            description: "hostile test".into(),
            source_path: PathBuf::from("dummy.md"),
            content: String::new(),
        };
        let res = SemanticValidator::validate_skills_normalization(&[skill]);
        assert!(
            res.is_err(),
            "Hostile skill ID '{}' must be rejected",
            hostile
        );
    }

    // Collision detection: snake_case vs kebab-case vs upper/lower case
    let skill_a = NormalizedSkill {
        id: "my_custom_tool".to_string(),
        display_name: "Skill A".to_string(),
        description: "a".into(),
        source_path: PathBuf::from("a.md"),
        content: "# Skill A".into(),
    };
    let skill_b = NormalizedSkill {
        id: "my-custom-tool".to_string(),
        display_name: "Skill B".to_string(),
        description: "b".into(),
        source_path: PathBuf::from("b.md"),
        content: "# Skill B".into(),
    };
    let coll_res = SemanticValidator::validate_skills_normalization(&[skill_a, skill_b]);
    assert!(
        coll_res.is_err(),
        "Normalized collision between 'my_custom_tool' and 'my-custom-tool' must be rejected"
    );
}

#[test]
fn test_l2_cycle_detection_in_nested_expressions_and_missing_refs() {
    use arc::compiler::validator::SemanticValidator;
    use arc::manifest::schema::{RuleExpression, RulesManifest};
    use std::collections::BTreeMap;

    // 1. Direct cycle: a -> b -> a
    let mut rules = BTreeMap::new();
    rules.insert(
        "a".to_string(),
        RuleExpression::RuleRef {
            rule: "b".to_string(),
        },
    );
    rules.insert(
        "b".to_string(),
        RuleExpression::RuleRef {
            rule: "a".to_string(),
        },
    );
    let manifest = RulesManifest {
        schema: "1.0".to_string(),
        rules,
    };
    let res = SemanticValidator::validate_rules_manifest(&manifest);
    assert!(res.is_err(), "Direct cycle must be detected");
    assert!(
        res.unwrap_err()
            .to_string()
            .contains("Cyclic rule dependency")
    );

    // 2. Cycle embedded inside All/Any/Not: x -> all([y]) -> not(x)
    let mut nested_cycle = BTreeMap::new();
    nested_cycle.insert(
        "x".to_string(),
        RuleExpression::All {
            all: vec![RuleExpression::RuleRef {
                rule: "y".to_string(),
            }],
        },
    );
    nested_cycle.insert(
        "y".to_string(),
        RuleExpression::Not {
            not: Box::new(RuleExpression::RuleRef {
                rule: "x".to_string(),
            }),
        },
    );
    let nested_manifest = RulesManifest {
        schema: "1.0".to_string(),
        rules: nested_cycle,
    };
    let nested_res = SemanticValidator::validate_rules_manifest(&nested_manifest);
    assert!(nested_res.is_err(), "Nested cycle must be detected");

    // 3. Missing rule reference fails validation
    let mut missing_map = BTreeMap::new();
    missing_map.insert(
        "entry".to_string(),
        RuleExpression::RuleRef {
            rule: "nonexistent_rule".to_string(),
        },
    );
    let missing_manifest = RulesManifest {
        schema: "1.0".to_string(),
        rules: missing_map,
    };
    let missing_res = SemanticValidator::validate_rules_manifest(&missing_manifest);
    assert!(
        missing_res.is_err(),
        "Missing rule reference must be rejected"
    );
}

#[test]
fn test_l5_declaration_order_preserved_on_order_ties_across_modules_and_runtime() {
    use arc::compiler::linker::GuardLinker;
    use arc::manifest::loader::LoadedArcProject;
    use arc::manifest::schema::{
        ActionType, GuardsConfig, LifecycleGuardConfig, LifecycleTrigger, OnFailureConfig,
        RuleExpression, TriggerSelector,
    };
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    let mut lifecycle = BTreeMap::new();
    // Guard 1 with declaration_order: 0, order: 0
    lifecycle.insert(
        "guard_first".to_string(),
        LifecycleGuardConfig {
            trigger: TriggerSelector::Single(LifecycleTrigger::Start),
            require: RuleExpression::Decide {
                decide: arc::manifest::schema::DecideConfig {
                    prompt: "first".into(),
                },
            },
            on_failure: OnFailureConfig {
                action: ActionType::Deny,
                feedback: Some("first failed".into()),
            },
            order: Some(0),
            declaration_order: 0,
        },
    );
    // Guard 2 with declaration_order: 1, order: 0 (tied order)
    lifecycle.insert(
        "guard_second".to_string(),
        LifecycleGuardConfig {
            trigger: TriggerSelector::Single(LifecycleTrigger::Start),
            require: RuleExpression::Decide {
                decide: arc::manifest::schema::DecideConfig {
                    prompt: "second".into(),
                },
            },
            on_failure: OnFailureConfig {
                action: ActionType::Deny,
                feedback: Some("second failed".into()),
            },
            order: Some(0),
            declaration_order: 1,
        },
    );

    let project = LoadedArcProject {
        manifest_path: PathBuf::from("arc.yaml"),
        manifest: arc::manifest::schema::ArcManifest {
            schema: "1.0".into(),
            root: arc::manifest::schema::RootConfig {
                workdir: PathBuf::from("."),
                instructions: None,
            },
            runtime: Default::default(),
            modules: None,
            skills: None,
            roles: None,
            guards: None,
        },
        workdir: PathBuf::from("."),
        instructions_path: None,
        instructions_content: None,
        skills: BTreeMap::new(),
        roles: BTreeMap::new(),
        role_sources: BTreeMap::new(),
        guards: GuardsConfig {
            lifecycle,
            tools: BTreeMap::new(),
        },
        rules: None,
        aliases: None,
    };

    let os_list = vec!["windows".to_string()];
    let (linked_lifecycle, _, _) = GuardLinker::link_project(&project, &os_list).unwrap();

    assert_eq!(linked_lifecycle.len(), 2);
    assert_eq!(linked_lifecycle[0].id, "guard_first");
    assert_eq!(linked_lifecycle[1].id, "guard_second");
}

#[test]
fn test_h4_hostile_paths_leaf_parent_reparse_rejection_and_atomic_replace() {
    use arc::emitters::{GeneratedArtifact, write_artifacts};
    use arc::target::{OsTarget, ProviderTarget};
    use std::path::PathBuf;

    let temp_root = std::env::temp_dir().join(format!("arc_h4_test_{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&temp_root).unwrap();

    // 1. Hostile artifact escaping root with .. is rejected
    let hostile_artifact = GeneratedArtifact {
        provider: ProviderTarget::Codex,
        target_os: OsTarget::new("windows").expect("windows is a valid test OS"),
        relative_path: PathBuf::from("../outside_arc.json"),
        content: "{}".into(),
        is_executable: false,
    };
    let err_escape = write_artifacts(&temp_root, &[hostile_artifact]).unwrap_err();
    assert!(
        err_escape
            .to_string()
            .contains("escapes base output directory")
            || err_escape.to_string().contains("traversal")
            || err_escape.to_string().contains("violates containment"),
        "Escaping artifact path must fail: {}",
        err_escape
    );

    // 2. Normal replacement writes and preserves clean files
    let valid_artifact = GeneratedArtifact {
        provider: ProviderTarget::Codex,
        target_os: OsTarget::new("windows").expect("windows is a valid test OS"),
        relative_path: PathBuf::from(".codex/config.json"),
        content: "{\"valid\": true}".into(),
        is_executable: false,
    };
    let write_res = write_artifacts(&temp_root, &[valid_artifact]);
    assert!(write_res.is_ok(), "Valid artifact write must succeed");
    assert!(temp_root.join(".codex").join("config.json").exists());

    #[cfg(unix)]
    {
        let outside = std::env::temp_dir().join(format!("arc_h4_outside_{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::remove_dir_all(temp_root.join(".codex")).unwrap();
        std::os::unix::fs::symlink(&outside, temp_root.join(".codex")).unwrap();
        let parent_link_artifact = GeneratedArtifact {
            provider: ProviderTarget::Codex,
            target_os: OsTarget::new("linux").expect("linux is a valid test OS"),
            relative_path: PathBuf::from(".codex/blocked.json"),
            content: "must not escape".into(),
            is_executable: false,
        };
        let parent_error = write_artifacts(&temp_root, &[parent_link_artifact]).unwrap_err();
        assert!(parent_error.to_string().contains("symlink"));
        assert!(!outside.join("blocked.json").exists());
        let _ = std::fs::remove_dir_all(&outside);
    }

    let _ = std::fs::remove_dir_all(&temp_root);
}

#[test]
fn test_m11_regex_re2_and_os_alias_validation_before_writes() {
    use arc::compiler::validator::SemanticValidator;
    use arc::manifest::schema::{AliasesManifest, InlineMatcher, MatcherAliasEntry, StringList};
    use std::collections::BTreeMap;

    // 1. Invalid regex in OS variant of MatcherAliasEntry fails semantic validation
    let mut matchers = BTreeMap::new();
    let mut win_matcher = InlineMatcher::default();
    win_matcher.regex = Some(StringList::Single(r"git(?=push)".into())); // lookahead forbidden in RE2

    matchers.insert(
        "git.push_alias".to_string(),
        MatcherAliasEntry {
            default: None,
            windows: Some(win_matcher),
            linux: None,
            macos: None,
        },
    );

    let aliases = AliasesManifest {
        schema: "1.0".into(),
        matchers: Some(matchers),
        operations: None,
    };

    let val_res = SemanticValidator::validate_aliases_manifest(&aliases);
    assert!(
        val_res.is_err(),
        "Aliases with non-RE2 regex in OS variant must fail validation"
    );
    assert!(
        val_res
            .unwrap_err()
            .to_string()
            .contains("lookaround assertions")
    );
}

#[test]
fn test_f03_preventive_security_fault_typed_classification() {
    use arc::PreventiveSecurityFaultError;

    let fault = PreventiveSecurityFaultError {
        tool_name: "Bash".into(),
        reason: "malformed payload".into(),
        raw: serde_json::json!({"unexpected": "arc-private-token-7", "nested": {"password": "arc-private-password-7"}}),
    };
    let err: anyhow::Error = fault.into();
    let downcasted = err.downcast_ref::<PreventiveSecurityFaultError>();
    assert!(
        downcasted.is_some(),
        "PreventiveSecurityFaultError must be downcastable without string matching"
    );
    let unwrapped = downcasted.unwrap();
    assert_eq!(unwrapped.tool_name, "Bash");
    assert_eq!(unwrapped.reason, "malformed payload");
    assert_eq!(unwrapped.raw["unexpected"], "arc-private-token-7");
    assert!(unwrapped.to_string().contains("Preventive security fault"));
    for rendered in [
        unwrapped.to_string(),
        format!("{unwrapped:?}"),
        format!("{unwrapped:#?}"),
        format!("{err:#}"),
        format!("{err:?}"),
    ] {
        assert!(!rendered.contains("arc-private-token-7"), "token leaked");
        assert!(
            !rendered.contains("arc-private-password-7"),
            "password leaked"
        );
        assert!(!rendered.contains("unexpected"), "argument key leaked");
        assert!(rendered.contains("type=object"), "missing argument type");
        assert!(rendered.contains("bytes="), "missing serialized size");
        assert!(rendered.contains("sha256="), "missing fingerprint");
    }
}

#[test]
fn preventive_fault_argument_summary_is_exact_and_bounded_for_every_json_type() {
    use sha2::{Digest, Sha256};
    for (kind, raw) in [
        ("null", serde_json::Value::Null),
        ("boolean", serde_json::json!(true)),
        ("number", serde_json::json!(42)),
        ("string", serde_json::json!("secreto 🦀\n".repeat(100_000))),
        ("array", serde_json::json!(["secret", {"token": "hidden"}])),
        (
            "object",
            serde_json::json!({"token": "hidden", "unicode": "á🦀"}),
        ),
    ] {
        let encoded = serde_json::to_vec(&raw).unwrap();
        let expected = format!(
            "type={kind}, bytes={}, sha256={}",
            encoded.len(),
            hex::encode(Sha256::digest(&encoded))
        );
        let fault = arc::PreventiveSecurityFaultError {
            tool_name: "Bash".into(),
            reason: "malformed payload".into(),
            raw,
        };
        for rendered in [
            fault.to_string(),
            format!("{fault:?}"),
            format!("{fault:#?}"),
        ] {
            assert!(rendered.contains(&expected), "incorrect summary for {kind}");
            assert!(rendered.len() < 512, "diagnostic must remain bounded");
            assert!(!rendered.contains("hidden"));
            assert!(!rendered.contains("secreto"));
        }
    }
}
