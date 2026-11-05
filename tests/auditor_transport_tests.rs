#[path = "guard_evaluation_support.rs"]
mod guard_evaluation_support;
use guard_evaluation_support::evaluate_session_event;

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::sync::Mutex;

use arc::{
    ArcEvent, ArcEventType, ArcRuntimeSession, AuditorInputPayload, AuditorOutputPayload,
    BoundRuleExpression, CliDecisionProvider, CurrentOperation, DecisionError, DecisionProvider,
    DecisionVerdict, GuardDecisionEvidence, MockDecisionProvider, MockProbeRunner, SessionContext,
    build_auditor_payload,
};

struct CaptureScript {
    script_path: PathBuf,
    capture_path: PathBuf,
}

impl CaptureScript {
    fn new() -> Self {
        let base =
            std::env::temp_dir().join(format!("arc_auditor_capture_{}", uuid::Uuid::new_v4()));
        let (script_path, script) = if cfg!(target_os = "windows") {
            let script_path = base.with_extension("bat");
            let script = r#"@echo off
set ARC_AUDITOR_PROMPT > "%~dpn0.capture"
echo {"decision":false,"findings":"captured"}
"#;
            (script_path, script.to_string())
        } else {
            let script_path = base.with_extension("sh");
            let script = r#"#!/bin/sh
if [ -z "$1" ]; then
  printf '%s\n' '{"decision":true,"findings":null}'
  exit 0
fi
printf '%s' "$1" > "${0%.*}.capture"
printf '%s\n' '{"decision":false,"findings":"captured"}'
"#;
            (script_path, script.to_string())
        };

        fs::write(&script_path, script).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut permissions = fs::metadata(&script_path).unwrap().permissions();
            permissions.set_mode(0o755);
            fs::set_permissions(&script_path, permissions).unwrap();
        }

        Self {
            capture_path: script_path.with_extension("capture"),
            script_path,
        }
    }

    fn command(&self) -> String {
        if cfg!(target_os = "windows") {
            format!("call {}", self.script_path.display())
        } else {
            self.script_path.to_string_lossy().into_owned()
        }
    }
}

impl Drop for CaptureScript {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.script_path);
        let _ = fs::remove_file(&self.capture_path);
    }
}

struct EmptyOutputScript {
    script_path: PathBuf,
}

impl EmptyOutputScript {
    fn new(write_stderr: bool) -> Self {
        let base =
            std::env::temp_dir().join(format!("arc_auditor_empty_stdout_{}", uuid::Uuid::new_v4()));
        let (script_path, script) = if cfg!(target_os = "windows") {
            let script_path = base.with_extension("bat");
            let stderr_line = if write_stderr {
                "echo transport diagnostic 1>&2\r\n"
            } else {
                ""
            };
            (
                script_path,
                format!("@echo off\r\n{stderr_line}exit /b 0\r\n"),
            )
        } else {
            let script_path = base.with_extension("sh");
            let stderr_line = if write_stderr {
                "printf '%s' 'transport diagnostic' >&2\n"
            } else {
                ""
            };
            (script_path, format!("#!/bin/sh\n{stderr_line}exit 0\n"))
        };

        fs::write(&script_path, script).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut permissions = fs::metadata(&script_path).unwrap().permissions();
            permissions.set_mode(0o755);
            fs::set_permissions(&script_path, permissions).unwrap();
        }
        Self { script_path }
    }

    fn command(&self) -> String {
        if cfg!(target_os = "windows") {
            format!("call {}", self.script_path.display())
        } else {
            self.script_path.to_string_lossy().into_owned()
        }
    }
}

impl Drop for EmptyOutputScript {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.script_path);
    }
}

fn verified_context() -> SessionContext {
    SessionContext {
        user_intent: "Validate the current release operation against the approved goal.".into(),
        ..SessionContext::default()
    }
}

fn tool_call_operation() -> CurrentOperation {
    CurrentOperation {
        event_type: ArcEventType::ToolCall,
        tool: Some("shell".into()),
        input: Some(serde_json::json!({"command": "release --dry-run"})),
        command_text: Some("release --dry-run".into()),
    }
}

#[test]
fn codex_and_gemini_share_the_same_bounded_auditor_payload() {
    let context = verified_context();
    let operation = tool_call_operation();
    let evidence = GuardDecisionEvidence {
        guard_id: "release-guard".into(),
        event: "pre_tool_use".into(),
        event_id: "evt-8".into(),
        scope: "tool".into(),
        ..GuardDecisionEvidence::default()
    };

    let codex_payload =
        build_auditor_payload("Is this release approved?", &context, &operation, &evidence);
    let gemini_payload =
        build_auditor_payload("Is this release approved?", &context, &operation, &evidence);

    assert_eq!(codex_payload, gemini_payload);
    assert_eq!(
        codex_payload.audit_request.role,
        "read_only_compliance_auditor"
    );
    assert!(codex_payload.current_operation.is_some());

    let serialized = serde_json::to_string(&codex_payload).unwrap();
    assert!(!serialized.contains("stdout"));
    assert!(!serialized.contains("stderr"));
    assert!(!serialized.contains("ARC_INTERNAL_RECURSION_V1"));
}

#[test]
fn missing_intent_and_current_operation_fail_closed_before_transport() {
    let provider =
        CliDecisionProvider::for_codex().with_custom_command("command-that-must-not-run");
    let operation = tool_call_operation();
    let evidence = GuardDecisionEvidence::default();

    let missing_intent = provider.decide(
        "Authorize this operation?",
        Some(&SessionContext::default()),
        Some(&operation),
        &evidence,
    );
    assert!(
        missing_intent.is_err(),
        "missing session intent is an evaluation fault, not a semantic deny"
    );
    assert!(
        missing_intent
            .unwrap_err()
            .to_string()
            .contains("session intent")
    );

    let missing_operation = provider
        .decide(
            "Authorize this operation?",
            Some(&verified_context()),
            None,
            &evidence,
        )
        .unwrap();
    assert!(!missing_operation.decision);
    assert!(
        missing_operation
            .findings
            .as_deref()
            .unwrap_or_default()
            .contains("current operation")
    );
}

#[test]
fn cli_decision_rejects_conversation_reuse_flags_before_spawn() {
    for command in [
        "agy --continue",
        "agy --conversation",
        "agy --conversation=old",
    ] {
        let provider = CliDecisionProvider::for_gemini().with_custom_command(command);
        let result = provider.decide(
            "Authorize this operation?",
            Some(&verified_context()),
            Some(&tool_call_operation()),
            &GuardDecisionEvidence::default(),
        );
        assert!(
            matches!(result, Err(DecisionError::IsolationViolation { .. })),
            "conversation reuse command must be rejected: {command}"
        );
    }
}

fn tool_ir(id: &str, expression: BoundRuleExpression) -> arc::ir::BehaviorIR {
    arc::ir::BehaviorIR {
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
        lifecycle_guards: Vec::new(),
        tool_guards: vec![arc::ir::BoundToolGuard {
            id: id.into(),
            matcher: arc::ir::BoundMatcher {
                exact_patterns: vec!["git status".into()],
                regex_patterns: vec![],
            },
            require: expression,
            on_failure: arc::manifest::schema::OnFailureConfig {
                action: arc::ActionType::Ask,
                feedback: None,
            },
            order: 1,
            declaration_order: 0,
        }],
        rules: BTreeMap::new(),
    }
}

#[test]
fn auditor_true_never_directly_authorizes_a_tool_call() {
    let expression = BoundRuleExpression::Decide {
        prompt: "Authorize this operation?".into(),
    };
    let ir = tool_ir("guard-auth", expression);
    let provider = std::sync::Arc::new(
        MockDecisionProvider::new().with_decision("Authorize this operation?", true),
    );
    let mut session = ArcRuntimeSession::new("test-session", ir).with_decision_provider(provider);
    let event = ArcEvent::tool_call("test-session", "ev-1", 1, "Bash", "git status");

    let eval_result = evaluate_session_event(&mut session, event).unwrap();
    assert_eq!(eval_result.authorization_requirements.len(), 1);
    assert_eq!(
        eval_result.authorization_requirements[0].guard_id,
        "guard-auth"
    );
    assert_eq!(eval_result.authorization_requirements[0].tool, "Bash");
}

#[test]
fn auditor_output_schema_rejects_unknown_fields() {
    let invalid = serde_json::json!({
        "decision": true,
        "findings": null,
        "error": null,
        "unexpected": "must be rejected"
    });

    assert!(serde_json::from_value::<AuditorOutputPayload>(invalid).is_err());
}

#[test]
fn query_auditor_forwards_the_effective_prompt_through_external_transport() {
    let capture = CaptureScript::new();
    let provider = CliDecisionProvider::for_codex().with_custom_command(capture.command());
    let context = verified_context();
    let operation = tool_call_operation();
    let evidence = GuardDecisionEvidence::default();

    let verdict = provider
        .decide(
            "Authorize this exact release operation?",
            Some(&context),
            Some(&operation),
            &evidence,
        )
        .unwrap();

    assert!(!verdict.decision);
    assert_eq!(verdict.findings.as_deref(), Some("captured"));

    let captured_prompt = fs::read_to_string(&capture.capture_path).unwrap();
    let payload_start = captured_prompt.find("{\"audit_request\"").unwrap();
    let payload: AuditorInputPayload =
        serde_json::from_str(captured_prompt[payload_start..].trim()).unwrap();

    assert_eq!(
        payload.audit_request.goal,
        "Authorize this exact release operation?"
    );
    assert_eq!(payload.audit_request.role, "read_only_compliance_auditor");
    assert_eq!(payload.session_context, context);
    assert_eq!(payload.current_operation, Some(operation));
}

#[test]
fn external_transport_rejects_success_with_empty_stdout() {
    for write_stderr in [false, true] {
        let script = EmptyOutputScript::new(write_stderr);
        let provider = CliDecisionProvider::for_codex().with_custom_command(script.command());
        let result = provider.decide(
            "Authorize this exact release operation?",
            Some(&verified_context()),
            Some(&tool_call_operation()),
            &GuardDecisionEvidence::default(),
        );

        match result {
            Err(DecisionError::UnparseableResponse { response, .. }) => {
                assert!(
                    response.is_empty(),
                    "empty stdout must remain empty even when stderr is non-empty"
                );
            }
            other => panic!(
                "successful external transport without stdout must fail closed, got {other:?}"
            ),
        }
    }
}

#[test]
fn probe_stdout_is_reduced_to_bounded_hash_before_auditor_payload() {
    struct CapturingProvider {
        captured: Mutex<Option<GuardDecisionEvidence>>,
    }

    impl DecisionProvider for CapturingProvider {
        fn decide(
            &self,
            _prompt: &str,
            _context: Option<&SessionContext>,
            _current_operation: Option<&CurrentOperation>,
            evidence: &GuardDecisionEvidence,
        ) -> Result<DecisionVerdict, DecisionError> {
            *self.captured.lock().unwrap() = Some(evidence.clone());
            Ok(DecisionVerdict::deny("captured evidence"))
        }
    }

    let stdout = format!("PROBE_STDOUT_SECRET:{}", "x".repeat(4096));
    let probes = MockProbeRunner::new()
        .with_output("emit-sensitive-evidence", stdout.clone())
        .with_output("emit-approved-evidence", "approved");
    let expression = BoundRuleExpression::All(vec![
        BoundRuleExpression::Any(vec![
            BoundRuleExpression::Probe {
                command: "emit-sensitive-evidence".into(),
                expected_in: vec!["expected".into()],
            },
            BoundRuleExpression::Probe {
                command: "emit-approved-evidence".into(),
                expected_in: vec!["approved".into()],
            },
        ]),
        BoundRuleExpression::Decide {
            prompt: "Is the evidence sufficient?".into(),
        },
    ]);
    let context = verified_context();
    let operation = tool_call_operation();
    let provider = std::sync::Arc::new(CapturingProvider {
        captured: Mutex::new(None),
    });

    let ir = tool_ir("test-guard", expression);
    let mut session = ArcRuntimeSession::new("test-session", ir)
        .with_probe_runner(std::sync::Arc::new(probes))
        .with_decision_provider(provider.clone());
    let event = ArcEvent::tool_call("test-session", "ev-1", 1, "Bash", "git status");
    let _ = evaluate_session_event(&mut session, event).unwrap();

    let evidence = provider.captured.lock().unwrap().clone().unwrap();
    assert_eq!(evidence.deterministic_evidence.len(), 2);
    assert_eq!(
        evidence.deterministic_evidence[0].operation,
        "emit-sensitive-evidence"
    );
    let hash = evidence.deterministic_evidence[0]
        .observed_sha256
        .strip_prefix("sha256:")
        .unwrap_or(&evidence.deterministic_evidence[0].observed_sha256);
    assert_eq!(hash.len(), 64);

    let payload = build_auditor_payload(
        "Is the evidence sufficient?",
        &context,
        &operation,
        &evidence,
    );
    let serialized = serde_json::to_string(&payload).unwrap();
    assert!(!serialized.contains("PROBE_STDOUT_SECRET"));
    assert!(!serialized.contains(&stdout));
    assert!(serialized.contains("observed_sha256"));
}
