use std::fs;
use std::io::Write;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use arc::{
    CoordinationInput, DecisionActor, DecisionChoice, DecisionIntegrity, DecisionReceipt,
    DecisionRequest, EvaluationSnapshot, GuardActivation, GuardExecutionCoordinator,
    GuardExecutionKey, GuardExecutionRecord, GuardExecutionState, GuardExecutionStateStore,
    InMemoryStateStore, ProviderSignals, ReasonCode, ReentryKind, RuntimeDisposition,
    SqliteStateStore, ViolationHandling, WriteOutcome,
};

fn trust_ir(hook_cwd: &std::path::Path, ir_path: &std::path::Path) {
    let state_path = hook_cwd.join(".arc-test-state/runtime-state.sqlite3");
    SqliteStateStore::open(&state_path)
        .unwrap()
        .trust_ir_file(ir_path)
        .unwrap();
}

fn run_codex_hook(cwd: &std::path::Path, event: &str, input: &str) -> serde_json::Value {
    let mut child = Command::new(env!("CARGO_BIN_EXE_arc"))
        .current_dir(cwd)
        .args(["hook", "run", "--event-type", event, "--provider", "codex"])
        .env("ARC_STATE_DIR", cwd.join(".arc-test-state"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

fn run_codex_hook_with_decision_ui(
    cwd: &std::path::Path,
    event: &str,
    input: &str,
    decision_ui: &str,
) -> serde_json::Value {
    run_hook_with_decision_ui_env(cwd, event, input, "codex", decision_ui, &[])
}

fn run_hook_with_decision_ui_env(
    cwd: &std::path::Path,
    event: &str,
    input: &str,
    provider: &str,
    decision_ui: &str,
    envs: &[(&str, &std::ffi::OsStr)],
) -> serde_json::Value {
    let child = spawn_hook_with_decision_ui_env(cwd, event, input, provider, decision_ui, envs);
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

fn spawn_hook_with_decision_ui_env(
    cwd: &std::path::Path,
    event: &str,
    input: &str,
    provider: &str,
    decision_ui: &str,
    envs: &[(&str, &std::ffi::OsStr)],
) -> std::process::Child {
    let mut command = Command::new(env!("CARGO_BIN_EXE_arc"));
    command
        .current_dir(cwd)
        .args([
            "hook",
            "run",
            "--event-type",
            event,
            "--provider",
            provider,
            "--decision-ui",
            decision_ui,
        ])
        .env("ARC_STATE_DIR", cwd.join(".arc-test-state"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (key, value) in envs {
        command.env(key, value);
    }
    let mut child = command.spawn().unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.as_bytes())
        .unwrap();
    child
}

#[test]
fn missing_ir_fails_closed_for_each_codex_event() {
    let root = std::env::temp_dir().join(format!("arc_codex_missing_ir_{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).unwrap();

    let pre = run_codex_hook(
        &root,
        "pre-tool-use",
        r#"{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"git push"}}"#,
    );
    assert_eq!(pre["hookSpecificOutput"]["permissionDecision"], "deny");
    assert!(
        pre["hookSpecificOutput"]["permissionDecisionReason"]
            .as_str()
            .unwrap()
            .contains("ARC-HOOK-001")
    );

    let stop = run_codex_hook(
        &root,
        "stop",
        r#"{"hook_event_name":"Stop","session_id":"s","turn_id":"t"}"#,
    );
    assert_eq!(stop["continue"], false);
    assert!(
        stop["stopReason"]
            .as_str()
            .unwrap()
            .contains("ARC-HOOK-001")
    );

    let start = run_codex_hook(
        &root,
        "session-start",
        r#"{"hook_event_name":"SessionStart","session_id":"s","cwd":"."}"#,
    );
    assert_eq!(start["continue"], false);
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn corrupt_ir_is_found_from_a_subdirectory_and_fails_closed() {
    let root = std::env::temp_dir().join(format!("arc_codex_bad_ir_{}", std::process::id()));
    let nested = root.join("nested/deeper");
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(root.join(".codex")).unwrap();
    fs::create_dir_all(&nested).unwrap();
    let ir_path = root.join(".codex/arc_ir.json");
    fs::write(&ir_path, "not json").unwrap();
    trust_ir(&nested, &ir_path);

    let output = run_codex_hook(
        &nested,
        "pre-tool-use",
        &format!(
            r#"{{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{{"command":"git push"}},"cwd":{}}}"#,
            serde_json::to_string(&nested.to_string_lossy()).unwrap()
        ),
    );
    assert_eq!(output["hookSpecificOutput"]["permissionDecision"], "deny");
    assert!(
        output["hookSpecificOutput"]["permissionDecisionReason"]
            .as_str()
            .unwrap()
            .contains("ARC-HOOK-001")
    );
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn malformed_codex_payload_fails_closed_with_valid_ir() {
    let root = std::env::temp_dir().join(format!("arc_codex_bad_payload_{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(root.join(".codex")).unwrap();
    fs::write(
        root.join(".codex/arc_ir.json"),
        r#"{"context":{"workdir":".","instructions_path":null,"instructions_content":null,"roles":{}},"skills":[],"lifecycle_guards":[],"tool_guards":[],"rules":{}}"#,
    ).unwrap();
    trust_ir(&root, &root.join(".codex/arc_ir.json"));

    let output = run_codex_hook(&root, "pre-tool-use", r#"{"unexpected":true}"#);
    assert_eq!(output["hookSpecificOutput"]["permissionDecision"], "deny");
    assert!(
        output["hookSpecificOutput"]["permissionDecisionReason"]
            .as_str()
            .unwrap()
            .contains("ARC-HOOK-001")
    );
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn malformed_provider_tool_arguments_fail_closed_and_are_journaled() {
    let root = setup_fase4_cli_contract_root();

    let codex_output = run_codex_hook(
        &root,
        "pre-tool-use",
        r#"{"hook_event_name":"PreToolUse","session_id":"malformed-codex-tool-input","tool_name":"Bash","tool_input":"not-an-object"}"#,
    );
    let gemini_output = run_agy_hook(
        &root,
        "pre-tool-use",
        r#"{"conversationId":"malformed-gemini-tool-input","toolCall":{"name":"run_command","args":"not-an-object"}}"#,
    );
    assert!(
        codex_output["hookSpecificOutput"]["permissionDecision"] == "deny"
            && gemini_output["decision"] == "deny",
        "malformed Codex and Gemini inputs must both be denied; got Codex={codex_output}, Gemini={gemini_output}"
    );
    assert!(
        codex_output["hookSpecificOutput"]["permissionDecisionReason"]
            .as_str()
            .is_some_and(|reason| reason.contains("ARC-HOOK-001"))
    );
    assert!(
        gemini_output["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("ARC-HOOK-001"))
    );

    let state_path = root.join(".arc-test-state/runtime-state.sqlite3");
    let journal = arc::ObservabilityJournal::open(&state_path).unwrap();
    let events = journal.query(&arc::EventQuery::default()).unwrap();
    let failed_events: Vec<_> = events
        .iter()
        .filter(|event| event.event_type == "HookFailed")
        .collect();
    assert_eq!(failed_events.len(), 2);
    assert!(failed_events.iter().any(|event| {
        event.provider.as_deref() == Some("codex")
            && event.reason_code.as_deref() == Some("invalid_hook_payload")
    }));
    assert!(failed_events.iter().any(|event| {
        event.provider.as_deref() == Some("gemini")
            && event.reason_code.as_deref() == Some("invalid_hook_payload")
    }));

    let _ = fs::remove_dir_all(root);
}

#[test]
fn malformed_tool_arguments_never_leak_to_hook_outputs_or_journal() {
    let root = setup_fase4_cli_contract_root();
    let secret = "arc-sensitive-token-issue-7";
    for arguments in [
        serde_json::json!({"unexpected": secret, "nested": {"password": secret}}),
        serde_json::json!({"command": "", "token": secret}),
        serde_json::json!({"command": [42, secret], "token": secret}),
    ] {
        for provider in ["codex", "gemini"] {
            let payload = if provider == "codex" {
                serde_json::json!({"hook_event_name": "PreToolUse", "session_id": "redacted-codex", "tool_name": "Bash", "tool_input": arguments})
            } else {
                serde_json::json!({"conversationId": "redacted-gemini", "toolCall": {"name": "run_command", "args": arguments}})
            };
            let child = spawn_hook_with_decision_ui_env(
                &root,
                "pre-tool-use",
                &payload.to_string(),
                provider,
                "provider",
                &[],
            );
            let output = child.wait_with_output().unwrap();
            assert!(output.status.success());
            let stdout = String::from_utf8(output.stdout).unwrap();
            let stderr = String::from_utf8(output.stderr).unwrap();
            assert!(
                !stdout.contains(secret),
                "{provider}: stdout leaked arguments"
            );
            assert!(
                !stderr.contains(secret),
                "{provider}: stderr leaked arguments"
            );
            assert!(
                stderr.contains("Preventive security fault"),
                "must reach the runtime error"
            );
            assert!(stderr.contains("type=object"));
            assert!(stderr.contains("sha256="));
            let response: serde_json::Value = serde_json::from_str(&stdout).unwrap();
            if provider == "codex" {
                assert_eq!(response["hookSpecificOutput"]["permissionDecision"], "deny");
            } else {
                assert_eq!(response["decision"], "deny");
            }
        }
    }
    let journal =
        arc::ObservabilityJournal::open(&root.join(".arc-test-state/runtime-state.sqlite3"))
            .unwrap();
    let events = journal.query(&arc::EventQuery::default()).unwrap();
    assert!(!serde_json::to_string(&events).unwrap().contains(secret));
    let failures: Vec<_> = events
        .iter()
        .filter(|event| event.event_type == "HookFailed")
        .collect();
    assert_eq!(failures.len(), 6);
    assert!(
        failures
            .iter()
            .all(|event| event.reason_code.as_deref() == Some("hook_execution_failed"))
    );
    drop(journal);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn cli_build_registers_the_generated_ir_for_hook_execution() {
    let root = std::env::temp_dir().join(format!(
        "arc_codex_build_trust_{}_{}",
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    fs::create_dir_all(&root).unwrap();
    fs::write(
        root.join("arc.yaml"),
        "schema: \"1.0\"\nroot:\n  workdir: \".\"\n",
    )
    .unwrap();

    let build = Command::new(env!("CARGO_BIN_EXE_arc"))
        .current_dir(&root)
        .args(["build", "--target", "codex", "--os", "windows"])
        .env("ARC_STATE_DIR", root.join(".arc-test-state"))
        .output()
        .unwrap();
    assert!(
        build.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&build.stderr)
    );

    let ir_path = root.join(".codex/arc_ir.json");
    let store =
        SqliteStateStore::open(&root.join(".arc-test-state/runtime-state.sqlite3")).unwrap();
    assert!(store.verify_trusted_ir_file(&ir_path).is_ok());
    let output = run_codex_hook(
        &root,
        "pre-tool-use",
        r#"{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"cargo test"}}"#,
    );
    assert_eq!(output, serde_json::json!({}));

    let _ = fs::remove_dir_all(root);
}

#[test]
fn externally_registered_ir_rejects_a_valid_replacement() {
    let root = std::env::temp_dir().join(format!(
        "arc_codex_replaced_ir_{}_{}",
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(root.join(".codex")).unwrap();
    let ir_path = root.join(".codex/arc_ir.json");
    let empty_ir = serde_json::json!({
        "context": {"workdir": ".", "instructions_path": null, "instructions_content": null, "roles": {}},
        "skills": [],
        "lifecycle_guards": [],
        "tool_guards": [],
        "rules": {}
    });
    fs::write(&ir_path, serde_json::to_vec(&empty_ir).unwrap()).unwrap();
    trust_ir(&root, &ir_path);

    let mut replacement = empty_ir;
    replacement["skills"] = serde_json::json!([{"name": "replacement"}]);
    fs::write(&ir_path, serde_json::to_vec(&replacement).unwrap()).unwrap();

    let output = run_codex_hook(
        &root,
        "pre-tool-use",
        r#"{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"git push"}}"#,
    );
    assert_eq!(output["hookSpecificOutput"]["permissionDecision"], "deny");
    assert!(
        output["hookSpecificOutput"]["permissionDecisionReason"]
            .as_str()
            .unwrap()
            .contains("ARC-HOOK-001")
    );
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn active_stop_hook_aborts_the_loop_without_treating_reentry_as_authorization() {
    let root = std::env::temp_dir().join(format!("arc_codex_active_stop_{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(root.join(".codex")).unwrap();
    let failing_command = if cfg!(windows) {
        "powershell -NoProfile -Command \"'dirty'\""
    } else {
        "printf dirty"
    };
    let ir = serde_json::json!({
        "context": {
            "workdir": ".",
            "instructions_path": null,
            "instructions_content": null,
            "roles": {}
        },
        "skills": [],
        "lifecycle_guards": [{
            "id": "must_be_clean",
            "triggers": ["end"],
            "require": {
                "probe": {
                    "command": failing_command,
                    "expected_in": ["clean"]
                }
            },
            "on_failure": {
                "action": "deny",
                "feedback": "workspace remains dirty"
            },
            "order": 10
        }],
        "tool_guards": [],
        "rules": {}
    });
    fs::write(
        root.join(".codex/arc_ir.json"),
        serde_json::to_vec_pretty(&ir).unwrap(),
    )
    .unwrap();
    trust_ir(&root, &root.join(".codex/arc_ir.json"));

    let first = run_codex_hook(
        &root,
        "stop",
        r#"{"hook_event_name":"Stop","session_id":"s","turn_id":"t","stop_hook_active":false}"#,
    );
    assert_eq!(first["continue"], false);
    assert!(
        first["stopReason"]
            .as_str()
            .unwrap()
            .contains("workspace remains dirty")
    );

    let output = run_codex_hook(
        &root,
        "stop",
        r#"{"hook_event_name":"Stop","session_id":"s","turn_id":"t","stop_hook_active":true}"#,
    );
    assert_eq!(output["continue"], false);
    assert!(
        output["stopReason"]
            .as_str()
            .unwrap()
            .contains("workspace remains dirty")
    );
    let database = root.join(".arc-test-state/runtime-state.sqlite3");
    let connection = rusqlite::Connection::open(database).unwrap();
    let provider_capability_count: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM observability_events
             WHERE event_type = 'ProviderCapability'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(provider_capability_count, 0);
    let degraded_count: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM observability_events
             WHERE event_type = 'CapabilityDegraded'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(degraded_count, 0);
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn active_ask_stop_after_allow_requests_another_decision() {
    let store = std::sync::Arc::new(InMemoryStateStore::default());
    let key = GuardExecutionKey {
        workspace_id: "workspace".into(),
        session_id: "ask-session".into(),
        turn_id: Some("ask-turn".into()),
        guard_id: "must_be_clean".into(),
        activation: GuardActivation::SessionStop,
        subject_id: None,
    };
    let mut record =
        GuardExecutionRecord::new("ask-execution".into(), key.clone(), current_unix_ms());
    record.state = GuardExecutionState::RemediationInProgress;
    record.revision = 1;
    assert_eq!(
        store.compare_and_swap(None, &record).unwrap(),
        WriteOutcome::Written
    );

    let coordinator = GuardExecutionCoordinator::new(store);
    let directive = coordinator
        .coordinate(CoordinationInput {
            key,
            invocation_id: "continued-stop".into(),
            signals: ProviderSignals {
                reentry: ReentryKind::ContinuedByHook,
                native_invocation_id: None,
                native_interaction_id: None,
            },
            evaluation: EvaluationSnapshot::Violated {
                feedback: Some("workspace remains dirty".into()),
            },
            violation_handling: ViolationHandling::RequireDecision,
        })
        .unwrap();

    assert_eq!(directive.disposition, RuntimeDisposition::RequestDecision);
    assert_eq!(directive.reason_code, ReasonCode::UserDecisionRequired);
    assert!(directive.decision_request.is_some());
}

#[test]
fn pending_ask_owned_by_another_invocation_does_not_open_a_duplicate_dialog() {
    let root = std::env::temp_dir().join(format!(
        "arc_codex_pending_ask_{}_{}",
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(root.join(".codex")).unwrap();
    let failing_command = if cfg!(windows) {
        "powershell -NoProfile -Command \"'dirty'\""
    } else {
        "printf dirty"
    };
    let ir = serde_json::json!({
        "context": {"workdir": ".", "instructions_path": null, "instructions_content": null, "roles": {}},
        "skills": [],
        "lifecycle_guards": [{
            "id": "must_be_clean",
            "triggers": ["end"],
            "require": {"probe": {"command": failing_command, "expected_in": ["clean"]}},
            "on_failure": {"action": "ask", "feedback": "workspace remains dirty"},
            "order": 10
        }],
        "tool_guards": [],
        "rules": {}
    });
    let ir_path = root.join(".codex/arc_ir.json");
    fs::write(&ir_path, serde_json::to_vec_pretty(&ir).unwrap()).unwrap();
    trust_ir(&root, &ir_path);

    let state_path = root.join(".arc-test-state/runtime-state.sqlite3");
    let store = SqliteStateStore::open(&state_path).unwrap();
    let workspace_id = store
        .resolve_workspace_id(&root.canonicalize().unwrap())
        .unwrap();
    let key = GuardExecutionKey {
        workspace_id,
        session_id: "pending-session".into(),
        turn_id: Some("pending-turn".into()),
        guard_id: "must_be_clean".into(),
        activation: GuardActivation::SessionStop,
        subject_id: None,
    };
    let mut record = GuardExecutionRecord::new("pending-execution".into(), key, current_unix_ms());
    record.state = GuardExecutionState::AwaitingDecision;
    record.pending_decision = Some(DecisionRequest {
        decision_id: "pending-decision".into(),
        execution_id: "pending-execution".into(),
        owner_invocation_id: Some("original-owner".into()),
        choices: vec![DecisionChoice::Allow, DecisionChoice::Deny],
        required_actor: DecisionActor::User,
        expires_at_unix_ms: current_unix_ms() + 60_000,
    });
    record.revision = 1;
    assert_eq!(
        store.compare_and_swap(None, &record).unwrap(),
        WriteOutcome::Written
    );

    let output = run_codex_hook(
        &root,
        "stop",
        r#"{"hook_event_name":"Stop","session_id":"pending-session","turn_id":"pending-turn","stop_hook_active":false}"#,
    );

    assert_eq!(output["continue"], false);
    assert!(
        output["stopReason"]
            .as_str()
            .unwrap()
            .contains("already pending")
    );
    let connection = rusqlite::Connection::open(&state_path).unwrap();
    let degraded_count: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM observability_events
             WHERE event_type = 'CapabilityDegraded'
               AND guard_id = 'must_be_clean'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(degraded_count, 0);
    let _ = fs::remove_dir_all(&root);
}

fn current_unix_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

#[test]
fn continued_stop_re_evaluates_and_proceeds_after_real_remediation() {
    let root = std::env::temp_dir().join(format!(
        "arc_codex_stop_progress_{}_{}",
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(root.join(".codex")).unwrap();
    let command = if cfg!(windows) {
        "powershell -NoProfile -Command \"if (Test-Path clean.flag) { 'clean' } else { 'dirty' }\""
    } else {
        "sh -c 'if [ -f clean.flag ]; then printf clean; else printf dirty; fi'"
    };
    let ir = serde_json::json!({
        "context": {
            "workdir": ".",
            "instructions_path": null,
            "instructions_content": null,
            "roles": {}
        },
        "skills": [],
        "lifecycle_guards": [{
            "id": "must_be_clean",
            "triggers": ["end"],
            "require": {"probe": {"command": command, "expected_in": ["clean"]}},
            "on_failure": {"action": "deny", "feedback": "workspace remains dirty"},
            "order": 10
        }],
        "tool_guards": [],
        "rules": {}
    });
    fs::write(
        root.join(".codex/arc_ir.json"),
        serde_json::to_vec_pretty(&ir).unwrap(),
    )
    .unwrap();
    trust_ir(&root, &root.join(".codex/arc_ir.json"));

    let first = run_codex_hook(
        &root,
        "stop",
        r#"{"hook_event_name":"Stop","session_id":"progress","turn_id":"turn","stop_hook_active":false}"#,
    );
    assert_eq!(first["continue"], false);
    assert!(
        first["stopReason"]
            .as_str()
            .unwrap()
            .contains("workspace remains dirty")
    );

    fs::write(root.join("clean.flag"), "remediated").unwrap();
    let second = run_codex_hook(
        &root,
        "stop",
        r#"{"hook_event_name":"Stop","session_id":"progress","turn_id":"turn","stop_hook_active":true}"#,
    );
    assert_eq!(second, serde_json::json!({}));
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn dirty_git_workspace_never_satisfies_clean_completion_guard() {
    let root = std::env::temp_dir().join(format!(
        "arc_codex_dirty_git_{}_{}",
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(root.join(".codex")).unwrap();

    let git = |args: &[&str]| {
        let output = Command::new("git")
            .current_dir(&root)
            .args(args)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "git {:?} failed: {}",
            args,
            String::from_utf8_lossy(&output.stderr)
        );
    };
    git(&["init"]);
    git(&["config", "user.name", "Arc Test"]);
    git(&["config", "user.email", "arc-test@example.invalid"]);
    fs::write(root.join("tracked.txt"), "baseline\n").unwrap();
    git(&["add", "tracked.txt"]);
    git(&["commit", "-m", "baseline"]);
    fs::write(root.join("tracked.txt"), "staged\n").unwrap();
    git(&["add", "tracked.txt"]);
    fs::write(root.join("tracked.txt"), "staged and unstaged\n").unwrap();

    let command = if cfg!(windows) {
        "powershell -NoProfile -Command \"$status = git status --porcelain 2>$null; if (-not $status) { 'clean' } else { 'dirty' }\""
    } else {
        "bash -c \"if [ -z \\\"$(git status --porcelain 2>/dev/null)\\\" ]; then echo clean; else echo dirty; fi\""
    };
    let ir = serde_json::json!({
        "context": {"workdir": ".", "instructions_path": null, "instructions_content": null, "roles": {}},
        "skills": [],
        "lifecycle_guards": [{
            "id": "ensure_clean_completion",
            "triggers": ["end"],
            "require": {"probe": {"command": command, "expected_in": ["clean"]}},
            "on_failure": {"action": "deny", "feedback": "workspace remains dirty"},
            "order": 90
        }],
        "tool_guards": [],
        "rules": {}
    });
    fs::write(
        root.join(".codex/arc_ir.json"),
        serde_json::to_vec_pretty(&ir).unwrap(),
    )
    .unwrap();
    trust_ir(&root, &root.join(".codex/arc_ir.json"));

    let output = run_codex_hook(
        &root,
        "stop",
        &format!(
            r#"{{"hook_event_name":"Stop","session_id":"dirty-git","turn_id":"turn","cwd":{},"stop_hook_active":false}}"#,
            serde_json::to_string(&root).unwrap()
        ),
    );

    assert_eq!(output["continue"], false, "unexpected output: {output}");
    assert!(
        output["stopReason"]
            .as_str()
            .is_some_and(|reason| reason.contains("workspace remains dirty"))
    );
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn corrupt_persistent_stop_state_aborts_instead_of_looping() {
    let root = std::env::temp_dir().join(format!(
        "arc_codex_corrupt_state_{}_{}",
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(root.join(".codex")).unwrap();
    let command = if cfg!(windows) {
        "powershell -NoProfile -Command \"'dirty'\""
    } else {
        "printf dirty"
    };
    let ir = serde_json::json!({
        "context": {"workdir": ".", "instructions_path": null, "instructions_content": null, "roles": {}},
        "skills": [],
        "lifecycle_guards": [{
            "id": "must_be_clean",
            "triggers": ["end"],
            "require": {"probe": {"command": command, "expected_in": ["clean"]}},
            "on_failure": {"action": "deny", "feedback": "dirty"},
            "order": 10
        }],
        "tool_guards": [],
        "rules": {}
    });
    fs::write(
        root.join(".codex/arc_ir.json"),
        serde_json::to_vec_pretty(&ir).unwrap(),
    )
    .unwrap();
    trust_ir(&root, &root.join(".codex/arc_ir.json"));

    let first = run_codex_hook(
        &root,
        "stop",
        r#"{"hook_event_name":"Stop","session_id":"corrupt","turn_id":"turn","stop_hook_active":false}"#,
    );
    assert_eq!(first["continue"], false);
    assert!(first["stopReason"].as_str().unwrap().contains("dirty"));
    let database = root.join(".arc-test-state/runtime-state.sqlite3");
    let connection = rusqlite::Connection::open(database).unwrap();
    connection
        .execute("UPDATE guard_executions SET record_json = 'not-json'", [])
        .unwrap();
    drop(connection);

    let second = run_codex_hook(
        &root,
        "stop",
        r#"{"hook_event_name":"Stop","session_id":"corrupt","turn_id":"turn","stop_hook_active":true}"#,
    );
    assert_eq!(second["continue"], false);
    assert!(
        second["stopReason"]
            .as_str()
            .unwrap()
            .contains("ARC-HOOK-001")
    );
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn codex_stop_coordinates_violated_guard_not_subsequent_satisfied_guard() {
    let root = std::env::temp_dir().join(format!(
        "arc_codex_stop_multi_{}_{}",
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(root.join(".codex")).unwrap();

    let fail_command = if cfg!(windows) {
        "powershell -NoProfile -Command \"'dirty'\""
    } else {
        "printf dirty"
    };
    let pass_command = if cfg!(windows) {
        "powershell -NoProfile -Command \"'clean'\""
    } else {
        "printf clean"
    };

    let ir = serde_json::json!({
        "context": {"workdir": ".", "instructions_path": null, "instructions_content": null, "roles": {}},
        "skills": [],
        "lifecycle_guards": [
            {
                "id": "guard_1_violated",
                "triggers": ["end"],
                "require": {"probe": {"command": fail_command, "expected_in": ["clean"]}},
                "on_failure": {"action": "deny", "feedback": "guard 1 denied"},
                "order": 1
            },
            {
                "id": "guard_2_satisfied",
                "triggers": ["end"],
                "require": {"probe": {"command": pass_command, "expected_in": ["clean"]}},
                "on_failure": {"action": "deny", "feedback": "guard 2 denied"},
                "order": 2
            }
        ],
        "tool_guards": [],
        "rules": {}
    });
    fs::write(
        root.join(".codex/arc_ir.json"),
        serde_json::to_vec_pretty(&ir).unwrap(),
    )
    .unwrap();
    trust_ir(&root, &root.join(".codex/arc_ir.json"));

    let output = run_codex_hook(
        &root,
        "stop",
        r#"{"hook_event_name":"Stop","session_id":"stop-multi","turn_id":"turn-1","stop_hook_active":false}"#,
    );

    assert_eq!(output["continue"], false);
    assert!(
        output["stopReason"]
            .as_str()
            .unwrap()
            .contains("guard 1 denied")
    );

    // Verify in database that guard_1_violated was coordinated, NOT guard_2_satisfied!
    let database = root.join(".arc-test-state/runtime-state.sqlite3");
    let connection = rusqlite::Connection::open(database).unwrap();
    let mut stmt = connection
        .prepare("SELECT record_json FROM guard_executions")
        .unwrap();
    let coordinated_guards: Vec<String> = stmt
        .query_map([], |row| {
            let json: String = row.get(0)?;
            let record: arc::GuardExecutionRecord = serde_json::from_str(&json).unwrap();
            Ok(record.key.guard_id)
        })
        .unwrap()
        .map(|res| res.unwrap())
        .collect();

    assert!(
        coordinated_guards.contains(&"guard_1_violated".to_string()),
        "guard_1_violated must be coordinated: {coordinated_guards:?}"
    );
    assert!(
        !coordinated_guards.contains(&"guard_2_satisfied".to_string()),
        "guard_2_satisfied must NOT be coordinated as violated: {coordinated_guards:?}"
    );

    let _ = fs::remove_dir_all(&root);
}

fn run_agy_hook(cwd: &std::path::Path, event: &str, input: &str) -> serde_json::Value {
    let mut child = Command::new(env!("CARGO_BIN_EXE_arc"))
        .current_dir(cwd)
        .args(["hook", "run", "--event-type", event, "--provider", "gemini"])
        .env("ARC_STATE_DIR", cwd.join(".arc-test-state"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    eprintln!(
        "run_agy_hook stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

fn run_agy_hook_with_decision_ui(
    cwd: &std::path::Path,
    event: &str,
    input: &str,
    decision_ui: &str,
) -> serde_json::Value {
    run_hook_with_decision_ui_env(cwd, event, input, "gemini", decision_ui, &[])
}

fn run_codex_hook_with_env(
    cwd: &std::path::Path,
    event: &str,
    input: &str,
    envs: &[(&str, &std::ffi::OsStr)],
) -> serde_json::Value {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_arc"));
    cmd.current_dir(cwd)
        .args(["hook", "run", "--event-type", event, "--provider", "codex"])
        .env("ARC_STATE_DIR", cwd.join(".arc-test-state"));
    for (k, v) in envs {
        cmd.env(k, v);
    }
    let mut child = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

fn run_agy_hook_with_env(
    cwd: &std::path::Path,
    event: &str,
    input: &str,
    envs: &[(&str, &std::ffi::OsStr)],
) -> serde_json::Value {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_arc"));
    cmd.current_dir(cwd)
        .args(["hook", "run", "--event-type", event, "--provider", "gemini"])
        .env("ARC_STATE_DIR", cwd.join(".arc-test-state"));
    for (k, v) in envs {
        cmd.env(k, v);
    }
    let mut child = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

fn setup_fase4_cli_contract_root() -> std::path::PathBuf {
    let root = std::env::temp_dir().join(format!(
        "arc_fase4_cli_contract_{}_{}",
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(root.join(".codex")).unwrap();
    fs::create_dir_all(root.join(".agents")).unwrap();

    let fail_command = if cfg!(windows) {
        "powershell -NoProfile -Command \"'dirty'\""
    } else {
        "printf dirty"
    };
    let ir = serde_json::json!({
        "context": {"workdir": ".", "instructions_path": null, "instructions_content": null, "roles": {}},
        "skills": [],
        "lifecycle_guards": [
            {
                "id": "start_denied",
                "triggers": ["start"],
                "require": {"probe": {"command": fail_command, "expected_in": ["clean"]}},
                "on_failure": {"action": "deny", "feedback": "lifecycle start denied"},
                "order": 1
            },
            {
                "id": "end_denied",
                "triggers": ["end"],
                "require": {"probe": {"command": fail_command, "expected_in": ["clean"]}},
                "on_failure": {"action": "deny", "feedback": "lifecycle end denied"},
                "order": 2
            }
        ],
        "tool_guards": [
            {
                "id": "ask_tool",
                "matcher": {"exact_patterns": ["ask command"]},
                "require": {"probe": {"command": fail_command, "expected_in": ["clean"]}},
                "on_failure": {"action": "ask", "feedback": "tool confirmation required"},
                "order": 1
            },
            {
                "id": "deny_tool",
                "matcher": {"exact_patterns": ["deny command"]},
                "require": {"probe": {"command": fail_command, "expected_in": ["clean"]}},
                "on_failure": {"action": "deny", "feedback": "tool denied"},
                "order": 2
            },
            {
                "id": "authorization_tool",
                "matcher": {"exact_patterns": ["auth command"]},
                "require": {"decide": {"prompt": "authorize exact operation"}},
                "on_failure": {"action": "deny", "feedback": "authorization denied"},
                "order": 3
            }
        ],
        "rules": {}
    });
    let mut canonical_ir: arc::BehaviorIR =
        serde_json::from_value(ir).expect("Fase 4 contract fixture must deserialize");
    canonical_ir.content_hash = Some(canonical_ir.compute_content_hash());
    let encoded_ir = serde_json::to_vec_pretty(&canonical_ir)
        .expect("Fase 4 contract fixture must use generated IR serialization");
    let codex_ir = root.join(".codex/arc_ir.json");
    let agy_ir = root.join(".agents/arc_ir.json");
    fs::write(&codex_ir, &encoded_ir).unwrap();
    fs::write(&agy_ir, &encoded_ir).unwrap();
    trust_ir(&root, &codex_ir);
    trust_ir(&root, &agy_ir);
    root
}

fn setup_fase4_cli_runtime_fault_root() -> std::path::PathBuf {
    let root = std::env::temp_dir().join(format!(
        "arc_fase4_cli_runtime_fault_{}_{}",
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(root.join(".codex")).unwrap();
    fs::create_dir_all(root.join(".agents")).unwrap();

    let ir = serde_json::json!({
        "context": {"workdir": ".", "instructions_path": null, "instructions_content": null, "roles": {}},
        "skills": [],
        "lifecycle_guards": [{
            "id": "end_runtime_fault",
            "triggers": ["end"],
            "require": {"rule_ref": {"name": "fault_a"}},
            "on_failure": {"action": "deny", "feedback": "unreachable fault feedback"},
            "order": 1
        }],
        "tool_guards": [],
        "rules": {
            "fault_a": {"rule_ref": {"name": "fault_b"}},
            "fault_b": {"rule_ref": {"name": "fault_a"}}
        }
    });
    let encoded_ir = serde_json::to_vec_pretty(&ir).unwrap();
    let codex_ir = root.join(".codex/arc_ir.json");
    let agy_ir = root.join(".agents/arc_ir.json");
    fs::write(&codex_ir, &encoded_ir).unwrap();
    fs::write(&agy_ir, &encoded_ir).unwrap();
    trust_ir(&root, &codex_ir);
    trust_ir(&root, &agy_ir);
    root
}

fn compile_allow_decision_ui_host(root: &std::path::Path) -> std::path::PathBuf {
    let source_path = root.join("deterministic-decision-ui-host.rs");
    let host_path = root.join(if cfg!(windows) {
        "deterministic-decision-ui-host.exe"
    } else {
        "deterministic-decision-ui-host"
    });
    let source = r#"
use std::io::{self, Read};

fn field(input: &str, key: &str) -> String {
    let marker = format!("\"{}\":\"", key);
    let start = input
        .find(&marker)
        .unwrap_or_else(|| panic!("missing request field: {key}"))
        + marker.len();
    let remainder = &input[start..];
    let end = remainder
        .find('"')
        .unwrap_or_else(|| panic!("unterminated request field: {key}"));
    remainder[..end].to_owned()
}

fn main() {
    let mut input = String::new();
    io::stdin()
        .read_to_string(&mut input)
        .expect("read decision request");
    if let Some(path) = std::env::var_os("ARC_TEST_UI_REQUEST_LOG") {
        std::fs::write(path, &input).expect("write decision request log");
    }
    let decision = std::env::var("ARC_TEST_UI_DECISION").unwrap_or_else(|_| "allow".into());
    assert!(matches!(decision.as_str(), "allow" | "deny"));
    let request_id = field(&input, "request_id");
    let bundle_fingerprint = field(&input, "bundle_fingerprint");
    println!(
        "{{\"schema\":\"arc.decision.dialog.response.v2\",\"request_id\":\"{}\",\"bundle_fingerprint\":\"{}\",\"decision\":{{\"status\":\"{}\"}},\"transport\":\"arc_embedded_ui\",\"theme\":\"dark\",\"message\":\"aggregate test response\"}}",
        request_id, bundle_fingerprint, decision
    );
}
"#;
    fs::write(&source_path, source).expect("write deterministic decision UI host source");
    let output = Command::new("rustc")
        .args(["--edition=2024", "-O"])
        .arg(&source_path)
        .args(["-o"])
        .arg(&host_path)
        .output()
        .expect("rustc must be available for the deterministic UI host fixture");
    assert!(
        output.status.success(),
        "failed to compile deterministic UI host: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    host_path
}

fn compile_blocking_allow_decision_ui_host(root: &std::path::Path) -> std::path::PathBuf {
    let source_path = root.join("blocking-decision-ui-host.rs");
    let host_path = root.join(if cfg!(windows) {
        "blocking-decision-ui-host.exe"
    } else {
        "blocking-decision-ui-host"
    });
    let source = r#"
use std::io::{self, Read};
use std::path::PathBuf;

fn field(input: &str, key: &str) -> String {
    let marker = format!("\"{}\":\"", key);
    let start = input
        .find(&marker)
        .unwrap_or_else(|| panic!("missing request field: {key}"))
        + marker.len();
    let remainder = &input[start..];
    let end = remainder
        .find('"')
        .unwrap_or_else(|| panic!("unterminated request field: {key}"));
    remainder[..end].to_owned()
}

fn main() {
    let mut input = String::new();
    io::stdin()
        .read_to_string(&mut input)
        .expect("read decision request");
    let ready = PathBuf::from(
        std::env::var_os("ARC_TEST_UI_READY").expect("ARC_TEST_UI_READY must be set"),
    );
    let release = PathBuf::from(
        std::env::var_os("ARC_TEST_UI_RELEASE").expect("ARC_TEST_UI_RELEASE must be set"),
    );
    std::fs::write(ready, &input).expect("write decision UI readiness marker");
    while !release.exists() {
        std::thread::yield_now();
    }
    let request_id = field(&input, "request_id");
    let bundle_fingerprint = field(&input, "bundle_fingerprint");
    println!(
        "{{\"schema\":\"arc.decision.dialog.response.v2\",\"request_id\":\"{}\",\"bundle_fingerprint\":\"{}\",\"decision\":{{\"status\":\"allow\"}},\"transport\":\"arc_embedded_ui\",\"theme\":\"dark\",\"message\":\"aggregate test approved\"}}",
        request_id, bundle_fingerprint
    );
}
"#;
    fs::write(&source_path, source).expect("write blocking decision UI host source");
    let output = Command::new("rustc")
        .args(["--edition=2024", "-O"])
        .arg(&source_path)
        .args(["-o"])
        .arg(&host_path)
        .output()
        .expect("rustc must be available for the blocking UI host fixture");
    assert!(
        output.status.success(),
        "failed to compile blocking decision UI host: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    host_path
}

fn load_guard_execution_record(
    state_path: &std::path::Path,
    guard_id: &str,
) -> Option<arc::GuardExecutionRecord> {
    let connection = rusqlite::Connection::open(state_path).ok()?;
    let mut statement = connection
        .prepare("SELECT record_json FROM guard_executions")
        .ok()?;
    let records = statement
        .query_map([], |row| {
            let json: String = row.get(0)?;
            Ok(serde_json::from_str::<arc::GuardExecutionRecord>(&json).unwrap())
        })
        .ok()?;
    records
        .filter_map(Result::ok)
        .find(|record| record.key.guard_id == guard_id)
}

fn wait_for_pending_guard_execution(
    state_path: &std::path::Path,
    ready_path: &std::path::Path,
    guard_id: &str,
) -> arc::GuardExecutionRecord {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if ready_path.is_file()
            && let Some(record) = load_guard_execution_record(state_path, guard_id)
            && record.state == GuardExecutionState::AwaitingDecision
            && record.pending_decision.is_some()
        {
            return record;
        }
        assert!(
            Instant::now() < deadline,
            "runtime did not persist an AwaitingDecision before the controlled UI became ready"
        );
        std::thread::yield_now();
    }
}

#[test]
fn sqlite_lifecycle_aggregate_resolution_commits_every_ask_record() {
    let root = std::env::temp_dir().join(format!(
        "arc_lifecycle_aggregate_sqlite_{}_{}",
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).unwrap();
    let store = Arc::new(SqliteStateStore::open(&root.join("runtime-state.sqlite3")).unwrap());
    let coordinator = GuardExecutionCoordinator::new(store.clone());
    let make_key = |guard_id: &str| GuardExecutionKey {
        workspace_id: "workspace-aggregate".into(),
        session_id: "session-aggregate".into(),
        turn_id: Some("turn-aggregate".into()),
        guard_id: guard_id.into(),
        activation: GuardActivation::SessionStop,
        subject_id: None,
    };
    let make_input = |key: GuardExecutionKey| CoordinationInput {
        key,
        invocation_id: "aggregate-owner".into(),
        signals: ProviderSignals {
            reentry: ReentryKind::FirstInvocation,
            native_invocation_id: None,
            native_interaction_id: None,
        },
        evaluation: EvaluationSnapshot::Violated {
            feedback: Some("aggregate guard failed".into()),
        },
        violation_handling: ViolationHandling::RequireDecision,
    };
    let first_key = make_key("ask-sqlite-a");
    let second_key = make_key("ask-sqlite-b");
    let first = coordinator
        .coordinate(make_input(first_key.clone()))
        .unwrap();
    let second = coordinator
        .coordinate(make_input(second_key.clone()))
        .unwrap();
    let first_request = first.decision_request.clone().unwrap();
    let second_request = second.decision_request.clone().unwrap();
    let receipt = DecisionReceipt {
        decision_id: first_request.decision_id.clone(),
        execution_id: first_request.execution_id.clone(),
        selected_choice: DecisionChoice::Deny,
        actor: DecisionActor::User,
        provider: "codex".into(),
        received_at_unix_ms: 1,
        integrity: DecisionIntegrity {
            transport: "test".into(),
            native_interaction_id: None,
        },
    };

    let applied = coordinator
        .apply_aggregate_decision(
            &[first_key.clone(), second_key.clone()],
            "arc:lifecycle:sqlite-aggregate",
            "aggregate-decision",
            "aggregate-owner",
            &receipt,
        )
        .unwrap();
    assert_eq!(applied.len(), 2);
    assert!(
        applied
            .iter()
            .all(|directive| directive.disposition == RuntimeDisposition::Proceed)
    );
    for key in [&first_key, &second_key] {
        let record = store.load(key).unwrap().unwrap();
        assert_eq!(record.state, GuardExecutionState::Waived);
        assert!(record.pending_decision.is_none());
        assert!(
            record
                .processed_invocations
                .contains_key("aggregate-decision")
        );
    }
    assert_ne!(first_request.decision_id, second_request.decision_id);

    let connection = rusqlite::Connection::open(root.join("runtime-state.sqlite3")).unwrap();
    let details: String = connection
        .query_row(
            "SELECT details_json FROM aggregate_resolutions WHERE resolution_id = ?1",
            ["arc:lifecycle:sqlite-aggregate"],
            |row| row.get(0),
        )
        .unwrap();
    let details: serde_json::Value = serde_json::from_str(&details).unwrap();
    assert_eq!(details["targets"].as_array().unwrap().len(), 2);
    assert_eq!(
        connection
            .query_row("SELECT count(*) FROM aggregate_resolutions", [], |row| row
                .get::<_, i64>(
                0
            ),)
            .unwrap(),
        1
    );

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn test_fase4_presented_lifecycle_aggregate_preserves_message_for_codex_and_agy() {
    let root = std::env::temp_dir().join(format!(
        "arc_fase4_presented_aggregate_{}_{}",
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(root.join(".codex")).unwrap();
    fs::create_dir_all(root.join(".agents")).unwrap();

    let fail_command = if cfg!(windows) {
        "powershell -NoProfile -Command \"'dirty'\""
    } else {
        "printf dirty"
    };
    let ir = serde_json::json!({
        "context": {"workdir": ".", "instructions_path": null, "instructions_content": null, "roles": {}},
        "skills": [],
        "lifecycle_guards": [
            {
                "id": "presented_message",
                "triggers": ["end"],
                "require": {"probe": {"command": fail_command, "expected_in": ["clean"]}},
                "on_failure": {"action": "message", "feedback": "presented Message feedback"},
                "order": 1
            },
            {
                "id": "presented_ask_b",
                "triggers": ["end"],
                "require": {"probe": {"command": fail_command, "expected_in": ["clean"]}},
                "on_failure": {"action": "ask", "feedback": "presented Ask B feedback"},
                "order": 2
            },
            {
                "id": "presented_ask_a",
                "triggers": ["end"],
                "require": {"probe": {"command": fail_command, "expected_in": ["clean"]}},
                "on_failure": {"action": "ask", "feedback": "presented Ask A feedback"},
                "order": 3
            }
        ],
        "tool_guards": [],
        "rules": {}
    });
    let encoded_ir = serde_json::to_vec_pretty(&ir).unwrap();
    let codex_ir = root.join(".codex/arc_ir.json");
    let agy_ir = root.join(".agents/arc_ir.json");
    fs::write(&codex_ir, &encoded_ir).unwrap();
    fs::write(&agy_ir, &encoded_ir).unwrap();
    trust_ir(&root, &codex_ir);
    trust_ir(&root, &agy_ir);

    let decision_host = compile_allow_decision_ui_host(&root);
    let request_log = root.join("presented-request.json");
    let host_env = [
        ("ARC_DECISION_UI_HOST", decision_host.as_os_str()),
        ("ARC_TEST_UI_REQUEST_LOG", request_log.as_os_str()),
    ];
    let codex = run_hook_with_decision_ui_env(
        &root,
        "stop",
        r#"{"hook_event_name":"Stop","session_id":"presented-codex","turn_id":"turn-1","stop_hook_active":false}"#,
        "codex",
        "native",
        &host_env,
    );
    assert_eq!(codex["decision"], "block");
    let codex_reason = codex["reason"].as_str().unwrap();
    assert!(codex_reason.contains("presented Message feedback"));
    assert!(codex_reason.contains("presented Ask A feedback"));
    assert!(codex_reason.contains("presented Ask B feedback"));

    let agy = run_hook_with_decision_ui_env(
        &root,
        "stop",
        r#"{"conversation_id":"presented-agy","execution_num":1}"#,
        "gemini",
        "native",
        &host_env,
    );
    assert_eq!(agy["decision"], "continue");
    let agy_reason = agy["reason"].as_str().unwrap();
    assert!(agy_reason.contains("presented Message feedback"));
    assert!(agy_reason.contains("presented Ask A feedback"));
    assert!(agy_reason.contains("presented Ask B feedback"));

    let presented_request: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&request_log).unwrap()).unwrap();
    let presented_guard_ids = presented_request["violations"]
        .as_array()
        .unwrap()
        .iter()
        .map(|violation| violation["guard_id"].as_str().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(presented_guard_ids.len(), 2);
    assert!(presented_guard_ids.contains(&"presented_ask_a"));
    assert!(presented_guard_ids.contains(&"presented_ask_b"));
    assert!(!presented_guard_ids.contains(&"presented_message"));

    let connection =
        rusqlite::Connection::open(root.join(".arc-test-state/runtime-state.sqlite3")).unwrap();
    let mut records_stmt = connection
        .prepare("SELECT record_json FROM guard_executions")
        .unwrap();
    let records: Vec<arc::GuardExecutionRecord> = records_stmt
        .query_map([], |row| {
            let json: String = row.get(0)?;
            Ok(serde_json::from_str(&json).unwrap())
        })
        .unwrap()
        .map(|result| result.unwrap())
        .collect();
    for guard_id in ["presented_ask_a", "presented_ask_b"] {
        let record = records
            .iter()
            .find(|record| record.key.guard_id == guard_id)
            .unwrap_or_else(|| panic!("missing aggregate target {guard_id}"));
        assert_eq!(record.state, GuardExecutionState::RemediationInProgress);
        assert!(record.pending_decision.is_none());
        assert!(record.processed_invocations.values().any(|directive| {
            directive.disposition == RuntimeDisposition::ContinueForRemediation
        }));
    }

    let mut resolution_stmt = connection
        .prepare("SELECT details_json FROM aggregate_resolutions ORDER BY resolution_id")
        .unwrap();
    let resolutions: Vec<serde_json::Value> = resolution_stmt
        .query_map([], |row| {
            let details: String = row.get(0)?;
            Ok(serde_json::from_str(&details).unwrap())
        })
        .unwrap()
        .map(|result| result.unwrap())
        .collect();
    assert_eq!(resolutions.len(), 2);
    assert!(resolutions.iter().all(|resolution| {
        resolution["targets"]
            .as_array()
            .is_some_and(|targets| targets.len() == 2)
    }));

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn test_fase4_presented_tool_ask_preserves_message_for_codex_and_agy() {
    let root = std::env::temp_dir().join(format!(
        "arc_fase4_presented_tool_{}_{}",
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(root.join(".codex")).unwrap();
    fs::create_dir_all(root.join(".agents")).unwrap();

    let fail_command = if cfg!(windows) {
        "powershell -NoProfile -Command \"'dirty'\""
    } else {
        "printf dirty"
    };
    let ir = serde_json::json!({
        "context": {"workdir": ".", "instructions_path": null, "instructions_content": null, "roles": {}},
        "skills": [],
        "lifecycle_guards": [],
        "tool_guards": [
            {
                "id": "tool_message",
                "matcher": {"exact_patterns": ["echo tool"]},
                "require": {"probe": {"command": fail_command, "expected_in": ["clean"]}},
                "on_failure": {"action": "message", "feedback": "tool Message feedback"},
                "order": 1
            },
            {
                "id": "tool_ask",
                "matcher": {"exact_patterns": ["echo tool"]},
                "require": {"probe": {"command": fail_command, "expected_in": ["clean"]}},
                "on_failure": {"action": "ask", "feedback": "tool Ask feedback"},
                "order": 2
            }
        ],
        "rules": {}
    });
    let encoded_ir = serde_json::to_vec_pretty(&ir).unwrap();
    let codex_ir = root.join(".codex/arc_ir.json");
    let agy_ir = root.join(".agents/arc_ir.json");
    fs::write(&codex_ir, &encoded_ir).unwrap();
    fs::write(&agy_ir, &encoded_ir).unwrap();
    trust_ir(&root, &codex_ir);
    trust_ir(&root, &agy_ir);

    let decision_host = compile_allow_decision_ui_host(&root);
    let request_log = root.join("presented-tool-request.json");
    let host_env = [
        ("ARC_DECISION_UI_HOST", decision_host.as_os_str()),
        ("ARC_TEST_UI_REQUEST_LOG", request_log.as_os_str()),
    ];
    let codex = run_hook_with_decision_ui_env(
        &root,
        "pre-tool-use",
        r#"{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"echo tool"},"session_id":"tool-codex"}"#,
        "codex",
        "native",
        &host_env,
    );
    assert_eq!(codex["hookSpecificOutput"]["permissionDecision"], "allow");
    let codex_context = codex["hookSpecificOutput"]["additionalContext"]
        .as_str()
        .unwrap();
    assert!(codex_context.contains("Arc Message feedback: tool Message feedback"));

    let agy = run_hook_with_decision_ui_env(
        &root,
        "pre-tool-use",
        r#"{"toolCall":{"name":"execute_command","args":{"command":"echo tool"}},"conversation_id":"tool-agy"}"#,
        "gemini",
        "native",
        &host_env,
    );
    assert_eq!(agy["decision"], "allow");
    assert!(
        agy["reason"]
            .as_str()
            .unwrap()
            .contains("Arc Message feedback: tool Message feedback")
    );

    let presented_request: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&request_log).unwrap()).unwrap();
    let presented_guard_ids = presented_request["violations"]
        .as_array()
        .unwrap()
        .iter()
        .map(|violation| violation["guard_id"].as_str().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(presented_guard_ids, vec!["tool_ask"]);
    assert!(!presented_guard_ids.contains(&"tool_message"));

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn test_fase4_cli_json_tool_contract() {
    let root = setup_fase4_cli_contract_root();
    fs::create_dir_all(root.join(".codex/sessions")).unwrap();
    let transcript = root.join(".codex/sessions/fase4-auth.jsonl");
    fs::write(
        &transcript,
        "{\"type\":\"session_meta\",\"payload\":{\"id\":\"fase4-auth\"}}\n\
         {\"type\":\"response_item\",\"payload\":{\"type\":\"message\",\"role\":\"user\",\"content\":[{\"type\":\"input_text\",\"text\":\"Run the authorization contract test\"}]}}\n",
    )
    .unwrap();
    let decision_script = if cfg!(windows) {
        let path = root.join("fase4-decision.bat");
        fs::write(&path, "@echo {\"decision\": true}\r\n").unwrap();
        path
    } else {
        let path = root.join("fase4-decision.sh");
        fs::write(&path, "#!/bin/sh\necho '{\"decision\": true}'\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut permissions = fs::metadata(&path).unwrap().permissions();
            permissions.set_mode(0o755);
            fs::set_permissions(&path, permissions).unwrap();
        }
        path
    };

    // ToolCall Ask reaches the provider-native AGY UI contract.
    let agy_ask = run_agy_hook_with_decision_ui(
        &root,
        "pre-tool-use",
        r#"{"toolCall":{"name":"Bash","args":{"command":"ask command"}},"conversationId":"agy-ask"}"#,
        "provider",
    );
    assert_eq!(agy_ask["decision"], "force_ask");

    // ToolCall Continue without exact authorization is emitted directly without Ask.
    let agy_continue = run_agy_hook(
        &root,
        "pre-tool-use",
        r#"{"toolCall":{"name":"Bash","args":{"command":"safe command"}},"conversationId":"agy-continue"}"#,
    );
    assert_eq!(agy_continue["decision"], "allow");
    let codex_continue = run_codex_hook(
        &root,
        "pre-tool-use",
        r#"{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"safe command"},"session_id":"codex-continue"}"#,
    );
    assert_eq!(codex_continue, serde_json::json!({}));

    // ToolCall Deny is preventive for both provider JSON contracts.
    let agy_deny = run_agy_hook(
        &root,
        "pre-tool-use",
        r#"{"toolCall":{"name":"Bash","args":{"command":"deny command"}},"conversationId":"agy-deny"}"#,
    );
    assert_eq!(agy_deny["decision"], "deny");
    let codex_deny = run_codex_hook(
        &root,
        "pre-tool-use",
        r#"{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"deny command"},"session_id":"codex-deny"}"#,
    );
    assert_eq!(
        codex_deny["hookSpecificOutput"]["permissionDecision"],
        "deny"
    );

    // A positive semantic authorization remains Continue in the aggregate, but
    // the current operation must wait for an exact Allow/Deny decision.
    let decision_host = compile_allow_decision_ui_host(&root);
    let request_log = root.join("exact-authorization-request.json");
    let codex_authorization_input = serde_json::json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "auth command"},
        "session_id": "fase4-auth",
        "tool_use_id": "auth-allow-1",
        "transcript_path": transcript.to_string_lossy(),
    });
    let codex_allow_env = [
        ("ARC_DECISION_UI_HOST", decision_host.as_os_str()),
        ("ARC_TEST_UI_REQUEST_LOG", request_log.as_os_str()),
        ("ARC_LLM_CLI", decision_script.as_os_str()),
        ("CODEX_HOME", root.as_os_str()),
    ];
    let codex_authorization = run_hook_with_decision_ui_env(
        &root,
        "pre-tool-use",
        &codex_authorization_input.to_string(),
        "codex",
        "native",
        &codex_allow_env,
    );
    assert_eq!(
        codex_authorization["hookSpecificOutput"]["permissionDecision"], "allow",
        "Codex must wait for and apply the embedded Allow decision"
    );
    let request: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&request_log).unwrap()).unwrap();
    assert_eq!(
        request["presentation_kind"],
        "exact_operation_authorization"
    );
    assert_eq!(request["authorizations"].as_array().unwrap().len(), 1);
    assert_eq!(
        request["authorizations"][0]["guard_id"],
        "authorization_tool"
    );
    assert!(
        request["operation"]
            .as_str()
            .unwrap()
            .contains("auth command")
    );

    // Deny is also an explicit UI response and must prevent provider execution.
    let deny_value = std::ffi::OsStr::new("deny");
    let codex_deny_env = [
        ("ARC_DECISION_UI_HOST", decision_host.as_os_str()),
        ("ARC_TEST_UI_REQUEST_LOG", request_log.as_os_str()),
        ("ARC_TEST_UI_DECISION", deny_value),
        ("ARC_LLM_CLI", decision_script.as_os_str()),
        ("CODEX_HOME", root.as_os_str()),
    ];
    let codex_deny_transcript = root.join(".codex/sessions/fase4-auth-deny.jsonl");
    fs::write(
        &codex_deny_transcript,
        "{\"type\":\"session_meta\",\"payload\":{\"id\":\"fase4-auth-deny\"}}\n\
         {\"type\":\"response_item\",\"payload\":{\"type\":\"message\",\"role\":\"user\",\"content\":[{\"type\":\"input_text\",\"text\":\"Run the authorization contract test\"}]}}\n",
    )
    .unwrap();
    let codex_deny_input = serde_json::json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "auth command"},
        "session_id": "fase4-auth-deny",
        "tool_use_id": "auth-deny-1",
        "transcript_path": codex_deny_transcript.to_string_lossy(),
    });
    let codex_denied = run_hook_with_decision_ui_env(
        &root,
        "pre-tool-use",
        &codex_deny_input.to_string(),
        "codex",
        "native",
        &codex_deny_env,
    );
    assert_eq!(
        codex_denied["hookSpecificOutput"]["permissionDecision"],
        "deny"
    );

    let agy_session_root = root.join(".gemini/antigravity/brain/agy-auth");
    fs::create_dir_all(&agy_session_root).unwrap();
    let agy_transcript = agy_session_root.join("transcript.jsonl");
    fs::write(
        &agy_transcript,
        "{\"type\":\"USER_INPUT\",\"content\":\"Run the authorization contract test\"}\n",
    )
    .unwrap();
    let agy_authorization_input = serde_json::json!({
        "toolCall": {"name": "Bash", "args": {"command": "auth command"}},
        "conversationId": "agy-auth",
        "transcriptPath": agy_transcript,
    });
    let agy_allow_env = [
        ("ARC_DECISION_UI_HOST", decision_host.as_os_str()),
        ("ARC_TEST_UI_REQUEST_LOG", request_log.as_os_str()),
        ("ARC_LLM_CLI", decision_script.as_os_str()),
        ("CODEX_HOME", root.as_os_str()),
        ("USERPROFILE", root.as_os_str()),
        ("HOME", root.as_os_str()),
    ];
    let agy_authorization = run_hook_with_decision_ui_env(
        &root,
        "pre-tool-use",
        &agy_authorization_input.to_string(),
        "gemini",
        "native",
        &agy_allow_env,
    );
    assert_eq!(
        agy_authorization["decision"], "allow",
        "Gemini must wait for and apply the embedded Allow decision: {agy_authorization}"
    );
    let request: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&request_log).unwrap()).unwrap();
    assert_eq!(
        request["presentation_kind"],
        "exact_operation_authorization"
    );
    assert_eq!(request["authorizations"].as_array().unwrap().len(), 1);
    assert_eq!(
        request["authorizations"][0]["guard_id"],
        "authorization_tool"
    );

    let agy_session_root = root.join(".gemini/antigravity/brain/agy-deny");
    fs::create_dir_all(&agy_session_root).unwrap();
    let agy_deny_transcript = agy_session_root.join("transcript.jsonl");
    fs::write(
        &agy_deny_transcript,
        "{\"type\":\"USER_INPUT\",\"content\":\"Run the authorization contract test\"}\n",
    )
    .unwrap();
    let agy_deny_input = serde_json::json!({
        "toolCall": {"name": "Bash", "args": {"command": "auth command"}},
        "conversationId": "agy-deny",
        "transcriptPath": agy_deny_transcript,
    });
    let agy_deny_env = [
        ("ARC_DECISION_UI_HOST", decision_host.as_os_str()),
        ("ARC_TEST_UI_REQUEST_LOG", request_log.as_os_str()),
        ("ARC_TEST_UI_DECISION", deny_value),
        ("ARC_LLM_CLI", decision_script.as_os_str()),
        ("CODEX_HOME", root.as_os_str()),
        ("USERPROFILE", root.as_os_str()),
        ("HOME", root.as_os_str()),
    ];
    let agy_denied = run_hook_with_decision_ui_env(
        &root,
        "pre-tool-use",
        &agy_deny_input.to_string(),
        "gemini",
        "native",
        &agy_deny_env,
    );
    assert_eq!(agy_denied["decision"], "deny");

    let state_path = root.join(".arc-test-state/runtime-state.sqlite3");
    let connection = rusqlite::Connection::open(&state_path).unwrap();
    for session_id in ["fase4-auth", "agy-auth"] {
        let count: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM exact_operation_authorizations WHERE session_id = ?1",
                [session_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 1, "Allow must record its exact current-call receipt");
        let remaining_uses: i64 = connection
            .query_row(
                "SELECT MAX(uses_remaining) FROM exact_operation_authorizations WHERE session_id = ?1",
                [session_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            remaining_uses, 0,
            "Allow must not create a future reusable grant"
        );
    }
    for session_id in ["fase4-auth-deny", "agy-deny"] {
        let count: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM exact_operation_authorizations WHERE session_id = ?1",
                [session_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 0, "Deny must not persist an authorization grant");
    }

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn test_fase4_cli_json_lifecycle_deny_is_terminal() {
    let root = setup_fase4_cli_contract_root();

    // Lifecycle Deny is terminal: AGY Start/End and Codex Start/End all emit
    // termination JSON and never request a remediation continuation.
    let agy_start = run_agy_hook(
        &root,
        "pre-invocation",
        r#"{"invocationNum":1,"conversationId":"agy-start"}"#,
    );
    assert_eq!(agy_start["decision"], "abort");
    let agy_end = run_agy_hook(
        &root,
        "stop",
        r#"{"conversationId":"agy-end","executionNum":1}"#,
    );
    assert_eq!(agy_end["decision"], "stop");

    let codex_start = run_codex_hook(
        &root,
        "session-start",
        r#"{"hook_event_name":"SessionStart","session_id":"codex-start","cwd":"."}"#,
    );
    assert_eq!(codex_start["continue"], false);
    let codex_end = run_codex_hook(
        &root,
        "stop",
        r#"{"hook_event_name":"Stop","session_id":"codex-end","turn_id":"turn-1","stop_hook_active":false}"#,
    );
    assert_eq!(codex_end["continue"], false);

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn test_fase4_cli_json_lifecycle_runtime_fault_is_terminal() {
    let root = setup_fase4_cli_runtime_fault_root();

    let agy_end = run_agy_hook(
        &root,
        "stop",
        r#"{"conversationId":"agy-runtime-fault","executionNum":1}"#,
    );
    assert_eq!(agy_end["decision"], "stop");
    assert_ne!(agy_end["decision"], "continue");
    assert!(
        agy_end["reason"]
            .as_str()
            .unwrap()
            .contains("[ARC PROBE ERROR]")
    );

    let codex_end = run_codex_hook(
        &root,
        "stop",
        r#"{"hook_event_name":"Stop","session_id":"codex-runtime-fault","turn_id":"turn-1","stop_hook_active":false}"#,
    );
    assert_eq!(codex_end["continue"], false);
    assert!(
        codex_end["stopReason"]
            .as_str()
            .unwrap()
            .contains("[ARC PROBE ERROR]")
    );

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn test_fase4_cli_json_lifecycle_deny_and_runtime_fault_are_terminal_without_ui() {
    let root = std::env::temp_dir().join(format!(
        "arc_fase4_deny_runtime_fault_{}_{}",
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(root.join(".codex")).unwrap();
    fs::create_dir_all(root.join(".agents")).unwrap();

    let fail_command = if cfg!(windows) {
        "powershell -NoProfile -Command \"'dirty'\""
    } else {
        "printf dirty"
    };
    let ir = serde_json::json!({
        "context": {"workdir": ".", "instructions_path": null, "instructions_content": null, "roles": {}},
        "skills": [],
        "lifecycle_guards": [
            {
                "id": "combined_deny",
                "triggers": ["end"],
                "require": {"probe": {"command": fail_command, "expected_in": ["clean"]}},
                "on_failure": {"action": "deny", "feedback": "combined Deny feedback"},
                "order": 1
            },
            {
                "id": "combined_fault",
                "triggers": ["end"],
                "require": {"rule_ref": {"name": "fault_a"}},
                "on_failure": {"action": "deny", "feedback": "fault guard feedback"},
                "order": 2
            }
        ],
        "tool_guards": [],
        "rules": {
            "fault_a": {"rule_ref": {"name": "fault_b"}},
            "fault_b": {"rule_ref": {"name": "fault_a"}}
        }
    });
    let encoded_ir = serde_json::to_vec_pretty(&ir).unwrap();
    let codex_ir = root.join(".codex/arc_ir.json");
    let agy_ir = root.join(".agents/arc_ir.json");
    fs::write(&codex_ir, &encoded_ir).unwrap();
    fs::write(&agy_ir, &encoded_ir).unwrap();
    trust_ir(&root, &codex_ir);
    trust_ir(&root, &agy_ir);

    let decision_host = compile_allow_decision_ui_host(&root);
    let request_log = root.join("must-not-present.json");
    let host_env = [
        ("ARC_DECISION_UI_HOST", decision_host.as_os_str()),
        ("ARC_TEST_UI_REQUEST_LOG", request_log.as_os_str()),
    ];
    let codex = run_hook_with_decision_ui_env(
        &root,
        "stop",
        r#"{"hook_event_name":"Stop","session_id":"combined-codex","turn_id":"turn-1"}"#,
        "codex",
        "native",
        &host_env,
    );
    assert_eq!(codex["continue"], false);
    let codex_reason = codex["stopReason"].as_str().unwrap();
    assert!(codex_reason.contains("[ARC PROBE ERROR]"));
    assert!(codex_reason.contains("combined Deny feedback"));

    let agy = run_hook_with_decision_ui_env(
        &root,
        "stop",
        r#"{"conversation_id":"combined-agy","execution_num":1}"#,
        "gemini",
        "native",
        &host_env,
    );
    assert_eq!(agy["decision"], "stop");
    let agy_reason = agy["reason"].as_str().unwrap();
    assert!(agy_reason.contains("[ARC PROBE ERROR]"));
    assert!(agy_reason.contains("combined Deny feedback"));
    assert!(!request_log.exists(), "terminal latch must suppress the UI");

    let connection =
        rusqlite::Connection::open(root.join(".arc-test-state/runtime-state.sqlite3")).unwrap();
    let mut records_stmt = connection
        .prepare("SELECT record_json FROM guard_executions")
        .unwrap();
    let records: Vec<arc::GuardExecutionRecord> = records_stmt
        .query_map([], |row| {
            let json: String = row.get(0)?;
            Ok(serde_json::from_str(&json).unwrap())
        })
        .unwrap()
        .map(|result| result.unwrap())
        .collect();
    assert_eq!(records.len(), 4);
    assert!(
        records
            .iter()
            .all(|record| record.pending_decision.is_none())
    );
    let aggregate_count: i64 = connection
        .query_row("SELECT count(*) FROM aggregate_resolutions", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(aggregate_count, 0);

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn test_fase4_observable_lifecycle_sequence_feedback_cache_release_output() {
    let root = std::env::temp_dir().join(format!(
        "arc_fase3_sequence_{}_{}",
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(root.join(".codex")).unwrap();

    let fail_command = if cfg!(windows) {
        "powershell -NoProfile -Command \"'dirty'\""
    } else {
        "printf dirty"
    };

    let ir = serde_json::json!({
        "context": {"workdir": ".", "instructions_path": null, "instructions_content": null, "roles": {}},
        "skills": [],
        "lifecycle_guards": [
            {
                "id": "must_be_clean",
                "triggers": ["end"],
                "require": {"probe": {"command": fail_command, "expected_in": ["clean"]}},
                "on_failure": {"action": "deny", "feedback": "workspace dirty"},
                "order": 1
            }
        ],
        "tool_guards": [],
        "rules": {}
    });
    fs::write(
        root.join(".codex/arc_ir.json"),
        serde_json::to_vec_pretty(&ir).unwrap(),
    )
    .unwrap();
    trust_ir(&root, &root.join(".codex/arc_ir.json"));

    let output = run_codex_hook(
        &root,
        "stop",
        r#"{"hook_event_name":"Stop","session_id":"s-fase3","turn_id":"t-fase3","stop_hook_active":false}"#,
    );
    assert_eq!(output["continue"], false);

    let database = root.join(".arc-test-state/runtime-state.sqlite3");
    let connection = rusqlite::Connection::open(database).unwrap();
    let mut stmt = connection
        .prepare("SELECT id, event_type, details_json FROM observability_events ORDER BY id ASC")
        .unwrap();
    let events: Vec<(i64, String, String)> = stmt
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
        .unwrap()
        .map(|res| res.unwrap())
        .collect();

    let feedback_entry = events
        .iter()
        .find(|(_, event_type, _)| event_type == "ProviderFeedbackPrepared")
        .expect("ProviderFeedbackPrepared must be logged in observability");
    let cache_entry = events
        .iter()
        .find(|(_, event_type, _)| event_type == "ActivationEvaluationCacheDropped")
        .expect("ActivationEvaluationCacheDropped must be logged in observability");
    let output_entry = events
        .iter()
        .find(|(_, event_type, _)| event_type == "ProviderOutput")
        .expect("ProviderOutput must be logged in observability");

    // Strict chronological ordering: Feedback -> Cache Dropped -> Output
    assert!(
        feedback_entry.0 < cache_entry.0,
        "ProviderFeedbackPrepared (id={}) must precede ActivationEvaluationCacheDropped (id={})",
        feedback_entry.0,
        cache_entry.0
    );
    assert!(
        cache_entry.0 < output_entry.0,
        "ActivationEvaluationCacheDropped (id={}) must precede ProviderOutput (id={})",
        cache_entry.0,
        output_entry.0
    );

    // Verify feedback details contains bundle_fingerprint and cache_active: true
    let details: serde_json::Value = serde_json::from_str(&feedback_entry.2).unwrap();
    assert!(
        details.get("bundle_fingerprint").is_some(),
        "bundle_fingerprint must be present"
    );
    assert_eq!(details["failed_guards"], 1);
    assert_eq!(
        details["cache_active"], true,
        "ProviderFeedbackPrepared must record cache_active: true before cache is dropped"
    );

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn test_fase3_stop_coordination_mixed_deny_and_ask_precedence_and_bundle_feedback() {
    let root = std::env::temp_dir().join(format!(
        "arc_fase3_stop_mixed_{}_{}",
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(root.join(".codex")).unwrap();

    let fail_command = if cfg!(windows) {
        "powershell -NoProfile -Command \"'dirty'\""
    } else {
        "printf dirty"
    };

    let ir = serde_json::json!({
        "context": {"workdir": ".", "instructions_path": null, "instructions_content": null, "roles": {}},
        "skills": [],
        "lifecycle_guards": [
            {
                "id": "deny_guard",
                "triggers": ["end"],
                "require": {"probe": {"command": fail_command, "expected_in": ["clean"]}},
                "on_failure": {"action": "deny", "feedback": "deny: clean workspace required"},
                "order": 1
            },
            {
                "id": "ask_guard",
                "triggers": ["end"],
                "require": {"probe": {"command": fail_command, "expected_in": ["clean"]}},
                "on_failure": {"action": "ask", "feedback": "ask: user approval required"},
                "order": 2
            }
        ],
        "tool_guards": [],
        "rules": {}
    });
    let mut ir: arc::ir::BehaviorIR =
        serde_json::from_value(ir).expect("deserialize canonical BehaviorIR fixture");
    ir.content_hash = Some(ir.compute_content_hash());
    let ir_bytes = serde_json::to_vec_pretty(&ir).expect("serialize canonical BehaviorIR fixture");
    fs::write(root.join(".codex/arc_ir.json"), ir_bytes).unwrap();
    trust_ir(&root, &root.join(".codex/arc_ir.json"));

    // First invocation: deny_guard is terminal; ask_guard is still evaluated
    // and retained in the aggregate failure bundle.
    let output1 = run_codex_hook(
        &root,
        "stop",
        r#"{"hook_event_name":"Stop","session_id":"stop-mixed","turn_id":"turn-1","stop_hook_active":false}"#,
    );
    assert_eq!(output1["continue"], false);
    let reason1 = output1["stopReason"].as_str().unwrap();
    assert!(
        reason1.contains("deny: clean workspace required"),
        "Must contain deny feedback: {reason1}"
    );
    assert!(
        reason1.contains("ask: user approval required"),
        "Must contain ask feedback from FailureBundle: {reason1}"
    );

    // Both guards coordinated in SQLite
    let database = root.join(".arc-test-state/runtime-state.sqlite3");
    let connection = rusqlite::Connection::open(database).unwrap();
    let mut stmt = connection
        .prepare("SELECT record_json FROM guard_executions")
        .unwrap();
    let records: Vec<arc::GuardExecutionRecord> = stmt
        .query_map([], |row| {
            let json: String = row.get(0)?;
            let record: arc::GuardExecutionRecord = serde_json::from_str(&json).unwrap();
            Ok(record)
        })
        .unwrap()
        .map(|res| res.unwrap())
        .collect();

    let deny_record = records.iter().find(|r| r.key.guard_id == "deny_guard");
    let ask_record = records.iter().find(|r| r.key.guard_id == "ask_guard");
    assert!(
        deny_record.is_some(),
        "deny_guard must be coordinated in SQLite"
    );
    assert!(
        ask_record.is_some(),
        "ask_guard must be coordinated in SQLite"
    );
    assert!(
        deny_record
            .expect("deny_guard record was just checked")
            .pending_decision
            .is_none(),
        "terminal Deny must not leave a pending decision"
    );
    assert!(
        ask_record
            .expect("ask_guard record was just checked")
            .pending_decision
            .is_none(),
        "terminal Deny latch must cancel the Ask pending decision"
    );

    // Second invocation remains terminal; Deny never becomes a remediation
    // continuation or a duplicate decision dialog.
    let output2 = run_codex_hook(
        &root,
        "stop",
        r#"{"hook_event_name":"Stop","session_id":"stop-mixed","turn_id":"turn-1","stop_hook_active":true}"#,
    );
    assert_eq!(output2["continue"], false);
    let reason2 = output2["stopReason"].as_str().unwrap();
    assert!(reason2.contains("deny: clean workspace required"));

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn test_fase4_agy_hook_pre_tool_use_and_stop_lifecycle_cli() {
    let root = std::env::temp_dir().join(format!(
        "arc_fase3_agy_lifecycle_{}_{}",
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(root.join(".agents")).unwrap();

    let fail_command = if cfg!(windows) {
        "powershell -NoProfile -Command \"'dirty'\""
    } else {
        "printf dirty"
    };

    let ir = serde_json::json!({
        "context": {"workdir": ".", "instructions_path": null, "instructions_content": null, "roles": {}},
        "skills": [],
        "lifecycle_guards": [
            {
                "id": "agy_stop_deny",
                "triggers": ["end"],
                "require": {"probe": {"command": fail_command, "expected_in": ["clean"]}},
                "on_failure": {"action": "deny", "feedback": "AGY end check failed: dirty"},
                "order": 1
            }
        ],
        "tool_guards": [
            {
                "id": "agy_tool_deny",
                "matcher": {
                    "regex_patterns": [".*rm -rf.*"]
                },
                "require": {"probe": {"command": fail_command, "expected_in": ["clean"]}},
                "on_failure": {"action": "deny", "feedback": "Destructive rm command blocked"},
                "order": 1
            }
        ],
        "rules": {}
    });
    fs::write(
        root.join(".agents/arc_ir.json"),
        serde_json::to_vec_pretty(&ir).unwrap(),
    )
    .unwrap();
    trust_ir(&root, &root.join(".agents/arc_ir.json"));

    // 1. Test PreToolUse hook for AGY
    let pre_output = run_agy_hook(
        &root,
        "pre-tool-use",
        r#"{"toolCall":{"name":"execute_command","args":{"command":"rm -rf /tmp/test"}},"session_id":"agy-sess-1"}"#,
    );
    assert_eq!(pre_output["decision"], "deny");
    let pre_reason = pre_output["reason"].as_str().unwrap();
    assert!(
        pre_reason.contains("Destructive rm command blocked"),
        "pre_reason: {pre_reason}"
    );

    // 2. Test Stop hook for AGY
    let stop_output = run_agy_hook(&root, "stop", r#"{"conversation_id":"agy-sess-1"}"#);
    assert_eq!(stop_output["decision"], "stop");
    let stop_reason = stop_output["reason"].as_str().unwrap();
    assert!(
        stop_reason.contains("AGY end check failed: dirty"),
        "stop_reason: {stop_reason}"
    );

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn test_fase4_agy_stop_coordination_aggregate_and_ask_lifecycle() {
    let root = std::env::temp_dir().join(format!(
        "arc_fase3_agy_stop_coord_{}_{}",
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(root.join(".agents")).unwrap();

    let fail_command = if cfg!(windows) {
        "powershell -NoProfile -Command \"'dirty'\""
    } else {
        "printf dirty"
    };

    let ir = serde_json::json!({
        "context": {"workdir": ".", "instructions_path": null, "instructions_content": null, "roles": {}},
        "skills": [],
        "lifecycle_guards": [
            {
                "id": "agy_deny_guard",
                "triggers": ["end"],
                "require": {"probe": {"command": fail_command, "expected_in": ["clean"]}},
                "on_failure": {"action": "deny", "feedback": "AGY deny: workspace is dirty"},
                "order": 1
            },
            {
                "id": "agy_ask_guard",
                "triggers": ["end"],
                "require": {"probe": {"command": fail_command, "expected_in": ["clean"]}},
                "on_failure": {"action": "ask", "feedback": "AGY ask: operator approval required"},
                "order": 2
            }
        ],
        "tool_guards": [],
        "rules": {}
    });
    fs::write(
        root.join(".agents/arc_ir.json"),
        serde_json::to_vec_pretty(&ir).unwrap(),
    )
    .unwrap();
    trust_ir(&root, &root.join(".agents/arc_ir.json"));

    // AGY Stop hook invocation:
    // Both guards evaluate and fail.
    // The shared lifecycle coordinator executes each guard through SQLite.
    // Deny wins over Ask as a terminal lifecycle disposition without bypassing
    // SQLite coordination or dropping aggregate feedback.
    let stop_output = run_agy_hook(
        &root,
        "stop",
        r#"{"conversation_id":"agy-stop-session","execution_num":1}"#,
    );
    assert_eq!(stop_output["decision"], "stop");
    let stop_reason = stop_output["reason"].as_str().unwrap();
    assert!(
        stop_reason.contains("AGY deny: workspace is dirty"),
        "Must contain deny feedback: {stop_reason}"
    );
    assert!(
        stop_reason.contains("AGY ask: operator approval required"),
        "Must contain ask feedback from FailureBundle: {stop_reason}"
    );

    // Verify both guards are recorded in SQLite
    let database = root.join(".arc-test-state/runtime-state.sqlite3");
    let connection = rusqlite::Connection::open(database).unwrap();
    let mut stmt = connection
        .prepare("SELECT record_json FROM guard_executions")
        .unwrap();
    let coordinated_guards: Vec<String> = stmt
        .query_map([], |row| {
            let json: String = row.get(0)?;
            let record: arc::GuardExecutionRecord = serde_json::from_str(&json).unwrap();
            Ok(record.key.guard_id)
        })
        .unwrap()
        .map(|res| res.unwrap())
        .collect();
    assert!(
        coordinated_guards.contains(&"agy_deny_guard".to_string()),
        "agy_deny_guard must be coordinated in SQLite"
    );
    assert!(
        coordinated_guards.contains(&"agy_ask_guard".to_string()),
        "agy_ask_guard must be coordinated in SQLite"
    );
    let mut records_stmt = connection
        .prepare("SELECT record_json FROM guard_executions")
        .unwrap();
    let records: Vec<arc::GuardExecutionRecord> = records_stmt
        .query_map([], |row| {
            let json: String = row.get(0)?;
            Ok(serde_json::from_str(&json).unwrap())
        })
        .unwrap()
        .map(|res| res.unwrap())
        .collect();
    assert!(
        records
            .iter()
            .all(|record| record.pending_decision.is_none()),
        "terminal Deny latch must leave no pending lifecycle decisions"
    );

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn test_fase4_cli_message_and_ask_preserve_feedback_and_fail_closed_without_transport() {
    let root = std::env::temp_dir().join(format!(
        "arc_fase4_message_ask_cli_{}_{}",
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(root.join(".codex")).unwrap();
    fs::create_dir_all(root.join(".agents")).unwrap();

    let fail_command = if cfg!(windows) {
        "powershell -NoProfile -Command \"'dirty'\""
    } else {
        "printf dirty"
    };
    let ir = serde_json::json!({
        "context": {"workdir": ".", "instructions_path": null, "instructions_content": null, "roles": {}},
        "skills": [],
        "lifecycle_guards": [
            {
                "id": "message_guard",
                "triggers": ["end"],
                "require": {"probe": {"command": fail_command, "expected_in": ["clean"]}},
                "on_failure": {"action": "message", "feedback": "message: workspace is dirty"},
                "order": 1
            },
            {
                "id": "ask_guard",
                "triggers": ["end"],
                "require": {"probe": {"command": fail_command, "expected_in": ["clean"]}},
                "on_failure": {"action": "ask", "feedback": "ask: operator approval required"},
                "order": 2
            }
        ],
        "tool_guards": [],
        "rules": {}
    });
    for provider_dir in [".codex", ".agents"] {
        let ir_path = root.join(provider_dir).join("arc_ir.json");
        fs::write(&ir_path, serde_json::to_vec_pretty(&ir).unwrap()).unwrap();
        trust_ir(&root, &ir_path);
    }

    let codex = run_codex_hook_with_decision_ui(
        &root,
        "stop",
        r#"{"hook_event_name":"Stop","session_id":"message-ask-codex","turn_id":"turn-1"}"#,
        "provider",
    );
    assert_eq!(codex["continue"], false);
    assert!(codex.get("decision").is_none());
    let codex_reason = codex["stopReason"].as_str().unwrap();
    assert!(codex_reason.contains("message: workspace is dirty"));
    assert!(codex_reason.contains("ask: operator approval required"));

    let agy = run_agy_hook_with_decision_ui(
        &root,
        "stop",
        r#"{"hook_event_name":"Stop","conversation_id":"message-ask-agy","execution_num":1}"#,
        "provider",
    );
    assert_eq!(agy["decision"], "stop");
    let agy_reason = agy["reason"].as_str().unwrap();
    assert!(agy_reason.contains("message: workspace is dirty"));
    assert!(agy_reason.contains("ask: operator approval required"));

    let connection =
        rusqlite::Connection::open(root.join(".arc-test-state/runtime-state.sqlite3")).unwrap();
    let mut stmt = connection
        .prepare("SELECT record_json FROM guard_executions")
        .unwrap();
    let records: Vec<arc::GuardExecutionRecord> = stmt
        .query_map([], |row| {
            let json: String = row.get(0)?;
            Ok(serde_json::from_str(&json).unwrap())
        })
        .unwrap()
        .map(|res| res.unwrap())
        .collect();
    assert_eq!(
        records.len(),
        4,
        "both providers must coordinate both Guards"
    );
    assert!(
        records
            .iter()
            .all(|record| record.pending_decision.is_none()),
        "unsupported lifecycle Ask must leave no pending decision"
    );

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn test_fase3_agy_stop_coordination_ask_winning_lifecycle_and_reentry_duplicate_refusal() {
    let root = std::env::temp_dir().join(format!(
        "arc_fase3_agy_ask_win_{}_{}",
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(root.join(".agents")).unwrap();

    let fail_command = if cfg!(windows) {
        "powershell -NoProfile -Command \"'dirty'\""
    } else {
        "printf dirty"
    };
    let ir = serde_json::json!({
        "context": {"workdir": ".", "instructions_path": null, "instructions_content": null, "roles": {}},
        "skills": [],
        "lifecycle_guards": [
            {
                "id": "agy_ask_only_guard",
                "triggers": ["end"],
                "require": {"probe": {"command": fail_command, "expected_in": ["clean"]}},
                "on_failure": {"action": "ask", "feedback": "AGY ask: operator confirmation required to finish"},
                "order": 1
            }
        ],
        "tool_guards": [],
        "rules": {}
    });
    fs::write(
        root.join(".agents/arc_ir.json"),
        serde_json::to_vec_pretty(&ir).unwrap(),
    )
    .unwrap();
    trust_ir(&root, &root.join(".agents/arc_ir.json"));

    let ready_path = root.join("decision-ui-ready.json");
    let release_path = root.join("decision-ui-release");
    let decision_host = compile_blocking_allow_decision_ui_host(&root);
    let host_env = [
        ("ARC_DECISION_UI_HOST", decision_host.as_os_str()),
        ("ARC_TEST_UI_READY", ready_path.as_os_str()),
        ("ARC_TEST_UI_RELEASE", release_path.as_os_str()),
    ];
    let state_path = root.join(".arc-test-state/runtime-state.sqlite3");
    let first = spawn_hook_with_decision_ui_env(
        &root,
        "stop",
        r#"{"conversationId":"s-agy-ask","executionNum":1}"#,
        "gemini",
        "native",
        &host_env,
    );

    let record_before_reentry =
        wait_for_pending_guard_execution(&state_path, &ready_path, "agy_ask_only_guard");
    let key = record_before_reentry.key.clone();
    let pending_request = record_before_reentry
        .pending_decision
        .clone()
        .expect("the real AGY invocation must persist a pending decision");
    assert_eq!(
        record_before_reentry.state,
        GuardExecutionState::AwaitingDecision
    );
    assert_eq!(
        pending_request.execution_id,
        record_before_reentry.execution_id
    );
    assert!(!pending_request.decision_id.is_empty());
    assert!(
        pending_request
            .owner_invocation_id
            .as_deref()
            .is_some_and(|owner| !owner.is_empty()),
        "the pending decision must retain the first coordinating invocation"
    );

    let second = spawn_hook_with_decision_ui_env(
        &root,
        "stop",
        r#"{"conversationId":"s-agy-ask","executionNum":1}"#,
        "gemini",
        "native",
        &[],
    );
    let second_raw = second.wait_with_output().unwrap();

    // Release the first real presentation before asserting the second result so
    // a failed duplicate-window assertion cannot orphan the blocked child.
    fs::write(&release_path, "release").unwrap();
    let first_raw = first.wait_with_output().unwrap();

    assert!(
        second_raw.status.success(),
        "duplicate re-entry stderr: {}",
        String::from_utf8_lossy(&second_raw.stderr)
    );
    let second_output: serde_json::Value = serde_json::from_slice(&second_raw.stdout).unwrap();
    assert_eq!(second_output["decision"], "stop");
    let second_reason = second_output["reason"].as_str().unwrap();
    assert!(
        second_reason.contains("A decision dialog for guard 'agy_ask_only_guard' is already pending; Arc refused to open a duplicate window."),
        "second AGY invocation must refuse the duplicate window: {second_reason}"
    );
    assert!(
        second_reason.contains(&pending_request.execution_id),
        "duplicate response must retain the durable execution identity: {second_reason}"
    );

    assert!(
        first_raw.status.success(),
        "first AGY invocation stderr: {}",
        String::from_utf8_lossy(&first_raw.stderr)
    );
    let first_output: serde_json::Value = serde_json::from_slice(&first_raw.stdout).unwrap();
    assert_eq!(first_output["decision"], "continue");
    assert!(
        first_output["reason"]
            .as_str()
            .unwrap()
            .contains("AGY ask: operator confirmation required to finish")
    );

    let record_after_resolution = load_guard_execution_record(&state_path, &key.guard_id)
        .expect("resolved AGY execution must remain in SQLite");
    assert_eq!(
        record_after_resolution.state,
        GuardExecutionState::RemediationInProgress
    );
    assert!(record_after_resolution.pending_decision.is_none());

    let connection = rusqlite::Connection::open(&state_path).unwrap();
    let receipt_json: String = connection
        .query_row(
            "SELECT receipt_json
             FROM decision_receipts WHERE decision_id = ?1",
            [&pending_request.decision_id],
            |row| row.get(0),
        )
        .unwrap();
    let receipt: arc::DecisionReceipt = serde_json::from_str(&receipt_json).unwrap();
    assert_eq!(receipt.execution_id, pending_request.execution_id);
    assert_eq!(receipt.selected_choice, arc::DecisionChoice::Allow);
    assert_eq!(receipt.provider, "gemini");
    assert_eq!(receipt.integrity.transport, "arc_embedded_ui");

    let resolution: (String, String, String, String) = connection
        .query_row(
            "SELECT decision_id, invocation_id, session_id, outcome
             FROM aggregate_resolutions WHERE decision_id = ?1",
            [&pending_request.decision_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .unwrap();
    assert_eq!(resolution.0, pending_request.decision_id);
    assert!(resolution.1.ends_with(":decision"));
    assert_eq!(resolution.2, "s-agy-ask");
    assert_eq!(
        resolution.3,
        serde_json::to_string(&arc::InteractiveDecisionOutcome::Allow).unwrap()
    );

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn test_fase4_agy_stop_coordination_ask_without_transport_fails_closed_and_cancels_pending() {
    let root = std::env::temp_dir().join(format!(
        "arc_fase3_agy_ask_win_{}_{}",
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(root.join(".agents")).unwrap();

    let fail_command = if cfg!(windows) {
        "powershell -NoProfile -Command \"'dirty'\""
    } else {
        "printf dirty"
    };

    let ir = serde_json::json!({
        "context": {"workdir": ".", "instructions_path": null, "instructions_content": null, "roles": {}},
        "skills": [],
        "lifecycle_guards": [
            {
                "id": "agy_ask_only_guard",
                "triggers": ["end"],
                "require": {"probe": {"command": fail_command, "expected_in": ["clean"]}},
                "on_failure": {"action": "ask", "feedback": "AGY ask: operator confirmation required to finish"},
                "order": 1
            }
        ],
        "tool_guards": [],
        "rules": {}
    });
    fs::write(
        root.join(".agents/arc_ir.json"),
        serde_json::to_vec_pretty(&ir).unwrap(),
    )
    .unwrap();
    trust_ir(&root, &root.join(".agents/arc_ir.json"));

    // 1. Gemini has no compatible provider-native End Ask transport. The
    // lifecycle must fail closed and cancel the decision it briefly creates.
    let stop_output1 = run_agy_hook_with_decision_ui(
        &root,
        "stop",
        r#"{"hook_event_name":"Stop","conversation_id":"s-agy-ask","execution_num":1}"#,
        "provider",
    );
    assert_eq!(stop_output1["decision"], "stop");
    let reason1 = stop_output1["reason"].as_str().unwrap();
    assert!(
        reason1.contains("AGY ask: operator confirmation required to finish"),
        "reason1 must contain configured feedback: {reason1}"
    );

    // Verify SQLite state: the runtime coordinated the Guard and closed the
    // non-presentable decision request durably.
    let state_path = root.join(".arc-test-state/runtime-state.sqlite3");
    let connection = rusqlite::Connection::open(&state_path).unwrap();
    let mut stmt = connection
        .prepare("SELECT record_json FROM guard_executions")
        .unwrap();
    let records: Vec<arc::GuardExecutionRecord> = stmt
        .query_map([], |row| {
            let json: String = row.get(0)?;
            let record: arc::GuardExecutionRecord = serde_json::from_str(&json).unwrap();
            Ok(record)
        })
        .unwrap()
        .map(|res| res.unwrap())
        .collect();

    let record1 = records
        .iter()
        .find(|r| r.key.guard_id == "agy_ask_only_guard")
        .expect("record must exist in SQLite");
    assert_eq!(record1.state, GuardExecutionState::Violated);
    assert!(
        record1.pending_decision.is_none(),
        "unsupported lifecycle Ask must not leave pending_decision in SQLite"
    );

    // 2. Re-entry remains terminal and cannot reopen the lifecycle.
    let stop_output2 = run_agy_hook_with_decision_ui(
        &root,
        "stop",
        r#"{"hook_event_name":"Stop","conversation_id":"s-agy-ask","execution_num":1}"#,
        "provider",
    );
    assert_eq!(stop_output2["decision"], "stop");
    let reason2 = stop_output2["reason"].as_str().unwrap();
    assert!(
        reason2.contains("AGY ask: operator confirmation required to finish"),
        "reason2 must preserve the aggregate lifecycle feedback: {reason2}"
    );

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn test_fase3_feedback_formatting_does_not_write_internal_bundle_artifacts() {
    use arc::{FailedGuardFeedback, FailureBundle, format_bundle_feedback_for_provider};

    let bundle = FailureBundle {
        schema: arc::FAILURE_BUNDLE_SCHEMA.to_string(),
        bundle_id: "bundle-test".to_string(),
        invocation_id: "inv-test".to_string(),
        event_id: "ev-test".to_string(),
        event_type: arc::ArcEventType::End,
        effective_disposition: arc::EffectiveDisposition::Deny,
        failed_guards: vec![FailedGuardFeedback {
            guard_id: "test_guard".to_string(),
            configured_action: arc::ActionType::Deny,
            faulted: false,
            configured_feedback: Some("configured guard feedback".to_string()),
            causes: vec![],
            evidence_fingerprint: "ev-fp".to_string(),
        }],
        evaluation_faults: vec![],
        completeness: arc::EvaluationCompleteness::Complete,
        input_fingerprint: "input-fp".to_string(),
        bundle_fingerprint: "test-bundle-fp".to_string(),
    };

    // The formatter takes only the bundle and the fallback text: it has no
    // workspace to write to, so no Arc artifact directory can appear.
    let arc_dir_before = std::path::Path::new(".arc").exists();
    let result = format_bundle_feedback_for_provider(&bundle, "fallback message");
    let feedback = result.expect("text feedback must not depend on artifact storage");
    assert!(feedback.contains("Configured feedback: configured guard feedback"));
    assert!(!feedback.contains("[ARC_FAILURE_BUNDLE_V1]"));
    assert!(!feedback.contains("test-bundle-fp"));
    assert_eq!(
        std::path::Path::new(".arc").exists(),
        arc_dir_before,
        "formatting must not create an internal artifact directory"
    );
}

#[test]
fn test_fase3_cli_codex_and_agy_aggregate_authorizations_and_no_loss_lifecycle() {
    let root = std::env::temp_dir().join(format!(
        "arc_fase3_cli_auth_{}_{}",
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(root.join(".codex/sessions")).unwrap();
    fs::create_dir_all(root.join(".gemini/antigravity/brain/session-auth-test")).unwrap();
    fs::create_dir_all(root.join(".agents")).unwrap();

    // 1. Write valid transcripts containing clear user_intent so CliDecisionProvider compliance auditor evaluates
    let codex_transcript = root.join(".codex/sessions/session-auth-test.jsonl");
    fs::write(
        &codex_transcript,
        "{\"type\":\"session_meta\",\"payload\":{\"id\":\"session-auth-test\"}}\n\
         {\"type\":\"response_item\",\"payload\":{\"type\":\"message\",\"role\":\"user\",\"content\":[{\"type\":\"input_text\",\"text\":\"Run compliance validation suite\"}]}}\n",
    )
    .unwrap();

    let agy_transcript = root.join(".gemini/antigravity/brain/session-auth-test/transcript.jsonl");
    fs::write(
        &agy_transcript,
        "{\"type\":\"USER_INPUT\",\"content\":\"Run compliance validation suite\"}\n",
    )
    .unwrap();

    // 2. Mock decision executable for ARC_LLM_CLI returning valid decision: true
    let script_path = if cfg!(windows) {
        let p = root.join("mock_llm.bat");
        fs::write(&p, "@echo {\"decision\": true}\r\n").unwrap();
        p
    } else {
        let p = root.join("mock_llm.sh");
        fs::write(&p, "#!/bin/sh\necho '{\"decision\": true}'\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(&p).unwrap().permissions();
            perms.set_mode(0o755);
            fs::set_permissions(&p, perms).unwrap();
        }
        p
    };

    let fail_command = if cfg!(windows) {
        "powershell -NoProfile -Command \"'dirty'\""
    } else {
        "printf dirty"
    };

    // 3. Configure BehaviorIR with:
    // - auth_decide_guard: requires decide (evaluates to Satisfied -> produces ExactOperationAuthorization)
    // - failing_probe_guard: failing probe -> produces Violated in failure bundle
    let ir = serde_json::json!({
        "context": {"workdir": ".", "instructions_path": null, "instructions_content": null, "roles": {}},
        "skills": [],
        "lifecycle_guards": [],
        "tool_guards": [
            {
                "id": "auth_decide_guard",
                "matcher": {
                    "exact_patterns": ["cargo test"]
                },
                "require": {
                    "decide": {
                        "prompt": "Verify command safety"
                    }
                },
                "on_failure": {
                    "action": "deny",
                    "feedback": "Decide safety check rejected"
                },
                "order": 1
            },
            {
                "id": "failing_probe_guard",
                "matcher": {
                    "exact_patterns": ["cargo test"]
                },
                "require": {
                    "probe": {
                        "command": fail_command,
                        "expected_in": ["clean"]
                    }
                },
                "on_failure": {
                    "action": "deny",
                    "feedback": "Destructive command blocked by probe"
                },
                "order": 2
            }
        ],
        "rules": {}
    });
    let mut ir: arc::ir::BehaviorIR =
        serde_json::from_value(ir).expect("deserialize canonical BehaviorIR fixture");
    ir.content_hash = Some(ir.compute_content_hash());
    let ir_bytes = serde_json::to_vec_pretty(&ir).expect("serialize canonical BehaviorIR fixture");

    fs::write(root.join(".codex/arc_ir.json"), &ir_bytes).unwrap();
    fs::write(root.join(".agents/arc_ir.json"), &ir_bytes).unwrap();
    trust_ir(&root, &root.join(".codex/arc_ir.json"));
    trust_ir(&root, &root.join(".agents/arc_ir.json"));

    // 4. Codex CLI PreToolUse: all failures in output, authorizations complete in aggregate, no false allow
    let codex_input = serde_json::json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "cargo test"},
        "session_id": "session-auth-test",
        "transcript_path": codex_transcript.to_string_lossy(),
    });
    let codex_output = run_codex_hook_with_env(
        &root,
        "pre-tool-use",
        &codex_input.to_string(),
        &[
            ("ARC_LLM_CLI", script_path.as_os_str()),
            ("CODEX_HOME", root.as_os_str()),
        ],
    );

    assert_eq!(
        codex_output["hookSpecificOutput"]["permissionDecision"], "deny",
        "Codex must not emit allow when guards fail; projection must not lose failure context"
    );
    let codex_reason = codex_output["hookSpecificOutput"]["permissionDecisionReason"]
        .as_str()
        .expect("permissionDecisionReason must be present on deny");
    assert!(codex_reason.starts_with("Arc guard feedback:"));
    assert!(!codex_reason.contains("[ARC_FAILURE_BUNDLE_V1]"));
    assert!(!codex_reason.contains("arc.provider_feedback.v1"));
    assert!(!codex_reason.contains("invocation_id:"));
    assert!(
        codex_reason.contains("Destructive command blocked by probe"),
        "Codex output must contain the configured corrective feedback: {codex_reason}"
    );

    // 5. AGY CLI PreToolUse: all failures in output, authorizations complete in aggregate, no false allow
    let agy_input = serde_json::json!({
        "toolCall": {"name": "Bash", "args": {"command": "cargo test"}},
        "conversationId": "session-auth-test",
        "transcriptPath": agy_transcript.to_string_lossy(),
    });
    let agy_output = run_agy_hook_with_env(
        &root,
        "pre-tool-use",
        &agy_input.to_string(),
        &[
            ("ARC_LLM_CLI", script_path.as_os_str()),
            ("USERPROFILE", root.as_os_str()),
            ("HOME", root.as_os_str()),
        ],
    );

    assert_eq!(
        agy_output["decision"], "deny",
        "AGY must not emit allow when guards fail; projection must not lose failure context"
    );
    let agy_reason = agy_output["reason"]
        .as_str()
        .expect("reason must be present on deny");
    assert!(agy_reason.starts_with("Arc guard feedback:"));
    assert!(!agy_reason.contains("[ARC_FAILURE_BUNDLE_V1]"));
    assert!(!agy_reason.contains("arc.provider_feedback.v1"));
    assert!(!agy_reason.contains("invocation_id:"));
    assert!(
        agy_reason.contains("Destructive command blocked by probe"),
        "AGY output must contain the configured corrective feedback: {agy_reason}"
    );

    // 6. Verify SQLite state store & aggregate authorizations:
    // Observability events confirm complete authorization requirements in the aggregate result
    let state_path = root.join(".arc-test-state/runtime-state.sqlite3");
    let connection = rusqlite::Connection::open(&state_path).unwrap();
    let mut stmt = connection
        .prepare(
            "SELECT invocation_id, session_id, provider, details_json
             FROM observability_events
             WHERE event_type = 'GuardEvaluationCompleted' ORDER BY id ASC",
        )
        .unwrap();
    let eval_events: Vec<(String, String, String, serde_json::Value)> = stmt
        .query_map([], |row| {
            let invocation_id: String = row
                .get::<_, Option<String>>(0)?
                .expect("GuardEvaluationCompleted must retain invocation_id");
            let session_id: String = row
                .get::<_, Option<String>>(1)?
                .expect("GuardEvaluationCompleted must retain session_id");
            let provider: String = row
                .get::<_, Option<String>>(2)?
                .expect("GuardEvaluationCompleted must retain provider");
            let details: String = row.get(3)?;
            Ok((
                invocation_id,
                session_id,
                provider,
                serde_json::from_str(&details).unwrap(),
            ))
        })
        .unwrap()
        .map(|r| r.unwrap())
        .collect();

    assert!(
        !eval_events.is_empty(),
        "GuardEvaluationCompleted events must be recorded in observability journal"
    );
    for (_, _, _, event) in &eval_events {
        let auth_count = event["authorization_requirements"]
            .as_u64()
            .expect("authorization_requirements count must be recorded");
        assert_eq!(auth_count, 1);
        let authorizations: Vec<arc::ExactOperationAuthorization> =
            serde_json::from_value(event["authorization_requirement_items"].clone())
                .expect("aggregate evaluation must persist the exact authorization vector");
        assert_eq!(
            authorizations.len(),
            1,
            "aggregate evaluation must retain the complete authorization requirement set"
        );
        assert_eq!(authorizations[0].guard_id, "auth_decide_guard");
        assert_eq!(authorizations[0].tool, "Bash");
        assert!(!authorizations[0].operation_fingerprint.is_empty());
        assert!(!authorizations[0].event_id.is_empty());
        assert!(
            !authorizations[0]
                .normalized_arguments_fingerprint
                .is_empty()
        );
    }

    let codex_event = eval_events
        .iter()
        .find(|event| event.2 == "codex")
        .expect("Codex CLI evaluation event must be present");
    let codex_authorizations: Vec<arc::ExactOperationAuthorization> =
        serde_json::from_value(codex_event.3["authorization_requirement_items"].clone())
            .expect("Codex aggregate authorization vector must be present");
    let cli_invocation_id = codex_event.0.clone();
    let cli_session_id = codex_event.1.clone();
    let resolution_id = format!("arc:tool:aggregate:{cli_invocation_id}");
    let decision_id = format!("decision:tool:{cli_invocation_id}");
    let resolution_invocation_id = format!("{cli_invocation_id}:resolution");

    // 7. A deny-only CLI hook has no durable pending targets. The canonical
    // aggregate boundary must reject synthetic application instead of
    // fabricating a permitted resolution or authorization consumption.
    let store = SqliteStateStore::open(&state_path).unwrap();
    let now = current_unix_ms();
    let apply_req = arc::AggregateResolutionApplyRequest {
        resolution_id,
        decision_id: Some(decision_id.clone()),
        invocation_id: resolution_invocation_id.clone(),
        session_id: cli_session_id,
        workspace_id: Some(
            codex_event.3["workspace_id"]
                .as_str()
                .unwrap_or("cli-workspace")
                .into(),
        ),
        provider: "codex".into(),
        outcome: arc::InteractiveDecisionOutcome::Allow,
        authorizations: codex_authorizations.clone(),
        now_unix_ms: now,
        expires_at_unix_ms: now + 60_000,
        decision_receipt: None,
        authorization_context: None,
    };
    let error = store
        .apply_aggregate_resolution(&apply_req)
        .expect_err("synthetic aggregate application must fail closed");
    assert!(error.to_string().contains("targets"));

    let persisted_rows: i64 = connection
        .query_row(
            "SELECT count(*) FROM exact_operation_authorizations WHERE decision_id = ?1",
            [&decision_id],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(persisted_rows, 0);

    drop(store);
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn cli_hook_rejects_incompatible_explicit_provider_and_event_combinations() {
    let root =
        std::env::temp_dir().join(format!("arc-cli-hook-reject-test-{}", uuid::Uuid::new_v4()));
    fs::create_dir_all(&root).unwrap();

    // 1. Incompatible: codex + pre-invocation
    let mut codex_pre_inv = Command::new(env!("CARGO_BIN_EXE_arc"))
        .current_dir(&root)
        .args([
            "hook",
            "run",
            "--event-type",
            "pre-invocation",
            "--provider",
            "codex",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let _ = codex_pre_inv.stdin.take().unwrap().write_all(b"{}");
    let codex_out = codex_pre_inv.wait_with_output().unwrap();
    assert_eq!(codex_out.status.code(), Some(2));
    assert!(
        codex_out.stdout.is_empty(),
        "stdout must be empty on CLI argument conflict"
    );
    let stderr = String::from_utf8_lossy(&codex_out.stderr);
    assert!(
        stderr.contains("pre-invocation"),
        "stderr must mention the conflicting argument: {stderr}"
    );
    assert!(
        stderr.contains("codex"),
        "stderr must mention the provider: {stderr}"
    );

    // 2. Incompatible: gemini + session-start
    let mut gemini_session = Command::new(env!("CARGO_BIN_EXE_arc"))
        .current_dir(&root)
        .args([
            "hook",
            "run",
            "--event-type",
            "session-start",
            "--provider",
            "gemini",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let _ = gemini_session.stdin.take().unwrap().write_all(b"{}");
    let gemini_out = gemini_session.wait_with_output().unwrap();
    assert_eq!(gemini_out.status.code(), Some(2));
    assert!(
        gemini_out.stdout.is_empty(),
        "stdout must be empty on CLI argument conflict"
    );
    let stderr = String::from_utf8_lossy(&gemini_out.stderr);
    assert!(
        stderr.contains("session-start"),
        "stderr must mention the conflicting argument: {stderr}"
    );
    assert!(
        stderr.contains("gemini"),
        "stderr must mention the provider: {stderr}"
    );

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn cli_hook_post_cli_parse_mismatch_fails_closed_in_resolved_provider_protocol() {
    let root =
        std::env::temp_dir().join(format!("arc-cli-post-parse-test-{}", uuid::Uuid::new_v4()));
    fs::create_dir_all(&root).unwrap();
    let state_dir = root.join(".arc-test-state");
    fs::create_dir_all(&state_dir).unwrap();

    // Set up a valid behavior IR
    let mut ir = arc::BehaviorIR {
        schema: "1.0".into(),
        compiler_version: env!("CARGO_PKG_VERSION").into(),
        build_id: None,
        content_hash: None,
        runtime: Default::default(),
        context: arc::WorkspaceContext {
            workdir: ".".into(),
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
    let ir_content = serde_json::to_string_pretty(&ir).unwrap();

    // 1. Test Codex workspace with .codex/arc_ir.json invoked with pre-invocation (omitting --provider)
    let codex_ws = root.join("ws_codex");
    let codex_dir = codex_ws.join(".codex");
    fs::create_dir_all(&codex_dir).unwrap();
    let codex_ir_path = codex_dir.join("arc_ir.json");
    fs::write(&codex_ir_path, &ir_content).unwrap();

    let state_path = state_dir.join("runtime-state.sqlite3");
    let store = SqliteStateStore::open(&state_path).unwrap();
    store.trust_ir_file(&codex_ir_path).unwrap();
    drop(store);

    let mut codex_child = Command::new(env!("CARGO_BIN_EXE_arc"))
        .current_dir(&codex_ws)
        .args([
            "hook",
            "run",
            "--event-type",
            "pre-invocation",
            "--ir-path",
            codex_ir_path.to_str().unwrap(),
        ])
        .env("ARC_STATE_DIR", &state_dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let _ = codex_child
        .stdin
        .take()
        .unwrap()
        .write_all(b"{\"session_id\":\"s-codex-mismatch\"}");
    let codex_res = codex_child.wait_with_output().unwrap();
    assert_eq!(codex_res.status.code(), Some(0));
    let codex_json: serde_json::Value =
        serde_json::from_slice(&codex_res.stdout).expect("codex failure output must be valid json");
    assert_eq!(codex_json["continue"], false);
    assert!(codex_json.get("injectSteps").is_none());
    assert!(codex_json.get("inject_steps").is_none());

    // 2. Test Gemini workspace with .agents/arc_ir.json invoked with session-start (omitting --provider)
    let gemini_ws = root.join("ws_gemini");
    let gemini_dir = gemini_ws.join(".agents");
    fs::create_dir_all(&gemini_dir).unwrap();
    let gemini_ir_path = gemini_dir.join("arc_ir.json");
    fs::write(&gemini_ir_path, &ir_content).unwrap();

    let store = SqliteStateStore::open(&state_path).unwrap();
    store.trust_ir_file(&gemini_ir_path).unwrap();
    drop(store);

    let mut gemini_child = Command::new(env!("CARGO_BIN_EXE_arc"))
        .current_dir(&gemini_ws)
        .args([
            "hook",
            "run",
            "--event-type",
            "session-start",
            "--ir-path",
            gemini_ir_path.to_str().unwrap(),
        ])
        .env("ARC_STATE_DIR", &state_dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let _ = gemini_child
        .stdin
        .take()
        .unwrap()
        .write_all(b"{\"conversationId\":\"s-gemini-mismatch\"}");
    let gemini_res = gemini_child.wait_with_output().unwrap();
    assert_eq!(gemini_res.status.code(), Some(0));
    let gemini_json: serde_json::Value = serde_json::from_slice(&gemini_res.stdout)
        .expect("gemini failure output must be valid json");
    assert_eq!(gemini_json["decision"], "deny");
    assert!(gemini_json.get("hookSpecificOutput").is_none());

    // Check observability journal
    let journal = arc::ObservabilityJournal::open(&state_path).unwrap();
    let events = journal.query(&arc::EventQuery::default()).unwrap();
    let failed_events: Vec<_> = events
        .iter()
        .filter(|e| e.event_type == "HookFailed")
        .collect();
    assert_eq!(failed_events.len(), 2);
    assert_eq!(failed_events[0].provider.as_deref(), Some("codex"));
    assert_eq!(
        failed_events[0].reason_code.as_deref(),
        Some("unsupported_provider_event")
    );
    assert_eq!(failed_events[1].provider.as_deref(), Some("gemini"));
    assert_eq!(
        failed_events[1].reason_code.as_deref(),
        Some("unsupported_provider_event")
    );

    let _ = fs::remove_dir_all(&root);
}
