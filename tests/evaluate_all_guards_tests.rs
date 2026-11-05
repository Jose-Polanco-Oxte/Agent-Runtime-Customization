#[path = "guard_evaluation_support.rs"]
mod guard_evaluation_support;
use guard_evaluation_support::{evaluate_session_event, evaluate_with_fixture_config};

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;

use arc::ir::{
    BehaviorIR, BoundLifecycleGuard, BoundMatcher, BoundRuleExpression, BoundToolGuard,
    WorkspaceContext,
};
use arc::manifest::schema::{LifecycleTrigger, OnFailureConfig};
use arc::{
    ActionType, ActivationEvaluationCache, ActivationSnapshot, AgyAdapter, ArcEvaluationError,
    ArcEvaluationResult, ArcEvent, ArcEventType, ArcRuntimeSession, CodexAdapter,
    DecisionExecutionProfile, EffectiveDisposition, EvaluationCompleteness, EvaluationFault,
    ExactOperationAuthorization, FailureBundle, GuardEvaluationBatchError, GuardEvaluationSpec,
    GuardExecutionStateStore, GuardResultState, MockDecisionProvider, MockProbeRunner,
    ProviderTarget, SessionContext,
};

fn exact_authorization_context(
    auths: &[ExactOperationAuthorization],
    event_id: &str,
    tool: &str,
    workspace_id: &str,
    session_id: &str,
    invocation_id: &str,
    policy_fingerprint: &str,
    evidence_fingerprint: &str,
) -> arc::ExactAuthorizationContext {
    arc::ExactAuthorizationContext::for_authorizations(
        event_id,
        tool,
        workspace_id,
        "codex",
        session_id,
        invocation_id,
        policy_fingerprint,
        evidence_fingerprint,
        auths,
    )
    .unwrap()
}

fn snapshot() -> ActivationSnapshot {
    ActivationSnapshot::from_event(
        "activation-1",
        "invocation-1",
        arc::ProviderTarget::Codex,
        &ArcEvent::lifecycle("session-1", "event-1", ArcEventType::End, 1),
        SessionContext {
            user_intent: "validate".into(),
            ..SessionContext::default()
        },
        Vec::new(),
        10_000,
    )
}

fn guard(id: &str, order: u32, action: ActionType, expected: &str) -> GuardEvaluationSpec {
    GuardEvaluationSpec {
        guard_id: id.into(),
        order,
        declaration_order: order as usize,
        action,
        configured_feedback: Some(format!("{id} feedback")),
        scope: "lifecycle:end".into(),
        expression: BoundRuleExpression::Probe {
            command: format!("probe-{id}").into(),
            expected_in: vec![expected.into()],
        },
        matcher_evidence: Vec::new(),
        matcher_evidence_truncated: false,
    }
}

fn behavior_ir_for_specs(guards: &[GuardEvaluationSpec]) -> BehaviorIR {
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
        lifecycle_guards: guards
            .iter()
            .map(|spec| BoundLifecycleGuard {
                id: spec.guard_id.clone(),
                triggers: vec![LifecycleTrigger::End],
                require: spec.expression.clone(),
                on_failure: OnFailureConfig {
                    action: spec.action,
                    feedback: spec.configured_feedback.clone(),
                },
                order: spec.order,
                declaration_order: spec.declaration_order,
            })
            .collect(),
        tool_guards: Vec::new(),
        rules: BTreeMap::new(),
    };
    ir.content_hash = Some(ir.compute_content_hash());
    ir
}

#[test]
fn evaluates_every_applicable_guard_and_reduces_in_contract_order() {
    let guards = vec![
        guard("ask-guard", 2, ActionType::Ask, "not-this"),
        guard("deny-guard", 1, ActionType::Deny, "not-this"),
        guard("satisfied-guard", 3, ActionType::Message, "observed"),
    ];
    let probes = Arc::new(
        MockProbeRunner::new()
            .with_output("probe-ask-guard", "wrong")
            .with_output("probe-deny-guard", "wrong")
            .with_output("probe-satisfied-guard", "observed"),
    );
    let report = evaluate_with_fixture_config(&snapshot(), &guards, &BTreeMap::new(), probes, None)
        .expect("all guards evaluate");
    assert_eq!(report.guard_results.len(), 3);
    assert_eq!(report.guard_results[0].guard_id, "deny-guard");
    assert_eq!(report.guard_results[1].guard_id, "ask-guard");
    assert_eq!(report.guard_results[2].guard_id, "satisfied-guard");
    assert!(matches!(
        report.guard_results[0].state,
        GuardResultState::Violated { .. }
    ));
    assert!(matches!(
        report.guard_results[1].state,
        GuardResultState::Violated { .. }
    ));
    assert!(matches!(
        report.guard_results[2].state,
        GuardResultState::Satisfied
    ));
    assert_eq!(
        report.effective_disposition,
        arc::EffectiveDisposition::Deny
    );
}

#[test]
fn ec_005_multiple_ask_guards_produce_single_ui_request_with_all_violations() {
    let guards = vec![
        guard("ask-1", 1, ActionType::Ask, "expected-1"),
        guard("ask-2", 2, ActionType::Ask, "expected-2"),
        guard("satisfied-guard", 3, ActionType::Message, "observed"),
    ];
    let probes = Arc::new(
        MockProbeRunner::new()
            .with_output("probe-ask-1", "mismatch")
            .with_output("probe-ask-2", "mismatch")
            .with_output("probe-satisfied-guard", "observed"),
    );
    let report = evaluate_with_fixture_config(&snapshot(), &guards, &BTreeMap::new(), probes, None)
        .expect("all guards evaluate");

    assert_eq!(report.guard_results.len(), 3);
    assert_eq!(report.guard_results[0].guard_id, "ask-1");
    assert_eq!(report.guard_results[1].guard_id, "ask-2");
    assert_eq!(report.guard_results[2].guard_id, "satisfied-guard");

    assert!(matches!(
        report.guard_results[0].state,
        GuardResultState::Violated { .. }
    ));
    assert!(matches!(
        report.guard_results[1].state,
        GuardResultState::Violated { .. }
    ));
    assert!(matches!(
        report.guard_results[2].state,
        GuardResultState::Satisfied
    ));

    assert_eq!(
        report.effective_disposition,
        arc::EffectiveDisposition::Ask,
        "Multiple ask guards without higher-precedence actions must yield Ask disposition"
    );

    // 1. FailureBundle preserves all failed guards
    let ir = behavior_ir_for_specs(&guards);
    let store = arc::SqliteStateStore::open_in_memory().unwrap();
    let anchor = store
        .trust_and_anchor_ir(Path::new("test.json"), &ir)
        .unwrap();
    let bundle = arc::FailureBundle::from_report_with_trusted_anchor(&report, &ir, &anchor)
        .expect("failure bundle created");
    assert_eq!(bundle.failed_guards.len(), 2);
    assert_eq!(bundle.failed_guards[0].guard_id, "ask-1");
    assert_eq!(bundle.failed_guards[0].configured_action, ActionType::Ask);
    assert_eq!(bundle.failed_guards[1].guard_id, "ask-2");
    assert_eq!(bundle.failed_guards[1].configured_action, ActionType::Ask);
    assert!(bundle.validate().is_ok());

    // 2. Single DialogRequest aggregation contains all violated Ask guards
    let violations = bundle
        .failed_guards
        .iter()
        .map(|failed| arc::DialogViolationItem {
            guard_id: failed.guard_id.clone(),
            summary: failed
                .causes
                .first()
                .map(|cause| cause.summary.clone())
                .unwrap_or_else(|| "Violated".into()),
            configured_feedback: failed.configured_feedback.clone(),
            auditor_findings: failed
                .causes
                .iter()
                .filter_map(|cause| cause.auditor_findings.clone())
                .reduce(|mut findings, finding| {
                    findings.push('\n');
                    findings.push_str(&finding);
                    findings
                }),
            scope: "lifecycle:end".into(),
            failed_probes: Vec::new(),
        })
        .collect::<Vec<_>>();

    let request = arc::DialogRequest::guard_failures(
        "req-ec-005",
        "Multiple ask guards required decision",
        "lifecycle:end",
        violations,
        bundle.bundle_fingerprint.clone(),
        10_000,
    );

    assert!(request.validate().is_ok());
    assert_eq!(request.violations.len(), 2);
    assert_eq!(request.violations[0].guard_id, "ask-1");
    assert_eq!(request.violations[1].guard_id, "ask-2");
    assert_eq!(
        request.presentation_kind,
        arc::PresentationKind::GuardFailures
    );

    // 3. ArcEvaluationResult preserves all Ask guards in the canonical aggregate.
    let bundle = FailureBundle::from_report_with_trusted_anchor(&report, &ir, &anchor)
        .expect("failure bundle");
    let eval_result =
        ArcEvaluationResult::from_report_and_bundle(report.clone(), bundle).expect("eval result");

    assert_eq!(eval_result.effective_disposition, EffectiveDisposition::Ask);
    assert_eq!(eval_result.report.guard_results.len(), 3);
    assert_eq!(eval_result.failure_bundle.failed_guards.len(), 2);
    assert_eq!(
        eval_result.failure_bundle.failed_guards[0].guard_id,
        "ask-1"
    );
    assert_eq!(
        eval_result.failure_bundle.failed_guards[1].guard_id,
        "ask-2"
    );

    // 4. interactive_decision_request_from_evaluation_result builds an InteractiveDecisionRequest with all guards
    let interactive_req = arc::interactive_decision_request_from_evaluation_result(
        &eval_result,
        ProviderTarget::Codex,
        ArcEventType::End,
        "event-ec-005",
        "inv-ec-005",
        None,
        None,
        "lifecycle:end",
    )
    .expect("interactive request from eval result succeeds")
    .expect("ask eval result must produce interactive request");

    assert_eq!(interactive_req.guards().len(), 2);
    assert_eq!(interactive_req.guards()[0].guard_id(), "ask-1");
    assert_eq!(interactive_req.guards()[1].guard_id(), "ask-2");

    let dialog_from_request =
        interactive_req.to_dialog_request("Multiple ask guards required decision");
    assert_eq!(
        dialog_from_request.presentation_kind,
        arc::PresentationKind::GuardFailures
    );
    assert_eq!(dialog_from_request.violations.len(), 2);
    assert_eq!(dialog_from_request.violations[0].guard_id, "ask-1");
    // Current contract (decision/context.rs `to_dialog_request`): with several guards the
    // summary is the neutral "requires confirmation" text and the configured feedback
    // travels in its own `configured_feedback` field.
    assert_eq!(
        dialog_from_request.violations[0].summary,
        "Guard 'ask-1' requires confirmation"
    );
    assert_eq!(
        dialog_from_request.violations[0]
            .configured_feedback
            .as_deref(),
        Some("ask-1 feedback")
    );
    assert_eq!(dialog_from_request.violations[1].guard_id, "ask-2");
    assert_eq!(
        dialog_from_request.violations[1].summary,
        "Guard 'ask-2' requires confirmation"
    );
    assert_eq!(
        dialog_from_request.violations[1]
            .configured_feedback
            .as_deref(),
        Some("ask-2 feedback")
    );
    assert!(dialog_from_request.validate().is_ok());
}

#[test]
fn ec_017_guard_message_and_satisfied_guard_preserves_message_without_escalation() {
    let guards = vec![
        guard("message-guard", 1, ActionType::Message, "expected-msg"),
        guard("satisfied-guard", 2, ActionType::Deny, "observed"),
    ];
    let probes = Arc::new(
        MockProbeRunner::new()
            .with_output("probe-message-guard", "mismatch")
            .with_output("probe-satisfied-guard", "observed"),
    );
    let report = evaluate_with_fixture_config(&snapshot(), &guards, &BTreeMap::new(), probes, None)
        .expect("all guards evaluate");

    assert_eq!(report.guard_results.len(), 2);
    assert!(matches!(
        report.guard_results[0].state,
        GuardResultState::Violated { .. }
    ));
    assert!(matches!(
        report.guard_results[1].state,
        GuardResultState::Satisfied
    ));
    assert_eq!(
        report.effective_disposition,
        arc::EffectiveDisposition::Message,
        "Violated Message guard with satisfied Deny guard must produce Message disposition without Deny escalation"
    );
}

#[test]
fn ec_017_satisfied_message_guard_does_not_change_disposition_to_message() {
    let guards = vec![
        guard("satisfied-message", 1, ActionType::Message, "observed"),
        guard("satisfied-deny", 2, ActionType::Deny, "observed"),
    ];
    let probes = Arc::new(
        MockProbeRunner::new()
            .with_output("probe-satisfied-message", "observed")
            .with_output("probe-satisfied-deny", "observed"),
    );
    let report = evaluate_with_fixture_config(&snapshot(), &guards, &BTreeMap::new(), probes, None)
        .expect("all guards evaluate");

    assert_eq!(report.guard_results.len(), 2);
    assert!(matches!(
        report.guard_results[0].state,
        GuardResultState::Satisfied
    ));
    assert!(matches!(
        report.guard_results[1].state,
        GuardResultState::Satisfied
    ));
    assert_eq!(
        report.effective_disposition,
        arc::EffectiveDisposition::Continue,
        "Satisfied Message guard must not change disposition to Message; must be Continue"
    );

    let bundle = FailureBundle::from_report(&report).expect("failure bundle succeeds");
    let result = ArcEvaluationResult::from_report_and_bundle(report.clone(), bundle)
        .expect("canonical aggregate succeeds");
    assert_eq!(result.effective_disposition, EffectiveDisposition::Continue);
    assert!(result.failure_bundle.failed_guards.is_empty());

    // A report claiming Message without a violated Message guard is rejected by the
    // canonical aggregate validator instead of being converted to a synthetic output.
    let mut synthetic_report = report.clone();
    synthetic_report.effective_disposition = arc::EffectiveDisposition::Message;
    assert!(FailureBundle::from_report(&synthetic_report).is_err());
}

#[test]
fn a_fault_does_not_hide_later_guard_results() {
    let guards = vec![
        guard("fault", 1, ActionType::Deny, "expected"),
        guard("later", 2, ActionType::Message, "expected"),
    ];
    let probes = Arc::new(MockProbeRunner::new().with_output("probe-later", "expected"));
    let report = evaluate_with_fixture_config(&snapshot(), &guards, &BTreeMap::new(), probes, None)
        .expect("report is produced");
    assert_eq!(report.guard_results.len(), 2);
    assert!(matches!(
        report.guard_results[0].state,
        GuardResultState::Faulted { .. }
    ));
    assert!(matches!(
        report.guard_results[1].state,
        GuardResultState::Satisfied
    ));
    assert_eq!(
        report.effective_disposition,
        arc::EffectiveDisposition::RuntimeFault
    );
}

#[test]
fn runtime_session_batch_api_evaluates_matching_guards_and_records_each_result() {
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
        lifecycle_guards: vec![
            BoundLifecycleGuard {
                id: "batch-deny".into(),
                triggers: vec![LifecycleTrigger::End],
                require: BoundRuleExpression::Probe {
                    command: "git branch".into(),
                    expected_in: vec!["main".into()],
                },
                on_failure: OnFailureConfig {
                    action: ActionType::Deny,
                    feedback: Some("deny feedback".into()),
                },
                order: 1,
                declaration_order: 1,
            },
            BoundLifecycleGuard {
                id: "batch-message".into(),
                triggers: vec![LifecycleTrigger::End],
                require: BoundRuleExpression::Probe {
                    command: "git branch".into(),
                    expected_in: vec!["feature".into()],
                },
                on_failure: OnFailureConfig {
                    action: ActionType::Message,
                    feedback: Some("message feedback".into()),
                },
                order: 2,
                declaration_order: 2,
            },
        ],
        tool_guards: Vec::new(),
        rules: BTreeMap::new(),
    };
    ir.content_hash = Some(ir.compute_content_hash());
    let store = arc::SqliteStateStore::open_in_memory().unwrap();
    let anchor = store
        .trust_and_anchor_ir(Path::new("batch.json"), &ir)
        .unwrap();
    let mut session = ArcRuntimeSession::new("batch-session", ir)
        .with_trusted_anchor(anchor)
        .unwrap()
        .with_probe_runner(Arc::new(
            MockProbeRunner::new().with_output("git branch", "feature"),
        ));
    let eval_result = session
        .evaluate_event_aggregate(
            ArcEvent::lifecycle("batch-session", "batch-event", ArcEventType::End, 1),
            DecisionExecutionProfile {
                provider: ProviderTarget::Codex,
                transport: "fixture".into(),
                model: None,
                adapter_contract_fingerprint: "adapter".into(),
                output_schema_fingerprint: "schema".into(),
                sandbox_mode: "read_only".into(),
                approval_policy: "never".into(),
            },
            Path::new("."),
            10_000,
        )
        .expect("batch report");
    let report = eval_result.report;
    let bundle = eval_result.failure_bundle;
    assert_eq!(report.guard_results.len(), 2);
    assert!(matches!(
        report.guard_results[0].state,
        GuardResultState::Violated { .. }
    ));
    assert!(matches!(
        report.guard_results[1].state,
        GuardResultState::Satisfied
    ));
    assert_eq!(report.activation_cache_summary.unique_probe_evaluations, 1);
    assert_eq!(bundle.failed_guards.len(), 1);
    assert_eq!(
        bundle.failed_guards[0].configured_feedback.as_deref(),
        Some("deny feedback")
    );
    assert_eq!(session.active_evaluations.len(), 2);
}

#[test]
fn ec_045_duplicate_guard_ids_are_rejected_in_evaluate_all_guards() {
    let guards = vec![
        guard("duplicate-guard", 1, ActionType::Deny, "ok"),
        guard("duplicate-guard", 2, ActionType::Ask, "ok"),
    ];
    let probes = Arc::new(MockProbeRunner::new().with_output("probe-duplicate-guard", "ok"));
    let result = evaluate_with_fixture_config(&snapshot(), &guards, &BTreeMap::new(), probes, None);
    assert!(matches!(
        result,
        Err(GuardEvaluationBatchError::DuplicateGuardId { guard_id }) if guard_id == "duplicate-guard"
    ));
}

#[test]
fn ec_045_duplicate_guard_ids_are_rejected_before_planning_in_cached_batch() {
    let guards = vec![
        guard("duplicate-guard", 1, ActionType::Deny, "ok"),
        guard("duplicate-guard", 2, ActionType::Ask, "ok"),
    ];
    let probes = Arc::new(MockProbeRunner::new().with_output("probe-duplicate-guard", "ok"));
    let cache = ActivationEvaluationCache::new("act-dup");
    let result = arc::evaluate_all_guards_with_cache_concurrency(
        &snapshot(),
        &guards,
        &BTreeMap::new(),
        Path::new("."),
        "env",
        "runner",
        &DecisionExecutionProfile {
            provider: ProviderTarget::Codex,
            transport: "fixture".into(),
            model: None,
            adapter_contract_fingerprint: "adapter".into(),
            output_schema_fingerprint: "schema".into(),
            sandbox_mode: "read_only".into(),
            approval_policy: "never".into(),
        },
        &cache,
        probes,
        None,
        4,
    );
    assert!(matches!(
        result,
        Err(GuardEvaluationBatchError::DuplicateGuardId { guard_id }) if guard_id == "duplicate-guard"
    ));
    assert_eq!(
        cache.logical_occurrences(),
        0,
        "No execution or cache lookup should happen for duplicate guards"
    );
}

#[test]
fn ec_045_empty_guard_id_is_rejected_before_evaluation() {
    let guards = vec![guard("   ", 1, ActionType::Deny, "ok")];
    let probes = Arc::new(MockProbeRunner::new());
    let result = evaluate_with_fixture_config(&snapshot(), &guards, &BTreeMap::new(), probes, None);
    assert!(matches!(
        result,
        Err(GuardEvaluationBatchError::Planning { guard_id, .. }) if guard_id.trim().is_empty()
    ));
}

#[test]
fn planning_failure_in_one_guard_does_not_abort_batch_evaluation() {
    let guards = vec![
        GuardEvaluationSpec {
            guard_id: "missing-rule-guard".into(),
            order: 1,
            declaration_order: 1,
            action: ActionType::Deny,
            configured_feedback: Some("missing rule".into()),
            scope: "lifecycle:end".into(),
            expression: BoundRuleExpression::RuleRef {
                name: "non_existent_rule".into(),
            },
            matcher_evidence: Vec::new(),
            matcher_evidence_truncated: false,
        },
        guard("healthy-guard", 2, ActionType::Message, "observed"),
    ];
    let probes = Arc::new(MockProbeRunner::new().with_output("probe-healthy-guard", "observed"));
    let cache = ActivationEvaluationCache::new("act-planning-fault");
    let report = arc::evaluate_all_guards_with_cache_concurrency(
        &snapshot(),
        &guards,
        &BTreeMap::new(),
        Path::new("."),
        "env",
        "runner",
        &DecisionExecutionProfile {
            provider: ProviderTarget::Codex,
            transport: "fixture".into(),
            model: None,
            adapter_contract_fingerprint: "adapter".into(),
            output_schema_fingerprint: "schema".into(),
            sandbox_mode: "read_only".into(),
            approval_policy: "never".into(),
        },
        &cache,
        probes,
        None,
        4,
    )
    .expect("batch evaluation should not abort when one guard has a planning failure");

    assert_eq!(report.guard_results.len(), 2);
    assert_eq!(report.guard_results[0].guard_id, "missing-rule-guard");
    assert!(matches!(
        &report.guard_results[0].state,
        GuardResultState::Faulted { faults, .. } if faults.iter().any(|f| matches!(f, arc::EvaluationFault::MissingRule { rule_name } if rule_name == "non_existent_rule"))
    ));
    assert_eq!(report.guard_results[1].guard_id, "healthy-guard");
    assert!(matches!(
        &report.guard_results[1].state,
        GuardResultState::Satisfied
    ));
    assert_eq!(
        report.effective_disposition,
        arc::EffectiveDisposition::RuntimeFault
    );
}

#[test]
fn ec_043_tool_call_with_malformed_arguments_fails_closed_before_scheduling() {
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
        lifecycle_guards: Vec::new(),
        tool_guards: vec![arc::ir::BoundToolGuard {
            id: "bash-guard".into(),
            matcher: arc::BoundMatcher {
                exact_patterns: vec!["rm -rf".into()],
                regex_patterns: vec![],
            },
            require: BoundRuleExpression::Probe {
                command: "echo test".into(),
                expected_in: vec!["test".into()],
            },
            on_failure: OnFailureConfig {
                action: ActionType::Deny,
                feedback: Some("cannot run".into()),
            },
            order: 1,
            declaration_order: 1,
        }],
        rules: BTreeMap::new(),
    };
    let mut session = ArcRuntimeSession::new("tool-session", ir);
    let event = ArcEvent {
        provider: Some(ProviderTarget::Codex),
        session_id: "tool-session".into(),
        event_id: "ev-tool-malformed".into(),
        event_type: ArcEventType::ToolCall,
        sequence: 1,
        correlation_id: None,
        transcript_path: None,
        payload: arc::ArcEventPayload::ToolCall {
            tool: "bash".into(),
            input: serde_json::json!({ "invalid": true }),
            argument_extraction: arc::ToolArgumentExtraction::MalformedOrUnrecognized {
                raw: serde_json::json!({ "invalid": true }),
                reason: "missing command argument".into(),
            },
            command_text: None,
        },
    };
    let result = session.evaluate_event_report(
        event,
        DecisionExecutionProfile {
            provider: ProviderTarget::Codex,
            transport: "fixture".into(),
            model: None,
            adapter_contract_fingerprint: "adapter".into(),
            output_schema_fingerprint: "schema".into(),
            sandbox_mode: "read_only".into(),
            approval_policy: "never".into(),
        },
        Path::new("."),
        10_000,
    );
    assert!(
        result.is_err(),
        "Malformed tool arguments with active tool guards must fail closed before scheduling (EC-043)"
    );
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("Preventive security fault"),
        "Error message should indicate preventive security fault: {err_msg}"
    );
}

#[test]
fn inv_016_ec_057_start_with_ask_is_rejected_before_evaluation() {
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
            id: "start-ask-guard".into(),
            triggers: vec![LifecycleTrigger::Start],
            require: BoundRuleExpression::Probe {
                command: "echo hello".into(),
                expected_in: vec!["hello".into()],
            },
            on_failure: OnFailureConfig {
                action: ActionType::Ask,
                feedback: Some("start ask feedback".into()),
            },
            order: 1,
            declaration_order: 1,
        }],
        tool_guards: Vec::new(),
        rules: BTreeMap::new(),
    };
    let mut session = ArcRuntimeSession::new("start-ask-session", ir);
    let event = ArcEvent::lifecycle("start-ask-session", "start-event", ArcEventType::Start, 1);
    let result = session.evaluate_event_report(
        event,
        DecisionExecutionProfile {
            provider: ProviderTarget::Codex,
            transport: "fixture".into(),
            model: None,
            adapter_contract_fingerprint: "adapter".into(),
            output_schema_fingerprint: "schema".into(),
            sandbox_mode: "read_only".into(),
            approval_policy: "never".into(),
        },
        Path::new("."),
        10_000,
    );
    assert!(
        result.is_err(),
        "Start + Ask must be rejected contractually (INV-016, EC-057)"
    );
}

#[test]
fn session_evaluates_all_matching_guards_without_fail_fast() {
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
        lifecycle_guards: vec![
            BoundLifecycleGuard {
                id: "guard-deny-1".into(),
                triggers: vec![LifecycleTrigger::End],
                require: BoundRuleExpression::Probe {
                    command: "echo val1".into(),
                    expected_in: vec!["unmatched1".into()],
                },
                on_failure: OnFailureConfig {
                    action: ActionType::Deny,
                    feedback: Some("deny feedback 1".into()),
                },
                order: 1,
                declaration_order: 1,
            },
            BoundLifecycleGuard {
                id: "guard-message-2".into(),
                triggers: vec![LifecycleTrigger::End],
                require: BoundRuleExpression::Probe {
                    command: "echo val2".into(),
                    expected_in: vec!["unmatched2".into()],
                },
                on_failure: OnFailureConfig {
                    action: ActionType::Message,
                    feedback: Some("message feedback 2".into()),
                },
                order: 2,
                declaration_order: 2,
            },
        ],
        tool_guards: Vec::new(),
        rules: BTreeMap::new(),
    };
    let mut session = ArcRuntimeSession::new("multi-guard-session", ir);
    let event = ArcEvent::lifecycle("multi-guard-session", "end-event", ArcEventType::End, 1);
    let eval_result = evaluate_session_event(&mut session, event).expect("evaluation succeeds");

    // Per INV-012, Deny takes precedence over Message
    assert_eq!(
        eval_result.effective_disposition,
        EffectiveDisposition::Deny
    );
    assert_eq!(eval_result.failure_bundle.failed_guards.len(), 2);
    assert_eq!(
        eval_result
            .failure_bundle
            .failed_guards
            .iter()
            .map(|guard| guard.guard_id.as_str())
            .collect::<Vec<_>>(),
        vec!["guard-deny-1", "guard-message-2"]
    );

    // Non-fail-fast requirement: BOTH guards must have been evaluated and recorded in active_evaluations
    assert_eq!(
        session.active_evaluations.len(),
        2,
        "All matching guards must be evaluated and recorded without early return"
    );
    assert_eq!(session.active_evaluations[0].guard_id, "guard-deny-1");
    assert_eq!(session.active_evaluations[1].guard_id, "guard-message-2");
}

#[test]
fn test_lazy_probes_not_executed_speculatively_in_all() {
    let probe_runner = Arc::new(
        MockProbeRunner::new()
            .with_output("probe-fail", "unmatched")
            .with_output("probe-side-effect", "ok"),
    );

    let rules = BTreeMap::new();
    let spec = GuardEvaluationSpec {
        guard_id: "all-lazy-guard".into(),
        order: 1,
        declaration_order: 1,
        action: ActionType::Deny,
        configured_feedback: Some("all lazy feedback".into()),
        scope: "lifecycle:end".into(),
        expression: BoundRuleExpression::All(vec![
            BoundRuleExpression::Probe {
                command: "probe-fail".into(),
                expected_in: vec!["matched".into()],
            },
            BoundRuleExpression::Probe {
                command: "probe-side-effect".into(),
                expected_in: vec!["ok".into()],
            },
        ]),
        matcher_evidence: Vec::new(),
        matcher_evidence_truncated: false,
    };

    let report =
        evaluate_with_fixture_config(&snapshot(), &[spec], &rules, probe_runner.clone(), None)
            .expect("batch evaluation succeeds");

    assert_eq!(report.guard_results.len(), 1);
    let guard_res = &report.guard_results[0];
    assert!(matches!(guard_res.state, GuardResultState::Violated { .. }));
    assert_eq!(
        guard_res.completeness,
        EvaluationCompleteness::CompleteForGuardResultWithNonCausalSkips,
        "Unexecuted non-causal probes must result in CompleteForGuardResultWithNonCausalSkips"
    );

    let calls = probe_runner.calls();
    assert_eq!(calls.len(), 1, "Only the failing probe should be executed");
    assert_eq!(calls[0], "probe-fail");
    assert!(
        !calls.contains(&"probe-side-effect".to_string()),
        "probe-side-effect must NOT be speculatively executed (INV-010, EC-037)"
    );
}

#[test]
fn test_lazy_probes_not_executed_speculatively_in_any() {
    let probe_runner = Arc::new(
        MockProbeRunner::new()
            .with_output("probe-pass", "match")
            .with_output("probe-side-effect", "ok"),
    );

    let rules = BTreeMap::new();
    let spec = GuardEvaluationSpec {
        guard_id: "any-lazy-guard".into(),
        order: 1,
        declaration_order: 1,
        action: ActionType::Deny,
        configured_feedback: Some("any lazy feedback".into()),
        scope: "lifecycle:end".into(),
        expression: BoundRuleExpression::Any(vec![
            BoundRuleExpression::Probe {
                command: "probe-pass".into(),
                expected_in: vec!["match".into()],
            },
            BoundRuleExpression::Probe {
                command: "probe-side-effect".into(),
                expected_in: vec!["ok".into()],
            },
        ]),
        matcher_evidence: Vec::new(),
        matcher_evidence_truncated: false,
    };

    let report =
        evaluate_with_fixture_config(&snapshot(), &[spec], &rules, probe_runner.clone(), None)
            .expect("batch evaluation succeeds");

    assert_eq!(report.guard_results.len(), 1);
    let guard_res = &report.guard_results[0];
    assert!(matches!(guard_res.state, GuardResultState::Satisfied));
    assert_eq!(
        guard_res.completeness,
        EvaluationCompleteness::CompleteForGuardResultWithNonCausalSkips,
        "Satisfied Any with skipped remaining probes must report CompleteForGuardResultWithNonCausalSkips"
    );

    let calls = probe_runner.calls();
    assert_eq!(calls.len(), 1, "Only the passing probe should be executed");
    assert_eq!(calls[0], "probe-pass");
    assert!(
        !calls.contains(&"probe-side-effect".to_string()),
        "probe-side-effect must NOT be speculatively executed in Any (INV-010, EC-037)"
    );
}

#[test]
fn test_not_any_inherits_completeness_when_skipping_lazy_probes() {
    let probe_runner = Arc::new(
        MockProbeRunner::new()
            .with_output("probe-pass", "match")
            .with_output("probe-side-effect", "ok"),
    );

    let rules = BTreeMap::new();
    let spec = GuardEvaluationSpec {
        guard_id: "not-any-lazy-guard".into(),
        order: 1,
        declaration_order: 1,
        action: ActionType::Deny,
        configured_feedback: Some("not any lazy feedback".into()),
        scope: "lifecycle:end".into(),
        expression: BoundRuleExpression::Not(Box::new(BoundRuleExpression::Any(vec![
            BoundRuleExpression::Probe {
                command: "probe-pass".into(),
                expected_in: vec!["match".into()],
            },
            BoundRuleExpression::Probe {
                command: "probe-side-effect".into(),
                expected_in: vec!["ok".into()],
            },
        ]))),
        matcher_evidence: Vec::new(),
        matcher_evidence_truncated: false,
    };

    let report =
        evaluate_with_fixture_config(&snapshot(), &[spec], &rules, probe_runner.clone(), None)
            .expect("batch evaluation succeeds");

    assert_eq!(report.guard_results.len(), 1);
    let guard_res = &report.guard_results[0];
    assert!(matches!(guard_res.state, GuardResultState::Violated { .. }));
    assert_eq!(
        guard_res.completeness,
        EvaluationCompleteness::CompleteForGuardResultWithNonCausalSkips,
        "not(any(true, skipped)) must inherit CompleteForGuardResultWithNonCausalSkips"
    );

    let calls = probe_runner.calls();
    assert_eq!(calls.len(), 1, "Only the passing probe should be executed");
    assert_eq!(calls[0], "probe-pass");
    assert!(
        !calls.contains(&"probe-side-effect".to_string()),
        "probe-side-effect must NOT be speculatively executed (INV-010, EC-037)"
    );
}

#[test]
fn test_not_all_inherits_completeness_when_skipping_lazy_probes() {
    let probe_runner = Arc::new(
        MockProbeRunner::new()
            .with_output("probe-fail", "unmatched")
            .with_output("probe-side-effect", "ok"),
    );

    let rules = BTreeMap::new();
    let spec = GuardEvaluationSpec {
        guard_id: "not-all-lazy-guard".into(),
        order: 1,
        declaration_order: 1,
        action: ActionType::Deny,
        configured_feedback: Some("not all lazy feedback".into()),
        scope: "lifecycle:end".into(),
        expression: BoundRuleExpression::Not(Box::new(BoundRuleExpression::All(vec![
            BoundRuleExpression::Probe {
                command: "probe-fail".into(),
                expected_in: vec!["matched".into()],
            },
            BoundRuleExpression::Probe {
                command: "probe-side-effect".into(),
                expected_in: vec!["ok".into()],
            },
        ]))),
        matcher_evidence: Vec::new(),
        matcher_evidence_truncated: false,
    };

    let report =
        evaluate_with_fixture_config(&snapshot(), &[spec], &rules, probe_runner.clone(), None)
            .expect("batch evaluation succeeds");

    assert_eq!(report.guard_results.len(), 1);
    let guard_res = &report.guard_results[0];
    assert!(matches!(guard_res.state, GuardResultState::Satisfied));
    assert_eq!(
        guard_res.completeness,
        EvaluationCompleteness::CompleteForGuardResultWithNonCausalSkips,
        "not(all(false, skipped)) must inherit CompleteForGuardResultWithNonCausalSkips"
    );

    let calls = probe_runner.calls();
    assert_eq!(calls.len(), 1, "Only the failing probe should be executed");
    assert_eq!(calls[0], "probe-fail");
    assert!(
        !calls.contains(&"probe-side-effect".to_string()),
        "probe-side-effect must NOT be speculatively executed (INV-010, EC-037)"
    );
}

#[test]
fn test_nested_rule_ref_evaluation_in_batch() {
    let probe_runner = Arc::new(MockProbeRunner::new().with_output("probe-nested", "deep"));

    let mut rules = BTreeMap::new();
    rules.insert(
        "rule_inner".into(),
        BoundRuleExpression::Probe {
            command: "probe-nested".into(),
            expected_in: vec!["deep".into()],
        },
    );
    rules.insert(
        "rule_outer".into(),
        BoundRuleExpression::RuleRef {
            name: "rule_inner".into(),
        },
    );

    let spec = GuardEvaluationSpec {
        guard_id: "nested-guard".into(),
        order: 1,
        declaration_order: 1,
        action: ActionType::Deny,
        configured_feedback: Some("nested feedback".into()),
        scope: "lifecycle:end".into(),
        expression: BoundRuleExpression::RuleRef {
            name: "rule_outer".into(),
        },
        matcher_evidence: Vec::new(),
        matcher_evidence_truncated: false,
    };

    let report =
        evaluate_with_fixture_config(&snapshot(), &[spec], &rules, probe_runner.clone(), None)
            .expect("batch evaluation succeeds");

    assert_eq!(report.guard_results.len(), 1);
    let guard_res = &report.guard_results[0];
    assert!(matches!(guard_res.state, GuardResultState::Satisfied));
    assert_eq!(guard_res.completeness, EvaluationCompleteness::Complete);
}

#[test]
fn test_rule_cycle_in_planning_does_not_abort_sibling_guards() {
    let probe_runner = Arc::new(MockProbeRunner::new().with_output("probe-healthy", "ok"));

    let mut rules = BTreeMap::new();
    rules.insert(
        "cycle_a".into(),
        BoundRuleExpression::RuleRef {
            name: "cycle_b".into(),
        },
    );
    rules.insert(
        "cycle_b".into(),
        BoundRuleExpression::RuleRef {
            name: "cycle_a".into(),
        },
    );

    let cyclic_spec = GuardEvaluationSpec {
        guard_id: "cyclic-guard".into(),
        order: 1,
        declaration_order: 1,
        action: ActionType::Deny,
        configured_feedback: Some("cyclic feedback".into()),
        scope: "lifecycle:end".into(),
        expression: BoundRuleExpression::RuleRef {
            name: "cycle_a".into(),
        },
        matcher_evidence: Vec::new(),
        matcher_evidence_truncated: false,
    };

    let healthy_spec = GuardEvaluationSpec {
        guard_id: "healthy-guard".into(),
        order: 2,
        declaration_order: 2,
        action: ActionType::Deny,
        configured_feedback: Some("healthy feedback".into()),
        scope: "lifecycle:end".into(),
        expression: BoundRuleExpression::Probe {
            command: "probe-healthy".into(),
            expected_in: vec!["ok".into()],
        },
        matcher_evidence: Vec::new(),
        matcher_evidence_truncated: false,
    };

    let report = evaluate_with_fixture_config(
        &snapshot(),
        &[cyclic_spec, healthy_spec],
        &rules,
        probe_runner,
        None,
    )
    .expect("batch evaluation should not abort due to a planning fault in one guard");

    assert_eq!(report.guard_results.len(), 2);
    let cyclic_res = &report.guard_results[0];
    assert_eq!(cyclic_res.guard_id, "cyclic-guard");
    match &cyclic_res.state {
        GuardResultState::Faulted { faults, .. } => {
            assert!(
                faults.iter().any(|f| matches!(f, EvaluationFault::RuleCycle { rule_name } if rule_name == "cycle_a" || rule_name == "cycle_b")),
                "Cyclic rule must produce EvaluationFault::RuleCycle"
            );
        }
        other => panic!("Expected Faulted state for cyclic rule, got: {:?}", other),
    }

    let healthy_res = &report.guard_results[1];
    assert_eq!(healthy_res.guard_id, "healthy-guard");
    assert!(matches!(healthy_res.state, GuardResultState::Satisfied));
}

#[test]
fn test_resume_decision_preserves_and_reuses_activation_cache() {
    let probe_runner = Arc::new(MockProbeRunner::new().with_output("shared-probe", "ok"));

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
        lifecycle_guards: vec![
            BoundLifecycleGuard {
                id: "guard-1-decide".into(),
                triggers: vec![LifecycleTrigger::End],
                require: BoundRuleExpression::All(vec![
                    BoundRuleExpression::Probe {
                        command: "shared-probe".into(),
                        expected_in: vec!["ok".into()],
                    },
                    BoundRuleExpression::Decide {
                        prompt: "Please approve".into(),
                    },
                ]),
                on_failure: OnFailureConfig {
                    action: ActionType::Ask,
                    feedback: Some("need approval".into()),
                },
                order: 1,
                declaration_order: 1,
            },
            BoundLifecycleGuard {
                id: "guard-2-probe".into(),
                triggers: vec![LifecycleTrigger::End],
                require: BoundRuleExpression::Probe {
                    command: "shared-probe".into(),
                    expected_in: vec!["ok".into()],
                },
                on_failure: OnFailureConfig {
                    action: ActionType::Deny,
                    feedback: Some("shared probe failed".into()),
                },
                order: 2,
                declaration_order: 2,
            },
        ],
        tool_guards: Vec::new(),
        rules: BTreeMap::new(),
    };

    let provider = Arc::new(MockDecisionProvider::new().with_decision("Please approve", true));
    let mut session = ArcRuntimeSession::new("continuation-cache-session", ir)
        .with_probe_runner(probe_runner.clone())
        .with_decision_provider(provider);
    let event = ArcEvent::lifecycle(
        "continuation-cache-session",
        "end-event",
        ArcEventType::End,
        1,
    );

    let eval_result = evaluate_session_event(&mut session, event).expect("evaluation succeeds");

    assert_eq!(
        eval_result.effective_disposition,
        EffectiveDisposition::Continue
    );
    assert!(eval_result.authorization_requirements.is_empty());

    // Shared probe was executed once during Guard 1
    assert_eq!(probe_runner.calls(), vec!["shared-probe"]);

    // INV-022: The activation cache reuses probe results across all guards in the batch!
    // Guard 2 requires "shared-probe", which was already executed and cached in Guard 1.
    // The physical probe runner MUST NOT have been called a second time!
    assert_eq!(
        probe_runner.calls().len(),
        1,
        "shared-probe must be reused from the activation cache across guards in batch"
    );

    // Both evaluations must be satisfied in the session
    assert_eq!(session.active_evaluations.len(), 2);
    assert!(matches!(
        session.active_evaluations[0].state,
        arc::runtime::EvaluationState::Satisfied
    ));
    assert!(matches!(
        session.active_evaluations[1].state,
        arc::runtime::EvaluationState::Satisfied
    ));
}

#[test]
fn planning_fails_closed_when_decision_profile_violates_isolation_contract() {
    let guards = vec![guard("g1", 1, ActionType::Deny, "expected")];
    let probes = Arc::new(MockProbeRunner::new().with_output("probe-g1", "expected"));
    let cache = ActivationEvaluationCache::new("act-invalid-profile");
    let mut bad_profile = DecisionExecutionProfile::default();
    bad_profile.sandbox_mode = "workspace-write".into();

    let err = arc::evaluate_all_guards_with_cache_concurrency(
        &snapshot(),
        &guards,
        &BTreeMap::new(),
        Path::new("."),
        "env-1",
        "runner-1",
        &bad_profile,
        &cache,
        probes,
        None,
        2,
    )
    .unwrap_err();

    match err {
        GuardEvaluationBatchError::Planning { message, .. } => {
            assert!(
                message.contains("invalid decision execution profile"),
                "Expected invalid decision execution profile planning error, got: {message}"
            );
        }
        other => panic!(
            "Expected GuardEvaluationBatchError::Planning, got: {:?}",
            other
        ),
    }
}

#[test]
fn test_session_evaluate_event_consumes_v1_report_and_reducer() {
    let probe_runner = Arc::new(
        MockProbeRunner::new()
            .with_output("probe-deny", "mismatch")
            .with_output("probe-msg", "mismatch"),
    );

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
        lifecycle_guards: vec![
            BoundLifecycleGuard {
                id: "guard-msg".into(),
                triggers: vec![LifecycleTrigger::End],
                require: BoundRuleExpression::Probe {
                    command: "probe-msg".into(),
                    expected_in: vec!["match".into()],
                },
                on_failure: OnFailureConfig {
                    action: ActionType::Message,
                    feedback: Some("msg feedback".into()),
                },
                order: 1,
                declaration_order: 1,
            },
            BoundLifecycleGuard {
                id: "guard-deny".into(),
                triggers: vec![LifecycleTrigger::End],
                require: BoundRuleExpression::Probe {
                    command: "probe-deny".into(),
                    expected_in: vec!["match".into()],
                },
                on_failure: OnFailureConfig {
                    action: ActionType::Deny,
                    feedback: Some("deny feedback".into()),
                },
                order: 2,
                declaration_order: 2,
            },
        ],
        tool_guards: Vec::new(),
        rules: BTreeMap::new(),
    };
    ir.content_hash = Some(ir.compute_content_hash());

    let store = arc::SqliteStateStore::open_in_memory().unwrap();
    let anchor = store
        .trust_and_anchor_ir(Path::new("test-v1.json"), &ir)
        .unwrap();
    let mut session = ArcRuntimeSession::new("test-v1-session", ir)
        .with_trusted_anchor(anchor)
        .unwrap()
        .with_probe_runner(probe_runner.clone());
    let event = ArcEvent::lifecycle("test-v1-session", "end-1", ArcEventType::End, 1);

    let eval_result = evaluate_session_event(&mut session, event).expect("evaluation succeeds");

    // INV-012: Deny takes precedence over Message in the reducer
    assert_eq!(
        eval_result.effective_disposition,
        EffectiveDisposition::Deny
    );
    assert_eq!(eval_result.failure_bundle.failed_guards.len(), 2);
    let deny_feedback = eval_result
        .failure_bundle
        .failed_guards
        .iter()
        .find(|guard| guard.guard_id == "guard-deny")
        .and_then(|guard| guard.configured_feedback.as_deref())
        .unwrap_or_default();
    assert!(
        deny_feedback.contains("deny feedback"),
        "Expected Deny feedback in the aggregate, got: {deny_feedback}"
    );

    // Both guards were evaluated in batch without premature fail-fast
    assert_eq!(session.active_evaluations.len(), 2);
    let guard_ids: Vec<_> = session
        .active_evaluations
        .iter()
        .map(|e| e.guard_id.as_str())
        .collect();
    assert_eq!(guard_ids, vec!["guard-msg", "guard-deny"]);
    assert!(matches!(
        session.active_evaluations[0].state,
        arc::runtime::EvaluationState::Failed
    ));
    assert!(matches!(
        session.active_evaluations[1].state,
        arc::runtime::EvaluationState::Failed
    ));
}

#[test]
fn ec_001_non_command_tool_call_ignores_command_guards_with_wildcard_matcher() {
    let probe_runner = Arc::new(MockProbeRunner::new().with_output("probe-check", "mismatch"));

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
        lifecycle_guards: Vec::new(),
        tool_guards: vec![BoundToolGuard {
            id: "command-guard-wildcard".into(),
            matcher: BoundMatcher {
                exact_patterns: Vec::new(),
                regex_patterns: vec![".*".into()],
            },
            require: BoundRuleExpression::Probe {
                command: "probe-check".into(),
                expected_in: vec!["match".into()],
            },
            on_failure: OnFailureConfig {
                action: ActionType::Deny,
                feedback: Some("Should never trigger on non-command tools".into()),
            },
            order: 1,
            declaration_order: 1,
        }],
        rules: BTreeMap::new(),
    };

    let mut session = ArcRuntimeSession::new("test-non-command-session", ir)
        .with_probe_runner(probe_runner.clone());

    let event = ArcEvent::non_command_tool_call(
        "test-non-command-session",
        "tool-1",
        1,
        "read_file",
        serde_json::json!({ "path": "test.txt" }),
    );

    // 1. Aggregate evaluation report directly: EC-001 (0 guards applicable, disposition Continue)
    let decision_profile = DecisionExecutionProfile {
        provider: ProviderTarget::Codex,
        transport: "fixture".into(),
        model: None,
        adapter_contract_fingerprint: "adapter".into(),
        output_schema_fingerprint: "schema".into(),
        sandbox_mode: "read_only".into(),
        approval_policy: "never".into(),
    };
    let report = session
        .evaluate_event_report(event.clone(), decision_profile, Path::new("."), 10_000)
        .expect("report evaluation succeeds");
    assert!(
        report.guard_results.is_empty(),
        "Non-command tool call must not match any command tool guards (EC-001)"
    );
    assert_eq!(
        report.effective_disposition,
        EffectiveDisposition::Continue,
        "Zero matching guards must yield EffectiveDisposition::Continue"
    );

    // 3. The canonical aggregate carries the empty authorization collection explicitly.
    assert!(report.authorization_requirements.is_empty());

    // 4. Full session evaluation returns EffectiveDisposition::Continue without evaluating command guard
    let event_result =
        evaluate_session_event(&mut session, event).expect("session evaluation succeeds");
    assert_eq!(
        event_result.effective_disposition,
        EffectiveDisposition::Continue
    );
}

#[test]
fn command_tool_call_still_matches_wildcard_and_evaluates_guard() {
    let probe_runner = Arc::new(MockProbeRunner::new().with_output("probe-check", "mismatch"));

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
        tool_guards: vec![BoundToolGuard {
            id: "command-guard-wildcard".into(),
            matcher: BoundMatcher {
                exact_patterns: Vec::new(),
                regex_patterns: vec![".*".into()],
            },
            require: BoundRuleExpression::Probe {
                command: "probe-check".into(),
                expected_in: vec!["match".into()],
            },
            on_failure: OnFailureConfig {
                action: ActionType::Deny,
                feedback: Some("Denied command".into()),
            },
            order: 1,
            declaration_order: 1,
        }],
        rules: BTreeMap::new(),
    };
    ir.content_hash = Some(ir.compute_content_hash());

    let store = arc::SqliteStateStore::open_in_memory().unwrap();
    let anchor = store
        .trust_and_anchor_ir(Path::new("test-cmd.json"), &ir)
        .unwrap();
    let mut session = ArcRuntimeSession::new("test-command-session", ir)
        .with_trusted_anchor(anchor)
        .unwrap()
        .with_probe_runner(probe_runner);

    let event = ArcEvent::tool_call("test-command-session", "tool-2", 1, "bash", "rm -rf /");

    let event_result =
        evaluate_session_event(&mut session, event).expect("session evaluation succeeds");
    assert_eq!(
        event_result.effective_disposition,
        EffectiveDisposition::Deny
    );
    assert_eq!(
        event_result.failure_bundle.failed_guards[0]
            .configured_feedback
            .as_deref(),
        Some("Denied command")
    );
}

#[test]
fn gea_002_probe_mismatch_preserves_deterministic_evidence_and_bundle() {
    let guards = vec![guard(
        "probe-check-guard",
        1,
        ActionType::Deny,
        "expected_output",
    )];
    let observed_output = "actual_output_mismatch";
    let probes =
        Arc::new(MockProbeRunner::new().with_output("probe-probe-check-guard", observed_output));

    let report = evaluate_with_fixture_config(&snapshot(), &guards, &BTreeMap::new(), probes, None)
        .expect("all guards evaluate");

    assert_eq!(report.guard_results.len(), 1);
    let guard_result = &report.guard_results[0];
    let GuardResultState::Violated { causes } = &guard_result.state else {
        panic!("expected Violated state, got {:?}", guard_result.state);
    };

    assert_eq!(causes.len(), 1);
    let cause = &causes[0];
    assert_eq!(cause.kind, arc::FailureCauseKind::ProbeMismatch);
    assert_eq!(
        cause.summary,
        "probe 'probe-probe-check-guard' did not match an expected value"
    );
    assert_eq!(cause.deterministic_evidence.len(), 1);

    let evidence = &cause.deterministic_evidence[0];
    assert_eq!(evidence.operation, "probe-probe-check-guard");
    assert_eq!(evidence.expected_values, vec!["expected_output"]);
    assert_eq!(evidence.result, false);
    let expected_hash = arc::fingerprint(observed_output.as_bytes());
    assert_eq!(evidence.observed_sha256, expected_hash);

    // Validate the cause contract bounds
    cause.validate().expect("FailureCause validates");

    // Verify FailureBundle preserves the cause with its deterministic evidence
    let ir = behavior_ir_for_specs(&guards);
    let store = arc::SqliteStateStore::open_in_memory().unwrap();
    let anchor = store
        .trust_and_anchor_ir(Path::new("test-ev.json"), &ir)
        .unwrap();
    let bundle = arc::FailureBundle::from_report_with_trusted_anchor(&report, &ir, &anchor)
        .expect("FailureBundle from report with specs");
    assert_eq!(bundle.failed_guards.len(), 1);
    let failed_guard = &bundle.failed_guards[0];
    assert_eq!(failed_guard.guard_id, "probe-check-guard");
    assert_eq!(failed_guard.causes.len(), 1);
    assert_eq!(failed_guard.causes[0].deterministic_evidence.len(), 1);
    assert_eq!(failed_guard.causes[0].deterministic_evidence[0], *evidence);

    // Verify bundle validates contract
    bundle.validate().expect("FailureBundle validates");

    // Verify serialization for provider feedback preserves the evidence intact
    let serialized_bundle = serde_json::to_string(&bundle).expect("serialize bundle");
    assert!(!serialized_bundle.contains("actual_output_mismatch")); // Raw output is not leaked
    assert!(serialized_bundle.contains(&expected_hash)); // Observed sha256 is present
    assert!(serialized_bundle.contains("expected_output")); // Expected value is present
    assert!(serialized_bundle.contains("\"result\":false")); // Result is false
}

#[test]
fn empty_expected_probe_output_keeps_codex_stop_as_ask() {
    let guards = vec![guard("empty-output-ask", 1, ActionType::Ask, "")];
    let ir = behavior_ir_for_specs(&guards);
    let store = arc::SqliteStateStore::open_in_memory().unwrap();
    let anchor = store
        .trust_and_anchor_ir(Path::new("empty-expected-stop.json"), &ir)
        .unwrap();
    let probes =
        Arc::new(MockProbeRunner::new().with_output("probe-empty-output-ask", " M src/main.rs"));
    let mut session = ArcRuntimeSession::new("codex-empty-output-stop", ir)
        .with_trusted_anchor(anchor)
        .unwrap()
        .with_probe_runner(probes);

    let event = ArcEvent::lifecycle(
        "codex-empty-output-stop",
        "event-stop",
        ArcEventType::End,
        1,
    );
    let result = evaluate_session_event(&mut session, event)
        .expect("dirty worktree returns the configured Ask instead of a runtime fault");
    assert_eq!(result.effective_disposition, EffectiveDisposition::Ask);
    assert_eq!(
        result.failure_bundle.failed_guards[0].causes[0].deterministic_evidence[0].expected_values,
        vec![""]
    );
}

#[test]
fn empty_expected_probe_output_reaches_codex_and_gemini_deny_adapters() {
    for (provider, session_id) in [
        (ProviderTarget::Codex, "codex-empty-probe-output"),
        (ProviderTarget::Gemini, "gemini-empty-probe-output"),
    ] {
        let mut ir = behavior_ir_for_specs(&[]);
        ir.tool_guards.push(BoundToolGuard {
            id: "dirty-deploy".into(),
            matcher: BoundMatcher {
                exact_patterns: vec!["npm run deploy:prod".into()],
                regex_patterns: Vec::new(),
            },
            require: BoundRuleExpression::Probe {
                command: "git status --porcelain".into(),
                expected_in: vec![String::new()],
            },
            on_failure: OnFailureConfig {
                action: ActionType::Deny,
                feedback: Some("Commit or discard pending changes before deploying.".into()),
            },
            order: 1,
            declaration_order: 0,
        });
        ir.content_hash = Some(ir.compute_content_hash());

        let store = arc::SqliteStateStore::open_in_memory().unwrap();
        let anchor = store
            .trust_and_anchor_ir(Path::new("empty-probe-output-deploy.json"), &ir)
            .unwrap();
        let profile = DecisionExecutionProfile {
            provider,
            ..DecisionExecutionProfile::default()
        };
        let probes = Arc::new(
            MockProbeRunner::new().with_output("git status --porcelain", " M src/main.rs"),
        );
        let mut session = ArcRuntimeSession::new(session_id, ir)
            .with_trusted_anchor(anchor)
            .unwrap()
            .with_probe_runner(probes)
            .with_decision_profile(profile);

        let event =
            ArcEvent::tool_call(session_id, "event-deploy", 1, "bash", "npm run deploy:prod");
        let result = evaluate_session_event(&mut session, event)
            .expect("dirty deploy returns the configured Deny instead of a runtime fault");
        assert_eq!(result.effective_disposition, EffectiveDisposition::Deny);
        assert_eq!(
            result.failure_bundle.failed_guards[0].causes[0].deterministic_evidence[0]
                .expected_values,
            vec![""]
        );

        match provider {
            ProviderTarget::Codex => {
                let output = CodexAdapter::evaluation_result_to_pre_tool_use_output(&result)
                    .expect("Codex adapter emits a normal Deny");
                assert_eq!(
                    output.hook_specific_output.unwrap().permission_decision,
                    "deny"
                );
            }
            ProviderTarget::Gemini => {
                let output = AgyAdapter::evaluation_result_to_pre_tool_use_output(&result)
                    .expect("Gemini adapter emits a normal Deny");
                assert_eq!(output.decision, "deny");
            }
            _ => panic!("unexpected provider in regression cases: {provider:?}"),
        }
    }
}

#[test]
fn gea_002_consumed_exact_authorization_included_in_aggregate_report_and_active_evaluations() {
    use arc::GuardExecutionStateStore;

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
        lifecycle_guards: Vec::new(),
        tool_guards: vec![
            BoundToolGuard {
                id: "guard-tool-auth".into(),
                matcher: BoundMatcher {
                    exact_patterns: Vec::new(),
                    regex_patterns: vec!["^git push --force".into()],
                },
                require: BoundRuleExpression::Probe {
                    command: "git branch".into(),
                    expected_in: vec!["feature".into()],
                },
                on_failure: OnFailureConfig {
                    action: ActionType::Deny,
                    feedback: Some("Force push forbidden".into()),
                },
                order: 1,
                declaration_order: 0,
            },
            BoundToolGuard {
                id: "guard-tool-second".into(),
                matcher: BoundMatcher {
                    exact_patterns: Vec::new(),
                    regex_patterns: vec!["^git push".into()],
                },
                require: BoundRuleExpression::Probe {
                    command: "git status".into(),
                    expected_in: vec!["clean".into()],
                },
                on_failure: OnFailureConfig {
                    action: ActionType::Ask,
                    feedback: Some("Uncommitted changes".into()),
                },
                order: 2,
                declaration_order: 1,
            },
        ],
        rules: BTreeMap::new(),
    };

    let probe_runner = Arc::new(
        MockProbeRunner::new()
            .with_output("git branch", "main")
            .with_output("git status", "dirty"),
    );

    let state_store = Arc::new(arc::InMemoryStateStore::default());

    let ev = ArcEvent::tool_call(
        "test-session-auth",
        "ev-tool-1",
        1,
        "bash",
        "git push --force origin main",
    );

    let current_op = arc::CurrentOperation::from(&ev);
    let op_fp = arc::exact_operation_fingerprint(&current_op);
    let args_fp = arc::normalized_arguments_fingerprint(&current_op);

    // Pre-record exact operation authorization for 1 use for guard-tool-auth
    let auth = arc::ExactOperationAuthorization {
        guard_id: "guard-tool-auth".into(),
        operation_fingerprint: op_fp.clone(),
        event_id: "ev-tool-1".into(),
        tool: "bash".into(),
        normalized_arguments_fingerprint: args_fp,
    };
    let auth_context = exact_authorization_context(
        std::slice::from_ref(&auth),
        "ev-tool-1",
        "bash",
        "ws-auth",
        "test-session-auth",
        "invocation-auth-1",
        "policy-auth",
        "evidence-auth",
    );
    state_store
        .record_exact_authorization(&auth, &auth_context, Some("waiver-1"), i64::MAX, 1)
        .unwrap();

    let mut session = ArcRuntimeSession::new("test-session-auth", ir)
        .with_probe_runner(probe_runner.clone())
        .with_state_store(state_store.clone());

    let decision_profile = DecisionExecutionProfile {
        provider: ProviderTarget::Codex,
        transport: "fixture".into(),
        model: None,
        adapter_contract_fingerprint: "adapter".into(),
        output_schema_fingerprint: "schema".into(),
        sandbox_mode: "read_only".into(),
        approval_policy: "never".into(),
    };

    // 1. Evaluate event report
    let report = session
        .evaluate_event_report(ev.clone(), decision_profile.clone(), Path::new("."), 10_000)
        .expect("evaluate_event_report succeeds");

    // Both guards must be present in guard_results!
    assert_eq!(report.guard_results.len(), 2);

    // First guard evaluated honestly against real probe -> Violated (C-08/F-03: no fake All([]) substitution)
    assert_eq!(report.guard_results[0].guard_id, "guard-tool-auth");
    assert!(matches!(
        report.guard_results[0].state,
        GuardResultState::Violated { .. }
    ));

    // Second guard failed probe -> Violated
    assert_eq!(report.guard_results[1].guard_id, "guard-tool-second");
    assert!(matches!(
        report.guard_results[1].state,
        GuardResultState::Violated { .. }
    ));

    // Both guards must be recorded symmetrically in session.active_evaluations
    assert_eq!(session.active_evaluations.len(), 2);
    assert_eq!(session.active_evaluations[0].guard_id, "guard-tool-auth");
    assert_eq!(
        session.active_evaluations[0].state,
        arc::EvaluationState::Failed
    );
    assert_eq!(session.active_evaluations[1].guard_id, "guard-tool-second");
    assert_eq!(
        session.active_evaluations[1].state,
        arc::EvaluationState::Failed
    );

    // Symmetrical invariant: active_evaluations and report.guard_results describe the identical set of guards
    assert_eq!(report.guard_results.len(), session.active_evaluations.len());

    // 2. Second event with the same operation: the 1-use authorization was consumed!
    let ev2 = ArcEvent::tool_call(
        "test-session-auth",
        "ev-tool-2",
        2,
        "bash",
        "git push --force origin main",
    );
    let report2 = session
        .evaluate_event_report(ev2, decision_profile, Path::new("."), 10_000)
        .expect("evaluate_event_report succeeds");

    assert_eq!(report2.guard_results.len(), 2);
    // Now guard-tool-auth is Violated because the authorization was already exhausted
    assert_eq!(report2.guard_results[0].guard_id, "guard-tool-auth");
    assert!(matches!(
        report2.guard_results[0].state,
        GuardResultState::Violated { .. }
    ));
}

#[test]
fn gea_002_evaluate_event_eliminates_primer_fallo_gana_for_decisions_and_asks() {
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
                id: "guard_tool_decide".into(),
                matcher: BoundMatcher {
                    exact_patterns: Vec::new(),
                    regex_patterns: vec!["^git push".into()],
                },
                require: BoundRuleExpression::Decide {
                    prompt: "Authorize force push?".into(),
                },
                on_failure: OnFailureConfig {
                    action: ActionType::Ask,
                    feedback: Some("Prompt decide feedback".into()),
                },
                order: 0,
                declaration_order: 0,
            },
            BoundToolGuard {
                id: "guard_tool_ask_probe".into(),
                matcher: BoundMatcher {
                    exact_patterns: Vec::new(),
                    regex_patterns: vec!["^git push".into()],
                },
                require: BoundRuleExpression::Probe {
                    command: "verify_repo_state".into(),
                    expected_in: vec!["clean".into()],
                },
                on_failure: OnFailureConfig {
                    action: ActionType::Ask,
                    feedback: Some("Working tree is dirty".into()),
                },
                order: 0,
                declaration_order: 1,
            },
        ],
        rules: BTreeMap::new(),
    };
    ir.content_hash = Some(ir.compute_content_hash());

    let probe_runner = Arc::new(MockProbeRunner::new().with_output("verify_repo_state", "dirty"));
    let provider =
        Arc::new(MockDecisionProvider::new().with_decision("Authorize force push?", false));
    let store = arc::SqliteStateStore::open_in_memory().unwrap();
    let anchor = store
        .trust_and_anchor_ir(Path::new("test-gea002.json"), &ir)
        .unwrap();
    let mut session = ArcRuntimeSession::new("test-session-gea002", ir)
        .with_trusted_anchor(anchor)
        .unwrap()
        .with_probe_runner(probe_runner)
        .with_decision_provider(provider);

    let event = ArcEvent::tool_call(
        "test-session-gea002",
        "ev-tool-push",
        1,
        "bash",
        "git push origin main",
    );

    // 1. Evaluate event: must NOT drop the probe ask failure in favor of decision only!
    let eval_result =
        evaluate_session_event(&mut session, event).expect("session evaluation succeeds");
    assert_eq!(eval_result.effective_disposition, EffectiveDisposition::Ask);
    assert_eq!(eval_result.failure_bundle.failed_guards.len(), 2);
    assert_eq!(
        eval_result.failure_bundle.failed_guards[0].guard_id,
        "guard_tool_decide"
    );
    assert_eq!(
        eval_result.failure_bundle.failed_guards[0]
            .configured_feedback
            .as_deref(),
        Some("Prompt decide feedback")
    );
    assert_eq!(
        eval_result.failure_bundle.failed_guards[1].guard_id,
        "guard_tool_ask_probe"
    );
    assert_eq!(
        eval_result.failure_bundle.failed_guards[1]
            .configured_feedback
            .as_deref(),
        Some("Working tree is dirty")
    );

    // 2. Both guards must already be evaluated and present in active_evaluations
    assert_eq!(session.active_evaluations.len(), 2);
    assert_eq!(session.active_evaluations[0].guard_id, "guard_tool_decide");
    assert_eq!(
        session.active_evaluations[0].state,
        arc::EvaluationState::Failed
    );
    assert_eq!(
        session.active_evaluations[1].guard_id,
        "guard_tool_ask_probe"
    );
    assert_eq!(
        session.active_evaluations[1].state,
        arc::EvaluationState::Failed
    );
}

#[test]
fn test_c02_rejects_authorization_for_guard_absent_from_report() {
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
        lifecycle_guards: Vec::new(),
        tool_guards: vec![BoundToolGuard {
            id: "guard-ask-simultaneous".into(),
            matcher: BoundMatcher {
                exact_patterns: vec!["git push".into()],
                regex_patterns: Vec::new(),
            },
            require: BoundRuleExpression::Probe {
                command: "git branch".into(),
                expected_in: vec!["feature".into()],
            },
            on_failure: OnFailureConfig {
                action: ActionType::Ask,
                feedback: Some("Branch is not feature".into()),
            },
            order: 1,
            declaration_order: 0,
        }],
        rules: BTreeMap::new(),
    };

    let probes = Arc::new(MockProbeRunner::new().with_output("git branch", "main"));
    let mut session = ArcRuntimeSession::new("test-c02", ir).with_probe_runner(probes);
    let mut report = session
        .evaluate_event_report(
            ArcEvent::tool_call("test-c02", "ev-c02-1", 1, "bash", "git push"),
            DecisionExecutionProfile {
                provider: ProviderTarget::Codex,
                transport: "fixture".into(),
                model: None,
                adapter_contract_fingerprint: "adapter".into(),
                output_schema_fingerprint: "schema".into(),
                sandbox_mode: "read_only".into(),
                approval_policy: "never".into(),
            },
            Path::new("."),
            10_000,
        )
        .expect("report generated");

    assert_eq!(report.effective_disposition, EffectiveDisposition::Ask);

    // Inject an authorization requirement to simulate simultaneous interactive domains
    report
        .authorization_requirements
        .push(ExactOperationAuthorization {
            guard_id: "guard-auth-other".into(),
            operation_fingerprint: "op-fp-1".into(),
            event_id: "ev-c02-1".into(),
            tool: "bash".into(),
            normalized_arguments_fingerprint: "args-fp-1".into(),
        });

    // An authorization for a Guard outside this activation must fail closed.
    let bundle = FailureBundle::from_report(&report).expect("bundle derives");
    let error = ArcEvaluationResult::from_report_and_bundle(report.clone(), bundle)
        .expect_err("foreign authorization must not enter the aggregate");
    match error {
        arc::ArcEvaluationError::InvalidReport { reason } => assert!(
            reason.contains("authorization_requirements.guard_id")
                && reason.contains("guard_results.guard_id"),
            "unexpected rejection reason: {reason}"
        ),
        other => panic!("expected InvalidReport, got: {other:?}"),
    }

    // A requirement tied to the evaluated Guard remains lossless.
    report.authorization_requirements[0].guard_id = "guard-ask-simultaneous".into();
    let bundle = FailureBundle::from_report(&report).expect("bundle derives");
    let result = ArcEvaluationResult::from_report_and_bundle(report.clone(), bundle)
        .expect("matching authorization remains aggregate data");
    assert_eq!(result.effective_disposition, EffectiveDisposition::Ask);
    assert_eq!(result.authorization_requirements.len(), 1);
    assert_eq!(
        result.authorization_requirements[0].guard_id,
        "guard-ask-simultaneous"
    );
    assert_eq!(result.failure_bundle.failed_guards.len(), 1);
    assert_eq!(
        result.failure_bundle.failed_guards[0].guard_id,
        "guard-ask-simultaneous"
    );
    assert_eq!(result.report.guard_results.len(), 1);
}

struct EchoAllowPresenter;

impl arc::DecisionPresenter for EchoAllowPresenter {
    fn present(
        &self,
        request: &arc::DialogRequest,
        _timeout: std::time::Duration,
    ) -> anyhow::Result<arc::DialogResponse> {
        Ok(arc::DialogResponse {
            schema: arc::DIALOG_RESPONSE_SCHEMA.into(),
            request_id: request.request_id.clone(),
            bundle_fingerprint: request.bundle_fingerprint.clone(),
            decision: arc::decision_ui::PortableDecision::Allow,
            transport: "arc_embedded_ui".into(),
            theme: "dark".into(),
            message: Some("Approved by user in test".into()),
        })
    }
}

#[test]
fn test_c02_aggregate_lossless_delivery_to_coordinator_and_resolution() {
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
        lifecycle_guards: Vec::new(),
        tool_guards: vec![
            BoundToolGuard {
                id: "guard-ask-fail".into(),
                matcher: BoundMatcher {
                    exact_patterns: vec!["git push".into()],
                    regex_patterns: Vec::new(),
                },
                require: BoundRuleExpression::Probe {
                    command: "git branch".into(),
                    expected_in: vec!["feature".into()],
                },
                on_failure: OnFailureConfig {
                    action: ActionType::Ask,
                    feedback: Some("Branch is not feature".into()),
                },
                order: 1,
                declaration_order: 0,
            },
            BoundToolGuard {
                id: "guard-auth-decide".into(),
                matcher: BoundMatcher {
                    exact_patterns: vec!["git push".into()],
                    regex_patterns: Vec::new(),
                },
                require: BoundRuleExpression::Decide {
                    prompt: "Audit git push operation".into(),
                },
                on_failure: OnFailureConfig {
                    action: ActionType::Deny,
                    feedback: Some("Audit declined".into()),
                },
                order: 2,
                declaration_order: 1,
            },
        ],
        rules: BTreeMap::new(),
    };

    let probes = Arc::new(MockProbeRunner::new().with_output("git branch", "main"));
    let decision_provider = Arc::new(MockDecisionProvider::new().with_verdict(
        "Audit git push operation",
        arc::DecisionVerdict {
            decision: true,
            findings: Some("The audit found no policy conflict for this operation.".into()),
        },
    ));
    let state_store = Arc::new(arc::InMemoryStateStore::default());

    let mut session = ArcRuntimeSession::new("test-c02-e2e", ir)
        .with_probe_runner(probes)
        .with_decision_provider(decision_provider)
        .with_state_store(state_store.clone());

    let observed = arc::HookObservationContext::new("codex", "test-c02-e2e", "inv-c02-e2e")
        .with_workspace("ws-c02")
        .with_turn("turn-c02");

    let event = ArcEvent::tool_call("test-c02-e2e", "ev-c02-e2e", 1, "bash", "git push");
    let operation = arc::CurrentOperation::from(&event);

    // 1. evaluate_guard_with_observability produces ArcEvaluationResult with simultaneous Ask + exact authorization
    let eval_result =
        arc::evaluate_guard_with_observability(&mut session, event.clone(), &None, &observed)
            .expect("observability evaluation succeeds");

    assert_eq!(eval_result.effective_disposition, EffectiveDisposition::Ask);
    assert_eq!(eval_result.authorization_requirements.len(), 1);
    assert_eq!(
        eval_result.authorization_requirements[0].guard_id,
        "guard-auth-decide"
    );
    let authorized_guard = eval_result
        .report
        .guard_results
        .iter()
        .find(|result| result.guard_id == "guard-auth-decide")
        .expect("authorization guard is in the report");
    assert!(matches!(
        &authorized_guard.state,
        GuardResultState::Satisfied
    ));
    assert_eq!(
        authorized_guard.satisfied_attributions[0]
            .auditor_findings
            .as_deref(),
        Some("The audit found no policy conflict for this operation.")
    );
    assert_eq!(eval_result.failure_bundle.failed_guards.len(), 1);
    assert_eq!(
        eval_result.failure_bundle.failed_guards[0].guard_id,
        "guard-ask-fail"
    );

    // 2. interactive_decision_request_from_evaluation_result delivers the complete aggregate losslessly
    let request = arc::interactive_decision_request_from_evaluation_result(
        &eval_result,
        ProviderTarget::Codex,
        ArcEventType::ToolCall,
        &event.event_id,
        "inv-c02-e2e",
        Some(operation),
        Some("bash git push".into()),
        "this exact tool call once",
    )
    .expect("build interactive request succeeds")
    .expect("interactive request must be Some for Ask disposition");

    // Verify all Guards, exact authorizations, and failure bundle are correlated in request
    assert_eq!(request.guards().len(), 1);
    assert_eq!(request.guards()[0].guard_id(), "guard-ask-fail");
    assert!(request.exact_authorizations().is_some());
    let req_auths = request.exact_authorizations().unwrap();
    assert_eq!(req_auths.len(), 1);
    assert_eq!(req_auths[0].guard_id, "guard-auth-decide");
    let dialog = request.to_dialog_request("Decision required");
    assert_eq!(
        dialog.authorizations[0].auditor_findings.as_deref(),
        Some("The audit found no policy conflict for this operation.")
    );
    assert!(request.failure_bundle().is_some());
    assert_eq!(
        request.failure_bundle().unwrap().failed_guards[0].guard_id,
        "guard-ask-fail"
    );
    assert!(request.evaluation_result().is_some());
    assert_eq!(
        request.evaluation_result().unwrap().effective_disposition,
        EffectiveDisposition::Ask
    );

    // 3. Dispatch through orchestrator to obtain resolution
    let orchestrator = arc::InteractiveDecisionOrchestrator::with_presenter(
        arc::OsTarget::host().expect("supported host"),
        arc::DecisionUiMode::Native,
        std::time::Duration::from_secs(5),
        Arc::new(EchoAllowPresenter),
    );

    let dispatch = orchestrator
        .dispatch(request)
        .expect("orchestrator dispatch succeeds");

    let resolution = match dispatch {
        arc::InteractiveDecisionDispatch::Presented { resolution, .. } => resolution,
        other => panic!("Expected Presented resolution, got: {other:?}"),
    };

    // 4. Verify resolution preserves the complete aggregate, authorizations, and failures
    assert_eq!(
        resolution.portable_decision(),
        arc::decision_ui::PortableDecision::Allow
    );
    assert_eq!(resolution.user_message(), Some("Approved by user in test"));
    let resolved_req = resolution.request();
    assert_eq!(resolved_req.guards().len(), 1);
    assert_eq!(resolved_req.guards()[0].guard_id(), "guard-ask-fail");
    assert!(resolved_req.exact_authorizations().is_some());
    let resolved_auths = resolved_req.exact_authorizations().unwrap();
    assert_eq!(resolved_auths.len(), 1);
    assert_eq!(resolved_auths[0].guard_id, "guard-auth-decide");
    assert!(resolved_req.failure_bundle().is_some());
    assert_eq!(
        resolved_req.failure_bundle().unwrap().failed_guards[0].guard_id,
        "guard-ask-fail"
    );
    assert!(resolved_req.evaluation_result().is_some());

    // 5. Apply resolution: ensure effective disposition is overridable, record authorization batch
    let req_eval = resolved_req.evaluation_result().unwrap();
    assert_ne!(req_eval.effective_disposition, EffectiveDisposition::Deny);
    assert_ne!(
        req_eval.effective_disposition,
        EffectiveDisposition::RuntimeFault
    );

    let auths_to_record = resolved_req
        .exact_authorizations()
        .unwrap_or(&req_eval.authorization_requirements);
    assert_eq!(auths_to_record.len(), 1);
    let auth_context = exact_authorization_context(
        auths_to_record,
        "ev-c02-e2e",
        "bash",
        "ws-c02",
        "test-c02-e2e",
        "inv-c02-e2e",
        &req_eval.report.report_fingerprint,
        &req_eval.failure_bundle.bundle_fingerprint,
    );

    state_store
        .record_exact_authorizations_bundle(
            auths_to_record,
            &auth_context,
            resolution.decision_id(),
            i64::MAX,
            1,
        )
        .expect("record exact authorizations bundle succeeds");

    // Verify the exact authorization is now active in durable state
    assert!(
        state_store
            .has_valid_exact_authorization(&auths_to_record[0], &auth_context, 1000,)
            .expect("query state store succeeds")
    );
}

#[test]
fn test_c02_structurally_invalid_inputs() {
    let report = snapshot_report();

    // 1. Duplicate guard_id in authorization_requirements is structurally invalid
    let mut dup_report = report.clone();
    dup_report.authorization_requirements = vec![
        ExactOperationAuthorization {
            guard_id: "guard-dup".into(),
            operation_fingerprint: "op1".into(),
            event_id: dup_report.event_id.clone(),
            tool: "bash".into(),
            normalized_arguments_fingerprint: "arg1".into(),
        },
        ExactOperationAuthorization {
            guard_id: "guard-dup".into(),
            operation_fingerprint: "op2".into(),
            event_id: dup_report.event_id.clone(),
            tool: "bash".into(),
            normalized_arguments_fingerprint: "arg2".into(),
        },
    ];
    let dup_bundle = FailureBundle::from_report(&dup_report).unwrap();
    assert!(ArcEvaluationResult::from_report_and_bundle(dup_report, dup_bundle).is_err());

    // 2. Mismatched event_id in authorization_requirements is structurally invalid
    let mut mismatch_report = report.clone();
    mismatch_report.authorization_requirements = vec![ExactOperationAuthorization {
        guard_id: "guard-mismatch".into(),
        operation_fingerprint: "op1".into(),
        event_id: "mismatched-event-id".into(),
        tool: "bash".into(),
        normalized_arguments_fingerprint: "arg1".into(),
    }];
    let mismatch_bundle = FailureBundle::from_report(&mismatch_report).unwrap();
    assert!(ArcEvaluationResult::from_report_and_bundle(mismatch_report, mismatch_bundle).is_err());
}

#[test]
fn test_c03_multiple_ask_guards_preserved_in_aggregate_result() {
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
        lifecycle_guards: Vec::new(),
        tool_guards: vec![
            BoundToolGuard {
                id: "ask-g1".into(),
                matcher: BoundMatcher {
                    exact_patterns: vec!["git push".into()],
                    regex_patterns: Vec::new(),
                },
                require: BoundRuleExpression::Probe {
                    command: "git branch".into(),
                    expected_in: vec!["feature".into()],
                },
                on_failure: OnFailureConfig {
                    action: ActionType::Ask,
                    feedback: Some("Feedback 1".into()),
                },
                order: 1,
                declaration_order: 0,
            },
            BoundToolGuard {
                id: "ask-g2".into(),
                matcher: BoundMatcher {
                    exact_patterns: vec!["git push".into()],
                    regex_patterns: Vec::new(),
                },
                require: BoundRuleExpression::Probe {
                    command: "git status".into(),
                    expected_in: vec!["clean".into()],
                },
                on_failure: OnFailureConfig {
                    action: ActionType::Ask,
                    feedback: Some("Feedback 2".into()),
                },
                order: 2,
                declaration_order: 1,
            },
            BoundToolGuard {
                id: "ask-g3".into(),
                matcher: BoundMatcher {
                    exact_patterns: vec!["git push".into()],
                    regex_patterns: Vec::new(),
                },
                require: BoundRuleExpression::Probe {
                    command: "git remote".into(),
                    expected_in: vec!["origin".into()],
                },
                on_failure: OnFailureConfig {
                    action: ActionType::Ask,
                    feedback: Some("Feedback 3".into()),
                },
                order: 3,
                declaration_order: 2,
            },
        ],
        rules: BTreeMap::new(),
    };

    let probes = Arc::new(
        MockProbeRunner::new()
            .with_output("git branch", "main")
            .with_output("git status", "dirty")
            .with_output("git remote", "upstream"),
    );

    let mut session = ArcRuntimeSession::new("test-c03", ir).with_probe_runner(probes);
    let result = session
        .evaluate_event_aggregate(
            ArcEvent::tool_call("test-c03", "ev-c03-1", 1, "bash", "git push"),
            DecisionExecutionProfile {
                provider: ProviderTarget::Codex,
                transport: "fixture".into(),
                model: None,
                adapter_contract_fingerprint: "adapter".into(),
                output_schema_fingerprint: "schema".into(),
                sandbox_mode: "read_only".into(),
                approval_policy: "never".into(),
            },
            Path::new("."),
            10_000,
        )
        .expect("evaluate_event_aggregate succeeds");

    assert_eq!(result.effective_disposition, EffectiveDisposition::Ask);
    assert_eq!(result.report.guard_results.len(), 3);
    for gr in &result.report.guard_results {
        assert!(matches!(gr.state, GuardResultState::Violated { .. }));
    }

    // FailureBundle preserves all 3 failed guards without dropping any for a primary guard
    assert_eq!(result.failure_bundle.failed_guards.len(), 3);
    assert_eq!(result.failure_bundle.failed_guards[0].guard_id, "ask-g1");
    assert_eq!(result.failure_bundle.failed_guards[1].guard_id, "ask-g2");
    assert_eq!(result.failure_bundle.failed_guards[2].guard_id, "ask-g3");
}

#[test]
fn test_c04_message_with_pending_authorizations_requires_authorization() {
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
        lifecycle_guards: Vec::new(),
        tool_guards: vec![BoundToolGuard {
            id: "msg-guard".into(),
            matcher: BoundMatcher {
                exact_patterns: vec!["cargo build".into()],
                regex_patterns: Vec::new(),
            },
            require: BoundRuleExpression::Probe {
                command: "rustc --version".into(),
                expected_in: vec!["nightly".into()],
            },
            on_failure: OnFailureConfig {
                action: ActionType::Message,
                feedback: Some("Not on nightly".into()),
            },
            order: 1,
            declaration_order: 0,
        }],
        rules: BTreeMap::new(),
    };

    let probes = Arc::new(MockProbeRunner::new().with_output("rustc --version", "nightly"));
    let mut session = ArcRuntimeSession::new("test-c04", ir).with_probe_runner(probes);

    // 1. Message guard is satisfied alone -> Continue outcome
    let ev = ArcEvent::tool_call("test-c04", "ev-c04-1", 1, "bash", "cargo build");
    let mut report = session
        .evaluate_event_report(
            ev,
            DecisionExecutionProfile {
                provider: ProviderTarget::Codex,
                transport: "fixture".into(),
                model: None,
                adapter_contract_fingerprint: "adapter".into(),
                output_schema_fingerprint: "schema".into(),
                sandbox_mode: "read_only".into(),
                approval_policy: "never".into(),
            },
            Path::new("."),
            10_000,
        )
        .expect("report succeeds");

    assert_eq!(report.guard_results[0].state, GuardResultState::Satisfied);
    assert_eq!(report.effective_disposition, EffectiveDisposition::Continue);
    let result = ArcEvaluationResult::from_report_and_bundle(
        report.clone(),
        FailureBundle::from_report(&report).expect("bundle succeeds"),
    )
    .expect("canonical aggregate succeeds");
    assert_eq!(result.effective_disposition, EffectiveDisposition::Continue);
    assert!(result.authorization_requirements.is_empty());

    // 2. Message guard is satisfied, but pending authorization exists -> NeedAuthorization
    report
        .authorization_requirements
        .push(ExactOperationAuthorization {
            guard_id: "msg-guard".into(),
            operation_fingerprint: "op-fp-msg".into(),
            event_id: "ev-c04-1".into(),
            tool: "bash".into(),
            normalized_arguments_fingerprint: "args-fp-msg".into(),
        });
    let auth_result = ArcEvaluationResult::from_report_and_bundle(
        report.clone(),
        FailureBundle::from_report(&report).expect("bundle succeeds"),
    )
    .expect("canonical aggregate succeeds");
    assert_eq!(auth_result.authorization_requirements.len(), 1);

    // 3. Message guard is violated AND pending authorization exists -> NeedAuthorization (not bypassed!)
    report.effective_disposition = EffectiveDisposition::Message;
    report.guard_results[0].state = GuardResultState::Violated { causes: Vec::new() };
    report.report_fingerprint =
        arc::fingerprint(&serde_json::to_vec(&report.guard_results).unwrap());
    let msg_auth_result = ArcEvaluationResult::from_report_and_bundle(
        report.clone(),
        FailureBundle::from_report(&report).expect("bundle succeeds"),
    )
    .expect("canonical aggregate succeeds");
    assert_eq!(msg_auth_result.authorization_requirements.len(), 1);

    // 4. Message guard is violated alone without authorization -> Message disposition
    report.authorization_requirements.clear();
    let msg_result = ArcEvaluationResult::from_report_and_bundle(
        report.clone(),
        FailureBundle::from_report(&report).expect("bundle succeeds"),
    )
    .expect("canonical aggregate succeeds");
    assert_eq!(
        msg_result.effective_disposition,
        EffectiveDisposition::Message
    );
    assert_eq!(msg_result.failure_bundle.failed_guards.len(), 1);
}

#[test]
fn test_c05_probe_mismatch_bounded_evidence() {
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
        lifecycle_guards: Vec::new(),
        tool_guards: vec![BoundToolGuard {
            id: "guard-probe-mismatch".into(),
            matcher: BoundMatcher {
                exact_patterns: vec!["deploy".into()],
                regex_patterns: Vec::new(),
            },
            require: BoundRuleExpression::Probe {
                command: "check-env".into(),
                expected_in: vec!["production".into()],
            },
            on_failure: OnFailureConfig {
                action: ActionType::Deny,
                feedback: Some("Environment mismatch".into()),
            },
            order: 1,
            declaration_order: 0,
        }],
        rules: BTreeMap::new(),
    };

    let long_output = "staging-environment-".repeat(100);
    let probes = Arc::new(MockProbeRunner::new().with_output("check-env", &long_output));
    let mut session = ArcRuntimeSession::new("test-c05", ir).with_probe_runner(probes);

    let result = session
        .evaluate_event_aggregate(
            ArcEvent::tool_call("test-c05", "ev-c05-1", 1, "bash", "deploy"),
            DecisionExecutionProfile {
                provider: ProviderTarget::Codex,
                transport: "fixture".into(),
                model: None,
                adapter_contract_fingerprint: "adapter".into(),
                output_schema_fingerprint: "schema".into(),
                sandbox_mode: "read_only".into(),
                approval_policy: "never".into(),
            },
            Path::new("."),
            10_000,
        )
        .expect("aggregate succeeds");

    assert_eq!(result.effective_disposition, EffectiveDisposition::Deny);
    assert_eq!(result.failure_bundle.failed_guards.len(), 1);
    let causes = &result.failure_bundle.failed_guards[0].causes;
    assert!(!causes.is_empty());
    for cause in causes {
        assert!(cause.deterministic_evidence.len() <= arc::MAX_DETERMINISTIC_EVIDENCE_ITEMS);
    }
}

#[test]
fn test_c08_no_expression_substitution_with_empty_all() {
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
        lifecycle_guards: Vec::new(),
        tool_guards: vec![BoundToolGuard {
            id: "guard-auth-c08".into(),
            matcher: BoundMatcher {
                exact_patterns: vec!["rm -rf /data".into()],
                regex_patterns: Vec::new(),
            },
            require: BoundRuleExpression::Probe {
                command: "check-safety".into(),
                expected_in: vec!["safe".into()],
            },
            on_failure: OnFailureConfig {
                action: ActionType::Ask,
                feedback: Some("Requires safety probe".into()),
            },
            order: 1,
            declaration_order: 0,
        }],
        rules: BTreeMap::new(),
    };

    let probes = Arc::new(MockProbeRunner::new().with_output("check-safety", "unsafe"));
    let state_store = Arc::new(arc::InMemoryStateStore::default());

    let ev = ArcEvent::tool_call("test-c08", "ev-c08-1", 1, "bash", "rm -rf /data");
    let current_op = arc::CurrentOperation::from(&ev);
    let op_fp = arc::exact_operation_fingerprint(&current_op);
    let args_fp = arc::normalized_arguments_fingerprint(&current_op);

    // Pre-record exact authorization in state store
    let auth = ExactOperationAuthorization {
        guard_id: "guard-auth-c08".into(),
        operation_fingerprint: op_fp.clone(),
        event_id: "ev-c08-1".into(),
        tool: "bash".into(),
        normalized_arguments_fingerprint: args_fp,
    };
    let auth_context = exact_authorization_context(
        std::slice::from_ref(&auth),
        "ev-c08-1",
        "bash",
        "ws-c08",
        "test-c08",
        "inv-c08-1",
        "policy-c08",
        "evidence-c08",
    );
    state_store
        .record_exact_authorization(&auth, &auth_context, Some("waiver-c08"), i64::MAX, 1)
        .unwrap();

    let mut session = ArcRuntimeSession::new("test-c08", ir)
        .with_probe_runner(probes)
        .with_state_store(state_store.clone());

    let report = session
        .evaluate_event_report(
            ev,
            DecisionExecutionProfile {
                provider: ProviderTarget::Codex,
                transport: "fixture".into(),
                model: None,
                adapter_contract_fingerprint: "adapter".into(),
                output_schema_fingerprint: "schema".into(),
                sandbox_mode: "read_only".into(),
                approval_policy: "never".into(),
            },
            Path::new("."),
            10_000,
        )
        .expect("report succeeds");

    // Evaluation must be purely semantic: probe output "unsafe" fails against "safe"
    assert_eq!(report.guard_results[0].guard_id, "guard-auth-c08");
    assert!(
        matches!(
            report.guard_results[0].state,
            GuardResultState::Violated { .. }
        ),
        "C-08: Evaluation must not fabricate Satisfied by rewriting expressions into All([])"
    );

    // The authorization in the store was NOT consumed during matching
    assert!(
        state_store
            .consume_exact_authorization(&auth, &auth_context, 1000)
            .unwrap(),
        "Authorizations must not be consumed during matching/evaluation phase"
    );
}

#[test]
fn test_c09_failure_bundle_aggregate_preserves_all_failures_under_dominant_disposition() {
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
        lifecycle_guards: Vec::new(),
        tool_guards: vec![
            BoundToolGuard {
                id: "guard-deny".into(),
                matcher: BoundMatcher {
                    exact_patterns: vec!["run-all".into()],
                    regex_patterns: Vec::new(),
                },
                require: BoundRuleExpression::Probe {
                    command: "probe-deny".into(),
                    expected_in: vec!["ok".into()],
                },
                on_failure: OnFailureConfig {
                    action: ActionType::Deny,
                    feedback: Some("Deny feedback".into()),
                },
                order: 1,
                declaration_order: 0,
            },
            BoundToolGuard {
                id: "guard-ask".into(),
                matcher: BoundMatcher {
                    exact_patterns: vec!["run-all".into()],
                    regex_patterns: Vec::new(),
                },
                require: BoundRuleExpression::Probe {
                    command: "probe-ask".into(),
                    expected_in: vec!["ok".into()],
                },
                on_failure: OnFailureConfig {
                    action: ActionType::Ask,
                    feedback: Some("Ask feedback".into()),
                },
                order: 2,
                declaration_order: 1,
            },
            BoundToolGuard {
                id: "guard-message".into(),
                matcher: BoundMatcher {
                    exact_patterns: vec!["run-all".into()],
                    regex_patterns: Vec::new(),
                },
                require: BoundRuleExpression::Probe {
                    command: "probe-message".into(),
                    expected_in: vec!["ok".into()],
                },
                on_failure: OnFailureConfig {
                    action: ActionType::Message,
                    feedback: Some("Message feedback".into()),
                },
                order: 3,
                declaration_order: 2,
            },
        ],
        rules: BTreeMap::new(),
    };

    let probes = Arc::new(
        MockProbeRunner::new()
            .with_output("probe-deny", "fail")
            .with_output("probe-ask", "fail")
            .with_output("probe-message", "fail"),
    );

    let mut session = ArcRuntimeSession::new("test-c09", ir).with_probe_runner(probes);
    let result = session
        .evaluate_event_aggregate(
            ArcEvent::tool_call("test-c09", "ev-c09-1", 1, "bash", "run-all"),
            DecisionExecutionProfile {
                provider: ProviderTarget::Codex,
                transport: "fixture".into(),
                model: None,
                adapter_contract_fingerprint: "adapter".into(),
                output_schema_fingerprint: "schema".into(),
                sandbox_mode: "read_only".into(),
                approval_policy: "never".into(),
            },
            Path::new("."),
            10_000,
        )
        .expect("aggregate succeeds");

    assert_eq!(result.effective_disposition, EffectiveDisposition::Deny);
    assert_eq!(result.report.guard_results.len(), 3);
    assert_eq!(result.failure_bundle.failed_guards.len(), 3);

    let failed_ids: Vec<&str> = result
        .failure_bundle
        .failed_guards
        .iter()
        .map(|fg| fg.guard_id.as_str())
        .collect();
    assert_eq!(failed_ids, vec!["guard-deny", "guard-ask", "guard-message"]);
}

#[test]
fn test_c10_typed_arc_evaluation_error_and_validation() {
    let report = snapshot_report();
    let bundle = FailureBundle::from_report(&report).unwrap();

    // 1. Valid construction succeeds
    let valid_result =
        ArcEvaluationResult::from_report_and_bundle(report.clone(), bundle.clone()).unwrap();
    valid_result.validate().unwrap();

    // 2. Duplicate guard_id in authorization_requirements is rejected by validate()
    let mut dup_report = report.clone();
    dup_report.authorization_requirements = vec![
        ExactOperationAuthorization {
            guard_id: "g-test".into(),
            operation_fingerprint: "op1".into(),
            event_id: dup_report.event_id.clone(),
            tool: "bash".into(),
            normalized_arguments_fingerprint: "arg1".into(),
        },
        ExactOperationAuthorization {
            guard_id: "g-test".into(),
            operation_fingerprint: "op2".into(),
            event_id: dup_report.event_id.clone(),
            tool: "bash".into(),
            normalized_arguments_fingerprint: "arg2".into(),
        },
    ];
    let dup_bundle = FailureBundle::from_report(&dup_report).unwrap();
    let dup_err = ArcEvaluationResult::from_report_and_bundle(dup_report, dup_bundle).unwrap_err();
    match dup_err {
        ArcEvaluationError::InvalidReport { reason } => {
            assert!(reason.contains("duplicate guard_id 'g-test' in authorization_requirements"));
        }
        other => panic!("Expected InvalidReport error, got: {other:?}"),
    }

    // 3. Mismatched event_id in authorization requirement is rejected
    let mut mismatch_auth_report = report.clone();
    mismatch_auth_report.authorization_requirements = vec![ExactOperationAuthorization {
        guard_id: "g-test".into(),
        operation_fingerprint: "op1".into(),
        event_id: "different-event-id".into(),
        tool: "bash".into(),
        normalized_arguments_fingerprint: "arg1".into(),
    }];
    let mismatch_bundle = FailureBundle::from_report(&mismatch_auth_report).unwrap();
    let mismatch_err =
        ArcEvaluationResult::from_report_and_bundle(mismatch_auth_report, mismatch_bundle)
            .unwrap_err();
    match mismatch_err {
        ArcEvaluationError::InvalidReport { reason } => {
            assert!(reason.contains("does not match report event_id"));
        }
        other => panic!("Expected InvalidReport error, got: {other:?}"),
    }

    // 4. Mismatched invocation_id between report and failure bundle is rejected
    let mut mismatched_report = report.clone();
    mismatched_report.invocation_id = "alien-invocation-id".into();
    let inv_err =
        ArcEvaluationResult::from_report_and_bundle(mismatched_report, bundle).unwrap_err();
    match inv_err {
        ArcEvaluationError::InvalidReport { reason } => {
            assert!(reason.contains("failure bundle invocation_id"));
        }
        other => panic!("Expected InvalidReport error, got: {other:?}"),
    }

    // 5. JSON serialization round-trip with deny_unknown_fields
    let json = serde_json::to_string(&valid_result).unwrap();
    let deserialized: ArcEvaluationResult = serde_json::from_str(&json).unwrap();
    assert_eq!(valid_result, deserialized);
}

fn snapshot_report() -> arc::EventEvaluationReport {
    let gr = arc::GuardResult::test_result("g-test", 1, 0, ActionType::Deny, true);
    let fp = arc::fingerprint(&serde_json::to_vec(&vec![gr.clone()]).unwrap());
    arc::EventEvaluationReport {
        schema: arc::EVENT_EVALUATION_REPORT_SCHEMA.into(),
        invocation_id: "inv-test".into(),
        provider: ProviderTarget::Codex,
        event_id: "ev-test".into(),
        event_type: ArcEventType::ToolCall,
        input_fingerprint: "input-fp".into(),
        guard_results: vec![gr],
        effective_disposition: EffectiveDisposition::Continue,
        authorization_requirements: Vec::new(),
        activation_cache_summary: arc::ActivationCacheSummary {
            logical_occurrences: 0,
            unique_probe_evaluations: 0,
            unique_decision_evaluations: 0,
            coalesced_in_flight: 0,
            reused_completed: 0,
            physical_faults: 0,
        },
        report_fingerprint: fp,
        started_unix_ms: 0,
        completed_unix_ms: 0,
    }
}

#[test]
fn test_f02_unconditional_authorization_preservation_across_guard_counts_and_dispositions() {
    let base_report = snapshot_report();

    let auth_1 = ExactOperationAuthorization {
        guard_id: "ask-guard-1".into(),
        operation_fingerprint: "op-fp-1".into(),
        event_id: base_report.event_id.clone(),
        tool: "Bash".into(),
        normalized_arguments_fingerprint: "args-fp-1".into(),
    };
    let auth_2 = ExactOperationAuthorization {
        guard_id: "ask-guard-2".into(),
        operation_fingerprint: "op-fp-2".into(),
        event_id: base_report.event_id.clone(),
        tool: "Bash".into(),
        normalized_arguments_fingerprint: "args-fp-2".into(),
    };

    let finalize = |mut r: arc::EventEvaluationReport| {
        r.report_fingerprint = arc::fingerprint(&serde_json::to_vec(&r.guard_results).unwrap());
        r.effective_disposition = arc::reduce_effective_disposition(&r.guard_results);
        r
    };

    // 1. Zero guards: ArcEvaluationResult is valid with empty authorizations
    let mut zero_report = base_report.clone();
    zero_report.guard_results = Vec::new();
    zero_report.authorization_requirements = Vec::new();
    let zero_report = finalize(zero_report);
    let zero_bundle = FailureBundle::from_report(&zero_report).unwrap();
    let zero_result =
        ArcEvaluationResult::from_report_and_bundle(zero_report, zero_bundle).unwrap();
    assert_eq!(zero_result.authorization_requirements.len(), 0);
    assert_eq!(zero_result.failure_bundle.failed_guards.len(), 0);
    assert!(zero_result.validate().is_ok());

    // 2. 1 Guard with Ask disposition + exact authorization: unconditionally preserved
    let mut one_report = base_report.clone();
    one_report.guard_results = vec![arc::GuardResult::test_result(
        "ask-guard-1",
        1,
        0,
        ActionType::Ask,
        false,
    )];
    one_report.authorization_requirements = vec![auth_1.clone()];
    let one_report = finalize(one_report);
    let one_bundle = FailureBundle::from_report(&one_report).unwrap();
    let one_result = ArcEvaluationResult::from_report_and_bundle(one_report, one_bundle).unwrap();
    assert_eq!(one_result.effective_disposition, EffectiveDisposition::Ask);
    assert_eq!(one_result.authorization_requirements.len(), 1);
    assert_eq!(
        one_result.authorization_requirements[0].guard_id,
        "ask-guard-1"
    );
    assert_eq!(one_result.failure_bundle.failed_guards.len(), 1);
    assert!(one_result.validate().is_ok());

    // 3. Multiple Guards (Ask + Deny + Message) + multiple exact authorizations:
    // Both failure bundle and authorization requirements preserved completely
    let mut multi_report = base_report.clone();
    multi_report.guard_results = vec![
        arc::GuardResult::test_result("deny-g", 1, 0, ActionType::Deny, false),
        arc::GuardResult::test_result("ask-g", 2, 1, ActionType::Ask, false),
        arc::GuardResult::test_result("msg-g", 3, 2, ActionType::Message, false),
    ];
    let mut multi_auth_1 = auth_1.clone();
    multi_auth_1.guard_id = "deny-g".into();
    let mut multi_auth_2 = auth_2.clone();
    multi_auth_2.guard_id = "ask-g".into();
    multi_report.authorization_requirements = vec![multi_auth_1, multi_auth_2];
    let multi_report = finalize(multi_report);
    let multi_bundle = FailureBundle::from_report(&multi_report).unwrap();
    let multi_result =
        ArcEvaluationResult::from_report_and_bundle(multi_report, multi_bundle).unwrap();
    assert_eq!(
        multi_result.effective_disposition,
        EffectiveDisposition::Deny
    );
    assert_eq!(multi_result.failure_bundle.failed_guards.len(), 3);
    assert_eq!(multi_result.authorization_requirements.len(), 2);
    assert!(multi_result.validate().is_ok());

    // 4. Dispositions Deny and RuntimeFault preserve authorizations without discarding them
    let mut fault_report = base_report.clone();
    fault_report.guard_results = vec![arc::GuardResult {
        guard_id: "fault-g".into(),
        order: 1,
        declaration_order: 0,
        configured_action: ActionType::Deny,
        state: GuardResultState::Faulted {
            faults: vec![arc::EvaluationFault::DeadlineExceeded],
            causes: Vec::new(),
        },
        satisfied_attributions: Vec::new(),
        completeness: EvaluationCompleteness::IncompleteDueToFault,
        evidence_fingerprint: arc::fingerprint(b"fault-g"),
    }];
    let mut fault_auth = auth_1.clone();
    fault_auth.guard_id = "fault-g".into();
    fault_report.authorization_requirements = vec![fault_auth];
    let fault_report = finalize(fault_report);
    let fault_bundle = FailureBundle::from_report(&fault_report).unwrap();
    let fault_result =
        ArcEvaluationResult::from_report_and_bundle(fault_report, fault_bundle).unwrap();
    assert_eq!(
        fault_result.effective_disposition,
        EffectiveDisposition::RuntimeFault
    );
    assert_eq!(fault_result.authorization_requirements.len(), 1);
    assert!(fault_result.validate().is_ok());
}

#[test]
fn test_f02_interactive_resolution_via_state_machine_no_future_grants() {
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
        lifecycle_guards: Vec::new(),
        tool_guards: vec![
            BoundToolGuard {
                id: "guard-ask-fail".into(),
                matcher: BoundMatcher {
                    exact_patterns: vec!["git push".into()],
                    regex_patterns: Vec::new(),
                },
                require: BoundRuleExpression::Probe {
                    command: "git branch".into(),
                    expected_in: vec!["feature".into()],
                },
                on_failure: OnFailureConfig {
                    action: ActionType::Ask,
                    feedback: Some("Branch is not feature".into()),
                },
                order: 1,
                declaration_order: 0,
            },
            BoundToolGuard {
                id: "guard-auth-decide".into(),
                matcher: BoundMatcher {
                    exact_patterns: vec!["git push".into()],
                    regex_patterns: Vec::new(),
                },
                require: BoundRuleExpression::Decide {
                    prompt: "Confirm push".into(),
                },
                on_failure: OnFailureConfig {
                    action: ActionType::Deny,
                    feedback: Some("Push rejected".into()),
                },
                order: 2,
                declaration_order: 1,
            },
        ],
        rules: BTreeMap::new(),
    };

    let probes = Arc::new(MockProbeRunner::new().with_output("git branch", "main"));
    let decision_provider =
        Arc::new(MockDecisionProvider::new().with_decision("Confirm push", true));
    let state_store = Arc::new(arc::InMemoryStateStore::default());

    let mut session = ArcRuntimeSession::new("test-f02-session", ir)
        .with_probe_runner(probes)
        .with_decision_provider(decision_provider)
        .with_state_store(state_store.clone());

    let observed = arc::HookObservationContext::new("codex", "test-f02-session", "inv-f02-1")
        .with_workspace("ws-f02");
    let event = ArcEvent::tool_call("test-f02-session", "ev-f02-1", 1, "bash", "git push");
    let operation = arc::CurrentOperation::from(&event);

    let eval_result =
        arc::evaluate_guard_with_observability(&mut session, event.clone(), &None, &observed)
            .expect("evaluates successfully");

    assert_eq!(eval_result.effective_disposition, EffectiveDisposition::Ask);
    assert_eq!(eval_result.authorization_requirements.len(), 1);

    let coordinator = arc::GuardExecutionCoordinator::new(state_store.clone());
    let ask_key = arc::GuardExecutionKey {
        workspace_id: "ws-f02".into(),
        session_id: "test-f02-session".into(),
        turn_id: None,
        guard_id: "guard-ask-fail".into(),
        activation: arc::GuardActivation::ToolCall,
        subject_id: Some("ev-f02-1".into()),
    };
    let ask_pending = coordinator
        .coordinate(arc::CoordinationInput {
            key: ask_key.clone(),
            invocation_id: "inv-f02-1".into(),
            signals: arc::ProviderSignals {
                reentry: arc::ReentryKind::FirstInvocation,
                ..arc::ProviderSignals::default()
            },
            evaluation: arc::EvaluationSnapshot::Violated {
                feedback: Some("Branch is not feature".into()),
            },
            violation_handling: arc::ViolationHandling::RequireDecision,
        })
        .expect("ask violation is durably coordinated")
        .decision_request
        .expect("ask violation has pending request");
    let auth_key = arc::GuardExecutionKey {
        guard_id: "guard-auth-decide".into(),
        ..ask_key.clone()
    };
    let auth_pending = coordinator
        .coordinate_authorization(
            auth_key.clone(),
            "inv-f02-1",
            &eval_result.failure_bundle.bundle_fingerprint,
        )
        .expect("exact authorization is durably coordinated");

    let mut request = arc::interactive_decision_request_from_evaluation_result(
        &eval_result,
        ProviderTarget::Codex,
        ArcEventType::ToolCall,
        &event.event_id,
        "inv-f02-1",
        Some(operation),
        Some("bash git push".into()),
        "this exact tool call once",
    )
    .expect("builds request")
    .expect("some request");

    let correlation = arc::DecisionCorrelation::new(
        ask_pending.decision_id.clone(),
        ask_pending.execution_id.clone(),
        Some("inv-f02-1".into()),
    )
    .unwrap();
    request.set_correlation(correlation);

    let orchestrator = arc::InteractiveDecisionOrchestrator::with_presenter(
        arc::OsTarget::host().expect("supported host"),
        arc::DecisionUiMode::Native,
        std::time::Duration::from_secs(5),
        Arc::new(EchoAllowPresenter),
    );

    let dispatch = orchestrator.dispatch(request).expect("dispatches");
    let resolution = match dispatch {
        arc::InteractiveDecisionDispatch::Presented { resolution, .. } => resolution,
        other => panic!("expected Presented, got {other:?}"),
    };

    let auth_context = exact_authorization_context(
        &eval_result.authorization_requirements,
        "ev-f02-1",
        "bash",
        "ws-f02",
        "test-f02-session",
        "inv-f02-1",
        &eval_result.report.report_fingerprint,
        &eval_result.failure_bundle.bundle_fingerprint,
    );
    let resolution_context = arc::InteractiveResolutionContext {
        keys: vec![ask_key.clone(), auth_key.clone()],
        pending_targets: vec![
            arc::InteractivePendingTarget {
                key: ask_key,
                decision_id: ask_pending.decision_id,
                execution_id: ask_pending.execution_id,
            },
            arc::InteractivePendingTarget {
                key: auth_key,
                decision_id: auth_pending
                    .decision_request
                    .as_ref()
                    .expect("authorization has pending request")
                    .decision_id
                    .clone(),
                execution_id: auth_pending
                    .decision_request
                    .as_ref()
                    .expect("authorization has pending request")
                    .execution_id
                    .clone(),
            },
        ],
        owner_invocation_id: "inv-f02-1".into(),
        resolution_invocation_id: "inv-f02-1".into(),
        expires_at_unix_ms: ask_pending.expires_at_unix_ms.min(
            auth_pending
                .decision_request
                .as_ref()
                .expect("authorization has pending request")
                .expires_at_unix_ms,
        ),
        receipt_received_at_unix_ms: 1_000,
        authorization_context: Some(auth_context.clone()),
    };

    let mut mismatched_request = arc::interactive_decision_request_from_evaluation_result(
        &eval_result,
        ProviderTarget::Codex,
        ArcEventType::ToolCall,
        &event.event_id,
        "attacker-invocation",
        Some(arc::CurrentOperation::from(&event)),
        Some("bash git push".into()),
        "this exact tool call once",
    )
    .expect("builds mismatched request")
    .expect("mismatched request is required");
    let mismatched_correlation = arc::DecisionCorrelation::new(
        "mismatched-decision",
        "mismatched-execution",
        Some("inv-f02-1".into()),
    )
    .expect("builds mismatched correlation");
    mismatched_request.set_correlation(mismatched_correlation);
    let mismatched_resolution = match orchestrator
        .dispatch(mismatched_request)
        .expect("dispatches mismatched request")
    {
        arc::InteractiveDecisionDispatch::Presented { resolution, .. } => resolution,
        other => panic!("expected mismatched request to be presented, got {other:?}"),
    };
    let invocation_error = arc::apply_interactive_resolution(
        &mismatched_resolution,
        &eval_result,
        &coordinator,
        &resolution_context,
    )
    .expect_err("mismatched resolution invocation must be rejected");
    assert!(invocation_error.to_string().contains("durable invocation"));

    let mut mismatched_context = resolution_context.clone();
    mismatched_context.resolution_invocation_id = "attacker-resolution".into();
    let context_invocation_error = arc::apply_interactive_resolution(
        &resolution,
        &eval_result,
        &coordinator,
        &mismatched_context,
    )
    .expect_err("context resolution invocation must match the request");
    assert!(
        context_invocation_error
            .to_string()
            .contains("durable invocation")
    );

    // Apply via canonical domain operation
    let apply_result = arc::apply_interactive_resolution(
        &resolution,
        &eval_result,
        &coordinator,
        &resolution_context,
    )
    .expect("apply succeeds");

    assert_eq!(
        apply_result.outcome,
        arc::AggregateResolutionApplyOutcome::Applied
    );
    assert!(matches!(
        apply_result.directive,
        arc::AppliedDecisionDirective::Allow { .. }
    ));

    // F-04 / §5.1: No future grants.
    // The exact authorization is persisted as consumed (uses_remaining = 0) for this pending call.
    // Subsequent calls cannot reuse it.
    let auth = &eval_result.authorization_requirements[0];
    assert!(
        !state_store
            .has_valid_exact_authorization(auth, &auth_context, 1500)
            .unwrap(),
        "Interactive Allow must NOT authorize future operations"
    );
    assert!(
        !state_store
            .consume_exact_authorization(auth, &auth_context, 1500)
            .unwrap(),
        "Subsequent call must not be able to consume the grant"
    );

    // Idempotency: replaying same resolution
    let replay_result = arc::apply_interactive_resolution(
        &resolution,
        &eval_result,
        &coordinator,
        &resolution_context,
    )
    .expect("replay succeeds");
    assert_eq!(
        replay_result.outcome,
        arc::AggregateResolutionApplyOutcome::IdempotentReplay
    );

    // Non-overridable disposition check: Allow cannot override Deny or RuntimeFault
    let mut deny_eval = eval_result.clone();
    deny_eval.effective_disposition = EffectiveDisposition::Deny;
    let deny_err = arc::apply_interactive_resolution(
        &resolution,
        &deny_eval,
        &coordinator,
        &resolution_context,
    )
    .unwrap_err();
    assert!(deny_err.to_string().contains("non-overridable disposition"));
}

#[test]
fn test_f02_concurrency_contention_and_late_response() {
    let root = std::env::temp_dir().join(format!(
        "arc_f02_conc_{}_{}",
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    std::fs::create_dir_all(&root).unwrap();
    let db_path = root.join("state.sqlite3");
    let store = Arc::new(arc::SqliteStateStore::open(&db_path).unwrap());

    use arc::DecisionPresentationClaimStore;

    // 1. Contention: First claim succeeds, second claim for same invocation_id fails
    assert!(
        store
            .claim_presentation("inv-conc-1", Some("dec-conc-1"))
            .unwrap()
    );
    assert!(
        !store
            .claim_presentation("inv-conc-1", Some("dec-conc-1"))
            .unwrap()
    );
    // Duplicate decision_id claim fails
    assert!(
        !store
            .claim_presentation("inv-conc-2", Some("dec-conc-1"))
            .unwrap()
    );

    // 2. Late response rejection: now >= expires_at
    let req = arc::AggregateResolutionApplyRequest {
        resolution_id: "res-late".into(),
        decision_id: Some("dec-late".into()),
        invocation_id: "inv-late".into(),
        session_id: "sess-late".into(),
        workspace_id: Some("ws-late".into()),
        provider: "codex".into(),
        outcome: arc::InteractiveDecisionOutcome::Allow,
        authorizations: vec![],
        now_unix_ms: 10_000,
        expires_at_unix_ms: 5_000, // Late/expired!
        decision_receipt: None,
        authorization_context: None,
    };
    let coordinator = arc::GuardExecutionCoordinator::new(store.clone());
    let key = arc::GuardExecutionKey {
        workspace_id: "ws-late".into(),
        session_id: "sess-late".into(),
        turn_id: None,
        guard_id: "guard-late".into(),
        activation: arc::GuardActivation::ToolCall,
        subject_id: Some("event-late".into()),
    };
    let pending = coordinator
        .coordinate(arc::CoordinationInput {
            key: key.clone(),
            invocation_id: "inv-late".into(),
            signals: arc::ProviderSignals::default(),
            evaluation: arc::EvaluationSnapshot::Violated { feedback: None },
            violation_handling: arc::ViolationHandling::RequireDecision,
        })
        .unwrap()
        .decision_request
        .unwrap();
    let current = store.load(&key).unwrap().unwrap();
    let mut resolved = current.clone();
    resolved.revision += 1;
    resolved.pending_decision = None;
    let target = arc::AggregateGuardResolutionTarget {
        key,
        expected_revision: current.revision,
        expected_decision_id: pending.decision_id.clone(),
        expected_execution_id: pending.execution_id.clone(),
        expected_owner_invocation_id: "inv-late".into(),
        record: resolved,
    };
    let mut req = req;
    req.decision_id = Some(pending.decision_id);
    let err = store
        .apply_aggregate_guard_resolution(&arc::AggregateGuardResolutionApplyRequest {
            resolution: req,
            targets: vec![target],
        })
        .unwrap_err();
    assert!(err.to_string().contains("expired"));

    drop(store);
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn test_f02_roundtrip_mixed_aggregate_presentation_lossless() {
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
        lifecycle_guards: Vec::new(),
        tool_guards: vec![
            BoundToolGuard {
                id: "guard-ask-fail".into(),
                matcher: BoundMatcher {
                    exact_patterns: vec!["git push".into()],
                    regex_patterns: Vec::new(),
                },
                require: BoundRuleExpression::Probe {
                    command: "git branch".into(),
                    expected_in: vec!["feature".into()],
                },
                on_failure: OnFailureConfig {
                    action: ActionType::Ask,
                    feedback: Some("Branch is not feature".into()),
                },
                order: 1,
                declaration_order: 0,
            },
            BoundToolGuard {
                id: "guard-auth-decide".into(),
                matcher: BoundMatcher {
                    exact_patterns: vec!["git push".into()],
                    regex_patterns: Vec::new(),
                },
                require: BoundRuleExpression::Decide {
                    prompt: "Confirm push".into(),
                },
                on_failure: OnFailureConfig {
                    action: ActionType::Deny,
                    feedback: Some("Push rejected".into()),
                },
                order: 2,
                declaration_order: 1,
            },
        ],
        rules: BTreeMap::new(),
    };

    let probes = Arc::new(MockProbeRunner::new().with_output("git branch", "main"));
    let decision_provider =
        Arc::new(MockDecisionProvider::new().with_decision("Confirm push", true));
    let state_store = Arc::new(arc::InMemoryStateStore::default());

    let mut session = ArcRuntimeSession::new("test-f02-mixed-session", ir)
        .with_probe_runner(probes)
        .with_decision_provider(decision_provider)
        .with_state_store(state_store);

    let observed =
        arc::HookObservationContext::new("codex", "test-f02-mixed-session", "inv-mixed-1")
            .with_workspace("ws-f02");
    let event = ArcEvent::tool_call(
        "test-f02-mixed-session",
        "ev-mixed-1",
        1,
        "bash",
        "git push",
    );
    let operation = arc::CurrentOperation::from(&event);

    let eval_result =
        arc::evaluate_guard_with_observability(&mut session, event.clone(), &None, &observed)
            .expect("evaluates successfully");

    assert_eq!(eval_result.effective_disposition, EffectiveDisposition::Ask);
    assert_eq!(eval_result.authorization_requirements.len(), 1);

    // 1. Build interactive decision request from evaluation result
    let request = arc::interactive_decision_request_from_evaluation_result(
        &eval_result,
        ProviderTarget::Codex,
        ArcEventType::ToolCall,
        &event.event_id,
        "inv-mixed-1",
        Some(operation),
        Some("bash git push".into()),
        "this exact tool call once",
    )
    .expect("builds request")
    .expect("some request");

    // Presentation kind MUST be AggregateDecision
    assert_eq!(
        request.presentation_kind(),
        arc::PresentationKind::AggregateDecision
    );
    assert_eq!(request.exact_authorizations().unwrap().len(), 1);

    // 2. Project to DialogRequest
    let dialog_req = request.to_dialog_request("Mixed Aggregate Title");
    assert_eq!(
        dialog_req.presentation_kind,
        arc::PresentationKind::AggregateDecision
    );
    assert_eq!(dialog_req.violations.len(), 1);
    assert_eq!(dialog_req.authorizations.len(), 1);
    assert_eq!(dialog_req.authorizations[0].guard_id, "guard-auth-decide");
    assert_eq!(
        dialog_req.bundle_fingerprint,
        eval_result.failure_bundle.bundle_fingerprint
    );
    dialog_req.validate().expect("dialog request validates");

    // 3. Serialized JSON round-trip
    let wire_bytes = serde_json::to_vec(&dialog_req).expect("serialize");
    let decoded_req: arc::DialogRequest = serde_json::from_slice(&wire_bytes).expect("deserialize");
    assert_eq!(decoded_req, dialog_req);

    // 4. Dialog response with matching bundle fingerprint
    let response = arc::DialogResponse {
        schema: arc::DIALOG_RESPONSE_SCHEMA.into(),
        request_id: dialog_req.request_id.clone(),
        bundle_fingerprint: dialog_req.bundle_fingerprint.clone(),
        decision: arc::PortableDecision::Allow,
        transport: "arc_embedded_ui".into(),
        theme: "dark".into(),
        message: Some("Operator confirmed mixed aggregate".into()),
    };
    response
        .validate_for(&dialog_req)
        .expect("response validates for request");

    // 5. Build InteractiveDecisionResolution
    let resolution = arc::InteractiveDecisionResolution::from_dialog_response(
        request,
        response,
        arc::DecisionTransport::ArcEmbeddedUi,
    )
    .expect("resolution from dialog response");
    assert_eq!(resolution.outcome(), arc::InteractiveDecisionOutcome::Allow);
    assert_eq!(resolution.portable_decision(), arc::PortableDecision::Allow);
    assert_eq!(
        resolution.request().exact_authorizations().unwrap().len(),
        1
    );
    assert_eq!(
        resolution.request().exact_authorizations().unwrap()[0].guard_id,
        "guard-auth-decide"
    );
}

#[test]
fn test_f02_bundle_fingerprint_semantic_validation_rejects_mismatched() {
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
        lifecycle_guards: Vec::new(),
        tool_guards: vec![BoundToolGuard {
            id: "guard-ask-fail".into(),
            matcher: BoundMatcher {
                exact_patterns: vec!["git push".into()],
                regex_patterns: Vec::new(),
            },
            require: BoundRuleExpression::Probe {
                command: "git branch".into(),
                expected_in: vec!["feature".into()],
            },
            on_failure: OnFailureConfig {
                action: ActionType::Ask,
                feedback: Some("Branch is not feature".into()),
            },
            order: 1,
            declaration_order: 0,
        }],
        rules: BTreeMap::new(),
    };

    let probes = Arc::new(MockProbeRunner::new().with_output("git branch", "main"));
    let state_store = Arc::new(arc::InMemoryStateStore::default());

    let mut session = ArcRuntimeSession::new("test-f02-fp-session", ir)
        .with_probe_runner(probes)
        .with_state_store(state_store);

    let observed = arc::HookObservationContext::new("codex", "test-f02-fp-session", "inv-fp-1")
        .with_workspace("ws-f02");
    let event = ArcEvent::tool_call("test-f02-fp-session", "ev-fp-1", 1, "bash", "git push");
    let operation = arc::CurrentOperation::from(&event);

    let eval_result =
        arc::evaluate_guard_with_observability(&mut session, event.clone(), &None, &observed)
            .expect("evaluates successfully");

    let request = arc::interactive_decision_request_from_evaluation_result(
        &eval_result,
        ProviderTarget::Codex,
        ArcEventType::ToolCall,
        &event.event_id,
        "inv-fp-1",
        Some(operation),
        Some("bash git push".into()),
        "this exact tool call once",
    )
    .expect("builds request")
    .expect("some request");

    let dialog_req = request.to_dialog_request("Title");
    assert_eq!(
        dialog_req.bundle_fingerprint,
        eval_result.failure_bundle.bundle_fingerprint
    );

    // Mismatched bundle fingerprint in response
    let spoofed_response = arc::DialogResponse {
        schema: arc::DIALOG_RESPONSE_SCHEMA.into(),
        request_id: dialog_req.request_id.clone(),
        bundle_fingerprint: "sha256:spoofed-fake-fingerprint".into(),
        decision: arc::PortableDecision::Allow,
        transport: "arc_embedded_ui".into(),
        theme: "dark".into(),
        message: None,
    };

    let err = arc::InteractiveDecisionResolution::from_dialog_response(
        request,
        spoofed_response,
        arc::DecisionTransport::ArcEmbeddedUi,
    )
    .unwrap_err();

    assert!(matches!(
        err,
        arc::DecisionContractError::CorrelationMismatch {
            field: "bundle_fingerprint"
        }
    ));
}

#[test]
fn test_f02_public_helper_isolated_pure_authorization_roundtrip_without_correlation() {
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
        lifecycle_guards: Vec::new(),
        tool_guards: vec![BoundToolGuard {
            id: "guard-auth-only".into(),
            matcher: BoundMatcher {
                exact_patterns: vec!["git push".into()],
                regex_patterns: Vec::new(),
            },
            require: BoundRuleExpression::Decide {
                prompt: "Confirm push".into(),
            },
            on_failure: OnFailureConfig {
                action: ActionType::Deny,
                feedback: Some("Push rejected".into()),
            },
            order: 1,
            declaration_order: 0,
        }],
        rules: BTreeMap::new(),
    };

    let decision_provider =
        Arc::new(MockDecisionProvider::new().with_decision("Confirm push", true));
    let state_store = Arc::new(arc::InMemoryStateStore::default());

    let mut session = ArcRuntimeSession::new("test-f02-pure-session", ir)
        .with_decision_provider(decision_provider)
        .with_state_store(state_store);

    let observed = arc::HookObservationContext::new("codex", "test-f02-pure-session", "inv-pure-1")
        .with_workspace("ws-f02");
    let event = ArcEvent::tool_call("test-f02-pure-session", "ev-pure-1", 1, "bash", "git push");
    let operation = arc::CurrentOperation::from(&event);

    let eval_result =
        arc::evaluate_guard_with_observability(&mut session, event.clone(), &None, &observed)
            .expect("evaluates successfully");

    assert_eq!(
        eval_result.effective_disposition,
        EffectiveDisposition::Continue
    );
    assert_eq!(eval_result.authorization_requirements.len(), 1);

    // Exact authorization requires an explicit Allow/Deny even though the
    // semantic disposition itself remains Continue.
    let request = arc::interactive_decision_request_from_evaluation_result(
        &eval_result,
        ProviderTarget::Codex,
        ArcEventType::ToolCall,
        &event.event_id,
        "inv-pure-1",
        Some(operation.clone()),
        Some("bash git push".into()),
        "this exact tool call once",
    )
    .expect("helper succeeds")
    .expect("request generated for exact authorization");

    assert!(request.correlation().is_none());
    assert_eq!(
        request.presentation_kind(),
        arc::PresentationKind::ExactOperationAuthorization
    );

    let dialog_req = request.to_dialog_request("Pure Authorization");
    assert_eq!(
        dialog_req.bundle_fingerprint,
        eval_result.failure_bundle.bundle_fingerprint
    );
    dialog_req.validate().expect("dialog request validates");

    let response = arc::DialogResponse {
        schema: arc::DIALOG_RESPONSE_SCHEMA.into(),
        request_id: dialog_req.request_id.clone(),
        bundle_fingerprint: dialog_req.bundle_fingerprint.clone(),
        decision: arc::PortableDecision::Allow,
        transport: "arc_embedded_ui".into(),
        theme: "dark".into(),
        message: None,
    };
    response
        .validate_for(&dialog_req)
        .expect("response validates");

    let resolution = arc::InteractiveDecisionResolution::from_dialog_response(
        request,
        response,
        arc::DecisionTransport::ArcEmbeddedUi,
    )
    .expect("resolution");
    assert_eq!(resolution.outcome(), arc::InteractiveDecisionOutcome::Allow);
    assert_eq!(resolution.portable_decision(), arc::PortableDecision::Allow);
    assert_eq!(
        resolution.request().exact_authorizations().unwrap().len(),
        1
    );
}

#[test]
fn test_f02_production_flow_with_explicit_correlation_roundtrip() {
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
        lifecycle_guards: Vec::new(),
        tool_guards: vec![BoundToolGuard {
            id: "guard-auth-prod".into(),
            matcher: BoundMatcher {
                exact_patterns: vec!["git push".into()],
                regex_patterns: Vec::new(),
            },
            require: BoundRuleExpression::Decide {
                prompt: "Confirm push".into(),
            },
            on_failure: OnFailureConfig {
                action: ActionType::Deny,
                feedback: Some("Push rejected".into()),
            },
            order: 1,
            declaration_order: 0,
        }],
        rules: BTreeMap::new(),
    };

    let decision_provider =
        Arc::new(MockDecisionProvider::new().with_decision("Confirm push", true));
    let state_store = Arc::new(arc::InMemoryStateStore::default());

    let mut session = ArcRuntimeSession::new("test-f02-prod-session", ir)
        .with_decision_provider(decision_provider)
        .with_state_store(state_store);

    let observed = arc::HookObservationContext::new("codex", "test-f02-prod-session", "inv-prod-1")
        .with_workspace("ws-f02");
    let event = ArcEvent::tool_call("test-f02-prod-session", "ev-prod-1", 1, "bash", "git push");
    let operation = arc::CurrentOperation::from(&event);

    let eval_result =
        arc::evaluate_guard_with_observability(&mut session, event.clone(), &None, &observed)
            .expect("evaluates successfully");

    assert_eq!(
        eval_result.effective_disposition,
        EffectiveDisposition::Continue
    );
    assert_eq!(eval_result.authorization_requirements.len(), 1);

    // Current contract (USAGE.md exact authorization; decision/context.rs): on Continue
    // the helper returns Ok(None) only when there is nothing to authorize. A Continue
    // result that carries an exact authorization requirement must still produce an
    // Allow/Deny request, otherwise it would fail closed without a round-trip.
    let mut no_authorization_result = eval_result.clone();
    no_authorization_result.authorization_requirements.clear();
    let no_req = arc::interactive_decision_request_from_evaluation_result(
        &no_authorization_result,
        ProviderTarget::Codex,
        ArcEventType::ToolCall,
        &event.event_id,
        "inv-prod-1",
        Some(operation.clone()),
        Some("bash git push".into()),
        "this exact tool call once",
    )
    .expect("helper succeeds");
    assert!(no_req.is_none());

    let exact_req = arc::interactive_decision_request_from_evaluation_result(
        &eval_result,
        ProviderTarget::Codex,
        ArcEventType::ToolCall,
        &event.event_id,
        "inv-prod-1",
        Some(operation.clone()),
        Some("bash git push".into()),
        "this exact tool call once",
    )
    .expect("helper succeeds")
    .expect("Continue with an exact authorization requirement must produce a request");
    assert_eq!(
        exact_req.presentation_kind(),
        arc::PresentationKind::ExactOperationAuthorization
    );
    assert_eq!(exact_req.exact_authorizations().unwrap().len(), 1);
    assert_eq!(
        exact_req.exact_authorizations().unwrap()[0].guard_id,
        "guard-auth-prod"
    );

    // When effective_disposition is Ask, production flow builds request and attaches explicit correlation
    let mut ask_eval_result = eval_result.clone();
    ask_eval_result.effective_disposition = EffectiveDisposition::Ask;

    // Production flow: build request and attach explicit correlation
    let mut request = arc::interactive_decision_request_from_evaluation_result(
        &ask_eval_result,
        ProviderTarget::Codex,
        ArcEventType::ToolCall,
        &event.event_id,
        "inv-prod-1",
        Some(operation),
        Some("bash git push".into()),
        "this exact tool call once",
    )
    .expect("helper succeeds")
    .expect("request generated");

    request.set_correlation(
        arc::DecisionCorrelation::new(
            "dec-prod-12345",
            "test-f02-prod-session",
            Some("inv-prod-1".into()),
        )
        .expect("valid correlation"),
    );

    assert_eq!(
        request.correlation().unwrap().execution_id(),
        "test-f02-prod-session"
    );
    assert_eq!(
        request.correlation().unwrap().decision_id(),
        "dec-prod-12345"
    );

    let dialog_req = request.to_dialog_request("Prod Authorization");
    // bundle_fingerprint is linked directly to FailureBundle
    assert_eq!(
        dialog_req.bundle_fingerprint,
        eval_result.failure_bundle.bundle_fingerprint
    );
    dialog_req.validate().expect("dialog request validates");

    let response = arc::DialogResponse {
        schema: arc::DIALOG_RESPONSE_SCHEMA.into(),
        request_id: dialog_req.request_id.clone(),
        bundle_fingerprint: dialog_req.bundle_fingerprint.clone(),
        decision: arc::PortableDecision::Allow,
        transport: "arc_embedded_ui".into(),
        theme: "light".into(),
        message: Some("Approved in prod".into()),
    };
    response
        .validate_for(&dialog_req)
        .expect("response validates");

    let resolution = arc::InteractiveDecisionResolution::from_dialog_response(
        request,
        response,
        arc::DecisionTransport::ArcEmbeddedUi,
    )
    .expect("resolution");
    assert_eq!(resolution.outcome(), arc::InteractiveDecisionOutcome::Allow);
    assert_eq!(resolution.portable_decision(), arc::PortableDecision::Allow);
    assert_eq!(
        resolution.request().correlation().unwrap().decision_id(),
        "dec-prod-12345"
    );
}

#[test]
fn test_fase3_six_guard_aggregate_fixture_mixing_continue_ask_deny_fault_and_authorizations() {
    let mut rules = BTreeMap::new();
    // Rule cycle between cycle_a and cycle_b to create a deterministic RuntimeFault (RuleEvaluationCycle)
    rules.insert(
        "cycle_a".into(),
        BoundRuleExpression::RuleRef {
            name: "cycle_b".into(),
        },
    );
    rules.insert(
        "cycle_b".into(),
        BoundRuleExpression::RuleRef {
            name: "cycle_a".into(),
        },
    );

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
            // 1. Guard 1: Satisfied / Continue (passes probe cleanly)
            BoundToolGuard {
                id: "guard_1_satisfied".into(),
                matcher: BoundMatcher {
                    exact_patterns: vec!["git push".into()],
                    regex_patterns: Vec::new(),
                },
                require: BoundRuleExpression::Probe {
                    command: "check_clean".into(),
                    expected_in: vec!["clean".into()],
                },
                on_failure: OnFailureConfig {
                    action: ActionType::Deny,
                    feedback: Some("guard 1 feedback".into()),
                },
                order: 10,
                declaration_order: 0,
            },
            // 2. Guard 2: Ask (fails probe, action Ask)
            BoundToolGuard {
                id: "guard_2_ask".into(),
                matcher: BoundMatcher {
                    exact_patterns: vec!["git push".into()],
                    regex_patterns: Vec::new(),
                },
                require: BoundRuleExpression::Probe {
                    command: "check_ask".into(),
                    expected_in: vec!["passed".into()],
                },
                on_failure: OnFailureConfig {
                    action: ActionType::Ask,
                    feedback: Some("guard 2 ask feedback".into()),
                },
                order: 20,
                declaration_order: 1,
            },
            // 3. Guard 3: Deny (fails probe, action Deny)
            BoundToolGuard {
                id: "guard_3_deny".into(),
                matcher: BoundMatcher {
                    exact_patterns: vec!["git push".into()],
                    regex_patterns: Vec::new(),
                },
                require: BoundRuleExpression::Probe {
                    command: "check_deny".into(),
                    expected_in: vec!["passed".into()],
                },
                on_failure: OnFailureConfig {
                    action: ActionType::Deny,
                    feedback: Some("guard 3 deny feedback".into()),
                },
                order: 30,
                declaration_order: 2,
            },
            // 4. Guard 4: RuntimeFault (triggers RuleEvaluationCycle)
            BoundToolGuard {
                id: "guard_4_fault".into(),
                matcher: BoundMatcher {
                    exact_patterns: vec!["git push".into()],
                    regex_patterns: Vec::new(),
                },
                require: BoundRuleExpression::RuleRef {
                    name: "cycle_a".into(),
                },
                on_failure: OnFailureConfig {
                    action: ActionType::Deny,
                    feedback: Some("guard 4 fault feedback".into()),
                },
                order: 40,
                declaration_order: 3,
            },
            // 5. Guard 5: Authorization requirement (Decide returns true, producing exact authorization)
            BoundToolGuard {
                id: "guard_5_auth".into(),
                matcher: BoundMatcher {
                    exact_patterns: vec!["git push".into()],
                    regex_patterns: Vec::new(),
                },
                require: BoundRuleExpression::Decide {
                    prompt: "Authorize git push".into(),
                },
                on_failure: OnFailureConfig {
                    action: ActionType::Deny,
                    feedback: Some("guard 5 auth feedback".into()),
                },
                order: 50,
                declaration_order: 4,
            },
            // 6. Guard 6: Message / Advisory (fails probe, action Message)
            BoundToolGuard {
                id: "guard_6_message".into(),
                matcher: BoundMatcher {
                    exact_patterns: vec!["git push".into()],
                    regex_patterns: Vec::new(),
                },
                require: BoundRuleExpression::Probe {
                    command: "check_msg".into(),
                    expected_in: vec!["passed".into()],
                },
                on_failure: OnFailureConfig {
                    action: ActionType::Message,
                    feedback: Some("guard 6 advisory message".into()),
                },
                order: 60,
                declaration_order: 5,
            },
        ],
        rules,
    };
    ir.content_hash = Some(ir.compute_content_hash());
    let store = arc::SqliteStateStore::open_in_memory().unwrap();
    let anchor = store
        .trust_and_anchor_ir(Path::new("six_guards.json"), &ir)
        .unwrap();

    let probe_runner = Arc::new(
        MockProbeRunner::new()
            .with_output("check_clean", "clean")
            .with_output("check_ask", "failed")
            .with_output("check_deny", "failed")
            .with_output("check_msg", "failed"),
    );
    let decision_provider =
        Arc::new(MockDecisionProvider::new().with_decision("Authorize git push", true));
    let state_store = Arc::new(arc::InMemoryStateStore::default());

    let mut session = ArcRuntimeSession::new("test-fase3-six-guards-session", ir)
        .with_trusted_anchor(anchor)
        .unwrap()
        .with_probe_runner(probe_runner)
        .with_decision_provider(decision_provider)
        .with_state_store(state_store);

    let observed =
        arc::HookObservationContext::new("codex", "test-fase3-six-guards-session", "inv-six-1")
            .with_workspace("ws-six");
    let event = ArcEvent::tool_call(
        "test-fase3-six-guards-session",
        "ev-six-1",
        1,
        "bash",
        "git push",
    );
    let operation = arc::CurrentOperation::from(&event);

    let eval_result =
        arc::evaluate_guard_with_observability(&mut session, event.clone(), &None, &observed)
            .expect("aggregate evaluation must succeed");

    // Invariant 1: Exactly six GuardResult in deterministic order
    assert_eq!(
        eval_result.report.guard_results.len(),
        6,
        "All six guards must be evaluated in aggregate"
    );
    let guard_ids: Vec<&str> = eval_result
        .report
        .guard_results
        .iter()
        .map(|gr| gr.guard_id.as_str())
        .collect();
    assert_eq!(
        guard_ids,
        vec![
            "guard_1_satisfied",
            "guard_2_ask",
            "guard_3_deny",
            "guard_4_fault",
            "guard_5_auth",
            "guard_6_message",
        ],
        "Deterministic evaluation order must be strictly preserved"
    );

    // Invariant 2: States match the heterogeneous mixture
    assert!(matches!(
        eval_result.report.guard_results[0].state,
        GuardResultState::Satisfied
    ));
    assert!(matches!(
        eval_result.report.guard_results[1].state,
        GuardResultState::Violated { .. }
    ));
    assert!(matches!(
        eval_result.report.guard_results[2].state,
        GuardResultState::Violated { .. }
    ));
    assert!(matches!(
        eval_result.report.guard_results[3].state,
        GuardResultState::Faulted { .. }
    ));
    assert!(matches!(
        eval_result.report.guard_results[4].state,
        GuardResultState::Satisfied
    ));
    assert!(matches!(
        eval_result.report.guard_results[5].state,
        GuardResultState::Violated { .. }
    ));

    // Invariant 3: Effective disposition is RuntimeFault (precedence RuntimeFault > Deny > Ask > Message > Continue)
    assert_eq!(
        eval_result.effective_disposition,
        EffectiveDisposition::RuntimeFault,
        "RuntimeFault must take precedence in aggregate effective disposition"
    );

    // Invariant 4: Authorization requirements are preserved and NOT dropped by Deny or Ask
    assert_eq!(
        eval_result.authorization_requirements.len(),
        1,
        "Authorization requirements must be preserved in ArcEvaluationResult"
    );
    assert_eq!(
        eval_result.authorization_requirements[0].guard_id,
        "guard_5_auth"
    );

    // Invariant 5: FailureBundle preserves all failed/faulted guards without primary guard loss
    assert_eq!(
        eval_result.failure_bundle.failed_guards.len(),
        4,
        "All failed and faulted guards must be present in FailureBundle"
    );
    let bundle_guard_ids: Vec<&str> = eval_result
        .failure_bundle
        .failed_guards
        .iter()
        .map(|fg| fg.guard_id.as_str())
        .collect();
    assert!(bundle_guard_ids.contains(&"guard_2_ask"));
    assert!(bundle_guard_ids.contains(&"guard_3_deny"));
    assert!(bundle_guard_ids.contains(&"guard_4_fault"));
    assert!(bundle_guard_ids.contains(&"guard_6_message"));
    assert!(
        eval_result
            .failure_bundle
            .failed_guards
            .iter()
            .find(|guard| guard.guard_id == "guard_4_fault")
            .is_some_and(|guard| guard.faulted),
        "the aggregate must identify the faulted Guard for provider-safe redaction"
    );
    assert!(
        eval_result
            .failure_bundle
            .failed_guards
            .iter()
            .filter(|guard| guard.guard_id != "guard_4_fault")
            .all(|guard| !guard.faulted),
        "non-faulted Guards must remain distinguishable in the aggregate"
    );

    // Invariant 6: The canonical bundle is lossless, while provider feedback
    // redacts technical-fault details without dropping non-fault Guard feedback.
    let formatted_feedback = arc::format_bundle_feedback_for_provider(
        &eval_result.failure_bundle,
        "Base failure summary",
    )
    .expect("formatting must succeed fail-closed");
    assert!(formatted_feedback.contains("Evaluation rule cycle detected"));
    assert!(formatted_feedback.contains("guard 2 ask feedback"));
    assert!(formatted_feedback.contains("guard 3 deny feedback"));
    assert!(formatted_feedback.contains("guard 6 advisory message"));
    assert!(!formatted_feedback.contains("guard 4 fault feedback"));
    assert!(!formatted_feedback.contains("cycle_a"));

    // Invariant 7: When disposition is RuntimeFault / Deny, interactive decision is NOT opened (non-overridable)
    let non_overridable = arc::interactive_decision_request_from_evaluation_result(
        &eval_result,
        ProviderTarget::Codex,
        ArcEventType::ToolCall,
        &event.event_id,
        "inv-six-1",
        Some(operation.clone()),
        Some("bash git push".into()),
        "six guards aggregate test",
    )
    .expect("interactive request construction succeeds");
    assert!(
        non_overridable.is_none(),
        "RuntimeFault/Deny cannot be overridden by interactive UI"
    );

    // Invariant 8: When Ask is the effective disposition, a single global resolution request is produced,
    // preserving all authorization requirements and all failed guards without primary guard bias
    let mut ask_eval_result = eval_result.clone();
    ask_eval_result.effective_disposition = EffectiveDisposition::Ask;
    let ask_req = arc::interactive_decision_request_from_evaluation_result(
        &ask_eval_result,
        ProviderTarget::Codex,
        ArcEventType::ToolCall,
        &event.event_id,
        "inv-six-1",
        Some(operation),
        Some("bash git push".into()),
        "six guards aggregate test",
    )
    .expect("interactive request construction succeeds")
    .expect("interactive request must be generated when effective disposition is Ask");

    assert!(
        !ask_req.presentation_id().is_empty(),
        "Exactly one global resolution_id must be assigned"
    );
    assert_eq!(
        ask_req.exact_authorizations().unwrap().len(),
        1,
        "Authorizations must be preserved"
    );
    assert_eq!(
        ask_req.exact_authorizations().unwrap()[0].guard_id,
        "guard_5_auth"
    );
    assert_eq!(
        ask_req.failure_bundle().unwrap().failed_guards.len(),
        4,
        "Failure bundle must be preserved without loss"
    );
}

fn make_test_ir(
    tool_guards: Vec<BoundToolGuard>,
    lifecycle_guards: Vec<BoundLifecycleGuard>,
) -> BehaviorIR {
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
        lifecycle_guards,
        tool_guards,
        rules: BTreeMap::new(),
    };
    ir.content_hash = Some(ir.compute_content_hash());
    ir
}

#[test]
fn test_f4_continue_with_authorizations_requires_ui_and_fails_closed_without_resolution() {
    let ir = make_test_ir(
        vec![BoundToolGuard {
            id: "guard-auth-decide".into(),
            matcher: BoundMatcher {
                exact_patterns: vec!["git push".into()],
                regex_patterns: Vec::new(),
            },
            require: BoundRuleExpression::Decide {
                prompt: "Audit git push".into(),
            },
            on_failure: OnFailureConfig {
                action: ActionType::Deny,
                feedback: Some("Declined".into()),
            },
            order: 1,
            declaration_order: 0,
        }],
        Vec::new(),
    );

    let decision_provider =
        Arc::new(MockDecisionProvider::new().with_decision("Audit git push", true));
    let state_store = Arc::new(arc::InMemoryStateStore::default());
    let mut session = ArcRuntimeSession::new("test-f4-auth-cont", ir)
        .with_decision_provider(decision_provider)
        .with_state_store(state_store.clone());

    let event = ArcEvent::tool_call("test-f4-auth-cont", "ev-tool-1", 1, "bash", "git push");
    let operation = arc::CurrentOperation::from(&event);

    let eval_result = evaluate_session_event(&mut session, event.clone()).expect("evaluates");
    assert_eq!(
        eval_result.effective_disposition,
        EffectiveDisposition::Continue
    );
    assert_eq!(eval_result.authorization_requirements.len(), 1);

    // 1. Exact authorization produces an Ask while preserving semantic Continue.
    let req = arc::interactive_decision_request_from_evaluation_result(
        &eval_result,
        ProviderTarget::Codex,
        ArcEventType::ToolCall,
        &event.event_id,
        "inv-f4-1",
        Some(operation),
        Some("bash git push".into()),
        "test reason",
    )
    .expect("helper succeeds")
    .expect("exact authorization must open Ask");
    assert_eq!(req.requested_action(), ActionType::Ask);
    assert_eq!(
        req.presentation_kind(),
        arc::PresentationKind::ExactOperationAuthorization
    );

    // 2. Adapter projection without the completed Ask round-trip must fail closed.
    let codex_out = CodexAdapter::evaluation_result_to_pre_tool_use_output(&eval_result)
        .expect("codex output succeeds");
    assert_eq!(
        codex_out.hook_specific_output.unwrap().permission_decision,
        "deny",
        "Codex must not allow an unresolved exact authorization"
    );
    let codex_resolution = arc::target::resolve_capability(arc::target::CapabilityContext::cli(
        ProviderTarget::Codex,
        arc::target::OsTarget::host().unwrap(),
        arc::target::CapabilityEvent::ToolCall,
        ActionType::Message,
        arc::target::DecisionUiMode::Auto,
    ));
    let codex_resolved_out =
        CodexAdapter::evaluation_result_to_pre_tool_use_output_with_resolution(
            &eval_result,
            &codex_resolution,
        )
        .expect("codex resolved output succeeds");
    assert_eq!(
        codex_resolved_out
            .hook_specific_output
            .unwrap()
            .permission_decision,
        "deny",
        "Capability resolution alone does not satisfy exact authorization"
    );

    // 3. AGY has the same fail-closed behavior without an explicit UI response.
    let agy_out = AgyAdapter::evaluation_result_to_pre_tool_use_output(&eval_result)
        .expect("agy output succeeds");
    assert_eq!(
        agy_out.decision, "deny",
        "AGY must not allow an unresolved exact authorization"
    );
    assert!(
        agy_out
            .reason
            .unwrap()
            .contains("without user confirmation")
    );
    let agy_resolution = arc::target::resolve_capability(arc::target::CapabilityContext::cli(
        ProviderTarget::Gemini,
        arc::target::OsTarget::host().unwrap(),
        arc::target::CapabilityEvent::ToolCall,
        ActionType::Message,
        arc::target::DecisionUiMode::Auto,
    ));
    let agy_resolved_out = AgyAdapter::evaluation_result_to_pre_tool_use_output_with_resolution(
        &eval_result,
        &agy_resolution,
    )
    .expect("agy resolved output succeeds");
    assert_eq!(
        agy_resolved_out.decision, "deny",
        "Capability resolution alone does not satisfy exact authorization"
    );
    assert!(
        agy_resolved_out
            .reason
            .unwrap()
            .contains("without user confirmation")
    );

    // 4. Verify no durable grant was created in the state store
    let auth = &eval_result.authorization_requirements[0];
    let auth_context = exact_authorization_context(
        std::slice::from_ref(auth),
        &auth.event_id,
        &auth.tool,
        "ws-f4",
        "test-f4-auth-cont",
        "inv-f4-1",
        "policy-f4",
        "evidence-f4",
    );
    let consumed = state_store
        .consume_exact_authorization(auth, &auth_context, 1000)
        .unwrap();
    assert!(
        !consumed,
        "No durable authorization grant should exist or be consumable"
    );
}

#[test]
fn test_f4_tool_call_mappings_ask_ui_continue_allow_deny_block() {
    let ir = make_test_ir(
        vec![
            BoundToolGuard {
                id: "guard-ask".into(),
                matcher: BoundMatcher {
                    exact_patterns: vec!["run-ask".into()],
                    regex_patterns: Vec::new(),
                },
                require: BoundRuleExpression::Probe {
                    command: "check".into(),
                    expected_in: vec!["ok".into()],
                },
                on_failure: OnFailureConfig {
                    action: ActionType::Ask,
                    feedback: Some("Prompt user for tool ask".into()),
                },
                order: 1,
                declaration_order: 0,
            },
            BoundToolGuard {
                id: "guard-continue".into(),
                matcher: BoundMatcher {
                    exact_patterns: vec!["run-cont".into()],
                    regex_patterns: Vec::new(),
                },
                require: BoundRuleExpression::Probe {
                    command: "check".into(),
                    expected_in: vec!["ok".into()],
                },
                on_failure: OnFailureConfig {
                    action: ActionType::Deny,
                    feedback: None,
                },
                order: 2,
                declaration_order: 1,
            },
            BoundToolGuard {
                id: "guard-deny".into(),
                matcher: BoundMatcher {
                    exact_patterns: vec!["run-deny".into()],
                    regex_patterns: Vec::new(),
                },
                require: BoundRuleExpression::Probe {
                    command: "check".into(),
                    expected_in: vec!["ok".into()],
                },
                on_failure: OnFailureConfig {
                    action: ActionType::Deny,
                    feedback: Some("Denied by policy".into()),
                },
                order: 3,
                declaration_order: 2,
            },
        ],
        Vec::new(),
    );

    let probes = Arc::new(MockProbeRunner::new().with_output("check", "fail"));
    let mut session =
        ArcRuntimeSession::new("test-f4-mappings", ir.clone()).with_probe_runner(probes);

    // Case 1: Ask -> Interactive request is built, and adapter maps to ask / UI
    let ev_ask = ArcEvent::tool_call("test-f4-mappings", "ev-ask", 1, "bash", "run-ask");
    let op_ask = arc::CurrentOperation::from(&ev_ask);
    let eval_ask = evaluate_session_event(&mut session, ev_ask.clone()).unwrap();
    assert_eq!(eval_ask.effective_disposition, EffectiveDisposition::Ask);

    let req_ask = arc::interactive_decision_request_from_evaluation_result(
        &eval_ask,
        ProviderTarget::Codex,
        ArcEventType::ToolCall,
        &ev_ask.event_id,
        "inv-1",
        Some(op_ask),
        Some("bash run-ask".into()),
        "test ask",
    )
    .expect("helper succeeds")
    .expect("interactive request generated on Ask");
    assert_eq!(
        req_ask.presentation_kind(),
        arc::PresentationKind::GuardFailures
    );

    // Case 2: Continue -> Direct allow
    let probes_ok = Arc::new(MockProbeRunner::new().with_output("check", "ok"));
    let mut session_ok =
        ArcRuntimeSession::new("test-f4-mappings-ok", ir.clone()).with_probe_runner(probes_ok);
    let ev_cont = ArcEvent::tool_call("test-f4-mappings-ok", "ev-cont", 2, "bash", "run-cont");
    let eval_cont = evaluate_session_event(&mut session_ok, ev_cont).unwrap();
    assert_eq!(
        eval_cont.effective_disposition,
        EffectiveDisposition::Continue
    );

    let codex_cont = CodexAdapter::evaluation_result_to_pre_tool_use_output(&eval_cont).unwrap();
    assert!(
        codex_cont.hook_specific_output.is_none(),
        "Codex allows directly on Continue"
    );
    let agy_cont = AgyAdapter::evaluation_result_to_pre_tool_use_output(&eval_cont).unwrap();
    assert_eq!(agy_cont.decision, "allow");

    // Case 3: Deny -> Tool blocked
    let ev_deny = ArcEvent::tool_call("test-f4-mappings", "ev-deny", 3, "bash", "run-deny");
    let eval_deny = evaluate_session_event(&mut session, ev_deny).unwrap();
    assert_eq!(eval_deny.effective_disposition, EffectiveDisposition::Deny);

    let codex_deny = CodexAdapter::evaluation_result_to_pre_tool_use_output(&eval_deny).unwrap();
    assert_eq!(
        codex_deny.hook_specific_output.unwrap().permission_decision,
        "deny"
    );
    let agy_deny = AgyAdapter::evaluation_result_to_pre_tool_use_output(&eval_deny).unwrap();
    assert_eq!(agy_deny.decision, "deny");

    // Case 4: RuntimeFault -> Fail closed
    let mut rules = BTreeMap::new();
    rules.insert(
        "c_a".into(),
        BoundRuleExpression::RuleRef { name: "c_b".into() },
    );
    rules.insert(
        "c_b".into(),
        BoundRuleExpression::RuleRef { name: "c_a".into() },
    );
    let mut ir_cycle = ir;
    ir_cycle.rules = rules;
    ir_cycle.tool_guards.push(BoundToolGuard {
        id: "guard-fault".into(),
        matcher: BoundMatcher {
            exact_patterns: vec!["run-fault".into()],
            regex_patterns: Vec::new(),
        },
        require: BoundRuleExpression::RuleRef { name: "c_a".into() },
        on_failure: OnFailureConfig {
            action: ActionType::Deny,
            feedback: None,
        },
        order: 4,
        declaration_order: 3,
    });
    let mut session_fault = ArcRuntimeSession::new("test-f4-mappings-fault", ir_cycle);
    let ev_fault =
        ArcEvent::tool_call("test-f4-mappings-fault", "ev-fault", 4, "bash", "run-fault");
    let eval_fault = evaluate_session_event(&mut session_fault, ev_fault).unwrap();
    assert_eq!(
        eval_fault.effective_disposition,
        EffectiveDisposition::RuntimeFault
    );

    let codex_fault = CodexAdapter::evaluation_result_to_pre_tool_use_output(&eval_fault).unwrap();
    assert_eq!(
        codex_fault
            .hook_specific_output
            .unwrap()
            .permission_decision,
        "deny"
    );
    let agy_fault = AgyAdapter::evaluation_result_to_pre_tool_use_output(&eval_fault).unwrap();
    assert_eq!(agy_fault.decision, "deny");
}

#[test]
fn test_f4_session_start_and_pre_invocation_deny_terminates_session() {
    let ir = make_test_ir(
        Vec::new(),
        vec![BoundLifecycleGuard {
            id: "guard-start-deny".into(),
            triggers: vec![LifecycleTrigger::Start],
            require: BoundRuleExpression::Probe {
                command: "check-start".into(),
                expected_in: vec!["authorized".into()],
            },
            on_failure: OnFailureConfig {
                action: ActionType::Deny,
                feedback: Some("Cannot start session on main branch".into()),
            },
            order: 1,
            declaration_order: 0,
        }],
    );

    let probes_deny = Arc::new(MockProbeRunner::new().with_output("check-start", "unauthorized"));
    let store = arc::SqliteStateStore::open_in_memory().unwrap();
    let anchor = store
        .trust_and_anchor_ir(Path::new("f4-start.json"), &ir)
        .unwrap();
    let mut session = ArcRuntimeSession::new("test-f4-start", ir.clone())
        .with_trusted_anchor(anchor)
        .unwrap()
        .with_probe_runner(probes_deny);

    // 1. AGY PreInvocation on Deny must produce explicit terminal abort output
    let ev_start = ArcEvent::lifecycle("test-f4-start", "ev-start-1", ArcEventType::Start, 1);
    let eval_start = evaluate_session_event(&mut session, ev_start).unwrap();
    assert_eq!(eval_start.effective_disposition, EffectiveDisposition::Deny);

    let agy_pre_out = AgyAdapter::evaluation_result_to_pre_invocation_output(&eval_start).unwrap();
    assert_eq!(
        agy_pre_out.decision.as_deref(),
        Some("abort"),
        "AGY PreInvocation must explicitly abort on Deny"
    );
    assert!(
        agy_pre_out
            .reason
            .as_deref()
            .unwrap()
            .contains("Cannot start session on main branch")
    );
    assert_eq!(agy_pre_out.inject_steps.len(), 1);
    assert!(
        agy_pre_out.inject_steps[0]["ephemeralMessage"]
            .as_str()
            .unwrap()
            .contains("Cannot start session on main branch")
    );

    // 2. AGY PreInvocation on Continue produces allow
    let probes_ok = Arc::new(MockProbeRunner::new().with_output("check-start", "authorized"));
    let mut session_ok =
        ArcRuntimeSession::new("test-f4-start-ok", ir).with_probe_runner(probes_ok);
    let ev_start_ok = ArcEvent::lifecycle("test-f4-start-ok", "ev-start-2", ArcEventType::Start, 2);
    let eval_start_ok = evaluate_session_event(&mut session_ok, ev_start_ok).unwrap();
    assert_eq!(
        eval_start_ok.effective_disposition,
        EffectiveDisposition::Continue
    );

    let agy_cont_out =
        AgyAdapter::evaluation_result_to_pre_invocation_output(&eval_start_ok).unwrap();
    assert!(
        agy_cont_out.decision.is_none(),
        "AGY PreInvocation on Continue emits empty allow without abort"
    );

    // 3. AGY PreInvocation on RuntimeFault produces explicit terminal abort output
    let mut rules = BTreeMap::new();
    rules.insert(
        "c_a".into(),
        BoundRuleExpression::RuleRef { name: "c_b".into() },
    );
    rules.insert(
        "c_b".into(),
        BoundRuleExpression::RuleRef { name: "c_a".into() },
    );
    let mut ir_fault = make_test_ir(
        Vec::new(),
        vec![BoundLifecycleGuard {
            id: "guard-start-fault".into(),
            triggers: vec![LifecycleTrigger::Start],
            require: BoundRuleExpression::RuleRef { name: "c_a".into() },
            on_failure: OnFailureConfig {
                action: ActionType::Deny,
                feedback: None,
            },
            order: 1,
            declaration_order: 0,
        }],
    );
    ir_fault.rules = rules;
    let mut session_fault = ArcRuntimeSession::new("test-f4-start-fault", ir_fault);
    let ev_start_fault =
        ArcEvent::lifecycle("test-f4-start-fault", "ev-start-3", ArcEventType::Start, 3);
    let eval_start_fault = evaluate_session_event(&mut session_fault, ev_start_fault).unwrap();
    assert_eq!(
        eval_start_fault.effective_disposition,
        EffectiveDisposition::RuntimeFault
    );

    let agy_fault_out =
        AgyAdapter::evaluation_result_to_pre_invocation_output(&eval_start_fault).unwrap();
    assert_eq!(
        agy_fault_out.decision.as_deref(),
        Some("abort"),
        "RuntimeFault must abort session"
    );
}

#[test]
fn test_f4_stop_deny_terminates_session_instead_of_continue_loop() {
    let ir = make_test_ir(
        Vec::new(),
        vec![BoundLifecycleGuard {
            id: "guard-stop-deny".into(),
            triggers: vec![LifecycleTrigger::End],
            require: BoundRuleExpression::Probe {
                command: "check-stop".into(),
                expected_in: vec!["clean".into()],
            },
            on_failure: OnFailureConfig {
                action: ActionType::Deny,
                feedback: Some("Unfinished tasks prevent stop".into()),
            },
            order: 1,
            declaration_order: 0,
        }],
    );

    let probes_deny = Arc::new(MockProbeRunner::new().with_output("check-stop", "dirty"));
    let store = arc::SqliteStateStore::open_in_memory().unwrap();
    let anchor = store
        .trust_and_anchor_ir(Path::new("f4-stop.json"), &ir)
        .unwrap();
    let mut session = ArcRuntimeSession::new("test-f4-stop", ir.clone())
        .with_trusted_anchor(anchor)
        .unwrap()
        .with_probe_runner(probes_deny);

    let ev_stop = ArcEvent::lifecycle("test-f4-stop", "ev-stop-1", ArcEventType::End, 1);
    let eval_stop = evaluate_session_event(&mut session, ev_stop).unwrap();
    assert_eq!(eval_stop.effective_disposition, EffectiveDisposition::Deny);

    // 1. Codex Stop output on Deny must terminate/abort session
    let codex_stop = CodexAdapter::evaluation_result_to_stop_output(&eval_stop).unwrap();
    assert_eq!(
        codex_stop.r#continue,
        Some(false),
        "Codex Stop output must abort session on Deny, never continue_loop"
    );
    assert!(
        codex_stop.decision.is_none(),
        "Must not be continue_loop block"
    );
    assert!(
        codex_stop
            .stop_reason
            .as_deref()
            .unwrap()
            .contains("Unfinished tasks prevent stop")
    );

    // 2. AGY Stop output on Deny must stop with reason, NEVER continue
    let agy_stop = AgyAdapter::evaluation_result_to_stop_output(&eval_stop).unwrap();
    assert_eq!(
        agy_stop.decision, "stop",
        "AGY Stop output must be 'stop' with reason on Deny, NEVER 'continue'"
    );
    assert!(
        agy_stop
            .reason
            .as_deref()
            .unwrap()
            .contains("Unfinished tasks prevent stop")
    );

    // 3. Continue disposition permits clean stop
    let probes_clean = Arc::new(MockProbeRunner::new().with_output("check-stop", "clean"));
    let mut session_clean =
        ArcRuntimeSession::new("test-f4-stop-clean", ir).with_probe_runner(probes_clean);
    let ev_stop_clean =
        ArcEvent::lifecycle("test-f4-stop-clean", "ev-stop-2", ArcEventType::End, 2);
    let eval_stop_clean = evaluate_session_event(&mut session_clean, ev_stop_clean).unwrap();
    assert_eq!(
        eval_stop_clean.effective_disposition,
        EffectiveDisposition::Continue
    );

    let codex_clean_stop =
        CodexAdapter::evaluation_result_to_stop_output(&eval_stop_clean).unwrap();
    assert!(
        codex_clean_stop.decision.is_none(),
        "Codex clean stop has no abort decision"
    );

    let agy_clean_stop = AgyAdapter::evaluation_result_to_stop_output(&eval_stop_clean).unwrap();
    assert_eq!(agy_clean_stop.decision, "stop", "AGY clean stop is 'stop'");
    assert!(
        agy_clean_stop.reason.is_none(),
        "AGY clean stop has no failure reason"
    );
}
