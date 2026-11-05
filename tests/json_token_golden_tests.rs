use arc::{
    ActionType, ActivationCacheSummary, ActivationSnapshot, ArcEvent, ArcEventType,
    CacheResolutionProvenance, CurrentOperation, DECISION_TASK_REQUEST_SCHEMA,
    DIALOG_REQUEST_SCHEMA, DIALOG_RESPONSE_SCHEMA, DecisionEvaluationInput,
    DecisionExecutionProfile, DecisionTaskFault, DecisionTaskRequest, DialogAuthorizationItem,
    DialogRequest, DialogResponse, DialogViolationItem, EVENT_EVALUATION_REPORT_SCHEMA,
    EffectiveDisposition, EvaluationCompleteness, EvaluationFault, EventEvaluationReport,
    ExactOperationAuthorization, ExpressionPathSegment, FAILURE_BUNDLE_SCHEMA, FailureBundle,
    FailureCause, FailureCauseKind, GuardResult, GuardResultState, MatchingGuardSnapshot,
    PortableDecision, ProviderTarget, SemanticDecisionEvidence, SessionContext, UnresolvedReason,
};
use serde_json::{Value, json};

fn violation() -> DialogViolationItem {
    DialogViolationItem {
        guard_id: "guard-a".into(),
        summary: "Tests are incomplete".into(),
        configured_feedback: Some("Run the tests.".into()),
        auditor_findings: Some("The suite did not run.".into()),
        scope: "lifecycle:end".into(),
        failed_probes: Vec::new(),
    }
}

fn authorization() -> DialogAuthorizationItem {
    DialogAuthorizationItem {
        guard_id: "guard-tool".into(),
        summary: "Authorize exact operation".into(),
        auditor_findings: None,
        operation_fingerprint: "sha256:operation".into(),
    }
}

fn dialog_guard_failures() -> Value {
    serde_json::to_value(DialogRequest::guard_failures(
        "request-1",
        "Arc policy decision",
        "this activation",
        vec![violation()],
        "sha256:bundle",
        100,
    ))
    .unwrap()
}

fn dialog_exact_authorization() -> Value {
    serde_json::to_value(DialogRequest::exact_authorizations(
        "request-2",
        "Authorize operation",
        "once",
        vec![authorization()],
        "git status",
        "sha256:bundle",
        100,
    ))
    .unwrap()
}

fn dialog_aggregate() -> Value {
    serde_json::to_value(DialogRequest::aggregate_decision(
        "request-3",
        "Aggregate policy decision",
        "activation",
        vec![violation()],
        vec![authorization()],
        Some("git commit -m test".into()),
        "sha256:bundle",
        100,
    ))
    .unwrap()
}

fn dialog_response(decision: PortableDecision) -> Value {
    serde_json::to_value(DialogResponse {
        schema: DIALOG_RESPONSE_SCHEMA.into(),
        request_id: "request-1".into(),
        bundle_fingerprint: "sha256:bundle".into(),
        decision,
        transport: "arc_embedded_ui".into(),
        theme: "dark".into(),
        message: Some("ok".into()),
    })
    .unwrap()
}

fn event_report() -> EventEvaluationReport {
    let mut violated = GuardResult::test_result("guard-deny", 1, 1, ActionType::Deny, false);
    violated.state = GuardResultState::Violated {
        causes: vec![FailureCause {
            occurrence_id: "occurrence-1".into(),
            physical_evaluation_id: "physical-1".into(),
            cache_provenance: CacheResolutionProvenance::Executed,
            expression_path: Vec::new(),
            kind: FailureCauseKind::DecisionViolated,
            summary: "configured policy failed".into(),
            auditor_findings: Some("review finding".into()),
            deterministic_evidence: Vec::new(),
        }],
    };
    let satisfied = GuardResult::test_result("guard-ok", 2, 2, ActionType::Message, true);
    EventEvaluationReport {
        schema: EVENT_EVALUATION_REPORT_SCHEMA.into(),
        invocation_id: "invocation-1".into(),
        provider: ProviderTarget::Codex,
        event_id: "event-1".into(),
        event_type: ArcEventType::End,
        input_fingerprint: "sha256:input".into(),
        guard_results: vec![violated, satisfied],
        effective_disposition: EffectiveDisposition::Deny,
        authorization_requirements: vec![ExactOperationAuthorization {
            guard_id: "guard-tool".into(),
            operation_fingerprint: "sha256:operation".into(),
            event_id: "event-1".into(),
            tool: "shell".into(),
            normalized_arguments_fingerprint: "sha256:arguments".into(),
        }],
        activation_cache_summary: ActivationCacheSummary {
            logical_occurrences: 2,
            unique_probe_evaluations: 1,
            unique_decision_evaluations: 1,
            coalesced_in_flight: 1,
            reused_completed: 0,
            physical_faults: 0,
        },
        report_fingerprint: "sha256:report".into(),
        started_unix_ms: 1,
        completed_unix_ms: 2,
    }
}

fn event_report_value() -> Value {
    serde_json::to_value(event_report()).unwrap()
}

fn failure_bundle() -> Value {
    let bundle = FailureBundle::from_report(&event_report()).expect("bundle");
    serde_json::to_value(bundle).unwrap()
}

fn decision_task_request() -> Value {
    serde_json::to_value(DecisionTaskRequest {
        schema: DECISION_TASK_REQUEST_SCHEMA.into(),
        physical_evaluation_id: "physical-1".into(),
        activation_id: "activation-1".into(),
        invocation_id: "invocation-1".into(),
        evaluation_key: "key-1".into(),
        profile: DecisionExecutionProfile {
            provider: ProviderTarget::Codex,
            transport: "fixture".into(),
            model: None,
            adapter_contract_fingerprint: "adapter".into(),
            output_schema_fingerprint: "schema".into(),
            sandbox_mode: "read_only".into(),
            approval_policy: "never".into(),
        },
        input: DecisionEvaluationInput {
            goal: "goal".into(),
            role: "read_only_compliance_auditor".into(),
            current_operation: CurrentOperation {
                event_type: ArcEventType::End,
                tool: None,
                input: None,
                command_text: None,
            },
            session_context: SessionContext {
                user_intent: "test".into(),
                ..SessionContext::default()
            },
            attested_evidence: SemanticDecisionEvidence {
                event_type: ArcEventType::End,
                event_id: "event-1".into(),
                scope: "test".into(),
                matcher_evidence: Vec::new(),
                matcher_evidence_truncated: false,
                deterministic_evidence: Vec::new(),
                deterministic_evidence_truncated: false,
            },
        },
        absolute_deadline_unix_ms: 100,
    })
    .unwrap()
}

fn activation_snapshot() -> Value {
    serde_json::to_value(ActivationSnapshot::from_event(
        "activation-1",
        "invocation-1",
        ProviderTarget::Codex,
        &ArcEvent::lifecycle("session-1", "event-1", ArcEventType::End, 1),
        SessionContext {
            user_intent: "validate".into(),
            ..SessionContext::default()
        },
        vec![MatchingGuardSnapshot {
            guard_id: "guard-a".into(),
            order: 1,
            declaration_order: 1,
            action: ActionType::Deny,
            configured_feedback: None,
            matcher_evidence: Vec::new(),
            matcher_evidence_truncated: false,
        }],
        100,
    ))
    .unwrap()
}

/// Dialog request, `guard_failures` kind: schema token, keys and kind token.
#[test]
fn dialog_request_guard_failures_json_is_pinned() {
    let expected = json!({
        "authorizations": [],
        "bundle_fingerprint": "sha256:bundle",
        "expires_at_unix_ms": 100,
        "operation": null,
        "presentation_kind": "guard_failures",
        "request_id": "request-1",
        "schema": "arc.decision.dialog.request.v2",
        "scope": "this activation",
        "title": "Arc policy decision",
        "violations": [
            {
                "auditor_findings": "The suite did not run.",
                "configured_feedback": "Run the tests.",
                "guard_id": "guard-a",
                "scope": "lifecycle:end",
                "summary": "Tests are incomplete"
            }
        ]
    });
    assert_eq!(dialog_guard_failures(), expected);
}

/// REQ-001: the optional `failed_probes` list of a violation, with every field set.
#[test]
fn dialog_request_failed_probes_json_is_pinned() {
    let mut item = violation();
    item.failed_probes = vec![arc::DialogFailedProbe {
        rule_name: Some("tests-green".into()),
        command: "cargo test".into(),
        reason: Some("negated expression evaluated to true".into()),
    }];
    let value = serde_json::to_value(DialogRequest::guard_failures(
        "request-1",
        "Arc policy decision",
        "this activation",
        vec![item],
        "sha256:bundle",
        100,
    ))
    .unwrap();
    let expected = json!({
        "authorizations": [],
        "bundle_fingerprint": "sha256:bundle",
        "expires_at_unix_ms": 100,
        "operation": null,
        "presentation_kind": "guard_failures",
        "request_id": "request-1",
        "schema": "arc.decision.dialog.request.v2",
        "scope": "this activation",
        "title": "Arc policy decision",
        "violations": [
            {
                "auditor_findings": "The suite did not run.",
                "configured_feedback": "Run the tests.",
                "failed_probes": [
                    {
                        "command": "cargo test",
                        "reason": "negated expression evaluated to true",
                        "rule_name": "tests-green"
                    }
                ],
                "guard_id": "guard-a",
                "scope": "lifecycle:end",
                "summary": "Tests are incomplete"
            }
        ]
    });
    assert_eq!(value, expected);
}

/// REQ-001: an inline probe carries its command alone; the absent optionals are
/// either omitted or null, both are accepted by the readers.
#[test]
fn dialog_request_inline_failed_probe_json_carries_the_command_alone() {
    let mut item = violation();
    item.failed_probes = vec![arc::DialogFailedProbe {
        rule_name: None,
        command: "git status --porcelain".into(),
        reason: None,
    }];
    let value = serde_json::to_value(DialogRequest::guard_failures(
        "request-1",
        "Arc policy decision",
        "this activation",
        vec![item],
        "sha256:bundle",
        100,
    ))
    .unwrap();
    let probes = value["violations"][0]["failed_probes"]
        .as_array()
        .expect("failed_probes list");
    assert_eq!(probes.len(), 1);
    assert_eq!(probes[0]["command"], "git status --porcelain");
    assert!(probes[0].get("rule_name").is_none_or(Value::is_null));
    assert!(probes[0].get("reason").is_none_or(Value::is_null));
}

/// Dialog request, `exact_operation_authorization` kind.
#[test]
fn dialog_request_exact_authorization_json_is_pinned() {
    let expected = json!({
        "authorizations": [
            {
                "guard_id": "guard-tool",
                "operation_fingerprint": "sha256:operation",
                "summary": "Authorize exact operation"
            }
        ],
        "bundle_fingerprint": "sha256:bundle",
        "expires_at_unix_ms": 100,
        "operation": "git status",
        "presentation_kind": "exact_operation_authorization",
        "request_id": "request-2",
        "schema": "arc.decision.dialog.request.v2",
        "scope": "once",
        "title": "Authorize operation",
        "violations": []
    });
    assert_eq!(dialog_exact_authorization(), expected);
}

/// Dialog request, `aggregate_decision` kind.
#[test]
fn dialog_request_aggregate_decision_json_is_pinned() {
    let expected = json!({
        "authorizations": [
            {
                "guard_id": "guard-tool",
                "operation_fingerprint": "sha256:operation",
                "summary": "Authorize exact operation"
            }
        ],
        "bundle_fingerprint": "sha256:bundle",
        "expires_at_unix_ms": 100,
        "operation": "git commit -m test",
        "presentation_kind": "aggregate_decision",
        "request_id": "request-3",
        "schema": "arc.decision.dialog.request.v2",
        "scope": "activation",
        "title": "Aggregate policy decision",
        "violations": [
            {
                "auditor_findings": "The suite did not run.",
                "configured_feedback": "Run the tests.",
                "guard_id": "guard-a",
                "scope": "lifecycle:end",
                "summary": "Tests are incomplete"
            }
        ]
    });
    assert_eq!(dialog_aggregate(), expected);
}

/// Dialog response with an `allow` decision.
#[test]
fn dialog_response_allow_json_is_pinned() {
    let expected = json!({
        "bundle_fingerprint": "sha256:bundle",
        "decision": {
            "status": "allow"
        },
        "message": "ok",
        "request_id": "request-1",
        "schema": "arc.decision.dialog.response.v2",
        "theme": "dark",
        "transport": "arc_embedded_ui"
    });
    assert_eq!(dialog_response(PortableDecision::Allow), expected);
}

/// Dialog response with a `deny` decision.
#[test]
fn dialog_response_deny_json_is_pinned() {
    let expected = json!({
        "bundle_fingerprint": "sha256:bundle",
        "decision": {
            "status": "deny"
        },
        "message": "ok",
        "request_id": "request-1",
        "schema": "arc.decision.dialog.response.v2",
        "theme": "dark",
        "transport": "arc_embedded_ui"
    });
    assert_eq!(dialog_response(PortableDecision::Deny), expected);
}

/// Dialog response with an `unresolved` decision and its reason token.
#[test]
fn dialog_response_unresolved_json_is_pinned() {
    let expected = json!({
        "bundle_fingerprint": "sha256:bundle",
        "decision": {
            "reason": "timed_out",
            "status": "unresolved"
        },
        "message": "ok",
        "request_id": "request-1",
        "schema": "arc.decision.dialog.response.v2",
        "theme": "dark",
        "transport": "arc_embedded_ui"
    });
    assert_eq!(
        dialog_response(PortableDecision::Unresolved(UnresolvedReason::TimedOut)),
        expected
    );
}

/// Event evaluation report: schema token, keys, state and disposition tokens.
#[test]
fn event_evaluation_report_json_is_pinned() {
    let expected = json!({
        "activation_cache_summary": {
            "coalesced_in_flight": 1,
            "logical_occurrences": 2,
            "physical_faults": 0,
            "reused_completed": 0,
            "unique_decision_evaluations": 1,
            "unique_probe_evaluations": 1
        },
        "authorization_requirements": [
            {
                "event_id": "event-1",
                "guard_id": "guard-tool",
                "normalized_arguments_fingerprint": "sha256:arguments",
                "operation_fingerprint": "sha256:operation",
                "tool": "shell"
            }
        ],
        "completed_unix_ms": 2,
        "effective_disposition": "deny",
        "event_id": "event-1",
        "event_type": "end",
        "guard_results": [
            {
                "completeness": "complete",
                "configured_action": "deny",
                "declaration_order": 1,
                "evidence_fingerprint": "sha256:1e6637ffaaa4d0d8b6cf3ea2252c6d2fe5f1c2951d0b4df70cca02908a680f45",
                "guard_id": "guard-deny",
                "order": 1,
                "state": {
                    "causes": [
                        {
                            "auditor_findings": "review finding",
                            "cache_provenance": "executed",
                            "deterministic_evidence": [],
                            "expression_path": [],
                            "kind": "decision_violated",
                            "occurrence_id": "occurrence-1",
                            "physical_evaluation_id": "physical-1",
                            "summary": "configured policy failed"
                        }
                    ],
                    "state": "violated"
                }
            },
            {
                "completeness": "complete",
                "configured_action": "message",
                "declaration_order": 2,
                "evidence_fingerprint": "sha256:c147bde910b924e8a50b4bdc2c47085e028c8c4ab0e54b2a18895bd48dc1e47d",
                "guard_id": "guard-ok",
                "order": 2,
                "state": {
                    "state": "satisfied"
                }
            }
        ],
        "input_fingerprint": "sha256:input",
        "invocation_id": "invocation-1",
        "provider": "codex",
        "report_fingerprint": "sha256:report",
        "schema": "arc.event_evaluation.report.v1",
        "started_unix_ms": 1
    });
    assert_eq!(event_report_value(), expected);
}

/// Failure bundle derived from the pinned report, including its fingerprints.
#[test]
fn failure_bundle_json_is_pinned() {
    let expected = json!({
        "bundle_fingerprint": "sha256:e7da6510fc5c47bbb159d62adde2b68ad98a2fb7fd7987d11cbb3baffa16e6ae",
        "bundle_id": "bundle-sha256:32d3febf04ed8ccb5b45b6b61ab440dc85d430771303bba099379b3fc2980637",
        "completeness": "complete",
        "effective_disposition": "deny",
        "evaluation_faults": [],
        "event_id": "event-1",
        "event_type": "end",
        "failed_guards": [
            {
                "causes": [
                    {
                        "auditor_findings": "review finding",
                        "cache_provenance": "executed",
                        "deterministic_evidence": [],
                        "expression_path": [],
                        "kind": "decision_violated",
                        "occurrence_id": "occurrence-1",
                        "physical_evaluation_id": "physical-1",
                        "summary": "configured policy failed"
                    }
                ],
                "configured_action": "deny",
                "configured_feedback": null,
                "evidence_fingerprint": "sha256:1e6637ffaaa4d0d8b6cf3ea2252c6d2fe5f1c2951d0b4df70cca02908a680f45",
                "faulted": false,
                "guard_id": "guard-deny"
            }
        ],
        "input_fingerprint": "sha256:input",
        "invocation_id": "invocation-1",
        "schema": "arc.failure_bundle.v1"
    });
    assert_eq!(failure_bundle(), expected);
}

/// Decision task request: schema token and nested keys.
#[test]
fn decision_task_request_json_is_pinned() {
    let expected = json!({
        "absolute_deadline_unix_ms": 100,
        "activation_id": "activation-1",
        "evaluation_key": "key-1",
        "input": {
            "attested_evidence": {
                "deterministic_evidence": [],
                "deterministic_evidence_truncated": false,
                "event_id": "event-1",
                "event_type": "end",
                "matcher_evidence": [],
                "matcher_evidence_truncated": false,
                "scope": "test"
            },
            "current_operation": {
                "event_type": "end"
            },
            "goal": "goal",
            "role": "read_only_compliance_auditor",
            "session_context": {
                "files_created_or_modified": [],
                "test_commands_run": [],
                "tools_executed_count": 0,
                "user_intent": "test"
            }
        },
        "invocation_id": "invocation-1",
        "physical_evaluation_id": "physical-1",
        "profile": {
            "adapter_contract_fingerprint": "adapter",
            "approval_policy": "never",
            "model": null,
            "output_schema_fingerprint": "schema",
            "provider": "codex",
            "sandbox_mode": "read_only",
            "transport": "fixture"
        },
        "schema": "arc.decision_task.request.v1"
    });
    assert_eq!(decision_task_request(), expected);
}

/// Activation inputs: the `arc.evaluation_snapshot.v1` token stays unchanged.
#[test]
fn activation_snapshot_json_is_pinned() {
    let expected = json!({
        "absolute_deadline_unix_ms": 100,
        "activation_id": "activation-1",
        "current_operation": {
            "event_type": "end"
        },
        "event_id": "event-1",
        "event_type": "end",
        "input_fingerprint": "sha256:657c0f04d1231ce0b6867270e41e577ee8ed5a266f3eca5522edaeff82a543ed",
        "invocation_id": "invocation-1",
        "matching_guards": [
            {
                "action": "deny",
                "configured_feedback": null,
                "declaration_order": 1,
                "guard_id": "guard-a",
                "matcher_evidence": [],
                "matcher_evidence_truncated": false,
                "order": 1
            }
        ],
        "provider": "codex",
        "schema": "arc.evaluation_snapshot.v1",
        "session_context": {
            "files_created_or_modified": [],
            "test_commands_run": [],
            "tools_executed_count": 0,
            "user_intent": "validate"
        },
        "session_id": "session-1"
    });
    assert_eq!(activation_snapshot(), expected);
}

#[test]
fn wire_schema_constants_keep_their_literal_values() {
    assert_eq!(DECISION_TASK_REQUEST_SCHEMA, "arc.decision_task.request.v1");
    assert_eq!(
        EVENT_EVALUATION_REPORT_SCHEMA,
        "arc.event_evaluation.report.v1"
    );
    assert_eq!(FAILURE_BUNDLE_SCHEMA, "arc.failure_bundle.v1");
    assert_eq!(DIALOG_REQUEST_SCHEMA, "arc.decision.dialog.request.v2");
    assert_eq!(DIALOG_RESPONSE_SCHEMA, "arc.decision.dialog.response.v2");
}

#[test]
fn enum_tokens_keep_their_snake_case_values() {
    assert_eq!(
        serde_json::to_value([
            EffectiveDisposition::RuntimeFault,
            EffectiveDisposition::Deny,
            EffectiveDisposition::Ask,
            EffectiveDisposition::Message,
            EffectiveDisposition::Continue,
        ])
        .unwrap(),
        json!(["runtime_fault", "deny", "ask", "message", "continue"])
    );
    assert_eq!(
        serde_json::to_value([
            EvaluationCompleteness::Complete,
            EvaluationCompleteness::CompleteForGuardResultWithNonCausalSkips,
            EvaluationCompleteness::IncompleteDueToFault,
        ])
        .unwrap(),
        json!([
            "complete",
            "complete_for_guard_result_with_non_causal_skips",
            "incomplete_due_to_fault"
        ])
    );
    assert_eq!(
        serde_json::to_value([
            FailureCauseKind::ProbeMismatch,
            FailureCauseKind::DecisionViolated,
            FailureCauseKind::NegatedTrue,
            FailureCauseKind::RuleReference,
        ])
        .unwrap(),
        json!([
            "probe_mismatch",
            "decision_violated",
            "negated_true",
            "rule_reference"
        ])
    );
    assert_eq!(
        serde_json::to_value([
            CacheResolutionProvenance::Executed,
            CacheResolutionProvenance::CoalescedInFlight,
            CacheResolutionProvenance::ReusedCompleted,
        ])
        .unwrap(),
        json!(["executed", "coalesced_in_flight", "reused_completed"])
    );
    assert_eq!(
        serde_json::to_value([
            EvaluationFault::DeadlineExceeded,
            EvaluationFault::Probe {
                summary: "s".into()
            },
        ])
        .unwrap(),
        json!([{"kind": "deadline_exceeded"}, {"kind": "probe", "summary": "s"}])
    );
    assert_eq!(
        serde_json::to_value([
            ExpressionPathSegment::All { index: 0 },
            ExpressionPathSegment::Not,
            ExpressionPathSegment::RuleRef { name: "r".into() },
        ])
        .unwrap(),
        json!([
            {"segment": "all", "index": 0},
            {"segment": "not"},
            {"segment": "rule_ref", "name": "r"}
        ])
    );
    assert_eq!(
        serde_json::to_value([DecisionTaskFault::QueueDeadlineExceeded]).unwrap(),
        json!([{"kind": "queue_deadline_exceeded"}])
    );
}
