use std::collections::BTreeMap;

use arc::ir::BoundRuleExpression;
use arc::{
    ActionType, ActivationCacheSummary, ActivationSnapshot, ArcEventType,
    CacheResolutionProvenance, CurrentOperation, DecisionEvaluationInput, DecisionExecutionProfile,
    DialogAuthorizationItem, DialogRequest, DialogViolationItem, EffectiveDisposition,
    EvaluationFault, EventEvaluationReport, ExpressionPathSegment, FailureBundle, FailureCauseKind,
    GuardResultState, LeafResult, MatchingGuardSnapshot, PortableDecision, ProviderTarget,
    RuleReduction, SessionContext, decision_evaluation_key, expression_path_key,
    physical_evaluation_id, reduce_effective_disposition, reduce_guard_result,
    reduce_rule_expression,
};

fn decision_input(event_id: &str) -> DecisionEvaluationInput {
    DecisionEvaluationInput {
        goal: "Validate the requested release".into(),
        role: "read_only_compliance_auditor".into(),
        current_operation: CurrentOperation {
            event_type: ArcEventType::End,
            tool: None,
            input: Some(serde_json::json!({"b": 2, "a": 1})),
            command_text: None,
        },
        session_context: SessionContext {
            user_intent: "Release the validated build".into(),
            ..SessionContext::default()
        },
        attested_evidence: arc::SemanticDecisionEvidence {
            event_type: ArcEventType::End,
            event_id: event_id.into(),
            scope: "lifecycle:end".into(),
            matcher_evidence: Vec::new(),
            matcher_evidence_truncated: false,
            deterministic_evidence: Vec::new(),
            deterministic_evidence_truncated: false,
        },
    }
}

fn profile() -> DecisionExecutionProfile {
    DecisionExecutionProfile {
        provider: ProviderTarget::Codex,
        transport: "codex_app_server".into(),
        model: Some("test-model".into()),
        adapter_contract_fingerprint: "adapter-v1".into(),
        output_schema_fingerprint: "schema-v1".into(),
        sandbox_mode: "read_only".into(),
        approval_policy: "never".into(),
    }
}

fn violated(path: Vec<ExpressionPathSegment>, id: &str, summary: &str) -> LeafResult {
    LeafResult::Violated {
        cause: arc::FailureCause {
            occurrence_id: id.into(),
            physical_evaluation_id: physical_evaluation_id("activation", id),
            cache_provenance: CacheResolutionProvenance::Executed,
            expression_path: path,
            kind: FailureCauseKind::DecisionViolated,
            summary: summary.into(),
            auditor_findings: Some("finding".into()),
            deterministic_evidence: Vec::new(),
        },
    }
}

fn faulted_leaf(summary: &str) -> LeafResult {
    LeafResult::Faulted {
        fault: EvaluationFault::Probe {
            summary: summary.into(),
        },
    }
}

#[test]
fn semantic_keys_are_framed_and_include_every_verdict_input() {
    let first = decision_evaluation_key(&profile(), &decision_input("event-a"));
    let equivalent_json_order = decision_evaluation_key(
        &profile(),
        &DecisionEvaluationInput {
            current_operation: CurrentOperation {
                input: Some(serde_json::json!({"a": 1, "b": 2})),
                ..decision_input("event-a").current_operation
            },
            ..decision_input("event-a")
        },
    );
    assert_eq!(first, equivalent_json_order);
    assert_ne!(
        first,
        decision_evaluation_key(&profile(), &decision_input("event-b"))
    );
    assert_ne!(
        physical_evaluation_id("activation-a", &first),
        physical_evaluation_id("activation-b", &first)
    );
}

#[test]
fn reducer_preserves_only_causal_failures_and_stable_paths() {
    let first_path = vec![ExpressionPathSegment::All { index: 0 }];
    let second_path = vec![ExpressionPathSegment::All { index: 1 }];
    let expression = BoundRuleExpression::All(vec![
        BoundRuleExpression::Probe {
            command: "first".into(),
            expected_in: vec!["ok".into()],
        },
        BoundRuleExpression::Decide {
            prompt: "second".into(),
        },
    ]);
    let leaves = BTreeMap::from([
        (expression_path_key(&first_path), LeafResult::satisfied()),
        (
            expression_path_key(&second_path),
            violated(second_path.clone(), "occ-2", "second failed"),
        ),
    ]);
    let reduction = reduce_rule_expression(&expression, &BTreeMap::new(), &leaves).unwrap();
    assert_eq!(reduction.decision, Some(false));
    assert_eq!(reduction.causes.len(), 1);
    assert_eq!(reduction.causes[0].occurrence_id, "occ-2");
    assert_eq!(reduction.causes[0].expression_path, second_path);

    let any = BoundRuleExpression::Any(vec![
        BoundRuleExpression::Probe {
            command: "false".into(),
            expected_in: vec!["ok".into()],
        },
        BoundRuleExpression::Probe {
            command: "true".into(),
            expected_in: vec!["ok".into()],
        },
    ]);
    let any_leaves = BTreeMap::from([
        (
            expression_path_key(&[ExpressionPathSegment::Any { index: 0 }]),
            violated(
                vec![ExpressionPathSegment::Any { index: 0 }],
                "occ-false",
                "alternative failed",
            ),
        ),
        (
            expression_path_key(&[ExpressionPathSegment::Any { index: 1 }]),
            LeafResult::satisfied(),
        ),
    ]);
    let any_reduction = reduce_rule_expression(&any, &BTreeMap::new(), &any_leaves).unwrap();
    assert_eq!(any_reduction, RuleReduction::satisfied());
}

#[test]
fn disposition_precedence_and_v2_request_do_not_mix_domains() {
    let results = vec![
        arc::GuardResult::test_result("ask", 1, 0, ActionType::Ask, false),
        arc::GuardResult::test_result("deny", 2, 1, ActionType::Deny, false),
    ];
    assert_eq!(
        reduce_effective_disposition(&results),
        EffectiveDisposition::Deny
    );

    let request = DialogRequest::guard_failures(
        "request-1",
        "Policy decision",
        "lifecycle:end",
        vec![DialogViolationItem {
            guard_id: "guard-1".into(),
            summary: "The check failed".into(),
            configured_feedback: None,
            auditor_findings: None,
            scope: "lifecycle:end".into(),
            failed_probes: Vec::new(),
        }],
        "bundle-1",
        100,
    );
    request.validate().unwrap();
    assert!(
        DialogRequest {
            authorizations: vec![DialogAuthorizationItem {
                guard_id: "guard-2".into(),
                summary: "Confirm exact operation".into(),
                auditor_findings: None,
                operation_fingerprint: "operation-1".into(),
            }],
            violations: request.violations.clone(),
            presentation_kind: arc::PresentationKind::ExactOperationAuthorization,
            ..request
        }
        .validate()
        .is_err()
    );
    let _ = PortableDecision::Allow;
}

#[test]
fn reducer_handles_empty_identity_not_and_rule_cycles_without_io() {
    let empty_all = reduce_rule_expression(
        &BoundRuleExpression::All(Vec::new()),
        &BTreeMap::new(),
        &BTreeMap::new(),
    )
    .unwrap();
    assert_eq!(empty_all, RuleReduction::satisfied());

    let empty_any = reduce_rule_expression(
        &BoundRuleExpression::Any(Vec::new()),
        &BTreeMap::new(),
        &BTreeMap::new(),
    )
    .unwrap();
    assert_eq!(empty_any.decision, Some(false));

    let not = BoundRuleExpression::Not(Box::new(BoundRuleExpression::Probe {
        command: "true".into(),
        expected_in: vec!["ok".into()],
    }));
    let path = vec![ExpressionPathSegment::Not];
    let leaves = BTreeMap::from([(expression_path_key(&path), LeafResult::satisfied())]);
    let not_reduction = reduce_rule_expression(&not, &BTreeMap::new(), &leaves).unwrap();
    assert_eq!(not_reduction.decision, Some(false));
    assert_eq!(not_reduction.causes[0].kind, FailureCauseKind::NegatedTrue);
    assert!(
        not_reduction.causes[0].validate().is_ok(),
        "Cause produced by not(true) without leaf attribution must pass contract validation"
    );

    let mut catalog = BTreeMap::new();
    catalog.insert(
        "a".into(),
        BoundRuleExpression::RuleRef { name: "b".into() },
    );
    catalog.insert(
        "b".into(),
        BoundRuleExpression::RuleRef { name: "a".into() },
    );
    let cycle = reduce_rule_expression(
        &BoundRuleExpression::RuleRef { name: "a".into() },
        &catalog,
        &BTreeMap::new(),
    );
    assert!(matches!(
        cycle,
        Err(arc::ReductionError::RuleCycle { rule_name }) if rule_name == "a"
    ));

    let invalid: Result<arc::DecisionTaskResult, _> = serde_json::from_value(serde_json::json!({
        "status": "satisfied",
        "physical_evaluation_id": "pe-1",
        "evaluation_key": "key-1",
        "findings": null,
        "provider_receipt": {
            "provider": "codex",
            "transport": "codex_app_server",
            "isolated_conversation_fingerprint": "id",
            "started_unix_ms": 1,
            "completed_unix_ms": 2,
            "queue_duration_ms": 0,
            "inference_duration_ms": 1
        },
        "extra": true
    }));
    assert!(invalid.is_err());
}

#[test]
fn snapshot_fingerprint_covers_matching_guard_selection() {
    let event = arc::ArcEvent::lifecycle("session-1", "event-1", ArcEventType::End, 1);
    let empty = ActivationSnapshot::from_event(
        "activation-1",
        "invocation-1",
        ProviderTarget::Codex,
        &event,
        SessionContext::default(),
        Vec::new(),
        i64::MAX,
    );
    let selected = ActivationSnapshot::from_event(
        "activation-1",
        "invocation-1",
        ProviderTarget::Codex,
        &event,
        SessionContext::default(),
        vec![MatchingGuardSnapshot {
            guard_id: "guard-1".into(),
            order: 1,
            declaration_order: 1,
            action: ActionType::Deny,
            configured_feedback: None,
            matcher_evidence: Vec::new(),
            matcher_evidence_truncated: false,
        }],
        i64::MAX,
    );
    assert_ne!(empty.input_fingerprint, selected.input_fingerprint);
}

#[test]
fn ec_018_all_with_false_and_fault_preserves_cause_and_fault() {
    let first_path = vec![ExpressionPathSegment::All { index: 0 }];
    let second_path = vec![ExpressionPathSegment::All { index: 1 }];
    let expression = BoundRuleExpression::All(vec![
        BoundRuleExpression::Probe {
            command: "first".into(),
            expected_in: vec!["ok".into()],
        },
        BoundRuleExpression::Probe {
            command: "second".into(),
            expected_in: vec!["ok".into()],
        },
    ]);
    let leaves = BTreeMap::from([
        (
            expression_path_key(&first_path),
            violated(first_path.clone(), "occ-violation", "first probe failed"),
        ),
        (
            expression_path_key(&second_path),
            faulted_leaf("second probe errored"),
        ),
    ]);

    let reduction = reduce_rule_expression(&expression, &BTreeMap::new(), &leaves).unwrap();
    assert_eq!(reduction.decision, None);
    assert_eq!(reduction.causes.len(), 1);
    assert_eq!(reduction.causes[0].occurrence_id, "occ-violation");
    assert_eq!(reduction.faults.len(), 1);
    assert!(matches!(
        &reduction.faults[0],
        EvaluationFault::Probe { summary } if summary == "second probe errored"
    ));

    let guard_result = reduce_guard_result(
        "guard-all-fault-and-false",
        1,
        0,
        ActionType::Deny,
        "sha256:evidence",
        &expression,
        &BTreeMap::new(),
        &leaves,
    )
    .unwrap();

    match &guard_result.state {
        GuardResultState::Faulted { faults, causes } => {
            assert_eq!(faults.len(), 1);
            assert_eq!(causes.len(), 1);
            assert_eq!(causes[0].occurrence_id, "occ-violation");
        }
        other => panic!("expected GuardResultState::Faulted with causes, got {other:?}"),
    }

    assert_eq!(
        reduce_effective_disposition(std::slice::from_ref(&guard_result)),
        EffectiveDisposition::RuntimeFault
    );

    let report = EventEvaluationReport {
        schema: "arc.event_evaluation.report.v1".into(),
        invocation_id: "inv-ec-018".into(),
        provider: ProviderTarget::Codex,
        event_id: "ev-ec-018".into(),
        event_type: ArcEventType::End,
        input_fingerprint: "sha256:input".into(),
        guard_results: vec![guard_result],
        effective_disposition: EffectiveDisposition::RuntimeFault,
        authorization_requirements: Vec::new(),
        activation_cache_summary: ActivationCacheSummary {
            logical_occurrences: 1,
            unique_probe_evaluations: 2,
            unique_decision_evaluations: 0,
            coalesced_in_flight: 0,
            reused_completed: 0,
            physical_faults: 1,
        },
        report_fingerprint: "sha256:report".into(),
        started_unix_ms: 1,
        completed_unix_ms: 2,
    };

    let bundle = FailureBundle::from_report(&report).expect("failure bundle");
    assert_eq!(
        bundle.effective_disposition,
        EffectiveDisposition::RuntimeFault
    );
    assert_eq!(bundle.failed_guards.len(), 1);
    assert_eq!(
        bundle.failed_guards[0].guard_id,
        "guard-all-fault-and-false"
    );
    assert_eq!(
        bundle.failed_guards[0].causes.len(),
        1,
        "Causes must not be empty for faulted guard with false branch"
    );
    assert_eq!(
        bundle.failed_guards[0].causes[0].occurrence_id,
        "occ-violation"
    );
    assert_eq!(bundle.evaluation_faults.len(), 1);
}

#[test]
fn ec_018_any_with_false_and_fault_preserves_cause_and_fault() {
    let first_path = vec![ExpressionPathSegment::Any { index: 0 }];
    let second_path = vec![ExpressionPathSegment::Any { index: 1 }];
    let expression = BoundRuleExpression::Any(vec![
        BoundRuleExpression::Probe {
            command: "first".into(),
            expected_in: vec!["ok".into()],
        },
        BoundRuleExpression::Probe {
            command: "second".into(),
            expected_in: vec!["ok".into()],
        },
    ]);
    let leaves = BTreeMap::from([
        (
            expression_path_key(&first_path),
            violated(first_path.clone(), "occ-any-false", "first probe failed"),
        ),
        (
            expression_path_key(&second_path),
            faulted_leaf("second probe errored"),
        ),
    ]);

    let reduction = reduce_rule_expression(&expression, &BTreeMap::new(), &leaves).unwrap();
    assert_eq!(reduction.decision, None);
    assert_eq!(reduction.causes.len(), 1);
    assert_eq!(reduction.causes[0].occurrence_id, "occ-any-false");
    assert_eq!(reduction.faults.len(), 1);

    let guard_result = reduce_guard_result(
        "guard-any-fault-and-false",
        1,
        0,
        ActionType::Ask,
        "sha256:evidence",
        &expression,
        &BTreeMap::new(),
        &leaves,
    )
    .unwrap();

    match &guard_result.state {
        GuardResultState::Faulted { faults, causes } => {
            assert_eq!(faults.len(), 1);
            assert_eq!(causes.len(), 1);
            assert_eq!(causes[0].occurrence_id, "occ-any-false");
        }
        other => panic!("expected GuardResultState::Faulted with causes, got {other:?}"),
    }

    let report = EventEvaluationReport {
        schema: "arc.event_evaluation.report.v1".into(),
        invocation_id: "inv-ec-018-any".into(),
        provider: ProviderTarget::Codex,
        event_id: "ev-ec-018-any".into(),
        event_type: ArcEventType::End,
        input_fingerprint: "sha256:input".into(),
        guard_results: vec![guard_result],
        effective_disposition: EffectiveDisposition::RuntimeFault,
        authorization_requirements: Vec::new(),
        activation_cache_summary: ActivationCacheSummary {
            logical_occurrences: 1,
            unique_probe_evaluations: 2,
            unique_decision_evaluations: 0,
            coalesced_in_flight: 0,
            reused_completed: 0,
            physical_faults: 1,
        },
        report_fingerprint: "sha256:report".into(),
        started_unix_ms: 1,
        completed_unix_ms: 2,
    };

    let bundle = FailureBundle::from_report(&report).expect("failure bundle");
    assert_eq!(bundle.failed_guards[0].causes.len(), 1);
    assert_eq!(
        bundle.failed_guards[0].causes[0].occurrence_id,
        "occ-any-false"
    );
    assert_eq!(bundle.evaluation_faults.len(), 1);
}

#[test]
fn ec_018_multi_guard_coexistence_preserves_independent_violations_and_faults() {
    let violation_path = vec![ExpressionPathSegment::All { index: 0 }];
    let violation_leaves = BTreeMap::from([(
        expression_path_key(&violation_path),
        violated(violation_path.clone(), "occ-v1", "policy violated"),
    )]);
    let violation_guard = reduce_guard_result(
        "guard-violated",
        1,
        0,
        ActionType::Deny,
        "sha256:ev-v",
        &BoundRuleExpression::All(vec![BoundRuleExpression::Probe {
            command: "p1".into(),
            expected_in: vec!["ok".into()],
        }]),
        &BTreeMap::new(),
        &violation_leaves,
    )
    .unwrap();

    let fault_path = vec![ExpressionPathSegment::All { index: 0 }];
    let fault_leaves = BTreeMap::from([(
        expression_path_key(&fault_path),
        faulted_leaf("infra timeout"),
    )]);
    let fault_guard = reduce_guard_result(
        "guard-faulted",
        2,
        1,
        ActionType::Ask,
        "sha256:ev-f",
        &BoundRuleExpression::All(vec![BoundRuleExpression::Probe {
            command: "p2".into(),
            expected_in: vec!["ok".into()],
        }]),
        &BTreeMap::new(),
        &fault_leaves,
    )
    .unwrap();

    let results = vec![violation_guard, fault_guard];
    assert_eq!(
        reduce_effective_disposition(&results),
        EffectiveDisposition::RuntimeFault
    );

    let report = EventEvaluationReport {
        schema: "arc.event_evaluation.report.v1".into(),
        invocation_id: "inv-multi".into(),
        provider: ProviderTarget::Codex,
        event_id: "ev-multi".into(),
        event_type: ArcEventType::End,
        input_fingerprint: "sha256:input".into(),
        guard_results: results,
        effective_disposition: EffectiveDisposition::RuntimeFault,
        authorization_requirements: Vec::new(),
        activation_cache_summary: ActivationCacheSummary {
            logical_occurrences: 2,
            unique_probe_evaluations: 2,
            unique_decision_evaluations: 0,
            coalesced_in_flight: 0,
            reused_completed: 0,
            physical_faults: 1,
        },
        report_fingerprint: "sha256:report".into(),
        started_unix_ms: 1,
        completed_unix_ms: 2,
    };

    let bundle = FailureBundle::from_report(&report).expect("bundle");
    assert_eq!(bundle.failed_guards.len(), 2);
    assert_eq!(bundle.failed_guards[0].guard_id, "guard-violated");
    assert_eq!(bundle.failed_guards[0].causes.len(), 1);
    assert_eq!(bundle.failed_guards[0].causes[0].occurrence_id, "occ-v1");
    assert_eq!(bundle.failed_guards[1].guard_id, "guard-faulted");
    assert_eq!(bundle.failed_guards[1].causes.len(), 0);
    assert_eq!(bundle.evaluation_faults.len(), 1);
}

#[test]
fn ec_018_serde_roundtrip_faulted_state_with_causes() {
    let faulted_with_causes = GuardResultState::Faulted {
        faults: vec![EvaluationFault::DeadlineExceeded],
        causes: vec![arc::FailureCause {
            occurrence_id: "occ-serde".into(),
            physical_evaluation_id: "pe-serde".into(),
            cache_provenance: CacheResolutionProvenance::Executed,
            expression_path: vec![ExpressionPathSegment::All { index: 0 }],
            kind: FailureCauseKind::ProbeMismatch,
            summary: "probe failed".into(),
            auditor_findings: None,
            deterministic_evidence: Vec::new(),
        }],
    };

    let json = serde_json::to_string(&faulted_with_causes).expect("serialize");
    assert!(json.contains("\"causes\""));
    assert!(json.contains("\"faults\""));
    let deserialized: GuardResultState = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(deserialized, faulted_with_causes);

    // Backward compatibility: JSON with no "causes" field deserializes to empty causes
    let legacy_json = r#"{"state":"faulted","faults":[{"kind":"deadline_exceeded"}]}"#;
    let legacy_deserialized: GuardResultState =
        serde_json::from_str(legacy_json).expect("legacy deserialize");
    assert_eq!(
        legacy_deserialized,
        GuardResultState::Faulted {
            faults: vec![EvaluationFault::DeadlineExceeded],
            causes: Vec::new(),
        }
    );
}

#[test]
fn ec_045_event_evaluation_report_validation_rejects_duplicate_guard_ids() {
    let guard_result_1 = arc::GuardResult::test_result("guard-1", 1, 0, ActionType::Deny, true);
    let guard_result_2 = arc::GuardResult::test_result("guard-1", 2, 1, ActionType::Ask, false);
    let mut report = EventEvaluationReport {
        schema: "arc.event_evaluation.report.v1".into(),
        invocation_id: "inv-dup".into(),
        provider: ProviderTarget::Codex,
        event_id: "ev-dup".into(),
        event_type: ArcEventType::End,
        input_fingerprint: "sha256:input".into(),
        guard_results: vec![guard_result_1, guard_result_2],
        effective_disposition: EffectiveDisposition::Deny,
        authorization_requirements: Vec::new(),
        activation_cache_summary: ActivationCacheSummary {
            logical_occurrences: 2,
            unique_probe_evaluations: 0,
            unique_decision_evaluations: 0,
            coalesced_in_flight: 0,
            reused_completed: 0,
            physical_faults: 0,
        },
        report_fingerprint: String::new(),
        started_unix_ms: 1,
        completed_unix_ms: 2,
    };
    report.report_fingerprint = serde_json::to_vec(&report.guard_results)
        .map(|b| arc::fingerprint(&b))
        .unwrap();

    let validation = report.validate();
    assert!(matches!(
        validation,
        Err(arc::GuardEvaluationContractError::DuplicateId { field, value })
            if field == "guard_results.guard_id" && value == "guard-1"
    ));
}

#[test]
fn p2_dialog_response_v2_validates_message_bounds_and_markup() {
    let request = arc::DialogRequest::guard_failures(
        "req-msg",
        "Title",
        "lifecycle:end",
        vec![arc::DialogViolationItem {
            guard_id: "guard-1".into(),
            summary: "summary".into(),
            configured_feedback: None,
            auditor_findings: None,
            scope: "lifecycle:end".into(),
            failed_probes: Vec::new(),
        }],
        "sha256:bundle",
        1_000_000,
    );

    let mut response = arc::DialogResponse {
        schema: arc::DIALOG_RESPONSE_SCHEMA.into(),
        request_id: "req-msg".into(),
        bundle_fingerprint: "sha256:bundle".into(),
        decision: arc::PortableDecision::Allow,
        transport: "cli".into(),
        theme: "default".into(),
        message: Some("<script>bad()</script>".into()),
    };

    assert!(matches!(
        response.validate_for(&request),
        Err(arc::GuardEvaluationContractError::UnsupportedMarkup { field: "message" })
    ));

    response.message = Some("x".repeat(600));
    assert!(response.validate_for(&request).is_ok());

    response.message = Some("x".repeat(arc::decision_ui::MAX_DIALOG_USER_MESSAGE_CHARS));
    assert!(response.validate_for(&request).is_ok());

    response.message = Some("x".repeat(arc::decision_ui::MAX_DIALOG_USER_MESSAGE_CHARS + 1));
    assert_eq!(
        response.validate_for(&request),
        Err(arc::GuardEvaluationContractError::FieldTooLong {
            field: "message",
            max: arc::decision_ui::MAX_DIALOG_USER_MESSAGE_CHARS,
            actual: arc::decision_ui::MAX_DIALOG_USER_MESSAGE_CHARS + 1,
        })
    );

    response.message = Some("   ".into());
    assert_eq!(
        response.validate_for(&request),
        Err(arc::GuardEvaluationContractError::EmptyField { field: "message" })
    );

    response.message = Some("A valid user remediation message.".into());
    assert!(response.validate_for(&request).is_ok());
}

#[test]
fn p2_evaluation_contracts_reject_unknown_fields() {
    let cause_json = r#"{
        "occurrence_id": "occ-1",
        "physical_evaluation_id": "pe-1",
        "cache_provenance": "executed",
        "expression_path": [],
        "kind": "probe_mismatch",
        "summary": "failed",
        "auditor_findings": null,
        "deterministic_evidence": [],
        "unauthorized_field": "injected"
    }"#;
    assert!(serde_json::from_str::<arc::FailureCause>(cause_json).is_err());

    let state_json = r#"{
        "state": "violated",
        "causes": [],
        "extra_field": "malicious"
    }"#;
    assert!(serde_json::from_str::<arc::GuardResultState>(state_json).is_err());

    let guard_result_json = r#"{
        "guard_id": "g-1",
        "order": 1,
        "declaration_order": 0,
        "configured_action": "deny",
        "state": { "state": "satisfied" },
        "evidence_fingerprint": "sha256:abc",
        "completeness": "complete",
        "unknown_flag": true
    }"#;
    assert!(serde_json::from_str::<arc::GuardResult>(guard_result_json).is_err());

    let report_json = r#"{
        "schema": "arc.event_evaluation.report.v1",
        "invocation_id": "inv-1",
        "provider": "codex",
        "event_id": "ev-1",
        "event_type": "end",
        "input_fingerprint": "sha256:in",
        "guard_results": [],
        "effective_disposition": "continue",
        "authorization_requirements": [],
        "activation_cache_summary": {
            "logical_occurrences": 0,
            "unique_probe_evaluations": 0,
            "unique_decision_evaluations": 0,
            "coalesced_in_flight": 0,
            "reused_completed": 0,
            "physical_faults": 0
        },
        "report_fingerprint": "sha256:rep",
        "started_unix_ms": 0,
        "completed_unix_ms": 1,
        "unexpected_prop": "error"
    }"#;
    assert!(serde_json::from_str::<arc::EventEvaluationReport>(report_json).is_err());

    let summary_json = r#"{
        "logical_occurrences": 0,
        "unique_probe_evaluations": 0,
        "unique_decision_evaluations": 0,
        "coalesced_in_flight": 0,
        "reused_completed": 0,
        "physical_faults": 0,
        "extra": 123
    }"#;
    assert!(serde_json::from_str::<arc::ActivationCacheSummary>(summary_json).is_err());

    let auth_json = r#"{
        "guard_id": "g-1",
        "operation_fingerprint": "sha256:op",
        "event_id": "ev-1",
        "tool": "bash",
        "normalized_arguments_fingerprint": "sha256:args",
        "unrecognized": "value"
    }"#;
    assert!(serde_json::from_str::<arc::ExactOperationAuthorization>(auth_json).is_err());
}

#[test]
fn p2_contract_validation_methods_enforce_invariants() {
    let cause = arc::FailureCause {
        occurrence_id: "occ-1".into(),
        physical_evaluation_id: "pe-1".into(),
        cache_provenance: arc::CacheResolutionProvenance::Executed,
        expression_path: vec![],
        kind: arc::FailureCauseKind::ProbeMismatch,
        summary: "valid summary".into(),
        auditor_findings: None,
        deterministic_evidence: vec![],
    };
    assert!(cause.validate().is_ok());

    let bad_cause = arc::FailureCause {
        occurrence_id: "occ-1".into(),
        physical_evaluation_id: "pe-1".into(),
        cache_provenance: arc::CacheResolutionProvenance::Executed,
        expression_path: vec![],
        kind: arc::FailureCauseKind::ProbeMismatch,
        summary: "<b>html not allowed</b>".into(),
        auditor_findings: None,
        deterministic_evidence: vec![],
    };
    assert!(bad_cause.validate().is_err());

    let evidence = arc::SemanticDecisionEvidence {
        event_type: arc::ArcEventType::End,
        event_id: "ev-1".into(),
        scope: "lifecycle:end".into(),
        matcher_evidence: vec![],
        matcher_evidence_truncated: false,
        deterministic_evidence: vec![],
        deterministic_evidence_truncated: false,
    };
    assert!(evidence.validate().is_ok());

    let input = arc::DecisionEvaluationInput {
        goal: "Confirm change".into(),
        role: "auditor".into(),
        current_operation: arc::CurrentOperation {
            event_type: arc::ArcEventType::End,
            tool: None,
            input: None,
            command_text: None,
        },
        session_context: arc::SessionContext {
            user_intent: "Fix issue".into(),
            ..Default::default()
        },
        attested_evidence: evidence.clone(),
    };
    assert!(input.validate().is_ok());

    let mut bad_input = input.clone();
    bad_input.goal = "x".repeat(5000);
    assert!(bad_input.validate().is_err());

    let profile = arc::DecisionExecutionProfile {
        provider: arc::ProviderTarget::Codex,
        transport: "codex_app_server".into(),
        model: Some("gpt-5".into()),
        adapter_contract_fingerprint: "sha256:adapter".into(),
        output_schema_fingerprint: "sha256:output".into(),
        sandbox_mode: "read_only".into(),
        approval_policy: "never".into(),
    };
    assert!(profile.validate().is_ok());

    let task_req = arc::DecisionTaskRequest {
        schema: arc::DECISION_TASK_REQUEST_SCHEMA.into(),
        physical_evaluation_id: "pe-1".into(),
        activation_id: "act-1".into(),
        invocation_id: "inv-1".into(),
        evaluation_key: "sha256:key".into(),
        profile: profile.clone(),
        input: input.clone(),
        absolute_deadline_unix_ms: 10_000,
    };
    assert!(task_req.validate().is_ok());

    let bad_task_req = arc::DecisionTaskRequest {
        schema: "wrong.schema".into(),
        physical_evaluation_id: "pe-1".into(),
        activation_id: "act-1".into(),
        invocation_id: "inv-1".into(),
        evaluation_key: "sha256:key".into(),
        profile: profile.clone(),
        input: input.clone(),
        absolute_deadline_unix_ms: 10_000,
    };
    assert!(bad_task_req.validate().is_err());

    let auth = arc::ExactOperationAuthorization {
        guard_id: "g-1".into(),
        operation_fingerprint: "sha256:op".into(),
        event_id: "ev-1".into(),
        tool: "bash".into(),
        normalized_arguments_fingerprint: "sha256:args".into(),
    };
    assert!(auth.validate().is_ok());

    let guard_result_faulted_empty = arc::GuardResult {
        guard_id: "g-1".into(),
        order: 1,
        declaration_order: 0,
        configured_action: arc::ActionType::Deny,
        state: arc::GuardResultState::Faulted {
            faults: vec![],
            causes: vec![],
        },
        satisfied_attributions: Vec::new(),
        evidence_fingerprint: "sha256:ev".into(),
        completeness: arc::EvaluationCompleteness::IncompleteDueToFault,
    };
    assert!(guard_result_faulted_empty.validate().is_err());
}

#[test]
fn ec_010_not_true_preserves_leaf_attribution_ids_and_evidence() {
    let expression = arc::BoundRuleExpression::Not(Box::new(arc::BoundRuleExpression::Probe {
        command: "git status".into(),
        expected_in: vec!["clean".into()],
    }));

    let path = vec![arc::ExpressionPathSegment::Not];
    let key = arc::expression_path_key(&path);

    let leaf_result = arc::LeafResult::Satisfied {
        attribution: Some(arc::LeafAttribution {
            occurrence_id: "occ-git-probe".into(),
            physical_evaluation_id: "pe-git-probe".into(),
            cache_provenance: arc::CacheResolutionProvenance::ReusedCompleted,
            expression_path: path.clone(),
            summary: "probe 'git status' matched expected value".into(),
            auditor_findings: None,
            deterministic_evidence: vec![arc::DeterministicEvidence {
                rule_path: vec!["not".into()],
                operation: "git status".into(),
                expected_values: vec!["clean".into()],
                result: true,
                observed_sha256: "sha256:clean".into(),
            }],
        }),
    };

    let leaves = std::collections::BTreeMap::from([(key, leaf_result)]);
    let reduction =
        arc::reduce_rule_expression(&expression, &std::collections::BTreeMap::new(), &leaves)
            .unwrap();

    assert_eq!(reduction.decision, Some(false));
    assert_eq!(reduction.causes.len(), 1);
    let cause = &reduction.causes[0];
    assert_eq!(cause.occurrence_id, "occ-git-probe");
    assert_eq!(cause.physical_evaluation_id, "pe-git-probe");
    assert_eq!(
        cause.cache_provenance,
        arc::CacheResolutionProvenance::ReusedCompleted
    );
    assert_eq!(cause.expression_path, path);
    assert_eq!(cause.kind, arc::FailureCauseKind::NegatedTrue);
    assert_eq!(cause.deterministic_evidence.len(), 1);
    assert_eq!(cause.deterministic_evidence[0].operation, "git status");
}

#[test]
fn ec_010_not_inherits_completeness_from_child_with_non_causal_skips() {
    // not(any([true, skipped])) -> decision: Some(false), completeness: CompleteForGuardResultWithNonCausalSkips
    let not_any_expr =
        arc::BoundRuleExpression::Not(Box::new(arc::BoundRuleExpression::Any(vec![
            arc::BoundRuleExpression::Probe {
                command: "probe-true".into(),
                expected_in: vec!["ok".into()],
            },
            arc::BoundRuleExpression::Probe {
                command: "probe-skipped".into(),
                expected_in: vec!["ok".into()],
            },
        ])));

    let path_true = vec![
        arc::ExpressionPathSegment::Not,
        arc::ExpressionPathSegment::Any { index: 0 },
    ];
    let path_skipped = vec![
        arc::ExpressionPathSegment::Not,
        arc::ExpressionPathSegment::Any { index: 1 },
    ];

    let leaf_true = arc::LeafResult::Satisfied {
        attribution: Some(arc::LeafAttribution {
            occurrence_id: "occ-true".into(),
            physical_evaluation_id: "pe-true".into(),
            cache_provenance: arc::CacheResolutionProvenance::Executed,
            expression_path: path_true.clone(),
            summary: "probe 'probe-true' matched".into(),
            auditor_findings: None,
            deterministic_evidence: vec![],
        }),
    };
    let leaf_skipped = arc::LeafResult::SkippedNonCausal {
        occurrence_id: "occ-skipped".into(),
        expression_path: path_skipped.clone(),
        summary: "skipped non-causal".into(),
    };

    let leaves = std::collections::BTreeMap::from([
        (arc::expression_path_key(&path_true), leaf_true),
        (arc::expression_path_key(&path_skipped), leaf_skipped),
    ]);

    let reduction =
        arc::reduce_rule_expression(&not_any_expr, &std::collections::BTreeMap::new(), &leaves)
            .unwrap();

    assert_eq!(reduction.decision, Some(false));
    assert_eq!(
        reduction.completeness,
        arc::EvaluationCompleteness::CompleteForGuardResultWithNonCausalSkips,
        "not(any(true, skipped)) must inherit CompleteForGuardResultWithNonCausalSkips"
    );

    // not(all([false, skipped])) -> decision: Some(true), completeness: CompleteForGuardResultWithNonCausalSkips
    let not_all_expr =
        arc::BoundRuleExpression::Not(Box::new(arc::BoundRuleExpression::All(vec![
            arc::BoundRuleExpression::Probe {
                command: "probe-false".into(),
                expected_in: vec!["ok".into()],
            },
            arc::BoundRuleExpression::Probe {
                command: "probe-skipped".into(),
                expected_in: vec!["ok".into()],
            },
        ])));

    let path_all_false = vec![
        arc::ExpressionPathSegment::Not,
        arc::ExpressionPathSegment::All { index: 0 },
    ];
    let path_all_skipped = vec![
        arc::ExpressionPathSegment::Not,
        arc::ExpressionPathSegment::All { index: 1 },
    ];

    let leaf_false = arc::LeafResult::Violated {
        cause: arc::FailureCause {
            occurrence_id: "occ-false".into(),
            physical_evaluation_id: "pe-false".into(),
            cache_provenance: arc::CacheResolutionProvenance::Executed,
            expression_path: path_all_false.clone(),
            kind: arc::FailureCauseKind::ProbeMismatch,
            summary: "probe did not match".into(),
            auditor_findings: None,
            deterministic_evidence: vec![],
        },
    };
    let leaf_all_skipped = arc::LeafResult::SkippedNonCausal {
        occurrence_id: "occ-skipped-2".into(),
        expression_path: path_all_skipped.clone(),
        summary: "skipped non-causal".into(),
    };

    let leaves_all = std::collections::BTreeMap::from([
        (arc::expression_path_key(&path_all_false), leaf_false),
        (
            arc::expression_path_key(&path_all_skipped),
            leaf_all_skipped,
        ),
    ]);

    let reduction_all = arc::reduce_rule_expression(
        &not_all_expr,
        &std::collections::BTreeMap::new(),
        &leaves_all,
    )
    .unwrap();

    assert_eq!(reduction_all.decision, Some(true));
    assert_eq!(
        reduction_all.completeness,
        arc::EvaluationCompleteness::CompleteForGuardResultWithNonCausalSkips,
        "not(all(false, skipped)) must inherit CompleteForGuardResultWithNonCausalSkips"
    );
}

#[test]
fn ec_012_nested_rule_ref_not_true_preserves_external_and_internal_path() {
    let top_expr = arc::BoundRuleExpression::All(vec![arc::BoundRuleExpression::RuleRef {
        name: "check_clean".into(),
    }]);

    let rule_def = arc::BoundRuleExpression::Not(Box::new(arc::BoundRuleExpression::Probe {
        command: "dirty_check".into(),
        expected_in: vec!["dirty".into()],
    }));

    let catalog = std::collections::BTreeMap::from([("check_clean".into(), rule_def)]);

    let full_path = vec![
        arc::ExpressionPathSegment::All { index: 0 },
        arc::ExpressionPathSegment::RuleRef {
            name: "check_clean".into(),
        },
        arc::ExpressionPathSegment::Not,
    ];
    let key = arc::expression_path_key(&full_path);

    let leaf_result = arc::LeafResult::Satisfied {
        attribution: Some(arc::LeafAttribution {
            occurrence_id: "occ-nested-probe".into(),
            physical_evaluation_id: "pe-nested-probe".into(),
            cache_provenance: arc::CacheResolutionProvenance::Executed,
            expression_path: full_path.clone(),
            summary: "probe 'dirty_check' matched dirty".into(),
            auditor_findings: None,
            deterministic_evidence: vec![],
        }),
    };

    let leaves = std::collections::BTreeMap::from([(key, leaf_result)]);
    let reduction = arc::reduce_rule_expression(&top_expr, &catalog, &leaves).unwrap();

    assert_eq!(reduction.decision, Some(false));
    assert_eq!(reduction.causes.len(), 1);
    let cause = &reduction.causes[0];
    assert_eq!(cause.occurrence_id, "occ-nested-probe");
    assert_eq!(cause.physical_evaluation_id, "pe-nested-probe");
    assert_eq!(cause.expression_path, full_path);
    assert_eq!(cause.kind, arc::FailureCauseKind::NegatedTrue);
}

#[test]
fn default_decision_execution_profile_complies_with_isolation_contract() {
    let profile = DecisionExecutionProfile::default();
    assert_eq!(profile.sandbox_mode, "read_only");
    assert_eq!(profile.approval_policy, "never");
    assert!(profile.validate().is_ok());

    let provider = std::sync::Arc::new(
        arc::MockDecisionProvider::new().with_decision("Validate the requested release", true),
    );
    let executor = arc::DecisionProviderExecutor::new(provider, "test_transport");
    let input = decision_input("event-default-profile");
    let request = arc::DecisionTaskRequest {
        schema: arc::DECISION_TASK_REQUEST_SCHEMA.into(),
        physical_evaluation_id: "pe-default-profile".into(),
        activation_id: "act-default-profile".into(),
        invocation_id: "inv-default-profile".into(),
        evaluation_key: "sha256:default-profile-key".into(),
        profile: profile.clone(),
        input,
        absolute_deadline_unix_ms: 100_000,
    };
    let result = arc::PhysicalDecisionExecutor::execute(&executor, request);
    match result {
        arc::DecisionTaskResult::Faulted { fault, .. } => {
            assert_ne!(
                fault,
                arc::DecisionTaskFault::IsolationViolation,
                "Default profile must not cause IsolationViolation"
            );
        }
        arc::DecisionTaskResult::Satisfied { .. } => {}
        arc::DecisionTaskResult::Violated { .. } => {}
    }

    let session = arc::ArcRuntimeSession::new(
        "session-default-profile",
        arc::ir::BehaviorIR {
            schema: "1.0".into(),
            compiler_version: "1.0.0".into(),
            build_id: Some("build-1".into()),
            content_hash: Some("hash-1".into()),
            runtime: Default::default(),
            context: arc::ir::WorkspaceContext {
                workdir: std::path::PathBuf::from("."),
                instructions_path: None,
                instructions_content: None,
                roles: std::collections::BTreeMap::new(),
            },
            skills: Vec::new(),
            lifecycle_guards: Vec::new(),
            tool_guards: Vec::new(),
            rules: std::collections::BTreeMap::new(),
        },
    );
    assert_eq!(session.decision_profile.sandbox_mode, "read_only");
    assert_eq!(session.decision_profile.approval_policy, "never");
}

#[test]
fn profile_and_task_request_validation_rejects_arbitrary_isolation_values() {
    let mut profile = DecisionExecutionProfile::default();
    assert!(profile.validate().is_ok());

    profile.sandbox_mode = "workspace-write".into();
    let err_sandbox = profile.validate().unwrap_err();
    assert!(matches!(
        err_sandbox,
        arc::GuardEvaluationContractError::InvalidField {
            field: "sandbox_mode",
            ..
        }
    ));

    profile.sandbox_mode = "read_only".into();
    profile.approval_policy = "always".into();
    let err_approval = profile.validate().unwrap_err();
    assert!(matches!(
        err_approval,
        arc::GuardEvaluationContractError::InvalidField {
            field: "approval_policy",
            ..
        }
    ));

    let bad_request = arc::DecisionTaskRequest {
        schema: arc::DECISION_TASK_REQUEST_SCHEMA.into(),
        physical_evaluation_id: "pe-invalid-profile".into(),
        activation_id: "act-1".into(),
        invocation_id: "inv-1".into(),
        evaluation_key: "key-1".into(),
        profile: DecisionExecutionProfile {
            sandbox_mode: "workspace-write".into(),
            ..DecisionExecutionProfile::default()
        },
        input: decision_input("event-invalid-profile"),
        absolute_deadline_unix_ms: 10_000,
    };
    assert!(bad_request.validate().is_err());
}

#[test]
fn event_evaluation_report_and_failure_bundle_reject_inconsistent_effective_disposition() {
    let guard_result = arc::GuardResult::test_result("guard-deny", 1, 0, ActionType::Deny, false);
    let mut report = EventEvaluationReport {
        schema: "arc.event_evaluation.report.v1".into(),
        invocation_id: "inv-inconsistent".into(),
        provider: ProviderTarget::Codex,
        event_id: "ev-inconsistent".into(),
        event_type: ArcEventType::End,
        input_fingerprint: "sha256:input".into(),
        guard_results: vec![guard_result],
        // Semantic inconsistency: guard is Violated with Deny, but disposition claims Continue
        effective_disposition: EffectiveDisposition::Continue,
        authorization_requirements: Vec::new(),
        activation_cache_summary: ActivationCacheSummary {
            logical_occurrences: 1,
            unique_probe_evaluations: 1,
            unique_decision_evaluations: 0,
            coalesced_in_flight: 0,
            reused_completed: 0,
            physical_faults: 0,
        },
        report_fingerprint: String::new(),
        started_unix_ms: 1,
        completed_unix_ms: 2,
    };
    report.report_fingerprint = serde_json::to_vec(&report.guard_results)
        .map(|b| arc::fingerprint(&b))
        .unwrap();

    let err = report.validate().unwrap_err();
    assert!(matches!(
        err,
        arc::GuardEvaluationContractError::InvalidField {
            field: "effective_disposition",
            ..
        }
    ));

    assert!(FailureBundle::from_report(&report).is_err());
}

#[test]
fn guard_result_validation_enforces_coherence_between_state_and_completeness() {
    // 1. Satisfied cannot be IncompleteDueToFault
    let satisfied_incomplete = arc::GuardResult {
        guard_id: "g-satisfied".into(),
        order: 1,
        declaration_order: 0,
        configured_action: arc::ActionType::Deny,
        state: arc::GuardResultState::Satisfied,
        satisfied_attributions: Vec::new(),
        evidence_fingerprint: "sha256:ev".into(),
        completeness: arc::EvaluationCompleteness::IncompleteDueToFault,
    };
    assert!(matches!(
        satisfied_incomplete.validate(),
        Err(arc::GuardEvaluationContractError::InvalidField {
            field: "completeness",
            ..
        })
    ));

    // 2. Violated cannot be IncompleteDueToFault
    let violated_incomplete = arc::GuardResult {
        guard_id: "g-violated".into(),
        order: 1,
        declaration_order: 0,
        configured_action: arc::ActionType::Deny,
        state: arc::GuardResultState::Violated { causes: Vec::new() },
        satisfied_attributions: Vec::new(),
        evidence_fingerprint: "sha256:ev".into(),
        completeness: arc::EvaluationCompleteness::IncompleteDueToFault,
    };
    assert!(matches!(
        violated_incomplete.validate(),
        Err(arc::GuardEvaluationContractError::InvalidField {
            field: "completeness",
            ..
        })
    ));

    // 3. Faulted cannot be Complete
    let faulted_complete = arc::GuardResult {
        guard_id: "g-faulted".into(),
        order: 1,
        declaration_order: 0,
        configured_action: arc::ActionType::Deny,
        state: arc::GuardResultState::Faulted {
            faults: vec![arc::EvaluationFault::DeadlineExceeded],
            causes: Vec::new(),
        },
        satisfied_attributions: Vec::new(),
        evidence_fingerprint: "sha256:ev".into(),
        completeness: arc::EvaluationCompleteness::Complete,
    };
    assert!(matches!(
        faulted_complete.validate(),
        Err(arc::GuardEvaluationContractError::InvalidField {
            field: "completeness",
            ..
        })
    ));

    // 4. Faulted with IncompleteDueToFault and valid faults is OK
    let faulted_valid = arc::GuardResult {
        guard_id: "g-faulted-ok".into(),
        order: 1,
        declaration_order: 0,
        configured_action: arc::ActionType::Deny,
        state: arc::GuardResultState::Faulted {
            faults: vec![arc::EvaluationFault::DeadlineExceeded],
            causes: Vec::new(),
        },
        satisfied_attributions: Vec::new(),
        evidence_fingerprint: "sha256:ev".into(),
        completeness: arc::EvaluationCompleteness::IncompleteDueToFault,
    };
    assert!(faulted_valid.validate().is_ok());
}

#[test]
fn not_true_without_leaf_attribution_produces_valid_cause_with_non_empty_ids() {
    // 1. Not over leaf probe with satisfied() without attribution
    let not_leaf = arc::BoundRuleExpression::Not(Box::new(arc::BoundRuleExpression::Probe {
        command: "test -f foo".into(),
        expected_in: vec!["true".into()],
    }));
    let path = vec![arc::ExpressionPathSegment::Not];
    let key = arc::expression_path_key(&path);
    let leaves = std::collections::BTreeMap::from([(key, arc::LeafResult::satisfied())]);

    let reduction =
        arc::reduce_rule_expression(&not_leaf, &std::collections::BTreeMap::new(), &leaves)
            .unwrap();
    assert_eq!(reduction.decision, Some(false));
    assert_eq!(reduction.causes.len(), 1);
    let cause = &reduction.causes[0];
    assert_eq!(cause.kind, arc::FailureCauseKind::NegatedTrue);
    assert!(
        !cause.occurrence_id.trim().is_empty(),
        "occurrence_id must not be empty"
    );
    assert!(
        !cause.physical_evaluation_id.trim().is_empty(),
        "physical_evaluation_id must not be empty"
    );
    assert!(cause.validate().is_ok());

    // 2. Reduce full guard result with not(all([])) and validate GuardResult
    let not_empty_all =
        arc::BoundRuleExpression::Not(Box::new(arc::BoundRuleExpression::All(Vec::new())));
    let guard_result = arc::reduce_guard_result(
        "guard-not-empty-all",
        1,
        0,
        arc::ActionType::Deny,
        "sha256:evidence",
        &not_empty_all,
        &std::collections::BTreeMap::new(),
        &std::collections::BTreeMap::new(),
    )
    .unwrap();

    assert_eq!(guard_result.guard_id, "guard-not-empty-all");
    match &guard_result.state {
        arc::GuardResultState::Violated { causes } => {
            assert_eq!(causes.len(), 1);
            assert_eq!(causes[0].kind, arc::FailureCauseKind::NegatedTrue);
            assert!(causes[0].validate().is_ok());
        }
        other => panic!("expected Violated state, got {other:?}"),
    }
    assert!(
        guard_result.validate().is_ok(),
        "GuardResult produced by not(true) without leaf attribution must pass validate()"
    );
}

#[test]
fn semantic_decision_evidence_validation_enforces_collection_cardinality_limits() {
    let valid_evidence = arc::SemanticDecisionEvidence {
        event_type: arc::ArcEventType::ToolCall,
        event_id: "ev-bounded".into(),
        scope: "tool:bash".into(),
        matcher_evidence: (0..arc::MAX_MATCHER_EVIDENCE_ITEMS)
            .map(|i| arc::MatcherEvidence {
                kind: format!("kind-{i}"),
                matcher: format!("pattern-{i}"),
                matched: true,
            })
            .collect(),
        matcher_evidence_truncated: false,
        deterministic_evidence: (0..arc::MAX_DETERMINISTIC_EVIDENCE_ITEMS)
            .map(|i| arc::DeterministicEvidence {
                rule_path: vec![format!("step-{i}")],
                operation: format!("echo {i}"),
                expected_values: vec!["ok".into()],
                result: true,
                observed_sha256: "sha256:observed".into(),
            })
            .collect(),
        deterministic_evidence_truncated: false,
    };
    assert!(valid_evidence.validate().is_ok());

    // 1. Exceed matcher_evidence limit (65 > 64)
    let mut bad_matcher = valid_evidence.clone();
    bad_matcher.matcher_evidence.push(arc::MatcherEvidence {
        kind: "overflow".into(),
        matcher: "overflow".into(),
        matched: false,
    });
    let err_matcher = bad_matcher.validate().unwrap_err();
    assert_eq!(
        err_matcher,
        arc::GuardEvaluationContractError::CollectionTooLarge {
            field: "matcher_evidence",
            max: arc::MAX_MATCHER_EVIDENCE_ITEMS,
            actual: arc::MAX_MATCHER_EVIDENCE_ITEMS + 1,
        }
    );

    // 2. Exceed deterministic_evidence limit (65 > 64)
    let mut bad_det = valid_evidence.clone();
    bad_det
        .deterministic_evidence
        .push(arc::DeterministicEvidence {
            rule_path: vec!["overflow".into()],
            operation: "echo overflow".into(),
            expected_values: vec!["ok".into()],
            result: true,
            observed_sha256: "sha256:overflow".into(),
        });
    let err_det = bad_det.validate().unwrap_err();
    assert_eq!(
        err_det,
        arc::GuardEvaluationContractError::CollectionTooLarge {
            field: "deterministic_evidence",
            max: arc::MAX_DETERMINISTIC_EVIDENCE_ITEMS,
            actual: arc::MAX_DETERMINISTIC_EVIDENCE_ITEMS + 1,
        }
    );

    // 3. Exceed rule_path limit in deterministic_evidence (65 > 64)
    let mut bad_path = valid_evidence.clone();
    bad_path.deterministic_evidence = vec![arc::DeterministicEvidence {
        rule_path: (0..arc::MAX_RULE_PATH_SEGMENTS + 1)
            .map(|i| format!("seg-{i}"))
            .collect(),
        operation: "echo deep".into(),
        expected_values: vec!["ok".into()],
        result: true,
        observed_sha256: "sha256:path".into(),
    }];
    let err_path = bad_path.validate().unwrap_err();
    assert_eq!(
        err_path,
        arc::GuardEvaluationContractError::CollectionTooLarge {
            field: "deterministic_evidence.rule_path",
            max: arc::MAX_RULE_PATH_SEGMENTS,
            actual: arc::MAX_RULE_PATH_SEGMENTS + 1,
        }
    );

    // 4. Exceed expected_values limit in deterministic_evidence (17 > 16)
    let mut bad_expected = valid_evidence.clone();
    bad_expected.deterministic_evidence = vec![arc::DeterministicEvidence {
        rule_path: vec!["root".into()],
        operation: "echo values".into(),
        expected_values: (0..arc::MAX_EXPECTED_VALUES_ITEMS + 1)
            .map(|i| format!("val-{i}"))
            .collect(),
        result: true,
        observed_sha256: "sha256:values".into(),
    }];
    let err_expected = bad_expected.validate().unwrap_err();
    assert_eq!(
        err_expected,
        arc::GuardEvaluationContractError::CollectionTooLarge {
            field: "deterministic_evidence.expected_values",
            max: arc::MAX_EXPECTED_VALUES_ITEMS,
            actual: arc::MAX_EXPECTED_VALUES_ITEMS + 1,
        }
    );

    // 5. DecisionEvaluationInput delegates and fails closed
    let input_with_bad_evidence = arc::DecisionEvaluationInput {
        goal: "Confirm bounded validation".into(),
        role: "auditor".into(),
        current_operation: arc::CurrentOperation {
            event_type: arc::ArcEventType::ToolCall,
            tool: Some("bash".into()),
            input: None,
            command_text: Some("echo test".into()),
        },
        session_context: arc::SessionContext::default(),
        attested_evidence: bad_matcher,
    };
    assert_eq!(
        input_with_bad_evidence.validate().unwrap_err(),
        arc::GuardEvaluationContractError::CollectionTooLarge {
            field: "matcher_evidence",
            max: arc::MAX_MATCHER_EVIDENCE_ITEMS,
            actual: arc::MAX_MATCHER_EVIDENCE_ITEMS + 1,
        }
    );
}

#[test]
fn ec_006_all_false_false_preserves_both_causes() {
    let first_path = vec![arc::ExpressionPathSegment::All { index: 0 }];
    let second_path = vec![arc::ExpressionPathSegment::All { index: 1 }];
    let expression = arc::BoundRuleExpression::All(vec![
        arc::BoundRuleExpression::Probe {
            command: "p1".into(),
            expected_in: vec!["ok".into()],
        },
        arc::BoundRuleExpression::Probe {
            command: "p2".into(),
            expected_in: vec!["ok".into()],
        },
    ]);
    let leaves = std::collections::BTreeMap::from([
        (
            arc::expression_path_key(&first_path),
            violated(first_path.clone(), "occ-0", "first probe failed"),
        ),
        (
            arc::expression_path_key(&second_path),
            violated(second_path.clone(), "occ-1", "second probe failed"),
        ),
    ]);

    let reduction =
        arc::reduce_rule_expression(&expression, &std::collections::BTreeMap::new(), &leaves)
            .expect("reduction succeeds");
    assert_eq!(reduction.decision, Some(false));
    assert_eq!(reduction.causes.len(), 2);
    assert_eq!(reduction.causes[0].expression_path, first_path);
    assert_eq!(reduction.causes[0].occurrence_id, "occ-0");
    assert_eq!(reduction.causes[1].expression_path, second_path);
    assert_eq!(reduction.causes[1].occurrence_id, "occ-1");

    let guard_result = arc::reduce_guard_result(
        "guard-all-false-false",
        1,
        0,
        arc::ActionType::Deny,
        "sha256:ev-all-false",
        &expression,
        &std::collections::BTreeMap::new(),
        &leaves,
    )
    .expect("guard reduction succeeds");

    match &guard_result.state {
        arc::GuardResultState::Violated { causes } => {
            assert_eq!(causes.len(), 2);
            assert_eq!(causes[0].occurrence_id, "occ-0");
            assert_eq!(causes[1].occurrence_id, "occ-1");
            for cause in causes {
                assert!(cause.validate().is_ok());
            }
        }
        other => panic!("expected Violated state with 2 causes, got {other:?}"),
    }
    assert!(guard_result.validate().is_ok());
}

#[test]
fn ec_007_all_false_true_preserves_only_false_cause() {
    let first_path = vec![arc::ExpressionPathSegment::All { index: 0 }];
    let second_path = vec![arc::ExpressionPathSegment::All { index: 1 }];
    let expression = arc::BoundRuleExpression::All(vec![
        arc::BoundRuleExpression::Probe {
            command: "p1".into(),
            expected_in: vec!["ok".into()],
        },
        arc::BoundRuleExpression::Probe {
            command: "p2".into(),
            expected_in: vec!["ok".into()],
        },
    ]);
    let leaves = std::collections::BTreeMap::from([
        (
            arc::expression_path_key(&first_path),
            violated(first_path.clone(), "occ-f", "first probe failed"),
        ),
        (
            arc::expression_path_key(&second_path),
            arc::LeafResult::satisfied(),
        ),
    ]);

    let reduction =
        arc::reduce_rule_expression(&expression, &std::collections::BTreeMap::new(), &leaves)
            .expect("reduction succeeds");
    assert_eq!(reduction.decision, Some(false));
    assert_eq!(reduction.causes.len(), 1);
    assert_eq!(reduction.causes[0].expression_path, first_path);
    assert_eq!(reduction.causes[0].occurrence_id, "occ-f");

    let guard_result = arc::reduce_guard_result(
        "guard-all-false-true",
        1,
        0,
        arc::ActionType::Deny,
        "sha256:ev-false-true",
        &expression,
        &std::collections::BTreeMap::new(),
        &leaves,
    )
    .expect("guard reduction succeeds");

    match &guard_result.state {
        arc::GuardResultState::Violated { causes } => {
            assert_eq!(causes.len(), 1);
            assert_eq!(causes[0].occurrence_id, "occ-f");
            assert!(causes[0].validate().is_ok());
        }
        other => panic!("expected Violated state with 1 cause, got {other:?}"),
    }
    assert!(guard_result.validate().is_ok());
}

#[test]
fn ec_009_any_false_false_preserves_both_causes() {
    let first_path = vec![arc::ExpressionPathSegment::Any { index: 0 }];
    let second_path = vec![arc::ExpressionPathSegment::Any { index: 1 }];
    let expression = arc::BoundRuleExpression::Any(vec![
        arc::BoundRuleExpression::Probe {
            command: "p1".into(),
            expected_in: vec!["ok".into()],
        },
        arc::BoundRuleExpression::Probe {
            command: "p2".into(),
            expected_in: vec!["ok".into()],
        },
    ]);
    let leaves = std::collections::BTreeMap::from([
        (
            arc::expression_path_key(&first_path),
            violated(first_path.clone(), "occ-any-0", "first alternative failed"),
        ),
        (
            arc::expression_path_key(&second_path),
            violated(
                second_path.clone(),
                "occ-any-1",
                "second alternative failed",
            ),
        ),
    ]);

    let reduction =
        arc::reduce_rule_expression(&expression, &std::collections::BTreeMap::new(), &leaves)
            .expect("reduction succeeds");
    assert_eq!(reduction.decision, Some(false));
    assert_eq!(reduction.causes.len(), 2);
    assert_eq!(reduction.causes[0].expression_path, first_path);
    assert_eq!(reduction.causes[0].occurrence_id, "occ-any-0");
    assert_eq!(reduction.causes[1].expression_path, second_path);
    assert_eq!(reduction.causes[1].occurrence_id, "occ-any-1");

    let guard_result = arc::reduce_guard_result(
        "guard-any-false-false",
        1,
        0,
        arc::ActionType::Deny,
        "sha256:ev-any-false",
        &expression,
        &std::collections::BTreeMap::new(),
        &leaves,
    )
    .expect("guard reduction succeeds");

    match &guard_result.state {
        arc::GuardResultState::Violated { causes } => {
            assert_eq!(causes.len(), 2);
            assert_eq!(causes[0].occurrence_id, "occ-any-0");
            assert_eq!(causes[1].occurrence_id, "occ-any-1");
            for cause in causes {
                assert!(cause.validate().is_ok());
            }
        }
        other => panic!("expected Violated state with 2 causes, got {other:?}"),
    }
    assert!(guard_result.validate().is_ok());
}

#[test]
fn ec_011_not_false_evaluates_to_satisfied() {
    let probe_path = vec![arc::ExpressionPathSegment::Not];
    let expression = arc::BoundRuleExpression::Not(Box::new(arc::BoundRuleExpression::Probe {
        command: "failing-probe".into(),
        expected_in: vec!["ok".into()],
    }));
    let leaves = std::collections::BTreeMap::from([(
        arc::expression_path_key(&probe_path),
        violated(
            probe_path.clone(),
            "occ-fail",
            "child probe failed as expected",
        ),
    )]);

    let reduction =
        arc::reduce_rule_expression(&expression, &std::collections::BTreeMap::new(), &leaves)
            .expect("reduction succeeds");
    assert_eq!(reduction.decision, Some(true));
    assert!(reduction.causes.is_empty());
    assert!(reduction.faults.is_empty());

    let guard_result = arc::reduce_guard_result(
        "guard-not-false",
        1,
        0,
        arc::ActionType::Deny,
        "sha256:ev-not-false",
        &expression,
        &std::collections::BTreeMap::new(),
        &leaves,
    )
    .expect("guard reduction succeeds");

    assert_eq!(guard_result.state, arc::GuardResultState::Satisfied);
    assert!(guard_result.validate().is_ok());
}

#[test]
fn ec_016_empty_or_whitespace_findings_are_explicitly_normalized() {
    // 1. DecisionProviderExecutor explicitly normalizes whitespace/empty findings without inventing text
    let provider_ws = std::sync::Arc::new(
        arc::MockDecisionProvider::new()
            .with_verdict(
                "Check whitespace pass",
                arc::DecisionVerdict {
                    decision: true,
                    findings: Some("   \t\n  ".into()),
                },
            )
            .with_verdict(
                "Check whitespace fail",
                arc::DecisionVerdict {
                    decision: false,
                    findings: Some("   ".into()),
                },
            ),
    );
    let executor = arc::DecisionProviderExecutor::new(provider_ws, "test_transport");
    let mut req_pass = arc::DecisionTaskRequest {
        schema: arc::DECISION_TASK_REQUEST_SCHEMA.into(),
        physical_evaluation_id: "pe-norm-pass".into(),
        activation_id: "act-norm".into(),
        invocation_id: "inv-norm".into(),
        evaluation_key: "sha256:norm-pass-key".into(),
        profile: arc::DecisionExecutionProfile::default(),
        input: decision_input("ev-norm-pass"),
        absolute_deadline_unix_ms: 100_000,
    };
    req_pass.input.goal = "Check whitespace pass".into();
    let res_pass = arc::PhysicalDecisionExecutor::execute(&executor, req_pass);
    match res_pass {
        arc::DecisionTaskResult::Satisfied { findings, .. } => {
            assert_eq!(findings, None, "Whitespace findings must normalize to None");
        }
        other => panic!("expected Satisfied, got {other:?}"),
    }

    let mut req_fail = arc::DecisionTaskRequest {
        schema: arc::DECISION_TASK_REQUEST_SCHEMA.into(),
        physical_evaluation_id: "pe-norm-fail".into(),
        activation_id: "act-norm".into(),
        invocation_id: "inv-norm".into(),
        evaluation_key: "sha256:norm-fail-key".into(),
        profile: arc::DecisionExecutionProfile::default(),
        input: decision_input("ev-norm-fail"),
        absolute_deadline_unix_ms: 100_000,
    };
    req_fail.input.goal = "Check whitespace fail".into();
    let res_fail = arc::PhysicalDecisionExecutor::execute(&executor, req_fail);
    match res_fail {
        arc::DecisionTaskResult::Violated { findings, .. } => {
            assert_eq!(
                findings, "decision provider rejected the goal",
                "Whitespace findings must fallback to standard message without inventing auditor text"
            );
        }
        other => panic!("expected Violated, got {other:?}"),
    }

    // 2. FailureCause / LeafAttribution reject raw whitespace in auditor_findings
    let bad_cause = arc::FailureCause {
        occurrence_id: "occ-1".into(),
        physical_evaluation_id: "pe-1".into(),
        cache_provenance: arc::CacheResolutionProvenance::Executed,
        expression_path: vec![],
        kind: arc::FailureCauseKind::DecisionViolated,
        summary: "valid summary".into(),
        auditor_findings: Some("   ".into()),
        deterministic_evidence: Vec::new(),
    };
    assert_eq!(
        bad_cause.validate().unwrap_err(),
        arc::GuardEvaluationContractError::EmptyField {
            field: "auditor_findings"
        }
    );

    let bad_attribution = arc::LeafAttribution {
        occurrence_id: "occ-1".into(),
        physical_evaluation_id: "pe-1".into(),
        cache_provenance: arc::CacheResolutionProvenance::Executed,
        expression_path: vec![],
        summary: "valid summary".into(),
        auditor_findings: Some("   ".into()),
        deterministic_evidence: Vec::new(),
    };
    assert_eq!(
        bad_attribution.validate().unwrap_err(),
        arc::GuardEvaluationContractError::EmptyField {
            field: "auditor_findings"
        }
    );

    // 3. Normalization preserves real findings without modification
    let good_cause = arc::FailureCause {
        occurrence_id: "occ-1".into(),
        physical_evaluation_id: "pe-1".into(),
        cache_provenance: arc::CacheResolutionProvenance::Executed,
        expression_path: vec![],
        kind: arc::FailureCauseKind::DecisionViolated,
        summary: "valid summary".into(),
        auditor_findings: Some("actual security finding".into()),
        deterministic_evidence: Vec::new(),
    };
    assert!(good_cause.validate().is_ok());
}

#[test]
fn ec_017_guard_message_and_satisfied_guard_preserves_message_without_deny_or_ask() {
    let message_guard = arc::GuardResult::test_result(
        "guard-message",
        1,
        0,
        arc::ActionType::Message,
        false, // violated
    );
    let satisfied_guard = arc::GuardResult::test_result(
        "guard-satisfied",
        2,
        1,
        arc::ActionType::Deny,
        true, // satisfied
    );

    let results = vec![message_guard, satisfied_guard];
    assert_eq!(
        arc::reduce_effective_disposition(&results),
        arc::EffectiveDisposition::Message
    );

    // Both satisfied -> Continue
    let satisfied_message =
        arc::GuardResult::test_result("guard-message-ok", 1, 0, arc::ActionType::Message, true);
    let satisfied_deny =
        arc::GuardResult::test_result("guard-deny-ok", 2, 1, arc::ActionType::Deny, true);
    let ok_results = vec![satisfied_message, satisfied_deny];
    assert_eq!(
        arc::reduce_effective_disposition(&ok_results),
        arc::EffectiveDisposition::Continue
    );
}
