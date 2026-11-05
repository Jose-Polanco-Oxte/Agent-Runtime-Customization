use std::collections::BTreeMap;
use std::path::Path;

use arc::ir::{BehaviorIR, BoundLifecycleGuard, BoundRuleExpression, WorkspaceContext};
use arc::manifest::schema::{LifecycleTrigger, OnFailureConfig};
use arc::{
    ActionType, ActivationCacheSummary, ArcEvaluationResult, ArcEventType, ArcRuntimeSession,
    EffectiveDisposition, EvaluationCompleteness, EvaluationFault, EventEvaluationReport,
    ExactOperationAuthorization, FailureBundle, FailureBundleError, FailureCause, FailureCauseKind,
    GuardEvaluationSpec, GuardResult, GuardResultState, TrustedIrAnchor,
    format_bundle_feedback_for_provider,
};
use sha2::{Digest, Sha256};

fn report() -> EventEvaluationReport {
    let mut report = EventEvaluationReport {
        schema: "arc.event_evaluation.report.v1".into(),
        invocation_id: "invocation-bundle".into(),
        provider: arc::ProviderTarget::Codex,
        event_id: "event-bundle".into(),
        event_type: ArcEventType::End,
        input_fingerprint: "sha256:input".into(),
        guard_results: vec![
            GuardResult::test_result("guard-deny", 1, 1, ActionType::Deny, false),
            GuardResult::test_result("guard-ask", 2, 2, ActionType::Ask, false),
            GuardResult::test_result("guard-ok", 3, 3, ActionType::Message, true),
        ],
        effective_disposition: EffectiveDisposition::Deny,
        authorization_requirements: Vec::new(),
        activation_cache_summary: ActivationCacheSummary {
            logical_occurrences: 2,
            unique_probe_evaluations: 1,
            unique_decision_evaluations: 1,
            coalesced_in_flight: 1,
            reused_completed: 0,
            physical_faults: 0,
        },
        report_fingerprint: String::new(),
        started_unix_ms: 1,
        completed_unix_ms: 2,
    };
    report_fingerprint(&mut report);
    report
}

fn specs(feedback: Option<String>) -> Vec<GuardEvaluationSpec> {
    vec![
        GuardEvaluationSpec {
            guard_id: "guard-deny".into(),
            order: 1,
            declaration_order: 1,
            action: ActionType::Deny,
            configured_feedback: feedback,
            scope: "lifecycle:end".into(),
            expression: BoundRuleExpression::All(Vec::new()),
            matcher_evidence: Vec::new(),
            matcher_evidence_truncated: false,
        },
        GuardEvaluationSpec {
            guard_id: "guard-ask".into(),
            order: 2,
            declaration_order: 2,
            action: ActionType::Ask,
            configured_feedback: None,
            scope: "lifecycle:end".into(),
            expression: BoundRuleExpression::All(Vec::new()),
            matcher_evidence: Vec::new(),
            matcher_evidence_truncated: false,
        },
        GuardEvaluationSpec {
            guard_id: "guard-ok".into(),
            order: 3,
            declaration_order: 3,
            action: ActionType::Message,
            configured_feedback: None,
            scope: "lifecycle:end".into(),
            expression: BoundRuleExpression::All(Vec::new()),
            matcher_evidence: Vec::new(),
            matcher_evidence_truncated: false,
        },
    ]
}

fn behavior_ir(feedback: Option<String>) -> BehaviorIR {
    let guard_specs = specs(feedback);
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
        lifecycle_guards: guard_specs
            .into_iter()
            .map(|spec| BoundLifecycleGuard {
                id: spec.guard_id,
                triggers: vec![LifecycleTrigger::End],
                require: spec.expression,
                on_failure: OnFailureConfig {
                    action: spec.action,
                    feedback: spec.configured_feedback,
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

fn report_fingerprint(report: &mut EventEvaluationReport) {
    report.report_fingerprint =
        arc::fingerprint(&serde_json::to_vec(&report.guard_results).unwrap());
}

fn bundle_fingerprint(bundle: &mut FailureBundle) {
    let mut unsigned = bundle.clone();
    unsigned.bundle_fingerprint.clear();
    bundle.bundle_fingerprint = arc::fingerprint(&serde_json::to_vec(&unsigned).unwrap());
}

fn semantic_failure_report() -> EventEvaluationReport {
    let mut report = report();
    report.guard_results[0].state = GuardResultState::Violated {
        causes: vec![FailureCause {
            occurrence_id: "occurrence-bundle".into(),
            physical_evaluation_id: "physical-bundle".into(),
            cache_provenance: arc::CacheResolutionProvenance::Executed,
            expression_path: Vec::new(),
            kind: FailureCauseKind::DecisionViolated,
            summary: "configured policy failed".into(),
            auditor_findings: Some("review finding".into()),
            deterministic_evidence: Vec::new(),
        }],
    };
    report_fingerprint(&mut report);
    report
}

fn fault_report() -> EventEvaluationReport {
    let mut report = report();
    report.guard_results = vec![GuardResult {
        guard_id: "guard-fault".into(),
        order: 1,
        declaration_order: 1,
        configured_action: ActionType::Deny,
        state: GuardResultState::Faulted {
            faults: vec![EvaluationFault::Probe {
                summary: "probe failed".into(),
            }],
            causes: Vec::new(),
        },
        satisfied_attributions: Vec::new(),
        evidence_fingerprint: "evidence-fault".into(),
        completeness: EvaluationCompleteness::IncompleteDueToFault,
    }];
    report.effective_disposition = EffectiveDisposition::RuntimeFault;
    report_fingerprint(&mut report);
    report
}

fn expect_projection_rejection(
    report: EventEvaluationReport,
    mutate: impl FnOnce(&mut FailureBundle),
    reason_fragment: &str,
) {
    let mut bundle = FailureBundle::from_report(&report).expect("bundle");
    mutate(&mut bundle);
    bundle_fingerprint(&mut bundle);
    let error = ArcEvaluationResult::from_report_and_bundle(report, bundle)
        .expect_err("tampered bundle must not be accepted");
    match error {
        arc::ArcEvaluationError::InvalidReport { reason } => {
            assert!(
                reason.contains(reason_fragment),
                "expected '{reason_fragment}' in rejection reason, got: {reason}"
            );
        }
        other => panic!("expected InvalidReport, got: {other:?}"),
    }
}

#[test]
fn bundle_preserves_all_failed_guards_and_round_trips_inline_json() {
    let feedback = "Revisión: 'sí' # literal\nC:\\workspace\\arc 🦀";
    let ir = behavior_ir(Some(feedback.into()));
    let store = arc::SqliteStateStore::open_in_memory().unwrap();
    let anchor = store
        .trust_and_anchor_ir(Path::new("test.json"), &ir)
        .unwrap();
    let bundle =
        FailureBundle::from_report_with_trusted_anchor(&report(), &ir, &anchor).expect("bundle");
    assert_eq!(bundle.failed_guards.len(), 2);
    assert_eq!(
        bundle.failed_guards[0].configured_feedback.as_deref(),
        Some(feedback)
    );
    let json = serde_json::to_vec(&bundle).expect("bundle json");
    let decoded: FailureBundle = serde_json::from_slice(&json).expect("bundle round trip");
    assert_eq!(decoded, bundle);
    decoded.validate().expect("decoded bundle still validates");
    let value: serde_json::Value = serde_json::from_slice(&json).expect("bundle json value");
    let mut keys: Vec<&str> = value
        .as_object()
        .expect("bundle serializes as a JSON object")
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        [
            "bundle_fingerprint",
            "bundle_id",
            "completeness",
            "effective_disposition",
            "evaluation_faults",
            "event_id",
            "event_type",
            "failed_guards",
            "input_fingerprint",
            "invocation_id",
            "schema",
        ],
        "the serialized bundle must carry exactly the retained fields"
    );
    assert_eq!(
        value["failed_guards"][0]["configured_feedback"], feedback,
        "configured feedback must survive the JSON round trip unchanged"
    );
    assert_eq!(bundle.bundle_fingerprint.len(), "sha256:".len() + 64);
}

#[test]
fn provider_hook_feedback_is_readable_text_without_internal_bundle_data() {
    let mut bundle =
        FailureBundle::from_report(&semantic_failure_report()).expect("failure bundle");
    bundle.failed_guards[0].configured_feedback =
        Some("Review this operation before continuing.".into());

    let feedback = format_bundle_feedback_for_provider(&bundle, "fallback message")
        .expect("provider feedback should be rendered");
    assert!(feedback.starts_with("Arc guard feedback:"));
    assert!(feedback.contains("Configured feedback: Review this operation before continuing."));
    assert!(feedback.contains("Auditor findings:\n- review finding"));
    assert!(!feedback.contains("[ARC_FAILURE_BUNDLE_V1]"));
    assert!(!feedback.contains("arc.provider_feedback.v1"));
    assert!(!feedback.contains("bundle_id:"));
    assert!(!feedback.contains("invocation_id:"));
    assert!(!feedback.contains("input_fingerprint:"));
}

#[test]
fn provider_hook_feedback_over_limit_fails_closed_without_truncating() {
    let mut bundle = FailureBundle::from_report(&semantic_failure_report()).expect("bundle");
    bundle.failed_guards[0].configured_feedback = Some("x".repeat(20 * 1024));

    let result = format_bundle_feedback_for_provider(&bundle, "fallback message");
    assert!(matches!(
        result,
        Err(FailureBundleError::InlineTooLarge { max, .. }) if max == 16 * 1024
    ));
}

#[test]
fn bundle_validation_rejects_content_tampering() {
    let mut bundle = FailureBundle::from_report(&report()).expect("bundle");
    bundle.failed_guards[0].guard_id = "tampered-guard".into();
    assert!(matches!(
        bundle.validate(),
        Err(FailureBundleError::InvalidBundle(message)) if message.contains("fingerprint")
    ));
}

#[test]
fn aggregate_rejects_semantically_divergent_bundle_with_valid_fingerprint() {
    expect_projection_rejection(
        semantic_failure_report(),
        |bundle| bundle.failed_guards[0].configured_action = ActionType::Ask,
        "configured_action",
    );
    expect_projection_rejection(
        semantic_failure_report(),
        |bundle| bundle.failed_guards[0].causes[0].summary = "tampered cause".into(),
        "causes",
    );
    expect_projection_rejection(
        semantic_failure_report(),
        |bundle| bundle.failed_guards[0].evidence_fingerprint = "tampered-evidence".into(),
        "evidence_fingerprint",
    );
    expect_projection_rejection(
        fault_report(),
        |bundle| bundle.failed_guards[0].faulted = false,
        "faulted",
    );
    expect_projection_rejection(
        fault_report(),
        |bundle| bundle.evaluation_faults.clear(),
        "evaluation_faults",
    );
    expect_projection_rejection(
        fault_report(),
        |bundle| bundle.completeness = EvaluationCompleteness::Complete,
        "completeness",
    );
}

#[test]
fn failure_bundle_validation_rejects_invalid_nested_guard_feedback() {
    let report = semantic_failure_report();
    let mut bundle = FailureBundle::from_report(&report).expect("bundle");
    bundle.failed_guards[0].guard_id.clear();
    bundle_fingerprint(&mut bundle);
    let error = bundle
        .validate()
        .expect_err("empty nested guard id must fail");
    assert!(error.to_string().contains("failed_guards.guard_id"));
}

#[test]
fn event_report_rejects_noncanonical_guard_results_after_refingerprinting() {
    let mut report = report();
    report.guard_results.swap(0, 1);
    report_fingerprint(&mut report);
    let error = report
        .validate()
        .expect_err("non-canonical guard result order must fail closed");
    assert!(error.to_string().contains("guard_results"));
    assert!(error.to_string().contains("canonical order"));
}

#[test]
fn aggregate_rejects_authorizations_out_of_structural_guard_order() {
    let mut report = report();
    report.authorization_requirements = vec![
        ExactOperationAuthorization {
            guard_id: "guard-ask".into(),
            operation_fingerprint: "operation-a".into(),
            event_id: report.event_id.clone(),
            tool: "bash".into(),
            normalized_arguments_fingerprint: "args-z".into(),
        },
        ExactOperationAuthorization {
            guard_id: "guard-deny".into(),
            operation_fingerprint: "operation-z".into(),
            event_id: report.event_id.clone(),
            tool: "bash".into(),
            normalized_arguments_fingerprint: "args-a".into(),
        },
    ];
    report_fingerprint(&mut report);
    let bundle = FailureBundle::from_report(&report).expect("bundle");
    let error = ArcEvaluationResult::from_report_and_bundle(report, bundle)
        .expect_err("non-canonical authorization order must fail closed");
    match error {
        arc::ArcEvaluationError::InvalidReport { reason } => {
            assert!(reason.contains("canonical"), "unexpected reason: {reason}");
        }
        other => panic!("expected InvalidReport, got: {other:?}"),
    }
}

#[test]
fn failure_bundle_validation_rejects_empty_identity_fields() {
    let assert_invalid = |mut bundle: FailureBundle, expected: &str| {
        bundle_fingerprint(&mut bundle);
        let error = bundle
            .validate()
            .expect_err("malformed standalone bundle must fail closed");
        assert!(
            error.to_string().contains(expected),
            "expected '{expected}' in rejection reason, got: {error}"
        );
    };

    let mut empty_invocation = FailureBundle::from_report(&report()).expect("bundle");
    empty_invocation.invocation_id.clear();
    assert_invalid(empty_invocation, "invocation_id");

    let mut empty_event = FailureBundle::from_report(&report()).expect("bundle");
    empty_event.event_id.clear();
    assert_invalid(empty_event, "event_id");

    let mut empty_input = FailureBundle::from_report(&report()).expect("bundle");
    empty_input.input_fingerprint.clear();
    assert_invalid(empty_input, "input_fingerprint");
}

#[test]
fn failure_bundle_requires_validated_behavior_ir_feedback_provenance() {
    let ir = behavior_ir(Some("configured feedback".into()));
    let ir_json_bytes = serde_json::to_vec_pretty(&ir).expect("serialize BehaviorIR JSON");
    let sqlite_digest = hex::encode(Sha256::digest(&ir_json_bytes));
    assert_eq!(
        ir.compute_raw_bytes_digest(),
        sqlite_digest,
        "computed raw bytes digest must match SHA-256 of pretty-printed JSON"
    );

    let store = arc::SqliteStateStore::open_in_memory().expect("open in-memory SQLite store");
    let canonical_path = Path::new("canonical/arc_ir.json");
    let authentic_anchor: TrustedIrAnchor = store
        .trust_and_anchor_ir(canonical_path, &ir)
        .expect("trust and anchor IR in SQLite store");
    assert_eq!(
        authentic_anchor.digest(),
        sqlite_digest,
        "store-issued anchor digest must match authoritative SQLite raw-bytes digest"
    );

    // 1. Unanchored FailureBundle::from_report leaves configured_feedback as None
    let unanchored_bundle = FailureBundle::from_report(&report()).expect("bundle without anchor");
    assert!(
        unanchored_bundle.failed_guards[0]
            .configured_feedback
            .is_none(),
        "unanchored bundle must NOT project unverified configured feedback"
    );

    // 2. Authentic store-issued anchor succeeds and provides authentic configured feedback
    let trusted_bundle =
        FailureBundle::from_report_with_trusted_anchor(&report(), &ir, &authentic_anchor)
            .expect("bundle with trusted anchor must succeed");
    assert_eq!(
        trusted_bundle.failed_guards[0]
            .configured_feedback
            .as_deref(),
        Some("configured feedback")
    );

    // 3. Adversarial Attack 1 (Auditor Finding F5-05-R1):
    // Caller mutates feedback, recalculates semantic content_hash and raw bytes digest,
    // and attempts to verify against the SQLite store.
    // Must be STRICTLY REJECTED because SQLite's trusted_irs table holds the authoritative digest.
    let mut tampered_ir_rehashed = ir.clone();
    tampered_ir_rehashed.lifecycle_guards[0].on_failure.feedback = Some("tampered feedback".into());
    tampered_ir_rehashed.content_hash = Some(tampered_ir_rehashed.compute_content_hash());

    let forge_err = store
        .verify_trusted_ir_anchor(canonical_path, &tampered_ir_rehashed)
        .expect_err("adversary cannot verify modified IR against SQLite trusted_irs");
    assert!(
        forge_err.to_string().contains("digest mismatch"),
        "expected digest mismatch error, got: {forge_err}"
    );

    // Caller attempts to verify modified IR against an un-trusted path in SQLite.
    let untrusted_err = store
        .verify_trusted_ir_anchor(Path::new("untrusted/ir.json"), &tampered_ir_rehashed)
        .expect_err("unregistered IR path must not be verified");
    assert!(
        untrusted_err
            .to_string()
            .contains("no external Arc trust record"),
        "expected no external Arc trust record error, got: {untrusted_err}"
    );

    // 4. Adversarial Attack 2 (Auditor Finding F5-05-R1):
    // Caller attempts to pass authentic store-issued anchor along with the tampered IR
    // directly to FailureBundle::from_report_with_trusted_anchor.
    // Must be REJECTED at construction because tampered IR digest does not match anchor digest.
    let tamper_bundle_err = FailureBundle::from_report_with_trusted_anchor(
        &report(),
        &tampered_ir_rehashed,
        &authentic_anchor,
    )
    .expect_err("FailureBundle must reject tampered IR with authentic anchor");
    assert!(
        tamper_bundle_err.to_string().contains("digest mismatch"),
        "expected digest mismatch error, got: {tamper_bundle_err}"
    );

    // 5. Public Session Unanchored Behavior (Auditor Finding F5-05-R1):
    // ArcRuntimeSession::new has NO trust anchor by default and does NOT produce authenticated configured feedback.
    let mut failing_ir = ir.clone();
    failing_ir.runtime.decision_timeout_seconds = 1;
    failing_ir.lifecycle_guards[0].require =
        BoundRuleExpression::Not(Box::new(BoundRuleExpression::All(Vec::new())));
    failing_ir.content_hash = Some(failing_ir.compute_content_hash());

    let provider =
        std::sync::Arc::new(arc::MockDecisionProvider::new().with_decision("decision", true));

    let mut unanchored_session = ArcRuntimeSession::new("session-unanchored", failing_ir.clone())
        .with_decision_provider(provider.clone());
    assert!(
        unanchored_session.trust_anchor().is_none(),
        "ArcRuntimeSession::new must not have a trust anchor by default"
    );
    assert!(
        unanchored_session.trusted_ir_digest().is_none(),
        "ArcRuntimeSession::new must not have a trusted digest by default"
    );
    let (_report, session_bundle) = unanchored_session
        .evaluate_event_with_bundle(
            arc::ArcEvent::lifecycle("session-unanchored", "ev1", ArcEventType::End, 1),
            arc::DecisionExecutionProfile::default(),
            Path::new("."),
            i64::MAX,
        )
        .expect("unanchored session evaluation succeeds");
    assert_eq!(session_bundle.failed_guards.len(), 1);
    assert!(
        session_bundle.failed_guards[0]
            .configured_feedback
            .is_none(),
        "unanchored session must NOT produce authenticated feedback"
    );

    // 6. Public Session Anchored Behavior:
    // Session anchored via with_trusted_anchor produces authenticated configured feedback.
    let failing_anchor = store
        .trust_and_anchor_ir(Path::new("canonical/failing_ir.json"), &failing_ir)
        .expect("trust and anchor failing IR");
    let mut anchored_session = ArcRuntimeSession::new("session-anchored", failing_ir)
        .with_decision_provider(provider)
        .with_trusted_anchor(failing_anchor)
        .expect("attaching valid anchor to matching session IR succeeds");
    assert!(anchored_session.trust_anchor().is_some());
    let (_report, anchored_bundle) = anchored_session
        .evaluate_event_with_bundle(
            arc::ArcEvent::lifecycle("session-anchored", "ev2", ArcEventType::End, 1),
            arc::DecisionExecutionProfile::default(),
            Path::new("."),
            i64::MAX,
        )
        .expect("anchored session evaluation succeeds");
    assert_eq!(anchored_bundle.failed_guards.len(), 1);
    assert_eq!(
        anchored_bundle.failed_guards[0]
            .configured_feedback
            .as_deref(),
        Some("configured feedback")
    );

    // 7. Public Session with_trusted_anchor rejects tampered IR (F5-05-R1):
    let tampered_session_err =
        ArcRuntimeSession::new("session-tampered", tampered_ir_rehashed.clone())
            .with_trusted_anchor(authentic_anchor.clone());
    assert!(
        tampered_session_err.is_err(),
        "attaching authentic anchor to tampered IR in session must fail with digest mismatch"
    );

    let new_with_trust_err = ArcRuntimeSession::new_with_trust(
        "session-tampered",
        tampered_ir_rehashed,
        authentic_anchor,
    );
    assert!(
        new_with_trust_err.is_err(),
        "new_with_trust with tampered IR must fail with digest mismatch"
    );

    // 8. Ordering and ID invariants:
    let mut mismatched_order_ir = ir.clone();
    mismatched_order_ir.lifecycle_guards[0].order = 99;
    mismatched_order_ir.content_hash = Some(mismatched_order_ir.compute_content_hash());
    let order_anchor = store
        .trust_and_anchor_ir(Path::new("canonical/order_ir.json"), &mismatched_order_ir)
        .expect("trust order IR");
    let error = FailureBundle::from_report_with_trusted_anchor(
        &report(),
        &mismatched_order_ir,
        &order_anchor,
    )
    .expect_err("BehaviorIR ordering must match report Guard identity");
    assert!(error.to_string().contains("identity"), "{error}");

    let mut missing_guard_ir = ir;
    missing_guard_ir.lifecycle_guards[0].id = "guard-not-in-report".into();
    missing_guard_ir.content_hash = Some(missing_guard_ir.compute_content_hash());
    let missing_anchor = store
        .trust_and_anchor_ir(Path::new("canonical/missing_ir.json"), &missing_guard_ir)
        .expect("trust missing guard IR");
    let error = FailureBundle::from_report_with_trusted_anchor(
        &report(),
        &missing_guard_ir,
        &missing_anchor,
    )
    .expect_err("BehaviorIR Guard IDs must match report Guard IDs");
    assert!(error.to_string().contains("absent"), "{error}");
}
