use arc::{
    ActionType, ActivationCacheSummary, AgyAdapter, ArcEvaluationResult, ArcEventType,
    CodexAdapter, EffectiveDisposition, EvaluationCompleteness, EvaluationFault,
    EventEvaluationReport, FailureBundle, FailureCause, FailureCauseKind, GuardResult,
    GuardResultState, format_bundle_feedback_for_provider,
};

fn base_report() -> EventEvaluationReport {
    let mut report = EventEvaluationReport {
        schema: "arc.event_evaluation.report.v1".into(),
        invocation_id: "invocation-golden".into(),
        provider: arc::ProviderTarget::Codex,
        event_id: "event-golden".into(),
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
    refingerprint(&mut report);
    report
}

fn refingerprint(report: &mut EventEvaluationReport) {
    report.report_fingerprint =
        arc::fingerprint(&serde_json::to_vec(&report.guard_results).unwrap());
}

/// Deny report whose first guard carries an auditor finding.
fn violated_report() -> EventEvaluationReport {
    let mut report = base_report();
    report.guard_results[0].state = GuardResultState::Violated {
        causes: vec![FailureCause {
            occurrence_id: "occurrence-golden".into(),
            physical_evaluation_id: "physical-golden".into(),
            cache_provenance: arc::CacheResolutionProvenance::Executed,
            expression_path: Vec::new(),
            kind: FailureCauseKind::DecisionViolated,
            summary: "configured policy failed".into(),
            auditor_findings: Some("review finding".into()),
            deterministic_evidence: Vec::new(),
        }],
    };
    refingerprint(&mut report);
    report
}

/// RuntimeFault report: one faulted guard with a probe fault and a decision fault.
fn fault_report() -> EventEvaluationReport {
    let mut report = base_report();
    report.guard_results = vec![GuardResult {
        guard_id: "guard-fault".into(),
        order: 1,
        declaration_order: 1,
        configured_action: ActionType::Deny,
        state: GuardResultState::Faulted {
            faults: vec![
                EvaluationFault::Probe {
                    summary: "probe failed".into(),
                },
                EvaluationFault::DeadlineExceeded,
            ],
            causes: Vec::new(),
        },
        satisfied_attributions: Vec::new(),
        evidence_fingerprint: "evidence-fault".into(),
        completeness: EvaluationCompleteness::IncompleteDueToFault,
    }];
    report.effective_disposition = EffectiveDisposition::RuntimeFault;
    refingerprint(&mut report);
    report
}

fn deny_bundle() -> FailureBundle {
    let mut bundle = FailureBundle::from_report(&violated_report()).expect("deny bundle");
    bundle.failed_guards[0].configured_feedback =
        Some("Review this operation before continuing.".into());
    refingerprint_bundle(&mut bundle);
    bundle
}

fn refingerprint_bundle(bundle: &mut FailureBundle) {
    let mut unsigned = bundle.clone();
    unsigned.bundle_fingerprint.clear();
    bundle.bundle_fingerprint = arc::fingerprint(&serde_json::to_vec(&unsigned).unwrap());
}

fn fault_bundle() -> FailureBundle {
    FailureBundle::from_report(&fault_report()).expect("fault bundle")
}

fn empty_feedback_bundle() -> FailureBundle {
    FailureBundle::from_report(&base_report()).expect("bundle without feedback")
}

fn deny_result() -> ArcEvaluationResult {
    ArcEvaluationResult::from_report_and_bundle(violated_report(), deny_bundle())
        .expect("deny result")
}

fn fault_result() -> ArcEvaluationResult {
    ArcEvaluationResult::from_report_and_bundle(fault_report(), fault_bundle())
        .expect("fault result")
}

fn empty_deny_result() -> ArcEvaluationResult {
    let report = base_report();
    let bundle = FailureBundle::from_report(&report).expect("bundle without feedback");
    ArcEvaluationResult::from_report_and_bundle(report, bundle).expect("empty deny result")
}

// Golden literals captured from the tree BEFORE REQ-003 changed any production code.
// Capture command (old signature, a throwaway `print_baseline` test that printed each value):
//   cargo test --offline --test provider_feedback_golden_tests -- --nocapture
const DENY_TEXT: &str = "Arc guard feedback:

Guard 'guard-deny':
Configured feedback: Review this operation before continuing.
Auditor findings:
- review finding";
const FAULT_TEXT: &str = "Arc guard feedback:

[ARC PROBE ERROR] Guard evaluation failed; see local Arc diagnostics.

Evaluation fault: Probe execution failed

Evaluation fault: Evaluation deadline exceeded";
const EMPTY_DENY_PRE_TOOL: &str = "Arc guard feedback:

Arc policy denied the tool call.";
const EMPTY_DENY_STOP: &str = "Arc guard feedback:

Session cannot end: Arc guard requirements unmet.";

#[test]
fn formatter_text_for_deny_bundle_with_feedback_and_findings_is_unchanged() {
    for fallback in ["fallback message", "  ", "Custom fallback."] {
        assert_eq!(
            format_bundle_feedback_for_provider(&deny_bundle(), fallback).unwrap(),
            DENY_TEXT,
            "fallback {fallback:?} must not alter text built from configured feedback"
        );
    }
}

#[test]
fn formatter_text_for_runtime_fault_bundle_is_unchanged() {
    assert_eq!(
        format_bundle_feedback_for_provider(&fault_bundle(), "fallback message").unwrap(),
        "Arc guard feedback:

fallback message

Evaluation fault: Probe execution failed

Evaluation fault: Evaluation deadline exceeded"
    );
    assert_eq!(
        format_bundle_feedback_for_provider(&fault_bundle(), "  ").unwrap(),
        "Arc guard feedback:

One or more Arc guards require attention.

Evaluation fault: Probe execution failed

Evaluation fault: Evaluation deadline exceeded"
    );
    assert_eq!(
        format_bundle_feedback_for_provider(&fault_bundle(), "Custom fallback.").unwrap(),
        "Arc guard feedback:

Custom fallback.

Evaluation fault: Probe execution failed

Evaluation fault: Evaluation deadline exceeded"
    );
}

#[test]
fn formatter_text_without_feedback_falls_back_to_the_default_message() {
    assert_eq!(
        format_bundle_feedback_for_provider(&empty_feedback_bundle(), "fallback message").unwrap(),
        "Arc guard feedback:

fallback message"
    );
    assert_eq!(
        format_bundle_feedback_for_provider(&empty_feedback_bundle(), "  ").unwrap(),
        "Arc guard feedback:

One or more Arc guards require attention."
    );
    assert_eq!(
        format_bundle_feedback_for_provider(&empty_feedback_bundle(), "Custom fallback.").unwrap(),
        "Arc guard feedback:

Custom fallback."
    );
}

#[test]
fn codex_outputs_carry_the_same_text_as_before() {
    let deny = deny_result();
    let pre = CodexAdapter::evaluation_result_to_pre_tool_use_output(&deny).unwrap();
    assert_eq!(
        pre.hook_specific_output
            .unwrap()
            .permission_decision_reason
            .as_deref(),
        Some(DENY_TEXT)
    );
    let stop = CodexAdapter::evaluation_result_to_stop_output(&deny).unwrap();
    assert_eq!(stop.stop_reason.as_deref(), Some(DENY_TEXT));
    assert_eq!(stop.r#continue, Some(false));
    assert!(stop.decision.is_none());

    let fault = fault_result();
    let pre = CodexAdapter::evaluation_result_to_pre_tool_use_output(&fault).unwrap();
    assert_eq!(
        pre.hook_specific_output
            .unwrap()
            .permission_decision_reason
            .as_deref(),
        Some(FAULT_TEXT)
    );
    let stop = CodexAdapter::evaluation_result_to_stop_output(&fault).unwrap();
    assert_eq!(stop.stop_reason.as_deref(), Some(FAULT_TEXT));
    assert_eq!(stop.r#continue, Some(false));

    let empty = empty_deny_result();
    let pre = CodexAdapter::evaluation_result_to_pre_tool_use_output(&empty).unwrap();
    assert_eq!(
        pre.hook_specific_output
            .unwrap()
            .permission_decision_reason
            .as_deref(),
        Some(EMPTY_DENY_PRE_TOOL)
    );
    let stop = CodexAdapter::evaluation_result_to_stop_output(&empty).unwrap();
    assert_eq!(stop.stop_reason.as_deref(), Some(EMPTY_DENY_STOP));
}

#[test]
fn agy_outputs_carry_the_same_text_as_before() {
    let deny = deny_result();
    let pre = AgyAdapter::evaluation_result_to_pre_tool_use_output(&deny).unwrap();
    assert_eq!(pre.decision, "deny");
    assert_eq!(pre.reason.as_deref(), Some(DENY_TEXT));
    let stop = AgyAdapter::evaluation_result_to_stop_output(&deny).unwrap();
    assert_eq!(stop.decision, "stop");
    assert_eq!(stop.reason.as_deref(), Some(DENY_TEXT));

    let fault = fault_result();
    let pre = AgyAdapter::evaluation_result_to_pre_tool_use_output(&fault).unwrap();
    assert_eq!(pre.decision, "deny");
    assert_eq!(pre.reason.as_deref(), Some(FAULT_TEXT));
    let stop = AgyAdapter::evaluation_result_to_stop_output(&fault).unwrap();
    assert_eq!(stop.decision, "stop");
    assert_eq!(stop.reason.as_deref(), Some(FAULT_TEXT));

    let empty = empty_deny_result();
    let pre = AgyAdapter::evaluation_result_to_pre_tool_use_output(&empty).unwrap();
    assert_eq!(pre.reason.as_deref(), Some(EMPTY_DENY_PRE_TOOL));
    let stop = AgyAdapter::evaluation_result_to_stop_output(&empty).unwrap();
    assert_eq!(stop.reason.as_deref(), Some(EMPTY_DENY_STOP));
}
