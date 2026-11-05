//! AC-003.6 / AC-012.4: an evaluation whose deadline expires must surface the
//! deadline outcome (RuntimeFault, guard Faulted with DeadlineExceeded), never
//! an allow. The hook computes its deadline with `default_evaluation_deadline_unix_ms`
//! (now + `DECISION_EVALUATION_TIMEOUT_SECONDS`); the aggregate entry takes the
//! same absolute unix-ms deadline as a parameter, so an already expired value
//! reproduces the same path without waiting for the real window.
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use arc::ir::{BehaviorIR, BoundLifecycleGuard, BoundRuleExpression, WorkspaceContext};
use arc::manifest::schema::{LifecycleTrigger, OnFailureConfig};
use arc::{
    ActionType, AgyAdapter, ArcEvaluationResult, ArcEvent, ArcEventType, ArcRuntimeSession,
    CodexAdapter, DecisionExecutionProfile, EffectiveDisposition, EvaluationCompleteness,
    EvaluationFault, GuardResultState, MockDecisionProvider, MockProbeRunner, ProviderTarget,
};

const DECISION_PROMPT: &str = "Approve this end of session";

fn lifecycle_guard(
    id: &str,
    order: u32,
    require: BoundRuleExpression,
    action: ActionType,
) -> BoundLifecycleGuard {
    BoundLifecycleGuard {
        id: id.into(),
        triggers: vec![LifecycleTrigger::End],
        require,
        on_failure: OnFailureConfig {
            action,
            feedback: Some(format!("{id} feedback")),
        },
        order,
        declaration_order: order as usize,
    }
}

fn ir_with(guards: Vec<BoundLifecycleGuard>) -> BehaviorIR {
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
        lifecycle_guards: guards,
        tool_guards: Vec::new(),
        rules: BTreeMap::new(),
    };
    ir.content_hash = Some(ir.compute_content_hash());
    ir
}

/// One decision guard that the provider would approve if it were consulted in time.
fn decision_session() -> ArcRuntimeSession {
    let ir = ir_with(vec![lifecycle_guard(
        "decision-guard",
        1,
        BoundRuleExpression::Decide {
            prompt: DECISION_PROMPT.into(),
        },
        ActionType::Deny,
    )]);
    ArcRuntimeSession::new("deadline-session", ir)
        .with_decision_provider(Arc::new(
            MockDecisionProvider::new().with_decision(DECISION_PROMPT, true),
        ))
        .with_probe_runner(Arc::new(MockProbeRunner::new()))
}

fn profile() -> DecisionExecutionProfile {
    DecisionExecutionProfile {
        provider: ProviderTarget::Codex,
        transport: "fixture".into(),
        model: None,
        adapter_contract_fingerprint: "contract-v1".into(),
        output_schema_fingerprint: "schema-v1".into(),
        sandbox_mode: "read_only".into(),
        approval_policy: "never".into(),
    }
}

fn now_unix_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64
}

fn evaluate(session: &mut ArcRuntimeSession, deadline_unix_ms: i64) -> ArcEvaluationResult {
    session
        .evaluate_event_aggregate(
            ArcEvent::lifecycle("deadline-session", "deadline-event", ArcEventType::End, 1),
            profile(),
            Path::new("."),
            deadline_unix_ms,
        )
        .expect("aggregate evaluation returns a result even when the deadline is exceeded")
}

fn assert_deadline_fault(result: &ArcEvaluationResult, guard_id: &str) {
    assert_eq!(
        result.effective_disposition,
        EffectiveDisposition::RuntimeFault,
        "an expired deadline must not yield an allow"
    );
    let guard = result
        .report
        .guard_results
        .iter()
        .find(|guard| guard.guard_id == guard_id)
        .expect("guard present in report");
    assert_eq!(
        guard.completeness,
        EvaluationCompleteness::IncompleteDueToFault
    );
    match &guard.state {
        GuardResultState::Faulted { faults, .. } => {
            assert!(
                faults.iter().any(|fault| matches!(
                    fault,
                    EvaluationFault::Decision { summary } if summary.contains("DeadlineExceeded")
                )),
                "expected a decision fault naming DeadlineExceeded, got: {faults:?}"
            );
        }
        other => panic!("expected Faulted guard, got: {other:?}"),
    }
    assert!(
        result.failure_bundle.failed_guards[0].faulted,
        "the failure bundle must carry the faulted guard"
    );
}

#[test]
fn expired_deadline_yields_runtime_fault_with_deadline_exceeded_not_continue() {
    let mut session = decision_session();
    let result = evaluate(&mut session, 1);
    assert_deadline_fault(&result, "decision-guard");
}

#[test]
fn deadline_one_millisecond_in_the_past_is_still_a_runtime_fault() {
    let mut session = decision_session();
    let result = evaluate(&mut session, now_unix_ms() - 1);
    assert_deadline_fault(&result, "decision-guard");
}

#[test]
fn deadline_far_in_the_future_lets_the_same_guard_continue() {
    let mut session = decision_session();
    let result = evaluate(&mut session, now_unix_ms() + 180_000);
    assert_eq!(result.effective_disposition, EffectiveDisposition::Continue);
    assert!(matches!(
        result.report.guard_results[0].state,
        GuardResultState::Satisfied
    ));
}

#[test]
fn maximum_deadline_lets_the_same_guard_continue() {
    let mut session = decision_session();
    let result = evaluate(&mut session, i64::MAX);
    assert_eq!(result.effective_disposition, EffectiveDisposition::Continue);
    assert!(result.failure_bundle.failed_guards.is_empty());
}

#[test]
fn expired_deadline_faults_only_the_decision_guard_and_keeps_probe_results() {
    let ir = ir_with(vec![
        lifecycle_guard(
            "probe-guard",
            1,
            BoundRuleExpression::Probe {
                command: "probe-ok".into(),
                expected_in: vec!["ok".into()],
            },
            ActionType::Deny,
        ),
        lifecycle_guard(
            "decision-guard",
            2,
            BoundRuleExpression::Decide {
                prompt: DECISION_PROMPT.into(),
            },
            ActionType::Deny,
        ),
    ]);
    let mut session = ArcRuntimeSession::new("deadline-session", ir)
        .with_decision_provider(Arc::new(
            MockDecisionProvider::new().with_decision(DECISION_PROMPT, true),
        ))
        .with_probe_runner(Arc::new(
            MockProbeRunner::new().with_output("probe-ok", "ok"),
        ));
    let result = evaluate(&mut session, 1);
    assert_eq!(
        result.effective_disposition,
        EffectiveDisposition::RuntimeFault
    );
    assert!(matches!(
        result.report.guard_results[0].state,
        GuardResultState::Satisfied
    ));
    assert!(matches!(
        result.report.guard_results[1].state,
        GuardResultState::Faulted { .. }
    ));
}

#[test]
fn hook_entry_default_deadline_is_in_the_future_so_a_passing_guard_continues() {
    // `evaluate_guard_with_observability` is the hook path; it derives its
    // deadline from `default_evaluation_deadline_unix_ms` (now + 180 s).
    let mut session = decision_session();
    let observed = arc::HookObservationContext::new("codex", "deadline-session", "inv-deadline");
    let result = arc::evaluate_guard_with_observability(
        &mut session,
        ArcEvent::lifecycle("deadline-session", "deadline-hook", ArcEventType::End, 1),
        &None,
        &observed,
    )
    .expect("hook evaluation succeeds");
    assert_eq!(result.effective_disposition, EffectiveDisposition::Continue);
}

#[test]
fn expired_deadline_is_denied_by_both_provider_adapters() {
    let mut session = decision_session();
    let result = evaluate(&mut session, 1);

    let codex_pre = CodexAdapter::evaluation_result_to_pre_tool_use_output(&result).unwrap();
    let specific = codex_pre.hook_specific_output.unwrap();
    assert_eq!(specific.permission_decision, "deny");
    let reason = specific.permission_decision_reason.unwrap();
    assert!(
        reason.contains("Guard evaluation failed"),
        "unexpected reason: {reason}"
    );

    let agy_pre = AgyAdapter::evaluation_result_to_pre_tool_use_output(&result).unwrap();
    assert_eq!(agy_pre.decision, "deny");
    assert!(
        agy_pre
            .reason
            .as_deref()
            .unwrap()
            .contains("Guard evaluation failed")
    );

    let codex_stop = CodexAdapter::evaluation_result_to_stop_output(&result).unwrap();
    assert_eq!(codex_stop.r#continue, Some(false));
    assert!(codex_stop.stop_reason.is_some());

    let agy_stop = AgyAdapter::evaluation_result_to_stop_output(&result).unwrap();
    assert_eq!(agy_stop.decision, "stop");
    assert!(agy_stop.reason.is_some());
}

/// Approves, but only after the real decision window has elapsed.
struct SlowApprovingProvider {
    delay: std::time::Duration,
}

impl arc::DecisionProvider for SlowApprovingProvider {
    fn decide(
        &self,
        _prompt: &str,
        _context: Option<&arc::SessionContext>,
        _current_operation: Option<&arc::CurrentOperation>,
        _evidence: &arc::GuardDecisionEvidence,
    ) -> Result<arc::DecisionVerdict, arc::DecisionError> {
        std::thread::sleep(self.delay);
        Ok(arc::DecisionVerdict {
            decision: true,
            findings: None,
        })
    }
}

/// Pins the wiring of the real hook path to the bounded default deadline.
/// The effective deadline is not exposed by the report, the journal or the
/// provider trait, so the only public effect is time: a provider that answers
/// after `DECISION_EVALUATION_TIMEOUT_SECONDS` must be cut off as a deadline
/// fault. A never-expiring deadline (`i64::MAX`) would let the late approval
/// through as `Continue`. Takes about 181 s, so it only runs on request:
/// `cargo test --test evaluation_deadline_tests -- --ignored`.
#[test]
#[ignore = "waits the real 180 s decision window; run with --ignored"]
fn hook_entry_cuts_off_a_decision_that_outlives_the_default_window() {
    let window =
        std::time::Duration::from_secs(arc::manifest::schema::DECISION_EVALUATION_TIMEOUT_SECONDS);
    let ir = ir_with(vec![lifecycle_guard(
        "decision-guard",
        1,
        BoundRuleExpression::Decide {
            prompt: DECISION_PROMPT.into(),
        },
        ActionType::Deny,
    )]);
    let mut session = ArcRuntimeSession::new("deadline-session", ir)
        .with_decision_provider(Arc::new(SlowApprovingProvider {
            delay: window + std::time::Duration::from_secs(1),
        }))
        .with_probe_runner(Arc::new(MockProbeRunner::new()));
    let observed = arc::HookObservationContext::new("codex", "deadline-session", "inv-slow");

    let result = arc::evaluate_guard_with_observability(
        &mut session,
        ArcEvent::lifecycle("deadline-session", "deadline-slow", ArcEventType::End, 1),
        &None,
        &observed,
    )
    .expect("hook evaluation returns a result even when the deadline is exceeded");

    assert_deadline_fault(&result, "decision-guard");
}
