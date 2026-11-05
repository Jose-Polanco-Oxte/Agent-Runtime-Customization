use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{self, Sender};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use arc::ir::BoundRuleExpression;
use arc::{
    ActionType, ActivationEvaluationCache, ActivationSnapshot, ArcEvent, ArcEventType,
    DecisionError, DecisionExecutionProfile, DecisionProvider, DecisionVerdict,
    GuardDecisionEvidence, GuardEvaluationSpec, MockDecisionProvider, MockProbeRunner,
    SessionContext, evaluate_all_guards_with_cache_concurrency,
};

struct CountingDecisionProvider {
    calls: AtomicUsize,
}

impl DecisionProvider for CountingDecisionProvider {
    fn decide(
        &self,
        _prompt: &str,
        _context: Option<&SessionContext>,
        _current_operation: Option<&arc::CurrentOperation>,
        _evidence: &GuardDecisionEvidence,
    ) -> Result<DecisionVerdict, DecisionError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(DecisionVerdict::deny("shared finding"))
    }
}

struct FailingDecisionProvider;

impl DecisionProvider for FailingDecisionProvider {
    fn decide(
        &self,
        _prompt: &str,
        _context: Option<&SessionContext>,
        _current_operation: Option<&arc::CurrentOperation>,
        _evidence: &GuardDecisionEvidence,
    ) -> Result<DecisionVerdict, DecisionError> {
        Err(DecisionError::SessionIntentUnavailable)
    }
}

fn snapshot() -> ActivationSnapshot {
    ActivationSnapshot::from_event(
        "activation-cache",
        "invocation-cache",
        arc::ProviderTarget::Codex,
        &ArcEvent::lifecycle("session-cache", "event-cache", ArcEventType::End, 1),
        SessionContext {
            user_intent: "validate".into(),
            ..SessionContext::default()
        },
        Vec::new(),
        i64::MAX,
    )
}

fn decide_guard(id: &str) -> GuardEvaluationSpec {
    GuardEvaluationSpec {
        guard_id: id.into(),
        order: id.parse().unwrap_or(0),
        declaration_order: id.parse().unwrap_or(0),
        action: ActionType::Deny,
        configured_feedback: None,
        scope: "lifecycle:end".into(),
        expression: BoundRuleExpression::Decide {
            prompt: "same semantic decision".into(),
        },
        matcher_evidence: Vec::new(),
        matcher_evidence_truncated: false,
    }
}

#[test]
fn equivalent_decisions_coalesce_without_losing_guard_causality() {
    let provider = Arc::new(CountingDecisionProvider {
        calls: AtomicUsize::new(0),
    });
    let cache = ActivationEvaluationCache::new("activation-cache");
    let report = evaluate_all_guards_with_cache_concurrency(
        &snapshot(),
        &[decide_guard("1"), decide_guard("2")],
        &BTreeMap::new(),
        std::path::Path::new("."),
        "env-v1",
        "runner-v1",
        &DecisionExecutionProfile {
            provider: arc::ProviderTarget::Codex,
            transport: "fixture".into(),
            model: None,
            adapter_contract_fingerprint: "adapter-v1".into(),
            output_schema_fingerprint: "schema-v1".into(),
            sandbox_mode: "read_only".into(),
            approval_policy: "never".into(),
        },
        &cache,
        Arc::new(MockProbeRunner::new()),
        Some(provider.clone()),
        4,
    )
    .expect("cached report");
    assert_eq!(provider.calls.load(Ordering::SeqCst), 1);
    assert_eq!(report.guard_results.len(), 2);
    let physical_ids: Vec<_> = report
        .guard_results
        .iter()
        .flat_map(|guard| match &guard.state {
            arc::GuardResultState::Violated { causes } => causes
                .iter()
                .map(|cause| cause.physical_evaluation_id.clone())
                .collect::<Vec<_>>(),
            arc::GuardResultState::Satisfied | arc::GuardResultState::Faulted { .. } => Vec::new(),
        })
        .collect();
    assert_eq!(physical_ids.len(), 2);
    assert_eq!(physical_ids[0], physical_ids[1]);
    assert_eq!(cache.summary().unique_decision_evaluations, 1);
    cache.close();
}

#[test]
fn physical_fault_summary_counts_one_fault_for_equivalent_consumers() {
    let cache = ActivationEvaluationCache::new("activation-fault");
    let report = evaluate_all_guards_with_cache_concurrency(
        &snapshot(),
        &[decide_guard("1"), decide_guard("2")],
        &BTreeMap::new(),
        std::path::Path::new("."),
        "env-v1",
        "runner-v1",
        &DecisionExecutionProfile {
            provider: arc::ProviderTarget::Codex,
            transport: "fixture".into(),
            model: None,
            adapter_contract_fingerprint: "adapter-v1".into(),
            output_schema_fingerprint: "schema-v1".into(),
            sandbox_mode: "read_only".into(),
            approval_policy: "never".into(),
        },
        &cache,
        Arc::new(MockProbeRunner::new()),
        Some(Arc::new(FailingDecisionProvider)),
        4,
    )
    .expect("faulted report remains complete across guards");

    assert_eq!(
        report.activation_cache_summary.unique_decision_evaluations,
        1
    );
    assert_eq!(report.activation_cache_summary.physical_faults, 1);
    assert!(
        report
            .guard_results
            .iter()
            .all(|guard| matches!(guard.state, arc::GuardResultState::Faulted { .. }))
    );
}

#[test]
fn equivalent_probes_are_observed_once_but_expected_values_stay_logical() {
    struct CountingProbe {
        calls: AtomicUsize,
        output: Mutex<String>,
    }
    impl arc::ProbeRunner for CountingProbe {
        fn run_probe(&self, _command: &str) -> anyhow::Result<String> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(self.output.lock().expect("output lock").clone())
        }
    }
    let probes = Arc::new(CountingProbe {
        calls: AtomicUsize::new(0),
        output: Mutex::new("observed".into()),
    });
    let guards = vec![
        GuardEvaluationSpec {
            guard_id: "probe-a".into(),
            order: 1,
            declaration_order: 1,
            action: ActionType::Deny,
            configured_feedback: None,
            scope: "lifecycle:end".into(),
            expression: BoundRuleExpression::Probe {
                command: "same-command".into(),
                expected_in: vec!["observed".into()],
            },
            matcher_evidence: Vec::new(),
            matcher_evidence_truncated: false,
        },
        GuardEvaluationSpec {
            guard_id: "probe-b".into(),
            order: 2,
            declaration_order: 2,
            action: ActionType::Deny,
            configured_feedback: None,
            scope: "lifecycle:end".into(),
            expression: BoundRuleExpression::Probe {
                command: "same-command".into(),
                expected_in: vec!["different".into()],
            },
            matcher_evidence: Vec::new(),
            matcher_evidence_truncated: false,
        },
    ];
    let cache = ActivationEvaluationCache::new("activation-probe");
    let report = evaluate_all_guards_with_cache_concurrency(
        &snapshot(),
        &guards,
        &BTreeMap::new(),
        std::path::Path::new("."),
        "env-v1",
        "runner-v1",
        &DecisionExecutionProfile {
            provider: arc::ProviderTarget::Codex,
            transport: "fixture".into(),
            model: None,
            adapter_contract_fingerprint: "adapter-v1".into(),
            output_schema_fingerprint: "schema-v1".into(),
            sandbox_mode: "read_only".into(),
            approval_policy: "never".into(),
        },
        &cache,
        probes.clone(),
        None,
        4,
    )
    .expect("cached probe report");
    assert_eq!(probes.calls.load(Ordering::SeqCst), 1);
    assert!(matches!(
        report.guard_results[0].state,
        arc::GuardResultState::Satisfied
    ));
    assert!(matches!(
        report.guard_results[1].state,
        arc::GuardResultState::Violated { .. }
    ));
    assert_eq!(cache.summary().unique_probe_evaluations, 1);
}

struct BlockingDecisionProvider {
    starts: Sender<usize>,
    releases: Mutex<mpsc::Receiver<()>>,
    calls: AtomicUsize,
}

impl DecisionProvider for BlockingDecisionProvider {
    fn decide(
        &self,
        _prompt: &str,
        _context: Option<&SessionContext>,
        _current_operation: Option<&arc::CurrentOperation>,
        _evidence: &GuardDecisionEvidence,
    ) -> Result<DecisionVerdict, DecisionError> {
        let call = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
        self.starts
            .send(call)
            .expect("scheduler test receiver exists");
        self.releases
            .lock()
            .expect("scheduler release lock")
            .recv()
            .expect("scheduler test release exists");
        Ok(DecisionVerdict {
            decision: true,
            findings: None,
        })
    }
}

#[test]
fn unique_decision_leaves_are_scheduled_concurrently() {
    let (starts_tx, starts_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let provider = Arc::new(BlockingDecisionProvider {
        starts: starts_tx,
        releases: Mutex::new(release_rx),
        calls: AtomicUsize::new(0),
    });
    let cache = ActivationEvaluationCache::new("activation-scheduler");
    let guards = vec![GuardEvaluationSpec {
        guard_id: "scheduler-guard".into(),
        order: 1,
        declaration_order: 1,
        action: ActionType::Deny,
        configured_feedback: None,
        scope: "lifecycle:end".into(),
        expression: BoundRuleExpression::All(vec![
            BoundRuleExpression::Decide {
                prompt: "decision-a".into(),
            },
            BoundRuleExpression::Decide {
                prompt: "decision-b".into(),
            },
        ]),
        matcher_evidence: Vec::new(),
        matcher_evidence_truncated: false,
    }];
    let profile = DecisionExecutionProfile {
        provider: arc::ProviderTarget::Codex,
        transport: "fixture".into(),
        model: None,
        adapter_contract_fingerprint: "adapter-v1".into(),
        output_schema_fingerprint: "schema-v1".into(),
        sandbox_mode: "read_only".into(),
        approval_policy: "never".into(),
    };
    let thread_provider = Arc::clone(&provider);
    let evaluation = std::thread::spawn(move || {
        evaluate_all_guards_with_cache_concurrency(
            &snapshot(),
            &guards,
            &BTreeMap::new(),
            std::path::Path::new("."),
            "env-v1",
            "runner-v1",
            &profile,
            &cache,
            Arc::new(MockProbeRunner::new()),
            Some(thread_provider),
            4,
        )
    });

    starts_rx
        .recv_timeout(Duration::from_secs(1))
        .expect("first physical decision should start");
    let second_started = starts_rx.recv_timeout(Duration::from_millis(250)).is_ok();
    for _ in 0..4 {
        release_tx
            .send(())
            .expect("scheduler worker release receiver exists");
    }
    let report = evaluation
        .join()
        .expect("evaluation thread should join")
        .expect("scheduled evaluation should complete");

    assert!(
        second_started,
        "the second unique decision must not wait for the first"
    );
    assert_eq!(provider.calls.load(Ordering::SeqCst), 2);
    assert_eq!(
        report.activation_cache_summary.unique_decision_evaluations,
        2
    );
}

#[test]
fn satisfied_tool_decision_creates_exact_authorization_without_guard_violation() {
    let event = ArcEvent::tool_call("session-tool", "event-tool", 1, "run_command", "git status");
    let snapshot = ActivationSnapshot::from_event(
        "activation-tool",
        "invocation-tool",
        arc::ProviderTarget::Codex,
        &event,
        SessionContext {
            user_intent: "inspect the repository".into(),
            ..SessionContext::default()
        },
        Vec::new(),
        i64::MAX,
    );
    let guard = GuardEvaluationSpec {
        guard_id: "tool-audit".into(),
        order: 1,
        declaration_order: 1,
        action: ActionType::Ask,
        configured_feedback: None,
        scope: "tool:run_command".into(),
        expression: BoundRuleExpression::Decide {
            prompt: "tool decision".into(),
        },
        matcher_evidence: Vec::new(),
        matcher_evidence_truncated: false,
    };
    let profile = DecisionExecutionProfile {
        provider: arc::ProviderTarget::Codex,
        transport: "fixture".into(),
        model: None,
        adapter_contract_fingerprint: "adapter-v1".into(),
        output_schema_fingerprint: "schema-v1".into(),
        sandbox_mode: "read_only".into(),
        approval_policy: "never".into(),
    };
    let cache = ActivationEvaluationCache::new("activation-tool");
    let report = evaluate_all_guards_with_cache_concurrency(
        &snapshot,
        &[guard],
        &BTreeMap::new(),
        std::path::Path::new("."),
        "env-v1",
        "runner-v1",
        &profile,
        &cache,
        Arc::new(MockProbeRunner::new()),
        Some(Arc::new(
            MockDecisionProvider::new().with_decision("tool decision", true),
        )),
        4,
    )
    .expect("tool decision report");

    assert!(matches!(
        report.guard_results[0].state,
        arc::GuardResultState::Satisfied
    ));
    assert_eq!(
        report.effective_disposition,
        arc::EffectiveDisposition::Continue
    );
    assert_eq!(report.authorization_requirements.len(), 1);
    let authorization = &report.authorization_requirements[0];
    assert_eq!(authorization.guard_id, "tool-audit");
    assert_eq!(authorization.event_id, "event-tool");
    assert_eq!(authorization.tool, "run_command");
    assert!(!authorization.operation_fingerprint.is_empty());
    assert!(!authorization.normalized_arguments_fingerprint.is_empty());
}
