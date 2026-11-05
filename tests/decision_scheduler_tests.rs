use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Barrier, Mutex};

use arc::{
    ArcEventType, CurrentOperation, DecisionEvaluationInput, DecisionExecutionProfile,
    DecisionProviderExecutor, DecisionScheduler, DecisionTaskFault, DecisionTaskRequest,
    DecisionTaskResult, PhysicalDecisionExecutor, ProviderTarget, SchedulerError,
    SemanticDecisionEvidence, SessionContext,
};

fn task(id: &str, deadline: i64) -> DecisionTaskRequest {
    DecisionTaskRequest {
        schema: "arc.decision_task.request.v1".into(),
        physical_evaluation_id: id.into(),
        activation_id: "activation-1".into(),
        invocation_id: "invocation-1".into(),
        evaluation_key: format!("key-{id}"),
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
            goal: id.into(),
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
        absolute_deadline_unix_ms: deadline,
    }
}

struct ControlledExecutor {
    active: AtomicUsize,
    peak: AtomicUsize,
    calls: Mutex<Vec<String>>,
    barrier: Option<Arc<Barrier>>,
}

impl PhysicalDecisionExecutor for ControlledExecutor {
    fn execute(&self, request: DecisionTaskRequest) -> DecisionTaskResult {
        let active = self.active.fetch_add(1, Ordering::SeqCst) + 1;
        self.peak.fetch_max(active, Ordering::SeqCst);
        self.calls
            .lock()
            .expect("calls lock")
            .push(request.physical_evaluation_id.clone());
        if let Some(barrier) = &self.barrier {
            barrier.wait();
        }
        self.active.fetch_sub(1, Ordering::SeqCst);
        DecisionTaskResult::Satisfied {
            physical_evaluation_id: request.physical_evaluation_id,
            evaluation_key: request.evaluation_key,
            findings: None,
            provider_receipt: arc::ProviderEvaluationReceipt {
                provider: ProviderTarget::Codex,
                transport: "fixture".into(),
                isolated_conversation_fingerprint: "conversation".into(),
                started_unix_ms: 1,
                completed_unix_ms: 2,
                queue_duration_ms: 0,
                inference_duration_ms: 1,
            },
        }
    }
}

#[test]
fn scheduler_enforces_fifo_at_one_worker_and_returns_id_ordered_results() {
    let executor = Arc::new(ControlledExecutor {
        active: AtomicUsize::new(0),
        peak: AtomicUsize::new(0),
        calls: Mutex::new(Vec::new()),
        barrier: None,
    });
    let scheduler = DecisionScheduler::new(1).expect("valid scheduler");
    let batch = scheduler
        .run(
            vec![task("pe-2", 10_000), task("pe-1", 10_000)],
            executor.clone(),
            || 1,
        )
        .expect("batch succeeds");
    assert_eq!(executor.peak.load(Ordering::SeqCst), 1);
    assert_eq!(
        *executor.calls.lock().expect("calls lock"),
        vec!["pe-2".to_string(), "pe-1".to_string()]
    );
    assert_eq!(
        batch
            .results
            .iter()
            .map(|result| match result {
                DecisionTaskResult::Satisfied {
                    physical_evaluation_id,
                    ..
                } => physical_evaluation_id.as_str(),
                DecisionTaskResult::Violated { .. } | DecisionTaskResult::Faulted { .. } => "fault",
            })
            .collect::<Vec<_>>(),
        vec!["pe-1", "pe-2"]
    );
}

#[test]
fn scheduler_bounds_parallelism_and_keeps_sibling_faults_independent() {
    let executor = Arc::new(ControlledExecutor {
        active: AtomicUsize::new(0),
        peak: AtomicUsize::new(0),
        calls: Mutex::new(Vec::new()),
        barrier: Some(Arc::new(Barrier::new(2))),
    });
    let scheduler = DecisionScheduler::new(2).expect("valid scheduler");
    let batch = scheduler
        .run(
            vec![
                task("pe-a", 10_000),
                task("pe-b", 10_000),
                task("pe-c", 10_000),
                task("pe-d", 10_000),
            ],
            executor.clone(),
            || 1,
        )
        .expect("batch succeeds");
    assert_eq!(executor.peak.load(Ordering::SeqCst), 2);
    assert_eq!(batch.results.len(), 4);
}

#[test]
fn queued_deadline_is_a_typed_fault_and_does_not_call_executor() {
    let executor = Arc::new(ControlledExecutor {
        active: AtomicUsize::new(0),
        peak: AtomicUsize::new(0),
        calls: Mutex::new(Vec::new()),
        barrier: None,
    });
    let scheduler = DecisionScheduler::new(1).expect("valid scheduler");
    let batch = scheduler
        .run(vec![task("pe-expired", 10)], executor.clone(), || 11)
        .expect("batch succeeds with typed fault");
    assert!(matches!(
        &batch.results[0],
        DecisionTaskResult::Faulted {
            fault: DecisionTaskFault::QueueDeadlineExceeded,
            ..
        }
    ));
    assert!(executor.calls.lock().expect("calls lock").is_empty());
}

struct FixedResultExecutor;

impl PhysicalDecisionExecutor for FixedResultExecutor {
    fn execute(&self, request: DecisionTaskRequest) -> DecisionTaskResult {
        DecisionTaskResult::Satisfied {
            physical_evaluation_id: "duplicate-result".into(),
            evaluation_key: request.evaluation_key,
            findings: None,
            provider_receipt: arc::ProviderEvaluationReceipt {
                provider: ProviderTarget::Codex,
                transport: "fixture".into(),
                isolated_conversation_fingerprint: "conversation".into(),
                started_unix_ms: 1,
                completed_unix_ms: 2,
                queue_duration_ms: 0,
                inference_duration_ms: 1,
            },
        }
    }
}

#[test]
fn scheduler_rejects_duplicate_physical_results() {
    let scheduler = DecisionScheduler::new(2).expect("valid scheduler");
    let result = scheduler.run(
        vec![task("request-a", 10_000), task("request-b", 10_000)],
        Arc::new(FixedResultExecutor),
        || 1,
    );
    assert!(matches!(
        result,
        Err(SchedulerError::DuplicatePhysicalEvaluationId { .. })
    ));
}

struct MismatchedResultExecutor;

impl PhysicalDecisionExecutor for MismatchedResultExecutor {
    fn execute(&self, request: DecisionTaskRequest) -> DecisionTaskResult {
        DecisionTaskResult::Satisfied {
            physical_evaluation_id: "unexpected-physical-id".into(),
            evaluation_key: format!("{}-unexpected", request.evaluation_key),
            findings: None,
            provider_receipt: arc::ProviderEvaluationReceipt {
                provider: ProviderTarget::Codex,
                transport: "fixture".into(),
                isolated_conversation_fingerprint: "conversation".into(),
                started_unix_ms: 1,
                completed_unix_ms: 2,
                queue_duration_ms: 0,
                inference_duration_ms: 1,
            },
        }
    }
}

#[test]
fn scheduler_rejects_mismatched_physical_result_identity() {
    let scheduler = DecisionScheduler::new(1).expect("valid scheduler");
    let result = scheduler.run(
        vec![task("request-a", 10_000)],
        Arc::new(MismatchedResultExecutor),
        || 1,
    );
    assert!(matches!(
        result,
        Err(SchedulerError::ResultIdentityMismatch { .. })
    ));
}

#[test]
fn scheduler_converts_a_result_that_finishes_after_deadline_to_a_typed_fault() {
    let executor = Arc::new(ControlledExecutor {
        active: AtomicUsize::new(0),
        peak: AtomicUsize::new(0),
        calls: Mutex::new(Vec::new()),
        barrier: None,
    });
    let clock = Arc::new(AtomicUsize::new(1));
    let clock_for_scheduler = Arc::clone(&clock);
    let scheduler = DecisionScheduler::new(1).expect("valid scheduler");
    let batch = scheduler
        .run(vec![task("pe-finished-late", 10)], executor, move || {
            if clock_for_scheduler.fetch_add(10, Ordering::SeqCst) == 1 {
                1
            } else {
                11
            }
        })
        .expect("batch succeeds with typed fault");
    assert!(matches!(
        &batch.results[0],
        DecisionTaskResult::Faulted {
            fault: DecisionTaskFault::DeadlineExceeded,
            ..
        }
    ));
}

struct AllowingProvider;

impl arc::DecisionProvider for AllowingProvider {
    fn decide(
        &self,
        _prompt: &str,
        _context: Option<&SessionContext>,
        _current_operation: Option<&CurrentOperation>,
        _evidence: &arc::GuardDecisionEvidence,
    ) -> Result<arc::DecisionVerdict, arc::DecisionError> {
        Ok(arc::DecisionVerdict::allow())
    }
}

struct FailingProvider;

impl arc::DecisionProvider for FailingProvider {
    fn decide(
        &self,
        _prompt: &str,
        _context: Option<&SessionContext>,
        _current_operation: Option<&CurrentOperation>,
        _evidence: &arc::GuardDecisionEvidence,
    ) -> Result<arc::DecisionVerdict, arc::DecisionError> {
        Err(arc::DecisionError::ExecutionFailed {
            command: "fixture-provider".into(),
            exit_code: Some(17),
            stderr_summary: "<redacted bytes=18 sha256=deadbeef>".into(),
            stdout_summary: "<redacted bytes=22 sha256=feedface>".into(),
        })
    }
}

#[test]
fn provider_executor_maps_process_failure_to_hashed_typed_fault() {
    let result = DecisionProviderExecutor::new(Arc::new(FailingProvider), "fixture-transport")
        .execute(task("physical-failed", 10_000));
    match result {
        DecisionTaskResult::Faulted {
            fault:
                DecisionTaskFault::ProcessFailed {
                    exit_code,
                    stdout_sha256,
                    stderr_sha256,
                },
            provider_receipt: None,
            ..
        } => {
            assert_eq!(exit_code, Some(17));
            assert!(!stdout_sha256.is_empty());
            assert!(!stderr_sha256.is_empty());
            assert!(!stdout_sha256.contains("feedface"));
            assert!(!stderr_sha256.contains("deadbeef"));
        }
        other => panic!("expected typed process failure, got {other:?}"),
    }
}

struct MissingSessionIntentProvider;

impl arc::DecisionProvider for MissingSessionIntentProvider {
    fn decide(
        &self,
        _prompt: &str,
        _context: Option<&SessionContext>,
        _current_operation: Option<&CurrentOperation>,
        _evidence: &arc::GuardDecisionEvidence,
    ) -> Result<arc::DecisionVerdict, arc::DecisionError> {
        Err(arc::DecisionError::SessionIntentUnavailable)
    }
}

#[test]
fn provider_executor_preserves_missing_session_intent_as_a_typed_fault() {
    let result =
        DecisionProviderExecutor::new(Arc::new(MissingSessionIntentProvider), "fixture-transport")
            .execute(task("physical-missing-session-intent", 10_000));

    assert!(matches!(
        result,
        DecisionTaskResult::Faulted {
            fault: DecisionTaskFault::SessionIntentUnavailable,
            provider_receipt: None,
            ..
        }
    ));
}

#[test]
fn provider_executor_returns_isolated_receipts_for_physical_tasks() {
    let scheduler = DecisionScheduler::new(2).expect("valid scheduler");
    let batch = scheduler
        .run(
            vec![task("physical-a", 10_000), task("physical-b", 10_000)],
            Arc::new(DecisionProviderExecutor::new(
                Arc::new(AllowingProvider),
                "fixture-transport",
            )),
            || 1,
        )
        .expect("provider batch");
    let receipts: Vec<_> = batch
        .results
        .iter()
        .map(|result| match result {
            DecisionTaskResult::Satisfied {
                provider_receipt, ..
            } => provider_receipt.isolated_conversation_fingerprint.clone(),
            DecisionTaskResult::Violated { .. } | DecisionTaskResult::Faulted { .. } => {
                panic!("provider fixture should allow")
            }
        })
        .collect();
    assert_eq!(receipts.len(), 2);
    assert_ne!(receipts[0], receipts[1]);
}

#[test]
fn provider_executor_rejects_non_read_only_execution_profiles() {
    let mut request = task("physical-invalid", i64::MAX);
    request.profile.approval_policy = "always".into();
    let result = DecisionProviderExecutor::new(Arc::new(AllowingProvider), "fixture-transport")
        .execute(request);
    assert!(matches!(
        result,
        DecisionTaskResult::Faulted {
            fault: DecisionTaskFault::IsolationViolation,
            provider_receipt: None,
            ..
        }
    ));
}
