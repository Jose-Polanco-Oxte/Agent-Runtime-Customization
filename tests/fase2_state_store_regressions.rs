use std::sync::Arc;

use arc::{
    AggregateGuardResolutionApplyRequest, AggregateGuardResolutionTarget,
    AggregateResolutionApplyOutcome, AggregateResolutionApplyRequest, DecisionActor,
    DecisionChoice, DecisionIntegrity, DecisionReceipt, DecisionRequest, ExactAuthorizationContext,
    ExactOperationAuthorization, GuardActivation, GuardExecutionKey, GuardExecutionRecord,
    GuardExecutionState, GuardExecutionStateStore, InMemoryStateStore, WriteOutcome,
};

fn authorization() -> ExactOperationAuthorization {
    ExactOperationAuthorization {
        guard_id: "guard-exact".into(),
        operation_fingerprint: "operation-fingerprint".into(),
        event_id: "event-1".into(),
        tool: "Bash".into(),
        normalized_arguments_fingerprint: "arguments-fingerprint".into(),
    }
}

fn authorization_context(
    auth: &ExactOperationAuthorization,
    session_id: &str,
    invocation_id: &str,
) -> ExactAuthorizationContext {
    ExactAuthorizationContext::for_authorizations(
        &auth.event_id,
        &auth.tool,
        "workspace-1",
        "codex",
        session_id,
        invocation_id,
        "policy-fingerprint",
        "evidence-fingerprint",
        std::slice::from_ref(auth),
    )
    .expect("test authorization context is valid")
}

fn pending_target(
    key: GuardExecutionKey,
    owner_invocation_id: &str,
    decision_id: &str,
) -> (GuardExecutionRecord, AggregateGuardResolutionTarget) {
    let mut pending = GuardExecutionRecord::new("execution-1".into(), key.clone(), 0);
    pending.revision = 1;
    pending.state = GuardExecutionState::AwaitingDecision;
    pending.pending_decision = Some(DecisionRequest {
        decision_id: decision_id.into(),
        execution_id: pending.execution_id.clone(),
        owner_invocation_id: Some(owner_invocation_id.into()),
        choices: vec![DecisionChoice::Allow, DecisionChoice::Deny],
        required_actor: DecisionActor::User,
        expires_at_unix_ms: 10_000,
    });
    let mut resolved = pending.clone();
    resolved.revision = 2;
    resolved.pending_decision = None;
    (
        pending,
        AggregateGuardResolutionTarget {
            key,
            expected_revision: 1,
            expected_decision_id: decision_id.into(),
            expected_execution_id: "execution-1".into(),
            expected_owner_invocation_id: owner_invocation_id.into(),
            record: resolved,
        },
    )
}

fn aggregate_request(
    invocation_id: &str,
    session_id: &str,
    decision_id: &str,
) -> AggregateResolutionApplyRequest {
    AggregateResolutionApplyRequest {
        resolution_id: "resolution-1".into(),
        decision_id: Some(decision_id.into()),
        invocation_id: invocation_id.into(),
        session_id: session_id.into(),
        workspace_id: Some("workspace-1".into()),
        provider: "codex".into(),
        outcome: arc::InteractiveDecisionOutcome::Allow,
        authorizations: Vec::new(),
        now_unix_ms: 1_000,
        expires_at_unix_ms: 10_000,
        decision_receipt: None,
        authorization_context: None,
    }
}

fn run_aggregate_regressions(store: Arc<dyn GuardExecutionStateStore>) {
    let key = GuardExecutionKey {
        workspace_id: "workspace-1".into(),
        session_id: "session-1".into(),
        turn_id: Some("turn-1".into()),
        guard_id: "guard-pending".into(),
        activation: GuardActivation::ToolCall,
        subject_id: Some("event-1".into()),
    };
    let (pending, target) = pending_target(key.clone(), "owner-1", "decision-1");
    assert_eq!(
        store.compare_and_swap(None, &pending).unwrap(),
        WriteOutcome::Written
    );

    // F2-01: a direct store application without durable targets is rejected.
    let no_target_error = store
        .apply_aggregate_resolution(&aggregate_request(
            "resolution-invocation",
            "session-1",
            "decision-1",
        ))
        .expect_err("aggregate resolution without a target must fail closed");
    assert!(no_target_error.to_string().contains("targets"));

    // F2-01: even a well-formed target cannot bypass the current owner.
    let mut wrong_owner_target = target.clone();
    wrong_owner_target.expected_owner_invocation_id = "attacker-invocation".into();
    let wrong_owner_error = store
        .apply_aggregate_guard_resolution(&AggregateGuardResolutionApplyRequest {
            resolution: aggregate_request("resolution-invocation", "session-1", "decision-1"),
            targets: vec![wrong_owner_target],
        })
        .expect_err("aggregate resolution must validate pending ownership");
    assert!(wrong_owner_error.to_string().contains("concurrently"));

    // F2-02: a target cannot be applied under a different request scope or decision.
    let mut wrong_scope_request =
        aggregate_request("resolution-invocation", "session-2", "decision-1");
    wrong_scope_request.workspace_id = Some("workspace-2".into());
    let wrong_scope_error = store
        .apply_aggregate_guard_resolution(&AggregateGuardResolutionApplyRequest {
            resolution: wrong_scope_request,
            targets: vec![target.clone()],
        })
        .expect_err("aggregate resolution must validate target scope");
    assert!(wrong_scope_error.to_string().contains("scope"));

    let wrong_decision_error = store
        .apply_aggregate_guard_resolution(&AggregateGuardResolutionApplyRequest {
            resolution: aggregate_request("resolution-invocation", "session-1", "decision-2"),
            targets: vec![target.clone()],
        })
        .expect_err("aggregate resolution must validate target decision");
    assert!(wrong_decision_error.to_string().contains("decision"));

    // F2-02: same decision and outcome with a changed invocation is a conflict.
    let applied = store
        .apply_aggregate_guard_resolution(&AggregateGuardResolutionApplyRequest {
            resolution: aggregate_request("resolution-invocation", "session-1", "decision-1"),
            targets: vec![target.clone()],
        })
        .unwrap();
    assert_eq!(applied, AggregateResolutionApplyOutcome::Applied);

    let mut changed_scope_request =
        aggregate_request("resolution-invocation", "session-2", "decision-1");
    changed_scope_request.workspace_id = Some("workspace-2".into());
    let scope_conflict = store
        .apply_aggregate_guard_resolution(&AggregateGuardResolutionApplyRequest {
            resolution: changed_scope_request,
            targets: vec![target.clone()],
        })
        .unwrap();
    assert_eq!(scope_conflict, AggregateResolutionApplyOutcome::Conflict);

    let conflict = store
        .apply_aggregate_guard_resolution(&AggregateGuardResolutionApplyRequest {
            resolution: aggregate_request("different-invocation", "session-1", "decision-1"),
            targets: vec![target],
        })
        .unwrap();
    assert_eq!(conflict, AggregateResolutionApplyOutcome::Conflict);
}

fn run_authorization_regressions(store: Arc<dyn GuardExecutionStateStore>) {
    let auth = authorization();
    let original_context = authorization_context(&auth, "session-1", "invocation-1");
    store
        .record_exact_authorization(&auth, &original_context, Some("decision-auth"), 10_000, 1)
        .unwrap();

    // F2-03: matching the Guard and operation is insufficient without context.
    let different_session = authorization_context(&auth, "session-2", "invocation-1");
    assert!(
        store
            .has_valid_exact_authorization(&auth, &original_context, 1_000)
            .unwrap()
    );
    assert!(
        !store
            .has_valid_exact_authorization(&auth, &different_session, 1_000)
            .unwrap()
    );
    assert!(
        !store
            .consume_exact_authorization(&auth, &different_session, 1_000)
            .unwrap()
    );
    assert!(
        store
            .consume_exact_authorization(&auth, &original_context, 1_000)
            .unwrap()
    );

    // F2-04: an equal receipt is idempotent; a contradictory receipt is rejected.
    let receipt = DecisionReceipt {
        decision_id: "decision-receipt".into(),
        execution_id: "execution-receipt".into(),
        selected_choice: DecisionChoice::Allow,
        actor: DecisionActor::User,
        provider: "codex".into(),
        received_at_unix_ms: 1_000,
        integrity: DecisionIntegrity {
            transport: "test".into(),
            native_interaction_id: Some("interaction-1".into()),
        },
    };
    store.record_decision_receipt(&receipt).unwrap();
    store.record_decision_receipt(&receipt).unwrap();
    let mut contradictory = receipt.clone();
    contradictory.selected_choice = DecisionChoice::Deny;
    let error = store
        .record_decision_receipt(&contradictory)
        .expect_err("contradictory receipts must not overwrite the first choice");
    assert!(error.to_string().contains("conflicting"));
    assert_eq!(
        store.load_decision_receipt(&receipt.decision_id).unwrap(),
        Some(receipt)
    );
}

fn run_aggregate_receipt_atomicity_regression(store: Arc<dyn GuardExecutionStateStore>) {
    let key = GuardExecutionKey {
        workspace_id: "workspace-1".into(),
        session_id: "session-1".into(),
        turn_id: Some("turn-atomic".into()),
        guard_id: "guard-atomicity".into(),
        activation: GuardActivation::ToolCall,
        subject_id: Some("event-atomicity".into()),
    };
    let (pending, target) = pending_target(key.clone(), "owner-1", "decision-atomic");
    assert_eq!(
        store
            .compare_and_swap(None, &pending)
            .expect("seed atomicity pending execution"),
        WriteOutcome::Written
    );

    let persisted_receipt = DecisionReceipt {
        decision_id: "decision-atomic".into(),
        execution_id: "execution-1".into(),
        selected_choice: DecisionChoice::Deny,
        actor: DecisionActor::User,
        provider: "codex".into(),
        received_at_unix_ms: 900,
        integrity: DecisionIntegrity {
            transport: "persisted".into(),
            native_interaction_id: Some("persisted-interaction".into()),
        },
    };
    store
        .record_decision_receipt(&persisted_receipt)
        .expect("seed persisted receipt");

    let conflicting_receipt = DecisionReceipt {
        selected_choice: DecisionChoice::Allow,
        received_at_unix_ms: 1_000,
        integrity: DecisionIntegrity {
            transport: "conflicting".into(),
            native_interaction_id: Some("conflicting-interaction".into()),
        },
        ..persisted_receipt.clone()
    };
    let mut request = aggregate_request("owner-1", "session-1", "decision-atomic");
    request.decision_receipt = Some(conflicting_receipt);

    let error = store
        .apply_aggregate_guard_resolution(&AggregateGuardResolutionApplyRequest {
            resolution: request,
            targets: vec![target],
        })
        .expect_err("conflicting receipt must abort the aggregate atomically");
    assert!(error.to_string().contains("conflicting"));
    assert_eq!(
        store
            .load(&key)
            .expect("load pending execution after rollback"),
        Some(pending)
    );
    assert_eq!(
        store
            .load_aggregate_resolution_by_decision("decision-atomic")
            .expect("load aggregate after rollback"),
        None
    );
    assert_eq!(
        store
            .load_decision_receipt("decision-atomic")
            .expect("load persisted receipt after rollback"),
        Some(persisted_receipt)
    );
}

fn run_resolution_id_collision_regression(store: Arc<dyn GuardExecutionStateStore>) {
    let first_key = GuardExecutionKey {
        workspace_id: "workspace-1".into(),
        session_id: "session-1".into(),
        turn_id: Some("turn-resolution-collision-first".into()),
        guard_id: "guard-resolution-collision-first".into(),
        activation: GuardActivation::ToolCall,
        subject_id: Some("event-resolution-collision-first".into()),
    };
    let (first_pending, first_target) =
        pending_target(first_key.clone(), "owner-first", "decision-first");
    assert_eq!(
        store
            .compare_and_swap(None, &first_pending)
            .expect("seed first resolution collision pending execution"),
        WriteOutcome::Written
    );
    let mut first_request = aggregate_request("invocation-first", "session-1", "decision-first");
    first_request.resolution_id = "resolution-collision".into();
    assert_eq!(
        store
            .apply_aggregate_guard_resolution(&AggregateGuardResolutionApplyRequest {
                resolution: first_request,
                targets: vec![first_target],
            })
            .expect("first resolution collision aggregate succeeds"),
        AggregateResolutionApplyOutcome::Applied
    );
    let first_resolution = store
        .load_aggregate_resolution_by_decision("decision-first")
        .expect("load first resolution collision aggregate")
        .expect("first resolution collision aggregate is durable");

    let second_key = GuardExecutionKey {
        turn_id: Some("turn-resolution-collision-second".into()),
        guard_id: "guard-resolution-collision-second".into(),
        subject_id: Some("event-resolution-collision-second".into()),
        ..first_key
    };
    let (second_pending, second_target) =
        pending_target(second_key.clone(), "owner-second", "decision-second");
    assert_eq!(
        store
            .compare_and_swap(None, &second_pending)
            .expect("seed second resolution collision pending execution"),
        WriteOutcome::Written
    );

    // F2-02: memory and SQLite must reject the same resolution_id under another decision.
    let collision = store
        .apply_aggregate_guard_resolution(&AggregateGuardResolutionApplyRequest {
            resolution: {
                let mut request =
                    aggregate_request("invocation-second", "session-1", "decision-second");
                request.resolution_id = "resolution-collision".into();
                request
            },
            targets: vec![second_target],
        })
        .expect("resolution_id collision must be a typed conflict in both stores");
    assert_eq!(collision, AggregateResolutionApplyOutcome::Conflict);
    assert_eq!(
        store
            .load(&second_key)
            .expect("load second pending execution after resolution collision"),
        Some(second_pending)
    );
    assert_eq!(
        store
            .load_aggregate_resolution_by_decision("decision-second")
            .expect("load colliding decision after rejection"),
        None
    );
    assert_eq!(
        store
            .load_aggregate_resolution_by_decision("decision-first")
            .expect("load first resolution after collision rejection"),
        Some(first_resolution)
    );
}

fn run_coordinator_replay_regression(store: Arc<dyn GuardExecutionStateStore>) {
    let coordinator = arc::GuardExecutionCoordinator::new(Arc::clone(&store));
    let key = GuardExecutionKey {
        workspace_id: "workspace-1".into(),
        session_id: "session-1".into(),
        turn_id: Some("turn-1".into()),
        guard_id: "guard-coordinator-replay".into(),
        activation: GuardActivation::ToolCall,
        subject_id: Some("event-1".into()),
    };
    let pending = coordinator
        .coordinate(arc::CoordinationInput {
            key: key.clone(),
            invocation_id: "owner-1".into(),
            signals: arc::ProviderSignals {
                reentry: arc::ReentryKind::FirstInvocation,
                ..arc::ProviderSignals::default()
            },
            evaluation: arc::EvaluationSnapshot::Violated {
                feedback: Some("test".into()),
            },
            violation_handling: arc::ViolationHandling::RequireDecision,
        })
        .expect("coordinator creates a durable pending decision")
        .decision_request
        .expect("pending decision is returned");
    let receipt = DecisionReceipt {
        decision_id: pending.decision_id.clone(),
        execution_id: pending.execution_id.clone(),
        selected_choice: DecisionChoice::Allow,
        actor: DecisionActor::User,
        provider: "codex".into(),
        received_at_unix_ms: 1_000,
        integrity: DecisionIntegrity {
            transport: "test".into(),
            native_interaction_id: Some("interaction-1".into()),
        },
    };
    let apply = |resolution_id: &str,
                 receipt: &DecisionReceipt,
                 authorizations: &[ExactOperationAuthorization],
                 authorization_context: Option<ExactAuthorizationContext>| {
        coordinator.apply_aggregate_decision_with_authorizations_outcome(
            std::slice::from_ref(&key),
            resolution_id,
            "owner-1",
            "owner-1",
            receipt,
            authorizations,
            authorization_context,
            Some(pending.expires_at_unix_ms),
        )
    };

    assert_eq!(
        apply("resolution-1", &receipt, &[], None)
            .expect("first aggregate application succeeds")
            .1,
        AggregateResolutionApplyOutcome::Applied
    );
    assert_eq!(
        apply("resolution-1", &receipt, &[], None)
            .expect("identical coordinator replay succeeds")
            .1,
        AggregateResolutionApplyOutcome::IdempotentReplay
    );

    let resolution_conflict = apply("resolution-2", &receipt, &[], None)
        .expect_err("changed resolution identity must not replay as Allow");
    assert!(
        resolution_conflict
            .to_string()
            .contains("conflict replaying")
    );

    let mut provider_changed = receipt.clone();
    provider_changed.provider = "gemini".into();
    let provider_conflict = apply("resolution-1", &provider_changed, &[], None)
        .expect_err("changed provider must not replay as Allow");
    assert!(
        provider_conflict.to_string().contains("conflict"),
        "unexpected provider replay error: {provider_conflict:#}"
    );

    let changed_auth = authorization();
    let changed_context = authorization_context(&changed_auth, "session-1", "owner-1");
    let authorization_conflict = apply(
        "resolution-1",
        &receipt,
        std::slice::from_ref(&changed_auth),
        Some(changed_context),
    )
    .expect_err("changed authorizations and context must not replay as Allow");
    assert!(
        authorization_conflict
            .to_string()
            .contains("conflict replaying")
    );

    let expiry_conflict = coordinator
        .apply_aggregate_decision_with_authorizations_outcome(
            std::slice::from_ref(&key),
            "resolution-1",
            "owner-1",
            "owner-1",
            &receipt,
            &[],
            None,
            Some(pending.expires_at_unix_ms - 1),
        )
        .expect_err("changed aggregate expiration must not replay as Allow");
    assert!(
        expiry_conflict.to_string().contains("conflict"),
        "unexpected expiration replay error: {expiry_conflict:#}"
    );

    let mut receipt_changed = receipt.clone();
    receipt_changed.integrity.native_interaction_id = Some("interaction-2".into());
    let receipt_conflict = apply("resolution-1", &receipt_changed, &[], None)
        .expect_err("changed receipt must not replay as Allow");
    assert!(
        receipt_conflict.to_string().contains("conflict"),
        "unexpected receipt replay error: {receipt_conflict:#}"
    );
}

#[test]
fn coordinator_replay_compares_the_canonical_aggregate_identity_in_memory() {
    run_coordinator_replay_regression(Arc::new(InMemoryStateStore::new()));
}

#[test]
fn coordinator_replay_compares_the_canonical_aggregate_identity_in_sqlite() {
    let root = std::env::temp_dir().join(format!(
        "arc_fase2_coordinator_replay_{}_{}",
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    std::fs::create_dir_all(&root).unwrap();
    let sqlite = arc::SqliteStateStore::open(&root.join("state.sqlite3")).unwrap();
    let store: Arc<dyn GuardExecutionStateStore> = Arc::new(sqlite);
    run_coordinator_replay_regression(store);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn fase2_regressions_hold_for_in_memory_store() {
    let store: Arc<dyn GuardExecutionStateStore> = Arc::new(InMemoryStateStore::new());
    run_aggregate_receipt_atomicity_regression(Arc::clone(&store));
    run_aggregate_regressions(Arc::clone(&store));
    run_resolution_id_collision_regression(Arc::clone(&store));
    run_authorization_regressions(store);
}

#[test]
fn fase2_regressions_hold_for_sqlite_store() {
    let root = std::env::temp_dir().join(format!(
        "arc_fase2_regressions_{}_{}",
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    std::fs::create_dir_all(&root).unwrap();
    let sqlite = Arc::new(arc::SqliteStateStore::open(&root.join("state.sqlite3")).unwrap());
    let store: Arc<dyn GuardExecutionStateStore> = sqlite;
    run_aggregate_receipt_atomicity_regression(Arc::clone(&store));
    run_aggregate_regressions(Arc::clone(&store));
    run_resolution_id_collision_regression(Arc::clone(&store));
    run_authorization_regressions(store);
    std::fs::remove_dir_all(root).unwrap();
}

// ---------------------------------------------------------------------------
// REQ-006: behavior formerly covered through the individual decision entry now
// goes through the aggregate path (`apply_aggregate_decision` with one key).
// The owner invocation is the invocation that created the pending request.
// ---------------------------------------------------------------------------

fn unix_ms_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64
}

fn session_stop_key() -> GuardExecutionKey {
    GuardExecutionKey {
        workspace_id: "workspace-1".into(),
        session_id: "session-1".into(),
        turn_id: Some("turn-1".into()),
        guard_id: "clean-worktree".into(),
        activation: GuardActivation::SessionStop,
        subject_id: None,
    }
}

fn coordination_input(
    invocation: &str,
    evaluation: arc::EvaluationSnapshot,
    reentry: arc::ReentryKind,
    handling: arc::ViolationHandling,
) -> arc::CoordinationInput {
    arc::CoordinationInput {
        key: session_stop_key(),
        invocation_id: invocation.into(),
        signals: arc::ProviderSignals {
            reentry,
            native_invocation_id: Some(invocation.into()),
            native_interaction_id: None,
        },
        evaluation,
        violation_handling: handling,
    }
}

fn ask_input(invocation: &str, reentry: arc::ReentryKind) -> arc::CoordinationInput {
    coordination_input(
        invocation,
        arc::EvaluationSnapshot::Violated {
            feedback: Some("workspace dirty".into()),
        },
        reentry,
        arc::ViolationHandling::RequireDecision,
    )
}

fn automatic_violation(invocation: &str, feedback: Option<&str>) -> arc::CoordinationInput {
    coordination_input(
        invocation,
        arc::EvaluationSnapshot::Violated {
            feedback: feedback.map(str::to_string),
        },
        arc::ReentryKind::Unknown,
        arc::ViolationHandling::AutomaticRemediation,
    )
}

fn embedded_ui_receipt(request: &DecisionRequest, choice: DecisionChoice) -> DecisionReceipt {
    DecisionReceipt {
        decision_id: request.decision_id.clone(),
        execution_id: request.execution_id.clone(),
        selected_choice: choice,
        actor: DecisionActor::User,
        provider: "codex".into(),
        received_at_unix_ms: unix_ms_now(),
        integrity: DecisionIntegrity {
            transport: "arc_embedded_ui".into(),
            native_interaction_id: None,
        },
    }
}

#[test]
fn allowed_ask_reentry_requests_a_new_decision_until_guard_is_satisfied_via_aggregate() {
    let store = Arc::new(InMemoryStateStore::default());
    let coordinator = arc::GuardExecutionCoordinator::new(store);
    let key = session_stop_key();
    let pending = coordinator
        .coordinate(ask_input("ask-owner", arc::ReentryKind::FirstInvocation))
        .unwrap()
        .decision_request
        .unwrap();
    assert_eq!(pending.owner_invocation_id.as_deref(), Some("ask-owner"));
    let receipt = embedded_ui_receipt(&pending, DecisionChoice::Allow);
    let applied = coordinator
        .apply_aggregate_decision(
            std::slice::from_ref(&key),
            "arc:test:resolution-ask-owner",
            "ask-owner:decision",
            "ask-owner",
            &receipt,
        )
        .unwrap();
    assert_eq!(applied.len(), 1);
    assert_eq!(
        applied[0].disposition,
        arc::RuntimeDisposition::ContinueForRemediation
    );

    let reentry = coordinator
        .coordinate(ask_input("ask-reentry", arc::ReentryKind::ContinuedByHook))
        .unwrap();
    assert_eq!(
        reentry.disposition,
        arc::RuntimeDisposition::RequestDecision
    );
    assert_eq!(reentry.reason_code, arc::ReasonCode::UserDecisionRequired);
    let retry_request = reentry.decision_request.unwrap();
    assert_ne!(retry_request.decision_id, pending.decision_id);
    assert_eq!(retry_request.execution_id, pending.execution_id);
    assert_eq!(
        retry_request.owner_invocation_id.as_deref(),
        Some("ask-reentry")
    );

    let provider_retry = coordinator
        .coordinate(ask_input(
            "ask-reentry-retry",
            arc::ReentryKind::RetriedByProvider,
        ))
        .unwrap();
    assert_eq!(
        provider_retry.disposition,
        arc::RuntimeDisposition::RequestDecision
    );
    let provider_request = provider_retry.decision_request.unwrap();
    assert_eq!(provider_request.decision_id, retry_request.decision_id);
    assert_eq!(
        provider_request.owner_invocation_id,
        retry_request.owner_invocation_id
    );

    let retry_receipt = embedded_ui_receipt(&retry_request, DecisionChoice::Allow);
    coordinator
        .apply_aggregate_decision(
            std::slice::from_ref(&key),
            "arc:test:resolution-ask-reentry",
            "ask-reentry:decision",
            "ask-reentry",
            &retry_receipt,
        )
        .unwrap();

    let satisfied = coordinator
        .coordinate(coordination_input(
            "ask-satisfied",
            arc::EvaluationSnapshot::Satisfied,
            arc::ReentryKind::ContinuedByHook,
            arc::ViolationHandling::RequireDecision,
        ))
        .unwrap();
    assert_eq!(satisfied.disposition, arc::RuntimeDisposition::Proceed);
    assert_eq!(satisfied.reason_code, arc::ReasonCode::GuardSatisfied);
}

#[test]
fn interactive_remediation_is_not_cut_off_by_automatic_circuit_breaker_via_aggregate() {
    let store = Arc::new(InMemoryStateStore::default());
    let coordinator =
        arc::GuardExecutionCoordinator::new(store).with_policy(arc::ExecutionPolicy {
            max_committed_transitions: 1,
            ..arc::ExecutionPolicy::default()
        });
    let key = session_stop_key();

    let first_request = coordinator
        .coordinate(ask_input("ask-owner", arc::ReentryKind::FirstInvocation))
        .unwrap()
        .decision_request
        .unwrap();
    let first_receipt = embedded_ui_receipt(&first_request, DecisionChoice::Allow);
    coordinator
        .apply_aggregate_decision(
            std::slice::from_ref(&key),
            "arc:test:resolution-breaker",
            "ask-owner:decision",
            "ask-owner",
            &first_receipt,
        )
        .unwrap();

    let next = coordinator
        .coordinate(ask_input("ask-reentry", arc::ReentryKind::ContinuedByHook))
        .unwrap();
    assert_eq!(next.disposition, arc::RuntimeDisposition::RequestDecision);
    assert_eq!(next.reason_code, arc::ReasonCode::UserDecisionRequired);
}

#[test]
fn correlated_deny_creates_one_use_waiver_via_aggregate() {
    let store = Arc::new(InMemoryStateStore::default());
    let coordinator = arc::GuardExecutionCoordinator::new(store.clone());
    let key = session_stop_key();
    coordinator
        .coordinate(automatic_violation("invocation-1", Some("dirty")))
        .unwrap();
    let escalation = coordinator
        .coordinate(automatic_violation("invocation-2", Some("dirty")))
        .unwrap();
    let request = escalation.decision_request.unwrap();
    assert_eq!(request.owner_invocation_id.as_deref(), Some("invocation-2"));
    let receipt = embedded_ui_receipt(&request, DecisionChoice::Deny);

    let applied = coordinator
        .apply_aggregate_decision(
            std::slice::from_ref(&key),
            "arc:test:resolution-deny",
            "decision-invocation",
            "invocation-2",
            &receipt,
        )
        .unwrap();
    assert_eq!(applied.len(), 1);
    let result = &applied[0];
    assert_eq!(result.disposition, arc::RuntimeDisposition::Proceed);
    assert_eq!(result.reason_code, arc::ReasonCode::WaiverAccepted);
    let record = store.load(&key).unwrap().unwrap();
    assert_eq!(record.state, GuardExecutionState::Waived);
    assert_eq!(record.waiver.unwrap().uses_remaining, 1);

    let consumed = coordinator
        .coordinate(automatic_violation("post-decision-stop", Some("dirty")))
        .unwrap();
    assert_eq!(consumed.disposition, arc::RuntimeDisposition::Proceed);
    assert_eq!(consumed.reason_code, arc::ReasonCode::WaiverAccepted);
    assert!(store.load(&key).unwrap().unwrap().waiver.is_none());
}

#[test]
fn allow_choice_does_not_create_a_waiver_via_aggregate() {
    let store = Arc::new(InMemoryStateStore::default());
    let coordinator = arc::GuardExecutionCoordinator::new(store.clone());
    let key = session_stop_key();
    coordinator
        .coordinate(automatic_violation("invocation-1", None))
        .unwrap();
    let request = coordinator
        .coordinate(automatic_violation("invocation-2", None))
        .unwrap()
        .decision_request
        .unwrap();
    assert_eq!(request.owner_invocation_id.as_deref(), Some("invocation-2"));
    let receipt = embedded_ui_receipt(&request, DecisionChoice::Allow);

    let applied = coordinator
        .apply_aggregate_decision(
            std::slice::from_ref(&key),
            "arc:test:resolution-allow",
            "decision-invocation",
            "invocation-2",
            &receipt,
        )
        .unwrap();
    assert_eq!(applied.len(), 1);
    assert_eq!(
        applied[0].disposition,
        arc::RuntimeDisposition::ContinueForRemediation
    );
    let record = store.load(&key).unwrap().unwrap();
    assert_eq!(record.state, GuardExecutionState::RemediationInProgress);
    assert!(record.waiver.is_none());
}

#[test]
fn aggregate_application_rejects_an_owner_that_did_not_create_the_pending_request() {
    // The aggregate path additionally binds the application to the owner
    // invocation that created the request; the removed individual entry did not.
    let store = Arc::new(InMemoryStateStore::default());
    let coordinator = arc::GuardExecutionCoordinator::new(store.clone());
    let key = session_stop_key();
    let request = coordinator
        .coordinate(ask_input("ask-owner", arc::ReentryKind::FirstInvocation))
        .unwrap()
        .decision_request
        .unwrap();
    let receipt = embedded_ui_receipt(&request, DecisionChoice::Allow);
    let before = store.load(&key).unwrap().unwrap();

    let error = coordinator
        .apply_aggregate_decision(
            std::slice::from_ref(&key),
            "arc:test:resolution-wrong-owner",
            "attacker:decision",
            "attacker-invocation",
            &receipt,
        )
        .expect_err("a non-owner invocation must not resolve the pending decision");
    assert!(error.to_string().contains("not owned"), "{error:#}");
    assert_eq!(store.load(&key).unwrap().unwrap(), before);
}

/// Store wrapper that simulates a concurrent writer: the first aggregate
/// application first bumps the revision of every target record (keeping the
/// pending decision intact), so the expected revision of the coordinator is stale.
struct RacingStore {
    inner: Arc<dyn GuardExecutionStateStore>,
    race_pending: std::sync::atomic::AtomicBool,
    raced: std::sync::Mutex<Vec<GuardExecutionRecord>>,
}

impl RacingStore {
    fn new(inner: Arc<dyn GuardExecutionStateStore>) -> Self {
        Self {
            inner,
            race_pending: std::sync::atomic::AtomicBool::new(false),
            raced: std::sync::Mutex::new(Vec::new()),
        }
    }

    fn arm(&self) {
        self.race_pending
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }

    fn raced_records(&self) -> Vec<GuardExecutionRecord> {
        self.raced.lock().unwrap().clone()
    }
}

impl GuardExecutionStateStore for RacingStore {
    fn load(&self, key: &GuardExecutionKey) -> anyhow::Result<Option<GuardExecutionRecord>> {
        self.inner.load(key)
    }
    fn compare_and_swap(
        &self,
        expected_revision: Option<u64>,
        record: &GuardExecutionRecord,
    ) -> anyhow::Result<WriteOutcome> {
        self.inner.compare_and_swap(expected_revision, record)
    }
    fn resolve_workspace_id(&self, canonical_root: &std::path::Path) -> anyhow::Result<String> {
        self.inner.resolve_workspace_id(canonical_root)
    }
    fn purge_expired(&self, older_than_unix_ms: i64) -> anyhow::Result<usize> {
        self.inner.purge_expired(older_than_unix_ms)
    }
    fn record_exact_authorization(
        &self,
        auth: &ExactOperationAuthorization,
        context: &ExactAuthorizationContext,
        decision_id: Option<&str>,
        expires_at_unix_ms: i64,
        uses: u32,
    ) -> anyhow::Result<()> {
        self.inner
            .record_exact_authorization(auth, context, decision_id, expires_at_unix_ms, uses)
    }
    fn record_exact_authorizations_bundle(
        &self,
        auths: &[ExactOperationAuthorization],
        context: &ExactAuthorizationContext,
        decision_id: Option<&str>,
        expires_at_unix_ms: i64,
        uses: u32,
    ) -> anyhow::Result<()> {
        self.inner.record_exact_authorizations_bundle(
            auths,
            context,
            decision_id,
            expires_at_unix_ms,
            uses,
        )
    }
    fn consume_exact_authorization(
        &self,
        auth: &ExactOperationAuthorization,
        context: &ExactAuthorizationContext,
        now_unix_ms: i64,
    ) -> anyhow::Result<bool> {
        self.inner
            .consume_exact_authorization(auth, context, now_unix_ms)
    }
    fn has_valid_exact_authorization(
        &self,
        auth: &ExactOperationAuthorization,
        context: &ExactAuthorizationContext,
        now_unix_ms: i64,
    ) -> anyhow::Result<bool> {
        self.inner
            .has_valid_exact_authorization(auth, context, now_unix_ms)
    }
    fn record_decision_receipt(&self, receipt: &DecisionReceipt) -> anyhow::Result<()> {
        self.inner.record_decision_receipt(receipt)
    }
    fn load_decision_receipt(&self, decision_id: &str) -> anyhow::Result<Option<DecisionReceipt>> {
        self.inner.load_decision_receipt(decision_id)
    }
    fn apply_aggregate_resolution(
        &self,
        request: &AggregateResolutionApplyRequest,
    ) -> anyhow::Result<AggregateResolutionApplyOutcome> {
        self.inner.apply_aggregate_resolution(request)
    }
    fn apply_aggregate_guard_resolution(
        &self,
        request: &AggregateGuardResolutionApplyRequest,
    ) -> anyhow::Result<AggregateResolutionApplyOutcome> {
        if self
            .race_pending
            .swap(false, std::sync::atomic::Ordering::SeqCst)
        {
            for target in &request.targets {
                let current = self
                    .inner
                    .load(&target.key)?
                    .expect("racing writer finds the pending execution");
                let mut bumped = current.clone();
                bumped.revision = current.revision + 1;
                bumped.updated_at_unix_ms = current.updated_at_unix_ms + 1;
                assert_eq!(
                    self.inner
                        .compare_and_swap(Some(current.revision), &bumped)?,
                    WriteOutcome::Written
                );
                self.raced.lock().unwrap().push(bumped);
            }
        }
        self.inner.apply_aggregate_guard_resolution(request)
    }
    fn load_aggregate_resolution_by_decision(
        &self,
        decision_id: &str,
    ) -> anyhow::Result<Option<AggregateGuardResolutionApplyRequest>> {
        self.inner
            .load_aggregate_resolution_by_decision(decision_id)
    }
}

fn run_stale_aggregate_application_regression(inner: Arc<dyn GuardExecutionStateStore>) {
    let racing = Arc::new(RacingStore::new(inner));
    let store: Arc<dyn GuardExecutionStateStore> = racing.clone();
    let coordinator = arc::GuardExecutionCoordinator::new(Arc::clone(&store));
    let key = session_stop_key();
    let request = coordinator
        .coordinate(ask_input("ask-owner", arc::ReentryKind::FirstInvocation))
        .unwrap()
        .decision_request
        .unwrap();
    let receipt = embedded_ui_receipt(&request, DecisionChoice::Allow);
    let seeded_revision = store.load(&key).unwrap().unwrap().revision;

    racing.arm();
    let error = coordinator
        .apply_aggregate_decision(
            std::slice::from_ref(&key),
            "arc:test:resolution-stale",
            "stale:decision",
            "ask-owner",
            &receipt,
        )
        .expect_err("a stale aggregate application must be rejected, not silently retried");
    assert!(
        error.to_string().contains("concurrently"),
        "unexpected stale application error: {error:#}"
    );

    // The race really happened: exactly one concurrent write, one revision ahead.
    let raced = racing.raced_records();
    assert_eq!(raced.len(), 1);
    assert_eq!(raced[0].revision, seeded_revision + 1);

    // The store keeps exactly what the concurrent writer wrote: decision still pending.
    let after = store.load(&key).unwrap().unwrap();
    assert_eq!(after, raced[0]);
    assert_eq!(after.state, GuardExecutionState::AwaitingDecision);
    assert_eq!(after.pending_decision.as_ref(), Some(&request));
    assert!(after.waiver.is_none());
    assert!(!after.processed_invocations.contains_key("stale:decision"));

    // No durable resolution and no receipt were written by the rejected application.
    assert_eq!(
        store
            .load_aggregate_resolution_by_decision(&request.decision_id)
            .unwrap(),
        None
    );
    assert_eq!(
        store.load_decision_receipt(&request.decision_id).unwrap(),
        None
    );

    // Failing closed leaves the decision resolvable: an explicit retry against
    // the fresh state succeeds.
    let retried = coordinator
        .apply_aggregate_decision(
            std::slice::from_ref(&key),
            "arc:test:resolution-stale",
            "stale:decision",
            "ask-owner",
            &receipt,
        )
        .expect("explicit retry against the fresh revision succeeds");
    assert_eq!(retried.len(), 1);
    assert_eq!(
        retried[0].disposition,
        arc::RuntimeDisposition::ContinueForRemediation
    );
    let resolved = store.load(&key).unwrap().unwrap();
    assert_eq!(resolved.state, GuardExecutionState::RemediationInProgress);
    assert!(resolved.pending_decision.is_none());
}

#[test]
fn stale_aggregate_application_is_rejected_and_leaves_the_store_unchanged_in_memory() {
    run_stale_aggregate_application_regression(Arc::new(InMemoryStateStore::new()));
}

#[test]
fn stale_aggregate_application_is_rejected_and_leaves_the_store_unchanged_in_sqlite() {
    let root = std::env::temp_dir().join(format!(
        "arc_req006_stale_aggregate_{}_{}",
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    std::fs::create_dir_all(&root).unwrap();
    let sqlite = arc::SqliteStateStore::open(&root.join("state.sqlite3")).unwrap();
    run_stale_aggregate_application_regression(Arc::new(sqlite));
    std::fs::remove_dir_all(root).unwrap();
}
