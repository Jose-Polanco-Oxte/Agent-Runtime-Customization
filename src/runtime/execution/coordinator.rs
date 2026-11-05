use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Result, bail};
use uuid::Uuid;

use crate::runtime::decision::InteractiveDecisionOutcome;
use crate::runtime::state_store::{
    AggregateGuardResolutionApplyRequest, AggregateGuardResolutionTarget,
    AggregateResolutionApplyRequest, ExactAuthorizationContext, GuardExecutionStateStore,
    WriteOutcome,
};

use super::{
    DecisionActor, DecisionChoice, DecisionReceipt, DecisionRequest, EvaluationSnapshot,
    ExecutionPolicy, GuardExecutionKey, GuardExecutionRecord, GuardExecutionState, GuardWaiver,
    ProviderSignals, ReasonCode, RuntimeDirective, RuntimeDisposition, unix_ms_to_iso8601,
};

pub struct CoordinationInput {
    pub key: GuardExecutionKey,
    pub invocation_id: String,
    pub signals: ProviderSignals,
    pub evaluation: EvaluationSnapshot,
    pub violation_handling: ViolationHandling,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ViolationHandling {
    /// The current lifecycle invocation is terminally denied.
    Terminal,
    /// The violation is delivered as feedback without requesting remediation.
    FeedbackOnly,
    AutomaticRemediation,
    RequireDecision,
}

pub struct GuardExecutionCoordinator {
    store: Arc<dyn GuardExecutionStateStore>,
    policy: ExecutionPolicy,
}

impl GuardExecutionCoordinator {
    pub fn new(store: Arc<dyn GuardExecutionStateStore>) -> Self {
        Self {
            store,
            policy: ExecutionPolicy::default(),
        }
    }

    pub fn with_policy(mut self, policy: ExecutionPolicy) -> Self {
        self.policy = policy;
        self
    }

    pub fn coordinate(&self, input: CoordinationInput) -> Result<RuntimeDirective> {
        self.store
            .purge_expired(now_unix_ms() - self.policy.execution_ttl_ms)?;
        for _ in 0..4 {
            let existing = self.store.load(&input.key)?;
            if input.violation_handling != ViolationHandling::Terminal
                && input.violation_handling != ViolationHandling::FeedbackOnly
                && let Some(record) = &existing
                && let Some(previous) = record.processed_invocations.get(&input.invocation_id)
                && (previous.disposition != RuntimeDisposition::RequestDecision
                    || record.pending_decision.is_some())
            {
                return Ok(previous.clone());
            }

            if existing.is_none()
                && matches!(
                    input.signals.reentry,
                    super::ReentryKind::ContinuedByHook | super::ReentryKind::RetriedByProvider
                )
            {
                let mut record = GuardExecutionRecord::new(
                    Uuid::new_v4().to_string(),
                    input.key.clone(),
                    now_unix_ms(),
                );
                record.state = GuardExecutionState::EvaluationFault;
                record.attempts.total_attempts = 1;
                record.attempts.fault_attempts = 1;
                record.attempts.committed_transitions = 1;
                record.revision = 1;
                let directive = directive(
                    &record,
                    RuntimeDisposition::Prevent,
                    Some(
                        "Provider reported guard re-entry but Arc has no prior execution state"
                            .into(),
                    ),
                    None,
                    ReasonCode::EvaluationFault,
                );
                record
                    .processed_invocations
                    .insert(input.invocation_id.clone(), directive.clone());
                match self.store.compare_and_swap(None, &record)? {
                    WriteOutcome::Written => return Ok(directive),
                    WriteOutcome::Conflict => continue,
                }
            }

            let expected_revision = existing.as_ref().map(|record| record.revision);
            let mut record = existing.unwrap_or_else(|| {
                GuardExecutionRecord::new(
                    Uuid::new_v4().to_string(),
                    input.key.clone(),
                    now_unix_ms(),
                )
            });
            let fingerprint = input.evaluation.fingerprint(&record.key.guard_id);
            if input.violation_handling != ViolationHandling::Terminal
                && input.violation_handling != ViolationHandling::FeedbackOnly
                && let Some(request) = record.pending_decision.as_ref()
                && request.expires_at_unix_ms >= now_unix_ms()
            {
                let mut pending = directive(
                    &record,
                    RuntimeDisposition::RequestDecision,
                    input.evaluation.message(),
                    Some(fingerprint),
                    ReasonCode::UserDecisionRequired,
                );
                pending.decision_request = Some(request.clone());
                return Ok(pending);
            }
            if record.pending_decision.take().is_some() {
                record.state = GuardExecutionState::Violated;
            }
            let directive = if let Some(waiver) = record.waiver.as_mut() {
                if waiver.evidence_fingerprint == fingerprint
                    && waiver.expires_at_unix_ms >= now_unix_ms()
                    && waiver.uses_remaining > 0
                {
                    waiver.uses_remaining -= 1;
                    let result = directive(
                        &record,
                        RuntimeDisposition::Proceed,
                        Some("Consumed the user's one-use guard waiver.".into()),
                        Some(fingerprint.clone()),
                        ReasonCode::WaiverAccepted,
                    );
                    if record
                        .waiver
                        .as_ref()
                        .is_some_and(|waiver| waiver.uses_remaining == 0)
                    {
                        record.waiver = None;
                    }
                    result
                } else {
                    record.waiver = None;
                    self.transition(&mut record, &input.evaluation, fingerprint.clone(), &input)
                }
            } else {
                self.transition(&mut record, &input.evaluation, fingerprint.clone(), &input)
            };
            record.last_evidence_fingerprint = Some(fingerprint);
            record.updated_at_unix_ms = now_unix_ms();
            record.revision = expected_revision.map_or(1, |revision| revision + 1);
            record
                .processed_invocations
                .insert(input.invocation_id.clone(), directive.clone());

            match self.store.compare_and_swap(expected_revision, &record)? {
                WriteOutcome::Written => return Ok(directive),
                WriteOutcome::Conflict => continue,
            }
        }
        bail!("guard execution state changed concurrently too many times")
    }

    /// Creates the durable pending request for an exact operation authorization.
    /// This is deliberately separate from ordinary violation evaluation: an
    /// authorization must be bound to the current invocation before a UI can
    /// produce a resolution for it.
    pub fn coordinate_authorization(
        &self,
        key: GuardExecutionKey,
        invocation_id: &str,
        evidence_fingerprint: &str,
    ) -> Result<RuntimeDirective> {
        if invocation_id.trim().is_empty() || evidence_fingerprint.trim().is_empty() {
            bail!("authorization coordination requires invocation and evidence identities")
        }
        self.store
            .purge_expired(now_unix_ms() - self.policy.execution_ttl_ms)?;
        for _ in 0..4 {
            let existing = self.store.load(&key)?;
            if let Some(record) = &existing {
                if let Some(previous) = record.processed_invocations.get(invocation_id)
                    && record.pending_decision.is_some()
                {
                    return Ok(previous.clone());
                }
                if let Some(pending) = &record.pending_decision
                    && pending.expires_at_unix_ms >= now_unix_ms()
                {
                    let mut directive = directive(
                        record,
                        RuntimeDisposition::RequestAuthorization,
                        Some(
                            "This exact operation requires a scoped authorization decision.".into(),
                        ),
                        Some(evidence_fingerprint.to_string()),
                        ReasonCode::UserDecisionRequired,
                    );
                    directive.decision_request = Some(pending.clone());
                    return Ok(directive);
                }
            }

            let expected_revision = existing.as_ref().map(|record| record.revision);
            let mut record = existing.unwrap_or_else(|| {
                GuardExecutionRecord::new(Uuid::new_v4().to_string(), key.clone(), now_unix_ms())
            });
            let decision_request = DecisionRequest {
                decision_id: Uuid::new_v4().to_string(),
                execution_id: record.execution_id.clone(),
                owner_invocation_id: Some(invocation_id.to_string()),
                choices: vec![DecisionChoice::Allow, DecisionChoice::Deny],
                required_actor: DecisionActor::User,
                expires_at_unix_ms: now_unix_ms() + 5 * 60 * 1000,
            };
            record.state = GuardExecutionState::AwaitingAuthorization;
            record.last_evidence_fingerprint = Some(evidence_fingerprint.to_string());
            record.pending_decision = Some(decision_request.clone());
            record.attempts.total_attempts = record.attempts.total_attempts.saturating_add(1);
            record.attempts.committed_transitions =
                record.attempts.committed_transitions.saturating_add(1);
            record.mark_requested(unix_ms_to_iso8601(now_unix_ms()));
            record.updated_at_unix_ms = now_unix_ms();
            record.revision = expected_revision.map_or(1, |revision| revision + 1);
            let mut result = directive(
                &record,
                RuntimeDisposition::RequestAuthorization,
                Some("This exact operation requires a scoped authorization decision.".into()),
                Some(evidence_fingerprint.to_string()),
                ReasonCode::UserDecisionRequired,
            );
            result.decision_request = Some(decision_request);
            record
                .processed_invocations
                .insert(invocation_id.to_string(), result.clone());
            match self.store.compare_and_swap(expected_revision, &record)? {
                WriteOutcome::Written => return Ok(result),
                WriteOutcome::Conflict => continue,
            }
        }
        bail!("authorization execution state changed concurrently too many times")
    }

    /// Applies one explicit decision to every pending Guard in an aggregate.
    ///
    /// The state store commits the parent resolution and all updated execution
    /// records in one local transaction. The first pending request is used only
    /// to correlate the UI receipt; it is never the enforcement scope.
    pub fn apply_aggregate_decision(
        &self,
        keys: &[GuardExecutionKey],
        resolution_id: &str,
        invocation_id: &str,
        owner_invocation_id: &str,
        receipt: &DecisionReceipt,
    ) -> Result<Vec<RuntimeDirective>> {
        self.apply_aggregate_decision_with_authorizations_outcome(
            keys,
            resolution_id,
            invocation_id,
            owner_invocation_id,
            receipt,
            &[],
            None,
            None,
        )
        .map(|(directives, _)| directives)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn apply_aggregate_decision_with_authorizations_outcome(
        &self,
        keys: &[GuardExecutionKey],
        resolution_id: &str,
        invocation_id: &str,
        owner_invocation_id: &str,
        receipt: &DecisionReceipt,
        authorizations: &[crate::runtime::guard_evaluation::ExactOperationAuthorization],
        authorization_context: Option<ExactAuthorizationContext>,
        expected_expires_at_unix_ms: Option<i64>,
    ) -> Result<(
        Vec<RuntimeDirective>,
        crate::runtime::state_store::AggregateResolutionApplyOutcome,
    )> {
        if keys.is_empty() {
            bail!("aggregate decision must include at least one guard execution")
        }
        if resolution_id.trim().is_empty() || invocation_id.trim().is_empty() {
            bail!("aggregate decision correlation identifiers must not be empty")
        }

        let mut seen = std::collections::BTreeSet::new();
        let mut current_records = Vec::with_capacity(keys.len());
        let mut replay_directives = Vec::with_capacity(keys.len());
        let aggregate_scope = &keys[0];
        for key in keys {
            if !seen.insert(key.storage_key()) {
                bail!("aggregate decision contains duplicate guard execution keys")
            }
            if key.workspace_id != aggregate_scope.workspace_id
                || key.session_id != aggregate_scope.session_id
                || key.turn_id != aggregate_scope.turn_id
                || key.activation != aggregate_scope.activation
                || key.subject_id != aggregate_scope.subject_id
            {
                bail!("aggregate decision targets cross an execution scope boundary")
            }
            let Some(record) = self.store.load(key)? else {
                bail!("aggregate decision refers to an unknown guard execution")
            };
            if let Some(previous) = record.processed_invocations.get(invocation_id)
                && !matches!(
                    previous.disposition,
                    RuntimeDisposition::RequestDecision | RuntimeDisposition::RequestAuthorization
                )
            {
                replay_directives.push(previous.clone());
            }
            current_records.push(record);
        }
        if replay_directives.len() == keys.len() {
            let existing = self
                .store
                .load_aggregate_resolution_by_decision(&receipt.decision_id)?
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "aggregate decision replay has no durable resolution for decision '{}'",
                        receipt.decision_id
                    )
                })?;
            let existing_target_keys = existing
                .targets
                .iter()
                .map(|target| target.key.storage_key())
                .collect::<std::collections::BTreeSet<_>>();
            if existing_target_keys != seen
                || existing
                    .targets
                    .iter()
                    .any(|target| target.expected_owner_invocation_id != owner_invocation_id)
            {
                bail!("aggregate decision replay does not match the durable owner or target set")
            }

            let replay_expires_at_unix_ms =
                expected_expires_at_unix_ms.unwrap_or(existing.resolution.expires_at_unix_ms);
            let replay_request = AggregateGuardResolutionApplyRequest {
                resolution: AggregateResolutionApplyRequest {
                    resolution_id: resolution_id.to_string(),
                    decision_id: Some(receipt.decision_id.clone()),
                    invocation_id: invocation_id.to_string(),
                    session_id: aggregate_scope.session_id.clone(),
                    workspace_id: Some(aggregate_scope.workspace_id.clone()),
                    provider: receipt.provider.clone(),
                    outcome: match receipt.selected_choice {
                        DecisionChoice::Allow => InteractiveDecisionOutcome::Allow,
                        DecisionChoice::Deny => InteractiveDecisionOutcome::Deny,
                    },
                    authorizations: authorizations.to_vec(),
                    now_unix_ms: now_unix_ms(),
                    expires_at_unix_ms: replay_expires_at_unix_ms,
                    decision_receipt: Some(receipt.clone()),
                    authorization_context: authorization_context.clone(),
                },
                targets: existing.targets.clone(),
            };
            match self
                .store
                .apply_aggregate_guard_resolution(&replay_request)?
            {
                crate::runtime::state_store::AggregateResolutionApplyOutcome::IdempotentReplay => {
                    let matches_choice = replay_directives.iter().all(|directive| {
                        matches!(
                            (receipt.selected_choice, directive.disposition),
                            (
                                DecisionChoice::Allow,
                                RuntimeDisposition::ContinueForRemediation
                            ) | (DecisionChoice::Deny, RuntimeDisposition::Proceed)
                        )
                    });
                    if !matches_choice {
                        bail!("aggregate decision replay conflicts with the durable directive")
                    }
                    return Ok((
                        replay_directives,
                        crate::runtime::state_store::AggregateResolutionApplyOutcome::IdempotentReplay,
                    ));
                }
                crate::runtime::state_store::AggregateResolutionApplyOutcome::Conflict => {
                    bail!("conflict replaying aggregate guard resolution '{resolution_id}'")
                }
                crate::runtime::state_store::AggregateResolutionApplyOutcome::Applied => {
                    bail!("aggregate decision replay unexpectedly created a new durable resolution")
                }
            }
        }
        if !replay_directives.is_empty() {
            bail!("aggregate decision has a partially applied prior invocation")
        }

        let now = now_unix_ms();
        let mut primary_target_index = None;
        let mut targets = Vec::with_capacity(current_records.len());
        let mut directives = Vec::with_capacity(current_records.len());
        let mut expires_at_unix_ms = i64::MAX;
        let outcome = match receipt.selected_choice {
            DecisionChoice::Allow => InteractiveDecisionOutcome::Allow,
            DecisionChoice::Deny => InteractiveDecisionOutcome::Deny,
        };

        for (index, mut record) in current_records.into_iter().enumerate() {
            let expected_revision = record.revision;
            let pending = record
                .pending_decision
                .clone()
                .ok_or_else(|| anyhow::anyhow!("guard execution is not awaiting a decision"))?;
            if pending.execution_id != record.execution_id
                || pending.owner_invocation_id.as_deref() != Some(owner_invocation_id)
            {
                bail!("aggregate decision target is not owned by the presenting invocation")
            }
            if receipt.actor != pending.required_actor {
                bail!("decision receipt actor does not satisfy an aggregate pending request")
            }
            if now > pending.expires_at_unix_ms {
                bail!("aggregate decision request has expired")
            }
            if !pending.choices.contains(&receipt.selected_choice) {
                bail!("aggregate decision choice is not available for a pending request")
            }
            if pending.decision_id == receipt.decision_id
                && pending.execution_id == receipt.execution_id
            {
                primary_target_index = Some(index);
            }
            expires_at_unix_ms = expires_at_unix_ms.min(pending.expires_at_unix_ms);

            record.attempts.committed_transitions += 1;
            let directive = match receipt.selected_choice {
                DecisionChoice::Allow => {
                    record.state = GuardExecutionState::RemediationInProgress;
                    directive(
                        &record,
                        RuntimeDisposition::ContinueForRemediation,
                        Some("The user allowed remediation; sensitive operations still require scoped authorization.".into()),
                        record.last_evidence_fingerprint.clone(),
                        ReasonCode::ProgressObserved,
                    )
                }
                DecisionChoice::Deny => {
                    let evidence_fingerprint =
                        record.last_evidence_fingerprint.clone().ok_or_else(|| {
                            anyhow::anyhow!(
                                "cannot waive a guard without observed aggregate evidence"
                            )
                        })?;
                    record.state = GuardExecutionState::Waived;
                    record.waiver = Some(GuardWaiver {
                        decision_id: receipt.decision_id.clone(),
                        execution_id: record.execution_id.clone(),
                        evidence_fingerprint: evidence_fingerprint.clone(),
                        expires_at_unix_ms: now + 5 * 60 * 1000,
                        uses_remaining: 1,
                    });
                    directive(
                        &record,
                        RuntimeDisposition::Proceed,
                        Some("User explicitly waived this guard for the observed evidence.".into()),
                        Some(evidence_fingerprint),
                        ReasonCode::WaiverAccepted,
                    )
                }
            };
            record.pending_decision = None;
            record.updated_at_unix_ms = now;
            record.revision = expected_revision
                .checked_add(1)
                .ok_or_else(|| anyhow::anyhow!("guard execution revision overflow"))?;
            let mut directive = directive;
            directive.attempts = record.attempts;
            record
                .processed_invocations
                .insert(invocation_id.to_string(), directive.clone());
            targets.push(AggregateGuardResolutionTarget {
                key: record.key.clone(),
                expected_revision,
                expected_decision_id: pending.decision_id,
                expected_execution_id: pending.execution_id,
                expected_owner_invocation_id: owner_invocation_id.to_string(),
                record,
            });
            directives.push(directive);
        }

        if primary_target_index.is_none() {
            bail!("decision receipt does not correlate with any aggregate pending request")
        }
        if let Some(expected_expires_at_unix_ms) = expected_expires_at_unix_ms
            && expires_at_unix_ms != expected_expires_at_unix_ms
        {
            bail!("aggregate decision expiration does not match the durable pending scope")
        }

        let first_key = &targets[0].key;
        let apply_request = AggregateGuardResolutionApplyRequest {
            resolution: AggregateResolutionApplyRequest {
                resolution_id: resolution_id.to_string(),
                decision_id: Some(receipt.decision_id.clone()),
                invocation_id: invocation_id.to_string(),
                session_id: first_key.session_id.clone(),
                workspace_id: Some(first_key.workspace_id.clone()),
                provider: receipt.provider.clone(),
                outcome,
                authorizations: authorizations.to_vec(),
                now_unix_ms: now,
                expires_at_unix_ms,
                decision_receipt: Some(receipt.clone()),
                authorization_context,
            },
            targets,
        };
        match self
            .store
            .apply_aggregate_guard_resolution(&apply_request)?
        {
            crate::runtime::state_store::AggregateResolutionApplyOutcome::Applied => Ok((
                directives,
                crate::runtime::state_store::AggregateResolutionApplyOutcome::Applied,
            )),
            crate::runtime::state_store::AggregateResolutionApplyOutcome::IdempotentReplay => {
                let replay = keys
                    .iter()
                    .map(|key| {
                        self.store
                            .load(key)?
                            .and_then(|record| record.processed_invocations.get(invocation_id).cloned())
                            .ok_or_else(|| {
                                anyhow::anyhow!(
                                    "aggregate resolution replay has no durable directive for guard '{}'",
                                    key.guard_id
                                )
                            })
                    })
                    .collect::<Result<Vec<_>>>()?;
                Ok((
                    replay,
                    crate::runtime::state_store::AggregateResolutionApplyOutcome::IdempotentReplay,
                ))
            }
            crate::runtime::state_store::AggregateResolutionApplyOutcome::Conflict => {
                bail!("conflict applying aggregate guard resolution '{resolution_id}'")
            }
        }
    }

    pub fn abandon_decision(
        &self,
        key: &GuardExecutionKey,
        owner_invocation_id: &str,
        decision_id: &str,
        execution_id: &str,
    ) -> Result<()> {
        for _ in 0..4 {
            let Some(mut record) = self.store.load(key)? else {
                bail!("decision refers to an unknown guard execution")
            };
            let request = record
                .pending_decision
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("guard execution is not awaiting a decision"))?;
            if request.decision_id != decision_id
                || request.execution_id != execution_id
                || record.execution_id != execution_id
                || request.owner_invocation_id.as_deref() != Some(owner_invocation_id)
            {
                bail!("decision correlation or ownership does not match the pending request")
            }
            let expected_revision = record.revision;
            record.pending_decision = None;
            record.state = GuardExecutionState::Violated;
            record.updated_at_unix_ms = now_unix_ms();
            record.revision += 1;
            match self
                .store
                .compare_and_swap(Some(expected_revision), &record)?
            {
                WriteOutcome::Written => return Ok(()),
                WriteOutcome::Conflict => continue,
            }
        }
        bail!("guard execution state changed concurrently too many times")
    }

    /// Closes a pending interactive decision when the aggregate has become
    /// terminal or when the provider cannot present the required UI.
    ///
    /// The compare-and-swap loop makes the transition durable without
    /// overwriting a concurrent state update.
    pub fn cancel_pending_decision(&self, key: &GuardExecutionKey) -> Result<bool> {
        for _ in 0..4 {
            let Some(mut record) = self.store.load(key)? else {
                return Ok(false);
            };
            if record.pending_decision.is_none() {
                return Ok(false);
            }
            let expected_revision = record.revision;
            record.pending_decision = None;
            record.state = GuardExecutionState::Violated;
            record.mark_completed(unix_ms_to_iso8601(now_unix_ms()));
            record.updated_at_unix_ms = now_unix_ms();
            record.revision += 1;
            match self
                .store
                .compare_and_swap(Some(expected_revision), &record)?
            {
                WriteOutcome::Written => return Ok(true),
                WriteOutcome::Conflict => continue,
            }
        }
        bail!("guard execution state changed concurrently too many times")
    }

    fn transition(
        &self,
        record: &mut GuardExecutionRecord,
        evaluation: &EvaluationSnapshot,
        fingerprint: String,
        input: &CoordinationInput,
    ) -> RuntimeDirective {
        record.attempts.total_attempts += 1;
        record.attempts.committed_transitions += 1;

        if input.violation_handling == ViolationHandling::Terminal {
            match evaluation {
                EvaluationSnapshot::Violated { feedback } => {
                    record.state = GuardExecutionState::Violated;
                    record.mark_completed(unix_ms_to_iso8601(now_unix_ms()));
                    return directive(
                        record,
                        RuntimeDisposition::Abort,
                        feedback.clone(),
                        Some(fingerprint),
                        ReasonCode::GuardDenied,
                    );
                }
                EvaluationSnapshot::Fault { message } => {
                    record.attempts.fault_attempts += 1;
                    record.state = GuardExecutionState::EvaluationFault;
                    record.mark_completed(unix_ms_to_iso8601(now_unix_ms()));
                    return directive(
                        record,
                        RuntimeDisposition::Prevent,
                        Some(message.clone()),
                        Some(fingerprint),
                        ReasonCode::EvaluationFault,
                    );
                }
                EvaluationSnapshot::Satisfied => {}
            }
        }

        // A `RequireDecision` violation is an interactive remediation loop. The
        // user must be able to authorize another attempt (or explicitly deny it)
        // until the guard is satisfied; applying the generic circuit breaker here
        // would silently terminate that contract after a fixed number of dialogs.
        // Automatic remediation remains bounded by the execution policy.
        if input.violation_handling == ViolationHandling::AutomaticRemediation
            && record.attempts.committed_transitions > self.policy.max_committed_transitions
        {
            record.state = GuardExecutionState::Exhausted;
            record.mark_completed(unix_ms_to_iso8601(now_unix_ms()));
            return directive(
                record,
                RuntimeDisposition::Abort,
                Some("Arc guard execution circuit breaker exhausted".into()),
                Some(fingerprint),
                ReasonCode::CircuitBreakerExhausted,
            );
        }

        match evaluation {
            EvaluationSnapshot::Satisfied => {
                record.state = GuardExecutionState::Satisfied;
                record.mark_completed(unix_ms_to_iso8601(now_unix_ms()));
                directive(
                    record,
                    RuntimeDisposition::Proceed,
                    None,
                    Some(fingerprint),
                    ReasonCode::GuardSatisfied,
                )
            }
            EvaluationSnapshot::Fault { message } => {
                record.attempts.fault_attempts += 1;
                record.state = GuardExecutionState::EvaluationFault;
                let disposition = if record.attempts.fault_attempts > self.policy.max_fault_retries
                {
                    record.mark_completed(unix_ms_to_iso8601(now_unix_ms()));
                    RuntimeDisposition::Prevent
                } else {
                    record.mark_requested(unix_ms_to_iso8601(now_unix_ms()));
                    RuntimeDisposition::ContinueForRemediation
                };
                directive(
                    record,
                    disposition,
                    Some(message.clone()),
                    Some(fingerprint),
                    ReasonCode::EvaluationFault,
                )
            }
            EvaluationSnapshot::Violated { feedback } => {
                if input.violation_handling == ViolationHandling::FeedbackOnly {
                    record.state = GuardExecutionState::Violated;
                    record.mark_completed(unix_ms_to_iso8601(now_unix_ms()));
                    return directive(
                        record,
                        RuntimeDisposition::ReportOnly,
                        feedback.clone(),
                        Some(fingerprint),
                        ReasonCode::MessageFeedback,
                    );
                }
                if input.violation_handling == ViolationHandling::RequireDecision {
                    // A failed interactive remediation is not terminal state.
                    // This includes records written by the old one-shot
                    // implementation (`Stalled`/`Exhausted`): neither state is
                    // an explicit user decision to ignore the guard. Re-enter
                    // the decision loop until the guard is satisfied or the
                    // user selects Deny.
                    record.state = GuardExecutionState::AwaitingDecision;
                    record.mark_requested(unix_ms_to_iso8601(now_unix_ms()));
                    let request = DecisionRequest {
                        decision_id: Uuid::new_v4().to_string(),
                        execution_id: record.execution_id.clone(),
                        owner_invocation_id: Some(input.invocation_id.clone()),
                        choices: vec![DecisionChoice::Allow, DecisionChoice::Deny],
                        required_actor: DecisionActor::User,
                        expires_at_unix_ms: now_unix_ms() + 5 * 60 * 1000,
                    };
                    record.pending_decision = Some(request.clone());
                    let mut result = directive(
                        record,
                        RuntimeDisposition::RequestDecision,
                        feedback.clone(),
                        Some(fingerprint),
                        ReasonCode::UserDecisionRequired,
                    );
                    result.decision_request = Some(request);
                    return result;
                }

                let prior_fingerprint = record.last_evidence_fingerprint.as_deref();
                let is_first_violation = matches!(
                    record.state,
                    GuardExecutionState::Dormant | GuardExecutionState::Evaluating
                );
                if is_first_violation
                    && record.attempts.total_attempts <= self.policy.automatic_remediations
                {
                    record.state = GuardExecutionState::RemediationRequested;
                    record.mark_requested(unix_ms_to_iso8601(now_unix_ms()));
                    return directive(
                        record,
                        RuntimeDisposition::ContinueForRemediation,
                        feedback.clone(),
                        Some(fingerprint),
                        ReasonCode::FirstRemediation,
                    );
                }

                if prior_fingerprint == Some(fingerprint.as_str()) {
                    record.attempts.stalled_attempts += 1;
                } else {
                    record.attempts.stalled_attempts = 0;
                }
                record.state = GuardExecutionState::AwaitingDecision;
                record.mark_requested(unix_ms_to_iso8601(now_unix_ms()));
                let request = DecisionRequest {
                    decision_id: Uuid::new_v4().to_string(),
                    execution_id: record.execution_id.clone(),
                    owner_invocation_id: Some(input.invocation_id.clone()),
                    choices: vec![DecisionChoice::Allow, DecisionChoice::Deny],
                    required_actor: DecisionActor::User,
                    expires_at_unix_ms: now_unix_ms() + 5 * 60 * 1000,
                };
                record.pending_decision = Some(request.clone());
                let mut result = directive(
                    record,
                    RuntimeDisposition::RequestDecision,
                    feedback.clone(),
                    Some(fingerprint),
                    ReasonCode::UserDecisionRequired,
                );
                result.decision_request = Some(request);
                result
            }
        }
    }
}

fn directive(
    record: &GuardExecutionRecord,
    disposition: RuntimeDisposition,
    message: Option<String>,
    evidence_fingerprint: Option<String>,
    reason_code: ReasonCode,
) -> RuntimeDirective {
    RuntimeDirective {
        disposition,
        execution_id: record.execution_id.clone(),
        message,
        attempts: record.attempts,
        evidence_fingerprint,
        reason_code,
        decision_request: None,
    }
}

fn now_unix_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::execution::{GuardActivation, ReentryKind};
    use crate::runtime::state_store::InMemoryStateStore;

    fn key() -> GuardExecutionKey {
        GuardExecutionKey {
            workspace_id: "workspace-1".into(),
            session_id: "session-1".into(),
            turn_id: Some("turn-1".into()),
            guard_id: "clean-worktree".into(),
            activation: GuardActivation::SessionStop,
            subject_id: None,
        }
    }

    fn key_for(guard_id: &str) -> GuardExecutionKey {
        let mut key = key();
        key.guard_id = guard_id.into();
        key
    }

    fn input(invocation: &str, evaluation: EvaluationSnapshot) -> CoordinationInput {
        CoordinationInput {
            key: key(),
            invocation_id: invocation.into(),
            signals: ProviderSignals {
                reentry: ReentryKind::Unknown,
                native_invocation_id: Some(invocation.into()),
                native_interaction_id: None,
            },
            evaluation,
            violation_handling: ViolationHandling::AutomaticRemediation,
        }
    }

    fn ask_input(invocation: &str, reentry: ReentryKind) -> CoordinationInput {
        let mut input = input(
            invocation,
            EvaluationSnapshot::Violated {
                feedback: Some("workspace dirty".into()),
            },
        );
        input.signals.reentry = reentry;
        input.violation_handling = ViolationHandling::RequireDecision;
        input
    }

    fn ask_input_for(guard_id: &str, invocation: &str, reentry: ReentryKind) -> CoordinationInput {
        let mut input = ask_input(invocation, reentry);
        input.key = key_for(guard_id);
        input
    }

    #[test]
    fn ask_violation_requests_a_decision_on_the_first_invocation() {
        let coordinator = GuardExecutionCoordinator::new(Arc::new(InMemoryStateStore::default()));

        let result = coordinator
            .coordinate(ask_input("ask-owner", ReentryKind::FirstInvocation))
            .unwrap();

        assert_eq!(result.disposition, RuntimeDisposition::RequestDecision);
        let request = result.decision_request.unwrap();
        assert_eq!(request.owner_invocation_id.as_deref(), Some("ask-owner"));
        assert_eq!(
            request.choices,
            vec![DecisionChoice::Allow, DecisionChoice::Deny]
        );
    }

    #[test]
    fn aggregate_decision_resolves_all_pending_guards_atomically_and_replays_idempotently() {
        let store = Arc::new(InMemoryStateStore::default());
        let coordinator = GuardExecutionCoordinator::new(store.clone());
        let first_key = key_for("ask-a");
        let second_key = key_for("ask-b");
        let first = coordinator
            .coordinate(ask_input_for(
                "ask-a",
                "aggregate-owner",
                ReentryKind::FirstInvocation,
            ))
            .unwrap();
        let second = coordinator
            .coordinate(ask_input_for(
                "ask-b",
                "aggregate-owner",
                ReentryKind::FirstInvocation,
            ))
            .unwrap();
        let first_request = first.decision_request.clone().unwrap();
        assert!(second.decision_request.is_some());
        let receipt = DecisionReceipt {
            decision_id: first_request.decision_id.clone(),
            execution_id: first_request.execution_id.clone(),
            selected_choice: DecisionChoice::Allow,
            actor: DecisionActor::User,
            provider: "codex".into(),
            received_at_unix_ms: now_unix_ms(),
            integrity: super::super::DecisionIntegrity {
                transport: "arc_embedded_ui".into(),
                native_interaction_id: None,
            },
        };

        let applied = coordinator
            .apply_aggregate_decision(
                &[first_key.clone(), second_key.clone()],
                "arc:lifecycle:aggregate-1",
                "aggregate-decision-invocation",
                "aggregate-owner",
                &receipt,
            )
            .unwrap();
        assert_eq!(applied.len(), 2);
        assert!(
            applied.iter().all(
                |directive| directive.disposition == RuntimeDisposition::ContinueForRemediation
            )
        );
        for key in [&first_key, &second_key] {
            let record = store.load(key).unwrap().unwrap();
            assert_eq!(record.state, GuardExecutionState::RemediationInProgress);
            assert!(record.pending_decision.is_none());
            assert!(
                record
                    .processed_invocations
                    .contains_key("aggregate-decision-invocation")
            );
        }

        let replay = coordinator
            .apply_aggregate_decision(
                &[first_key.clone(), second_key.clone()],
                "arc:lifecycle:aggregate-1",
                "aggregate-decision-invocation",
                "aggregate-owner",
                &receipt,
            )
            .unwrap();
        assert_eq!(replay, applied);

        let contradictory = DecisionReceipt {
            selected_choice: DecisionChoice::Deny,
            ..receipt
        };
        assert!(
            coordinator
                .apply_aggregate_decision(
                    &[first_key, second_key],
                    "arc:lifecycle:aggregate-1",
                    "aggregate-decision-invocation",
                    "aggregate-owner",
                    &contradictory,
                )
                .is_err()
        );
    }

    #[test]
    fn concurrent_ask_reuses_the_pending_decision_without_transferring_ownership() {
        let coordinator = GuardExecutionCoordinator::new(Arc::new(InMemoryStateStore::default()));
        let first = coordinator
            .coordinate(ask_input("ask-owner", ReentryKind::FirstInvocation))
            .unwrap();
        let first_request = first.decision_request.unwrap();

        let concurrent = coordinator
            .coordinate(ask_input("ask-follower", ReentryKind::RetriedByProvider))
            .unwrap();
        let concurrent_request = concurrent.decision_request.unwrap();

        assert_eq!(concurrent.disposition, RuntimeDisposition::RequestDecision);
        assert_eq!(concurrent_request.decision_id, first_request.decision_id);
        assert_eq!(
            concurrent_request.owner_invocation_id,
            first_request.owner_invocation_id
        );
    }

    #[test]
    fn legacy_stalled_interactive_execution_can_request_a_new_decision() {
        let store = Arc::new(InMemoryStateStore::default());
        let mut record = GuardExecutionRecord::new("legacy-execution".into(), key(), now_unix_ms());
        record.state = GuardExecutionState::Stalled;
        record.revision = 1;
        store.compare_and_swap(None, &record).unwrap();

        let coordinator = GuardExecutionCoordinator::new(store.clone());
        let directive = coordinator
            .coordinate(ask_input("legacy-reentry", ReentryKind::ContinuedByHook))
            .unwrap();

        assert_eq!(directive.disposition, RuntimeDisposition::RequestDecision);
        assert_eq!(directive.reason_code, ReasonCode::UserDecisionRequired);
        assert_eq!(
            store.load(&key()).unwrap().unwrap().state,
            GuardExecutionState::AwaitingDecision
        );
    }

    #[test]
    fn unresolved_ask_releases_ownership_and_can_be_requested_again() {
        let store = Arc::new(InMemoryStateStore::default());
        let coordinator = GuardExecutionCoordinator::new(store);
        let pending = coordinator
            .coordinate(ask_input("ask-owner", ReentryKind::FirstInvocation))
            .unwrap()
            .decision_request
            .unwrap();

        coordinator
            .abandon_decision(
                &key(),
                pending.owner_invocation_id.as_deref().unwrap_or(""),
                &pending.decision_id,
                &pending.execution_id,
            )
            .unwrap();

        let retried = coordinator
            .coordinate(ask_input("ask-retry", ReentryKind::ContinuedByHook))
            .unwrap();
        let retry_request = retried.decision_request.unwrap();
        assert_eq!(retried.disposition, RuntimeDisposition::RequestDecision);
        assert_ne!(retry_request.decision_id, pending.decision_id);
        assert_eq!(
            retry_request.owner_invocation_id.as_deref(),
            Some("ask-retry")
        );
    }

    #[test]
    fn first_violation_remediates_then_unchanged_escalates() {
        let coordinator = GuardExecutionCoordinator::new(Arc::new(InMemoryStateStore::default()));
        let first = coordinator
            .coordinate(input(
                "invocation-1",
                EvaluationSnapshot::Violated {
                    feedback: Some("workspace dirty".into()),
                },
            ))
            .unwrap();
        assert_eq!(
            first.disposition,
            RuntimeDisposition::ContinueForRemediation
        );

        let second = coordinator
            .coordinate(input(
                "invocation-2",
                EvaluationSnapshot::Violated {
                    feedback: Some("workspace dirty".into()),
                },
            ))
            .unwrap();
        assert_eq!(second.disposition, RuntimeDisposition::RequestDecision);
        assert_eq!(second.execution_id, first.execution_id);
        assert_eq!(second.attempts.stalled_attempts, 1);
        assert_eq!(
            second.decision_request.unwrap().choices,
            vec![DecisionChoice::Allow, DecisionChoice::Deny]
        );
    }

    #[test]
    fn changed_violation_evidence_is_not_counted_as_stalled() {
        let coordinator = GuardExecutionCoordinator::new(Arc::new(InMemoryStateStore::default()));
        coordinator
            .coordinate(input(
                "invocation-1",
                EvaluationSnapshot::Violated {
                    feedback: Some("workspace dirty".into()),
                },
            ))
            .unwrap();

        let changed = coordinator
            .coordinate(input(
                "invocation-2",
                EvaluationSnapshot::Violated {
                    feedback: Some("tests pending".into()),
                },
            ))
            .unwrap();

        assert_eq!(changed.disposition, RuntimeDisposition::RequestDecision);
        assert_eq!(changed.attempts.stalled_attempts, 0);
    }

    #[test]
    fn duplicate_invocation_is_idempotent() {
        let coordinator = GuardExecutionCoordinator::new(Arc::new(InMemoryStateStore::default()));
        let first = coordinator
            .coordinate(input(
                "same-invocation",
                EvaluationSnapshot::Violated { feedback: None },
            ))
            .unwrap();
        let duplicate = coordinator
            .coordinate(input(
                "same-invocation",
                EvaluationSnapshot::Violated { feedback: None },
            ))
            .unwrap();
        assert_eq!(duplicate, first);
        assert_eq!(duplicate.attempts.total_attempts, 1);
    }

    #[test]
    fn remediation_followed_by_satisfaction_proceeds() {
        let coordinator = GuardExecutionCoordinator::new(Arc::new(InMemoryStateStore::default()));
        coordinator
            .coordinate(input(
                "invocation-1",
                EvaluationSnapshot::Violated { feedback: None },
            ))
            .unwrap();
        let result = coordinator
            .coordinate(input("invocation-2", EvaluationSnapshot::Satisfied))
            .unwrap();
        assert_eq!(result.disposition, RuntimeDisposition::Proceed);
        assert_eq!(result.reason_code, ReasonCode::GuardSatisfied);
    }

    #[test]
    fn preventive_fault_does_not_retry() {
        let coordinator = GuardExecutionCoordinator::new(Arc::new(InMemoryStateStore::default()));
        let result = coordinator
            .coordinate(input(
                "invocation-1",
                EvaluationSnapshot::Fault {
                    message: "probe unavailable".into(),
                },
            ))
            .unwrap();
        assert_eq!(result.disposition, RuntimeDisposition::Prevent);
        assert_eq!(result.reason_code, ReasonCode::EvaluationFault);
    }

    #[test]
    fn terminal_deny_does_not_enter_remediation() {
        let store = Arc::new(InMemoryStateStore::default());
        let coordinator = GuardExecutionCoordinator::new(store.clone());
        let mut terminal = input(
            "terminal-deny",
            EvaluationSnapshot::Violated {
                feedback: Some("lifecycle denied".into()),
            },
        );
        terminal.violation_handling = ViolationHandling::Terminal;

        let result = coordinator.coordinate(terminal).unwrap();

        assert_eq!(result.disposition, RuntimeDisposition::Abort);
        assert_eq!(result.reason_code, ReasonCode::GuardDenied);
        assert_eq!(result.message.as_deref(), Some("lifecycle denied"));
        let record = store.load(&key()).unwrap().unwrap();
        assert_eq!(record.state, GuardExecutionState::Violated);
        assert!(record.completed_at.is_some());
        assert!(record.pending_decision.is_none());
    }

    #[test]
    fn terminal_fault_does_not_enter_remediation() {
        let store = Arc::new(InMemoryStateStore::default());
        let coordinator = GuardExecutionCoordinator::new(store.clone());
        let mut terminal = input(
            "terminal-fault",
            EvaluationSnapshot::Fault {
                message: "lifecycle evaluation failed".into(),
            },
        );
        terminal.violation_handling = ViolationHandling::Terminal;

        let result = coordinator.coordinate(terminal).unwrap();

        assert_eq!(result.disposition, RuntimeDisposition::Prevent);
        assert_eq!(result.reason_code, ReasonCode::EvaluationFault);
        assert_eq!(
            result.message.as_deref(),
            Some("lifecycle evaluation failed")
        );
        let record = store.load(&key()).unwrap().unwrap();
        assert_eq!(record.state, GuardExecutionState::EvaluationFault);
        assert!(record.completed_at.is_some());
        assert!(record.pending_decision.is_none());
    }

    #[test]
    fn terminal_transition_clears_existing_pending_decision() {
        let store = Arc::new(InMemoryStateStore::default());
        let coordinator = GuardExecutionCoordinator::new(store.clone());
        let pending = coordinator
            .coordinate(ask_input("ask-owner", ReentryKind::FirstInvocation))
            .unwrap();
        assert_eq!(pending.disposition, RuntimeDisposition::RequestDecision);
        assert!(
            store
                .load(&key())
                .unwrap()
                .unwrap()
                .pending_decision
                .is_some()
        );

        let mut terminal = ask_input("ask-owner", ReentryKind::ContinuedByHook);
        terminal.violation_handling = ViolationHandling::Terminal;
        let result = coordinator.coordinate(terminal).unwrap();

        assert_eq!(result.disposition, RuntimeDisposition::Abort);
        let record = store.load(&key()).unwrap().unwrap();
        assert_eq!(record.state, GuardExecutionState::Violated);
        assert!(record.pending_decision.is_none());
        assert!(record.completed_at.is_some());
    }

    #[test]
    fn feedback_only_violation_is_report_only_and_completed() {
        let store = Arc::new(InMemoryStateStore::default());
        let coordinator = GuardExecutionCoordinator::new(store.clone());
        let mut input = input(
            "message-invocation",
            EvaluationSnapshot::Violated {
                feedback: Some("message feedback".into()),
            },
        );
        input.violation_handling = ViolationHandling::FeedbackOnly;

        let result = coordinator.coordinate(input).unwrap();

        assert_eq!(result.disposition, RuntimeDisposition::ReportOnly);
        assert_eq!(result.reason_code, ReasonCode::MessageFeedback);
        let record = store.load(&key()).unwrap().unwrap();
        assert_eq!(record.state, GuardExecutionState::Violated);
        assert!(record.completed_at.is_some());
        assert!(record.pending_decision.is_none());
    }

    #[test]
    fn reentry_without_prior_state_fails_closed() {
        let coordinator = GuardExecutionCoordinator::new(Arc::new(InMemoryStateStore::default()));
        let mut reentry = input(
            "continued-without-state",
            EvaluationSnapshot::Violated {
                feedback: Some("dirty".into()),
            },
        );
        reentry.signals.reentry = ReentryKind::ContinuedByHook;
        let result = coordinator.coordinate(reentry).unwrap();
        assert_eq!(result.disposition, RuntimeDisposition::Prevent);
        assert_eq!(result.reason_code, ReasonCode::EvaluationFault);
        assert!(result.message.unwrap().contains("no prior execution state"));
    }
}
