use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Mutex;

use anyhow::Result;
use uuid::Uuid;

use crate::runtime::decision::{DecisionPresentationClaimStore, InteractiveDecisionOutcome};
use crate::runtime::execution::{DecisionReceipt, GuardExecutionKey, GuardExecutionRecord};
use crate::runtime::guard_evaluation::ExactOperationAuthorization;

use super::{
    AggregateGuardResolutionApplyRequest, AggregateResolutionApplyOutcome,
    AggregateResolutionApplyRequest, ExactAuthorizationContext, GuardExecutionStateStore,
    WriteOutcome,
};

#[derive(Clone)]
struct StoredExactAuthorization {
    guard_id: String,
    operation_fingerprint: String,
    event_id: String,
    tool: String,
    normalized_arguments_fingerprint: String,
    context: Option<ExactAuthorizationContext>,
    expires_at_unix_ms: i64,
    uses_remaining: u32,
}

#[derive(Clone)]
struct StoredAggregateResolution {
    request: AggregateGuardResolutionApplyRequest,
    idempotency_fingerprint: String,
}

#[derive(Default)]
pub struct InMemoryStateStore {
    state_transaction: Mutex<()>,
    executions: Mutex<BTreeMap<String, GuardExecutionRecord>>,
    workspaces: Mutex<BTreeMap<String, String>>,
    exact_authorizations: Mutex<Vec<StoredExactAuthorization>>,
    decision_receipts: Mutex<BTreeMap<String, DecisionReceipt>>,
    aggregate_resolutions: Mutex<BTreeMap<String, StoredAggregateResolution>>,
    presentation_claims: Mutex<BTreeMap<String, i64>>,
}

impl InMemoryStateStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record_uncorrelated_exact_authorization(
        &self,
        auth: &ExactOperationAuthorization,
        _decision_id: Option<&str>,
        expires_at_unix_ms: i64,
        uses: u32,
    ) -> Result<()> {
        let _state_transaction = self.state_transaction.lock().unwrap();
        let mut auths = self.exact_authorizations.lock().unwrap();
        auths.push(StoredExactAuthorization {
            guard_id: auth.guard_id.clone(),
            operation_fingerprint: auth.operation_fingerprint.clone(),
            event_id: auth.event_id.clone(),
            tool: auth.tool.clone(),
            normalized_arguments_fingerprint: auth.normalized_arguments_fingerprint.clone(),
            context: None,
            expires_at_unix_ms,
            uses_remaining: uses,
        });
        Ok(())
    }
}

impl DecisionPresentationClaimStore for InMemoryStateStore {
    fn claim_presentation(&self, invocation_id: &str, decision_id: Option<&str>) -> Result<bool> {
        let _state_transaction = self.state_transaction.lock().unwrap();
        let mut claims = self.presentation_claims.lock().unwrap();
        let inv_key = format!("invocation:{invocation_id}");
        if claims.contains_key(&inv_key) {
            return Ok(false);
        }
        if let Some(dec_id) = decision_id {
            let dec_key = format!("decision:{dec_id}");
            if claims.contains_key(&dec_key) {
                return Ok(false);
            }
            claims.insert(dec_key, 0);
        }
        claims.insert(inv_key, 0);
        Ok(true)
    }
}

impl GuardExecutionStateStore for InMemoryStateStore {
    fn load(&self, key: &GuardExecutionKey) -> Result<Option<GuardExecutionRecord>> {
        let _state_transaction = self.state_transaction.lock().unwrap();
        Ok(self
            .executions
            .lock()
            .unwrap()
            .get(&key.storage_key())
            .cloned())
    }

    fn compare_and_swap(
        &self,
        expected_revision: Option<u64>,
        record: &GuardExecutionRecord,
    ) -> Result<WriteOutcome> {
        let _state_transaction = self.state_transaction.lock().unwrap();
        let mut executions = self.executions.lock().unwrap();
        let storage_key = record.key.storage_key();
        let actual = executions.get(&storage_key).map(|value| value.revision);
        if actual != expected_revision {
            return Ok(WriteOutcome::Conflict);
        }
        executions.insert(storage_key, record.clone());
        Ok(WriteOutcome::Written)
    }

    fn resolve_workspace_id(&self, canonical_root: &Path) -> Result<String> {
        let _state_transaction = self.state_transaction.lock().unwrap();
        let key = canonical_root.to_string_lossy().into_owned();
        let mut workspaces = self.workspaces.lock().unwrap();
        Ok(workspaces
            .entry(key)
            .or_insert_with(|| Uuid::new_v4().to_string())
            .clone())
    }

    fn purge_expired(&self, older_than_unix_ms: i64) -> Result<usize> {
        let _state_transaction = self.state_transaction.lock().unwrap();
        let mut executions = self.executions.lock().unwrap();
        let before = executions.len();
        executions.retain(|_, record| record.updated_at_unix_ms >= older_than_unix_ms);
        let removed_exec = before - executions.len();

        let mut auths = self.exact_authorizations.lock().unwrap();
        auths.retain(|auth| {
            auth.expires_at_unix_ms >= older_than_unix_ms && auth.uses_remaining > 0
        });

        Ok(removed_exec)
    }

    fn record_exact_authorization(
        &self,
        auth: &ExactOperationAuthorization,
        context: &ExactAuthorizationContext,
        _decision_id: Option<&str>,
        expires_at_unix_ms: i64,
        uses: u32,
    ) -> Result<()> {
        let _state_transaction = self.state_transaction.lock().unwrap();
        context.validate_for(std::slice::from_ref(auth))?;
        let mut auths = self.exact_authorizations.lock().unwrap();
        auths.push(StoredExactAuthorization {
            guard_id: auth.guard_id.clone(),
            operation_fingerprint: auth.operation_fingerprint.clone(),
            event_id: auth.event_id.clone(),
            tool: auth.tool.clone(),
            normalized_arguments_fingerprint: auth.normalized_arguments_fingerprint.clone(),
            context: Some(context.clone()),
            expires_at_unix_ms,
            uses_remaining: uses,
        });
        Ok(())
    }

    fn record_exact_authorizations_bundle(
        &self,
        auth_items: &[ExactOperationAuthorization],
        context: &ExactAuthorizationContext,
        _decision_id: Option<&str>,
        expires_at_unix_ms: i64,
        uses: u32,
    ) -> Result<()> {
        let _state_transaction = self.state_transaction.lock().unwrap();
        context.validate_for(auth_items)?;
        let mut auths = self.exact_authorizations.lock().unwrap();
        for auth in auth_items {
            auths.push(StoredExactAuthorization {
                guard_id: auth.guard_id.clone(),
                operation_fingerprint: auth.operation_fingerprint.clone(),
                event_id: auth.event_id.clone(),
                tool: auth.tool.clone(),
                normalized_arguments_fingerprint: auth.normalized_arguments_fingerprint.clone(),
                context: Some(context.clone()),
                expires_at_unix_ms,
                uses_remaining: uses,
            });
        }
        Ok(())
    }

    fn consume_exact_authorization(
        &self,
        requested_auth: &ExactOperationAuthorization,
        context: &ExactAuthorizationContext,
        now_unix_ms: i64,
    ) -> Result<bool> {
        let _state_transaction = self.state_transaction.lock().unwrap();
        let mut auths = self.exact_authorizations.lock().unwrap();
        for stored in auths.iter_mut() {
            if stored.guard_id == requested_auth.guard_id
                && stored.operation_fingerprint == requested_auth.operation_fingerprint
                && stored.event_id == requested_auth.event_id
                && stored.tool == requested_auth.tool
                && stored.normalized_arguments_fingerprint
                    == requested_auth.normalized_arguments_fingerprint
                && stored.context.as_ref() == Some(context)
                && stored.expires_at_unix_ms > now_unix_ms
                && stored.uses_remaining > 0
            {
                stored.uses_remaining -= 1;
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn has_valid_exact_authorization(
        &self,
        requested_auth: &ExactOperationAuthorization,
        context: &ExactAuthorizationContext,
        now_unix_ms: i64,
    ) -> Result<bool> {
        let _state_transaction = self.state_transaction.lock().unwrap();
        let auths = self.exact_authorizations.lock().unwrap();
        Ok(auths.iter().any(|stored| {
            stored.guard_id == requested_auth.guard_id
                && stored.operation_fingerprint == requested_auth.operation_fingerprint
                && stored.event_id == requested_auth.event_id
                && stored.tool == requested_auth.tool
                && stored.normalized_arguments_fingerprint
                    == requested_auth.normalized_arguments_fingerprint
                && stored.context.as_ref() == Some(context)
                && stored.expires_at_unix_ms > now_unix_ms
                && stored.uses_remaining > 0
        }))
    }

    fn record_decision_receipt(&self, receipt: &DecisionReceipt) -> Result<()> {
        let _state_transaction = self.state_transaction.lock().unwrap();
        let mut receipts = self.decision_receipts.lock().unwrap();
        if let Some(existing) = receipts.get(&receipt.decision_id) {
            if existing != receipt {
                anyhow::bail!(
                    "conflicting decision receipt for decision '{}'",
                    receipt.decision_id
                );
            }
            return Ok(());
        }
        receipts.insert(receipt.decision_id.clone(), receipt.clone());
        Ok(())
    }

    fn load_decision_receipt(&self, decision_id: &str) -> Result<Option<DecisionReceipt>> {
        let _state_transaction = self.state_transaction.lock().unwrap();
        let receipts = self.decision_receipts.lock().unwrap();
        Ok(receipts.get(decision_id).cloned())
    }

    fn apply_aggregate_resolution(
        &self,
        request: &AggregateResolutionApplyRequest,
    ) -> Result<AggregateResolutionApplyOutcome> {
        self.apply_aggregate_resolution_with_targets(request, &[])
    }

    fn apply_aggregate_guard_resolution(
        &self,
        request: &AggregateGuardResolutionApplyRequest,
    ) -> Result<AggregateResolutionApplyOutcome> {
        self.apply_aggregate_resolution_with_targets(&request.resolution, &request.targets)
    }

    fn load_aggregate_resolution_by_decision(
        &self,
        decision_id: &str,
    ) -> Result<Option<AggregateGuardResolutionApplyRequest>> {
        let _state_transaction = self.state_transaction.lock().unwrap();
        let resolutions = self.aggregate_resolutions.lock().unwrap();
        Ok(resolutions
            .values()
            .find(|stored| {
                stored.request.resolution.decision_id.as_deref() == Some(decision_id)
                    || stored.request.resolution.resolution_id == decision_id
            })
            .map(|stored| stored.request.clone()))
    }
}

impl InMemoryStateStore {
    fn apply_aggregate_resolution_with_targets(
        &self,
        request: &AggregateResolutionApplyRequest,
        targets: &[super::AggregateGuardResolutionTarget],
    ) -> Result<AggregateResolutionApplyOutcome> {
        let _state_transaction = self.state_transaction.lock().unwrap();
        request.validate(targets.len())?;
        let candidate = AggregateGuardResolutionApplyRequest {
            resolution: request.clone(),
            targets: targets.to_vec(),
        };
        let idempotency_fingerprint = candidate.idempotency_fingerprint()?;
        let mut receipts = self.decision_receipts.lock().unwrap();
        if let Some(receipt) = &request.decision_receipt
            && let Some(existing) = receipts.get(&receipt.decision_id)
            && existing != receipt
        {
            anyhow::bail!(
                "conflicting decision receipt for decision '{}'",
                receipt.decision_id
            );
        }
        let mut resolutions = self.aggregate_resolutions.lock().unwrap();
        let existing = resolutions.values().find(|stored| {
            stored.request.resolution.resolution_id == request.resolution_id
                || stored.request.resolution.decision_id == request.decision_id
        });
        if let Some(existing) = existing {
            if existing.request.resolution.outcome == request.outcome
                && existing.idempotency_fingerprint == idempotency_fingerprint
            {
                return Ok(AggregateResolutionApplyOutcome::IdempotentReplay);
            } else {
                return Ok(AggregateResolutionApplyOutcome::Conflict);
            }
        }
        candidate.validate_target_scope()?;

        {
            let mut executions = self.executions.lock().unwrap();
            let mut seen = std::collections::BTreeSet::new();
            for target in targets {
                if !seen.insert(target.key.storage_key()) {
                    anyhow::bail!(
                        "aggregate resolution contains duplicate guard execution targets"
                    );
                }
                if target.record.key != target.key
                    || target.record.revision != target.expected_revision + 1
                {
                    anyhow::bail!("aggregate resolution target record is inconsistent");
                }
                let Some(current) = executions.get(&target.key.storage_key()) else {
                    anyhow::bail!("aggregate resolution refers to an unknown guard execution");
                };
                if current.revision != target.expected_revision
                    || current.key != target.key
                    || current.execution_id != target.expected_execution_id
                    || current
                        .pending_decision
                        .as_ref()
                        .map(|request| request.decision_id.as_str())
                        != Some(target.expected_decision_id.as_str())
                    || current
                        .pending_decision
                        .as_ref()
                        .map(|request| request.execution_id.as_str())
                        != Some(target.expected_execution_id.as_str())
                    || current
                        .pending_decision
                        .as_ref()
                        .and_then(|request| request.owner_invocation_id.as_deref())
                        != Some(target.expected_owner_invocation_id.as_str())
                {
                    anyhow::bail!("aggregate resolution target changed concurrently");
                }
            }
            for target in targets {
                executions.insert(target.key.storage_key(), target.record.clone());
            }
        }

        resolutions.insert(
            request.resolution_id.clone(),
            StoredAggregateResolution {
                request: candidate,
                idempotency_fingerprint,
            },
        );

        if request.outcome == InteractiveDecisionOutcome::Allow {
            let mut auths = self.exact_authorizations.lock().unwrap();
            for auth in &request.authorizations {
                auths.push(StoredExactAuthorization {
                    guard_id: auth.guard_id.clone(),
                    operation_fingerprint: auth.operation_fingerprint.clone(),
                    event_id: auth.event_id.clone(),
                    tool: auth.tool.clone(),
                    normalized_arguments_fingerprint: auth.normalized_arguments_fingerprint.clone(),
                    context: request.authorization_context.clone(),
                    expires_at_unix_ms: request.expires_at_unix_ms,
                    uses_remaining: 0, // Consumed immediately for this pending invocation!
                });
            }
        }

        if let Some(receipt) = &request.decision_receipt
            && !receipts.contains_key(&receipt.decision_id)
        {
            receipts.insert(receipt.decision_id.clone(), receipt.clone());
        }

        Ok(AggregateResolutionApplyOutcome::Applied)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::execution::GuardActivation;
    use crate::runtime::execution::{
        DecisionActor, DecisionChoice, DecisionRequest, GuardExecutionState,
    };
    use crate::runtime::state_store::AggregateGuardResolutionTarget;

    fn authorization_context(
        auths: &[ExactOperationAuthorization],
        session_id: &str,
        invocation_id: &str,
    ) -> ExactAuthorizationContext {
        ExactAuthorizationContext::for_authorizations(
            &auths[0].event_id,
            &auths[0].tool,
            "workspace-1",
            "codex",
            session_id,
            invocation_id,
            "policy-1",
            "evidence-1",
            auths,
        )
        .unwrap()
    }

    fn target_for(
        key: GuardExecutionKey,
        decision_id: &str,
    ) -> (GuardExecutionRecord, AggregateGuardResolutionTarget) {
        let mut record = GuardExecutionRecord::new("execution-1".into(), key.clone(), 0);
        record.revision = 1;
        record.state = GuardExecutionState::AwaitingAuthorization;
        record.pending_decision = Some(DecisionRequest {
            decision_id: decision_id.into(),
            execution_id: record.execution_id.clone(),
            owner_invocation_id: Some("inv-mem-1".into()),
            choices: vec![DecisionChoice::Allow, DecisionChoice::Deny],
            required_actor: DecisionActor::User,
            expires_at_unix_ms: 5000,
        });
        let mut resolved = record.clone();
        resolved.revision = 2;
        resolved.pending_decision = None;
        (
            record,
            AggregateGuardResolutionTarget {
                key,
                expected_revision: 1,
                expected_decision_id: decision_id.into(),
                expected_execution_id: "execution-1".into(),
                expected_owner_invocation_id: "inv-mem-1".into(),
                record: resolved,
            },
        )
    }

    #[test]
    fn memory_uncorrelated_legacy_records_denied_authority() {
        let store = InMemoryStateStore::new();
        let auth = ExactOperationAuthorization {
            guard_id: "guard-mem-bash".into(),
            operation_fingerprint: "op-fp-mem".into(),
            event_id: "ev-1".into(),
            tool: "Bash".into(),
            normalized_arguments_fingerprint: "args-1".into(),
        };

        store
            .record_uncorrelated_exact_authorization(&auth, None, 2000, 1)
            .unwrap();
        let context = authorization_context(std::slice::from_ref(&auth), "session-1", "inv-1");

        // Authority must be denied
        assert!(
            !store
                .has_valid_exact_authorization(&auth, &context, 1000)
                .unwrap()
        );
        assert!(
            !store
                .consume_exact_authorization(&auth, &context, 1000)
                .unwrap()
        );

        // Verify history row is preserved in memory
        let count = store.exact_authorizations.lock().unwrap().len();
        assert_eq!(count, 1);
    }

    #[test]
    fn memory_apply_aggregate_resolution_atomic_idempotent_conflict_and_no_future_grants() {
        let store = InMemoryStateStore::new();
        let auth = ExactOperationAuthorization {
            guard_id: "guard-mem-write".into(),
            operation_fingerprint: "op-fp-mem-write".into(),
            event_id: "ev-1".into(),
            tool: "Write".into(),
            normalized_arguments_fingerprint: "args-1".into(),
        };

        let req = AggregateResolutionApplyRequest {
            resolution_id: "res-mem-1".into(),
            decision_id: Some("dec-mem-1".into()),
            invocation_id: "inv-mem-1".into(),
            session_id: "sess-mem-1".into(),
            workspace_id: Some("workspace-1".into()),
            provider: "codex".into(),
            outcome: crate::runtime::decision::InteractiveDecisionOutcome::Allow,
            authorizations: vec![auth.clone()],
            now_unix_ms: 1000,
            expires_at_unix_ms: 5000,
            decision_receipt: None,
            authorization_context: Some(authorization_context(
                std::slice::from_ref(&auth),
                "sess-mem-1",
                "inv-mem-1",
            )),
        };

        let key = GuardExecutionKey {
            workspace_id: "workspace-1".into(),
            session_id: "sess-mem-1".into(),
            turn_id: Some("turn-1".into()),
            guard_id: auth.guard_id.clone(),
            activation: GuardActivation::ToolCall,
            subject_id: Some(auth.event_id.clone()),
        };
        let (pending, target) = target_for(key, "dec-mem-1");
        store.compare_and_swap(None, &pending).unwrap();

        // 1. First apply returns Applied
        let outcome = store
            .apply_aggregate_guard_resolution(&AggregateGuardResolutionApplyRequest {
                resolution: req.clone(),
                targets: vec![target.clone()],
            })
            .unwrap();
        assert_eq!(outcome, AggregateResolutionApplyOutcome::Applied);

        // 2. F-04 / §5.1: No future grants. Authorization is persisted with uses_remaining = 0
        assert!(
            !store
                .has_valid_exact_authorization(
                    &auth,
                    req.authorization_context.as_ref().unwrap(),
                    1500
                )
                .unwrap(),
            "Interactive Allow must NOT authorize future operations (uses_remaining = 0)"
        );

        // Verify row in memory has uses_remaining = 0
        let auths = store.exact_authorizations.lock().unwrap();
        let stored = auths
            .iter()
            .find(|a| a.guard_id == "guard-mem-write")
            .unwrap();
        assert_eq!(stored.uses_remaining, 0);
        drop(auths);

        // 3. Idempotent replay
        let replay = store
            .apply_aggregate_guard_resolution(&AggregateGuardResolutionApplyRequest {
                resolution: req.clone(),
                targets: vec![target],
            })
            .unwrap();
        assert_eq!(replay, AggregateResolutionApplyOutcome::IdempotentReplay);

        // 4. Contradictory decision returns Conflict
        let mut contradictory_req = req.clone();
        contradictory_req.outcome = crate::runtime::decision::InteractiveDecisionOutcome::Deny;
        let conflict = store
            .apply_aggregate_guard_resolution(&AggregateGuardResolutionApplyRequest {
                resolution: contradictory_req,
                targets: vec![
                    target_for(
                        GuardExecutionKey {
                            workspace_id: "workspace-1".into(),
                            session_id: "sess-mem-1".into(),
                            turn_id: Some("turn-1".into()),
                            guard_id: auth.guard_id.clone(),
                            activation: GuardActivation::ToolCall,
                            subject_id: Some(auth.event_id.clone()),
                        },
                        "dec-mem-1",
                    )
                    .1,
                ],
            })
            .unwrap();
        assert_eq!(conflict, AggregateResolutionApplyOutcome::Conflict);
    }

    #[test]
    fn memory_apply_aggregate_resolution_expiration_rejection() {
        let store = InMemoryStateStore::new();
        let req = AggregateResolutionApplyRequest {
            resolution_id: "res-exp".into(),
            decision_id: Some("dec-exp".into()),
            invocation_id: "inv-1".into(),
            session_id: "sess-1".into(),
            workspace_id: Some("workspace-1".into()),
            provider: "codex".into(),
            outcome: crate::runtime::decision::InteractiveDecisionOutcome::Allow,
            authorizations: vec![],
            now_unix_ms: 5000,
            expires_at_unix_ms: 4000, // Expired!
            decision_receipt: None,
            authorization_context: None,
        };
        let key = GuardExecutionKey {
            workspace_id: "workspace-1".into(),
            session_id: "sess-1".into(),
            turn_id: Some("turn-1".into()),
            guard_id: "guard-expired".into(),
            activation: GuardActivation::ToolCall,
            subject_id: Some("event-expired".into()),
        };
        let (pending, target) = target_for(key, "dec-exp");
        store.compare_and_swap(None, &pending).unwrap();

        let err = store
            .apply_aggregate_guard_resolution(&AggregateGuardResolutionApplyRequest {
                resolution: req,
                targets: vec![target],
            })
            .unwrap_err();
        assert!(err.to_string().contains("expired"));
    }
}
