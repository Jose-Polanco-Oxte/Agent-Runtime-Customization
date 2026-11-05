#[cfg(any(test, feature = "test-support"))]
mod memory;
mod path;
mod sqlite;

use std::path::Path;

use anyhow::{Result, bail};
use sha2::{Digest, Sha256};

use crate::runtime::decision::InteractiveDecisionOutcome;
use crate::runtime::execution::{DecisionReceipt, GuardExecutionKey, GuardExecutionRecord};
use crate::runtime::guard_evaluation::ExactOperationAuthorization;

use serde::{Deserialize, Serialize};

#[cfg(any(test, feature = "test-support"))]
pub use memory::InMemoryStateStore;
pub use path::{canonical_workspace_root, default_state_database_path};
pub use sqlite::{IncompatibleStateSchema, SqliteStateStore, TrustedIrSnapshot};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WriteOutcome {
    Written,
    Conflict,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AggregateResolutionApplyRequest {
    pub resolution_id: String,
    pub decision_id: Option<String>,
    pub invocation_id: String,
    pub session_id: String,
    pub workspace_id: Option<String>,
    #[serde(default)]
    pub provider: String,
    pub outcome: InteractiveDecisionOutcome,
    pub authorizations: Vec<ExactOperationAuthorization>,
    pub now_unix_ms: i64,
    pub expires_at_unix_ms: i64,
    pub decision_receipt: Option<DecisionReceipt>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization_context: Option<ExactAuthorizationContext>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExactAuthorizationContext {
    pub origin: String,
    pub destination: String,
    pub workspace_id: String,
    pub provider: String,
    pub session_id: String,
    pub invocation_id: String,
    pub guard_set_fingerprint: String,
    pub policy_fingerprint: String,
    pub evidence_fingerprint: String,
}

impl ExactAuthorizationContext {
    #[allow(clippy::too_many_arguments)]
    pub fn for_authorizations(
        origin: impl Into<String>,
        destination: impl Into<String>,
        workspace_id: impl Into<String>,
        provider: impl Into<String>,
        session_id: impl Into<String>,
        invocation_id: impl Into<String>,
        policy_fingerprint: impl Into<String>,
        evidence_fingerprint: impl Into<String>,
        authorizations: &[ExactOperationAuthorization],
    ) -> Result<Self> {
        let context = Self {
            origin: origin.into(),
            destination: destination.into(),
            workspace_id: workspace_id.into(),
            provider: provider.into(),
            session_id: session_id.into(),
            invocation_id: invocation_id.into(),
            guard_set_fingerprint: guard_set_fingerprint(authorizations)?,
            policy_fingerprint: policy_fingerprint.into(),
            evidence_fingerprint: evidence_fingerprint.into(),
        };
        context.validate_for(authorizations)?;
        Ok(context)
    }

    pub(crate) fn validate_for(
        &self,
        authorizations: &[ExactOperationAuthorization],
    ) -> Result<()> {
        for (field, value) in [
            ("authorization origin", self.origin.as_str()),
            ("authorization destination", self.destination.as_str()),
            ("authorization workspace", self.workspace_id.as_str()),
            ("authorization provider", self.provider.as_str()),
            ("authorization session", self.session_id.as_str()),
            ("authorization invocation", self.invocation_id.as_str()),
            (
                "authorization guard set",
                self.guard_set_fingerprint.as_str(),
            ),
            ("authorization policy", self.policy_fingerprint.as_str()),
            ("authorization evidence", self.evidence_fingerprint.as_str()),
        ] {
            if value.trim().is_empty() {
                bail!("{field} must not be empty");
            }
        }
        if authorizations.is_empty() {
            bail!("authorization context requires at least one authorization");
        }
        for authorization in authorizations {
            if authorization.event_id != self.origin {
                bail!("authorization origin does not match the authorized event");
            }
            if authorization.tool != self.destination {
                bail!("authorization destination does not match the authorized tool");
            }
        }
        if self.guard_set_fingerprint != guard_set_fingerprint(authorizations)? {
            bail!("authorization guard set fingerprint does not match the authorization bundle");
        }
        Ok(())
    }
}

impl AggregateResolutionApplyRequest {
    pub(crate) fn validate(&self, target_count: usize) -> Result<()> {
        for (field, value) in [
            ("resolution_id", self.resolution_id.as_str()),
            ("invocation_id", self.invocation_id.as_str()),
            ("session_id", self.session_id.as_str()),
            ("provider", self.provider.as_str()),
        ] {
            if value.trim().is_empty() {
                bail!("aggregate {field} must not be empty");
            }
        }
        if self.decision_id.as_deref().is_none_or(str::is_empty) {
            bail!("aggregate decision_id must not be empty");
        }
        if target_count == 0 {
            bail!("aggregate resolution requires durable guard execution targets");
        }
        let workspace_id = self
            .workspace_id
            .as_deref()
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| anyhow::anyhow!("aggregate workspace_id is required"))?;
        if self.now_unix_ms >= self.expires_at_unix_ms {
            bail!(
                "Decision resolution expired: now {} >= expires_at {}",
                self.now_unix_ms,
                self.expires_at_unix_ms
            );
        }
        if let Some(context) = &self.authorization_context {
            context.validate_for(&self.authorizations)?;
            if context.workspace_id != workspace_id
                || context.provider != self.provider
                || context.session_id != self.session_id
                || context.invocation_id != self.invocation_id
            {
                bail!("authorization context does not match aggregate resolution scope");
            }
        } else if !self.authorizations.is_empty() {
            bail!("aggregate authorizations require their complete authorization context");
        }
        if let Some(receipt) = &self.decision_receipt
            && (receipt.decision_id != self.decision_id.as_deref().unwrap_or_default()
                || receipt.provider != self.provider)
        {
            bail!("decision receipt does not match aggregate resolution identity");
        }
        Ok(())
    }
}

pub fn guard_set_fingerprint(authorizations: &[ExactOperationAuthorization]) -> Result<String> {
    let mut canonical = authorizations
        .iter()
        .map(serde_json::to_vec)
        .collect::<std::result::Result<Vec<_>, _>>()?;
    canonical.sort();
    let mut bytes = Vec::new();
    for item in canonical {
        bytes.extend_from_slice(&(item.len() as u64).to_be_bytes());
        bytes.extend_from_slice(&item);
    }
    Ok(format!("sha256:{}", hex::encode(Sha256::digest(bytes))))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AggregateGuardResolutionTarget {
    pub key: GuardExecutionKey,
    pub expected_revision: u64,
    pub expected_decision_id: String,
    pub expected_execution_id: String,
    pub expected_owner_invocation_id: String,
    pub record: GuardExecutionRecord,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AggregateGuardResolutionApplyRequest {
    pub resolution: AggregateResolutionApplyRequest,
    pub targets: Vec<AggregateGuardResolutionTarget>,
}

impl AggregateGuardResolutionApplyRequest {
    pub(crate) fn validate_target_scope(&self) -> Result<()> {
        let workspace_id = self
            .resolution
            .workspace_id
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("aggregate workspace_id is required"))?;
        let decision_id = self
            .resolution
            .decision_id
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("aggregate decision_id is required"))?;

        let mut decision_matches_target = false;
        for target in &self.targets {
            if target.key.workspace_id != workspace_id
                || target.key.session_id != self.resolution.session_id
            {
                bail!(
                    "aggregate resolution target scope does not match the resolution workspace/session"
                );
            }
            if target.expected_decision_id == decision_id {
                decision_matches_target = true;
            }
        }
        if !decision_matches_target {
            bail!("aggregate resolution decision does not match any durable pending target");
        }
        Ok(())
    }

    pub(crate) fn target_fingerprint(&self) -> Result<String> {
        let mut identities = self
            .targets
            .iter()
            .map(|target| {
                serde_json::to_string(&(
                    &target.key,
                    target.expected_revision,
                    &target.expected_decision_id,
                    &target.expected_execution_id,
                    &target.expected_owner_invocation_id,
                ))
            })
            .collect::<std::result::Result<Vec<_>, _>>()?;
        identities.sort();
        Ok(format!("[{}]", identities.join(",")))
    }

    pub(crate) fn idempotency_fingerprint(&self) -> Result<String> {
        let mut canonical_authorizations = Vec::with_capacity(self.resolution.authorizations.len());
        for authorization in &self.resolution.authorizations {
            canonical_authorizations
                .push((serde_json::to_string(authorization)?, authorization.clone()));
        }
        canonical_authorizations.sort_by(|left, right| left.0.cmp(&right.0));
        let authorizations = canonical_authorizations
            .into_iter()
            .map(|(_, authorization)| authorization)
            .collect::<Vec<_>>();
        let identity = serde_json::json!({
            "resolution_id": self.resolution.resolution_id,
            "decision_id": self.resolution.decision_id,
            "invocation_id": self.resolution.invocation_id,
            "session_id": self.resolution.session_id,
            "workspace_id": self.resolution.workspace_id,
            "provider": self.resolution.provider,
            "outcome": self.resolution.outcome,
            "authorizations": authorizations,
            "expires_at_unix_ms": self.resolution.expires_at_unix_ms,
            "decision_receipt": self.resolution.decision_receipt,
            "authorization_context": self.resolution.authorization_context,
            "targets": self.target_fingerprint()?,
        });
        let canonical = serde_json::to_vec(&identity)?;
        Ok(format!("sha256:{}", hex::encode(Sha256::digest(canonical))))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AggregateResolutionApplyOutcome {
    Applied,
    IdempotentReplay,
    Conflict,
}

pub trait GuardExecutionStateStore: Send + Sync {
    fn load(&self, key: &GuardExecutionKey) -> Result<Option<GuardExecutionRecord>>;
    fn compare_and_swap(
        &self,
        expected_revision: Option<u64>,
        record: &GuardExecutionRecord,
    ) -> Result<WriteOutcome>;
    fn resolve_workspace_id(&self, canonical_root: &Path) -> Result<String>;
    fn purge_expired(&self, older_than_unix_ms: i64) -> Result<usize>;

    fn record_exact_authorization(
        &self,
        auth: &ExactOperationAuthorization,
        context: &ExactAuthorizationContext,
        decision_id: Option<&str>,
        expires_at_unix_ms: i64,
        uses: u32,
    ) -> Result<()>;
    fn record_exact_authorizations_bundle(
        &self,
        auths: &[ExactOperationAuthorization],
        context: &ExactAuthorizationContext,
        decision_id: Option<&str>,
        expires_at_unix_ms: i64,
        uses: u32,
    ) -> Result<()> {
        for auth in auths {
            self.record_exact_authorization(auth, context, decision_id, expires_at_unix_ms, uses)?;
        }
        Ok(())
    }
    fn consume_exact_authorization(
        &self,
        auth: &ExactOperationAuthorization,
        context: &ExactAuthorizationContext,
        now_unix_ms: i64,
    ) -> Result<bool>;
    fn has_valid_exact_authorization(
        &self,
        auth: &ExactOperationAuthorization,
        context: &ExactAuthorizationContext,
        now_unix_ms: i64,
    ) -> Result<bool>;
    fn record_decision_receipt(&self, receipt: &DecisionReceipt) -> Result<()>;
    fn load_decision_receipt(&self, decision_id: &str) -> Result<Option<DecisionReceipt>>;

    fn apply_aggregate_resolution(
        &self,
        request: &AggregateResolutionApplyRequest,
    ) -> Result<AggregateResolutionApplyOutcome>;

    fn apply_aggregate_guard_resolution(
        &self,
        request: &AggregateGuardResolutionApplyRequest,
    ) -> Result<AggregateResolutionApplyOutcome>;
    fn load_aggregate_resolution_by_decision(
        &self,
        decision_id: &str,
    ) -> Result<Option<AggregateGuardResolutionApplyRequest>>;
}
