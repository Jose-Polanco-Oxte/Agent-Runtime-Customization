pub use crate::decision_ui::MAX_DIALOG_USER_MESSAGE_CHARS;
use crate::decision_ui::PortableDecision;
use crate::ir::{BehaviorIR, BoundRuleExpression};
use crate::manifest::schema::ActionType;
use crate::runtime::context::{CommandTelemetry, SessionContext};
use crate::runtime::evaluator::{
    CurrentOperation, DecisionError, DecisionProvider, DeterministicEvidence,
    GuardDecisionEvidence, MAX_PROBE_OUTPUT_BYTES, MatcherEvidence, ProbeRunner,
};
use crate::runtime::events::{ArcEvent, ArcEventType};
use crate::target::ProviderTarget;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

pub const DECISION_TASK_REQUEST_SCHEMA: &str = "arc.decision_task.request.v1";
pub const EVENT_EVALUATION_REPORT_SCHEMA: &str = "arc.event_evaluation.report.v1";
pub const FAILURE_BUNDLE_SCHEMA: &str = "arc.failure_bundle.v1";
pub const DIALOG_REQUEST_SCHEMA: &str = "arc.decision.dialog.request.v2";
pub const DIALOG_RESPONSE_SCHEMA: &str = "arc.decision.dialog.response.v2";

pub const MAX_ID_CHARS: usize = 256;
pub const MAX_SUMMARY_CHARS: usize = 512;
pub const MAX_SCOPE_CHARS: usize = 2_048;
pub const MAX_TITLE_CHARS: usize = 256;
pub const MAX_OPERATION_CHARS: usize = 4_096;
pub const MAX_DIALOG_CONFIGURED_FEEDBACK_CHARS: usize = 16 * 1024;
pub const MAX_DIALOG_AUDITOR_FINDINGS_CHARS: usize = 16 * 1024;
pub const MAX_PROVIDER_FEEDBACK_INLINE_BYTES: usize = 16 * 1024;
pub const MAX_MATCHER_EVIDENCE_ITEMS: usize = 64;
pub const MAX_DETERMINISTIC_EVIDENCE_ITEMS: usize = 64;
pub const MAX_RULE_PATH_SEGMENTS: usize = 64;
pub const MAX_DIALOG_FAILED_PROBES: usize = 64;
pub const MAX_EXPECTED_VALUES_ITEMS: usize = 16;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "segment", rename_all = "snake_case", deny_unknown_fields)]
pub enum ExpressionPathSegment {
    All { index: usize },
    Any { index: usize },
    Not,
    RuleRef { name: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureCauseKind {
    ProbeMismatch,
    DecisionViolated,
    NegatedTrue,
    RuleReference,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum EvaluationFault {
    MissingLeaf { expression_path: String },
    RuleCycle { rule_name: String },
    MissingRule { rule_name: String },
    Probe { summary: String },
    Decision { summary: String },
    DeadlineExceeded,
    ProviderUnavailable,
    InvalidPlan { summary: String },
    CacheKeyCollision,
    Canceled { reason: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvaluationCompleteness {
    Complete,
    CompleteForGuardResultWithNonCausalSkips,
    IncompleteDueToFault,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EffectiveDisposition {
    RuntimeFault,
    Deny,
    Ask,
    Message,
    Continue,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticDecisionEvidence {
    pub event_type: ArcEventType,
    pub event_id: String,
    pub scope: String,
    pub matcher_evidence: Vec<MatcherEvidence>,
    pub matcher_evidence_truncated: bool,
    pub deterministic_evidence: Vec<DeterministicEvidence>,
    pub deterministic_evidence_truncated: bool,
}

impl SemanticDecisionEvidence {
    pub fn validate(&self) -> Result<(), GuardEvaluationContractError> {
        validate_text("event_id", &self.event_id, MAX_ID_CHARS)?;
        validate_text("scope", &self.scope, MAX_SCOPE_CHARS)?;
        validate_matcher_evidence(&self.matcher_evidence)?;
        validate_deterministic_evidence(&self.deterministic_evidence)?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecisionEvaluationInput {
    pub goal: String,
    pub role: String,
    pub current_operation: CurrentOperation,
    pub session_context: SessionContext,
    pub attested_evidence: SemanticDecisionEvidence,
}

impl DecisionEvaluationInput {
    pub fn validate(&self) -> Result<(), GuardEvaluationContractError> {
        validate_text("goal", &self.goal, MAX_OPERATION_CHARS)?;
        validate_text("role", &self.role, MAX_ID_CHARS)?;
        self.attested_evidence.validate()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecisionExecutionProfile {
    pub provider: ProviderTarget,
    pub transport: String,
    pub model: Option<String>,
    pub adapter_contract_fingerprint: String,
    pub output_schema_fingerprint: String,
    pub sandbox_mode: String,
    pub approval_policy: String,
}

impl DecisionExecutionProfile {
    pub fn validate(&self) -> Result<(), GuardEvaluationContractError> {
        validate_text("transport", &self.transport, MAX_ID_CHARS)?;
        validate_text(
            "adapter_contract_fingerprint",
            &self.adapter_contract_fingerprint,
            MAX_ID_CHARS,
        )?;
        validate_text(
            "output_schema_fingerprint",
            &self.output_schema_fingerprint,
            MAX_ID_CHARS,
        )?;
        validate_text("sandbox_mode", &self.sandbox_mode, MAX_ID_CHARS)?;
        if self.sandbox_mode != "read_only" {
            return Err(GuardEvaluationContractError::InvalidField {
                field: "sandbox_mode",
                reason: "must be 'read_only'",
            });
        }
        validate_text("approval_policy", &self.approval_policy, MAX_ID_CHARS)?;
        if self.approval_policy != "never" {
            return Err(GuardEvaluationContractError::InvalidField {
                field: "approval_policy",
                reason: "must be 'never'",
            });
        }
        if let Some(model) = &self.model {
            validate_text("model", model, MAX_ID_CHARS)?;
        }
        Ok(())
    }
}

impl Default for DecisionExecutionProfile {
    fn default() -> Self {
        Self {
            provider: ProviderTarget::Codex,
            transport: "app_server".to_string(),
            model: None,
            adapter_contract_fingerprint: "default-adapter-v1".to_string(),
            output_schema_fingerprint: "default-schema-v1".to_string(),
            sandbox_mode: "read_only".to_string(),
            approval_policy: "never".to_string(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProbeEvaluationInput {
    pub resolved_command: String,
    pub canonical_workspace_root: PathBuf,
    pub effective_environment_fingerprint: String,
    pub runner_contract_fingerprint: String,
    pub timeout_ms: u64,
    pub max_output_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MatchingGuardSnapshot {
    pub guard_id: String,
    pub order: u32,
    pub declaration_order: usize,
    pub action: ActionType,
    pub configured_feedback: Option<String>,
    pub matcher_evidence: Vec<MatcherEvidence>,
    pub matcher_evidence_truncated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// Non-wire snapshot of the matched Guard configuration used to derive the
/// provider-facing feedback projection. The aggregate constructor requires a
/// complete snapshot whose Guard IDs, structural order, and actions match the
/// evaluated report; production sessions obtain the snapshot from their
/// validated `BehaviorIR`, not from a standalone feedback map.
pub struct GuardEvaluationSpec {
    pub guard_id: String,
    pub order: u32,
    pub declaration_order: usize,
    pub action: ActionType,
    pub configured_feedback: Option<String>,
    pub scope: String,
    pub expression: BoundRuleExpression,
    pub matcher_evidence: Vec<MatcherEvidence>,
    pub matcher_evidence_truncated: bool,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum GuardEvaluationBatchError {
    #[error("failed to serialize guard evaluation report")]
    ReportSerialization,
    #[error("guard '{guard_id}' planning failed: {message}")]
    Planning { guard_id: String, message: String },
    #[error("activation cache failed: {0}")]
    Cache(#[from] ActivationCacheError),
    #[error("duplicate guard id '{guard_id}' detected before evaluation")]
    DuplicateGuardId { guard_id: String },
    #[error(
        "decision provider is missing for transport '{transport}': decision rules cannot be evaluated without a configured decision provider"
    )]
    MissingDecisionProvider { transport: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActivationSnapshot {
    pub schema: &'static str,
    pub activation_id: String,
    pub invocation_id: String,
    pub provider: ProviderTarget,
    pub session_id: String,
    pub event_id: String,
    pub event_type: ArcEventType,
    pub current_operation: CurrentOperation,
    pub session_context: SessionContext,
    pub matching_guards: Vec<MatchingGuardSnapshot>,
    pub input_fingerprint: String,
    pub absolute_deadline_unix_ms: i64,
}

impl ActivationSnapshot {
    pub const SCHEMA: &'static str = "arc.evaluation_snapshot.v1";

    pub fn from_event(
        activation_id: impl Into<String>,
        invocation_id: impl Into<String>,
        provider: ProviderTarget,
        event: &ArcEvent,
        session_context: SessionContext,
        matching_guards: Vec<MatchingGuardSnapshot>,
        absolute_deadline_unix_ms: i64,
    ) -> Self {
        let current_operation = CurrentOperation::from(event);
        let mut bytes = Vec::new();
        encode_str(&mut bytes, "provider", provider.as_str());
        encode_str(&mut bytes, "session_id", &event.session_id);
        encode_str(&mut bytes, "event_id", &event.event_id);
        encode_str(&mut bytes, "event_type", &event.event_type.to_string());
        encode_current_operation(&mut bytes, &current_operation);
        encode_session_context(&mut bytes, &session_context);
        encode_matching_guards(&mut bytes, &matching_guards);
        let input_fingerprint = fingerprint(&bytes);
        Self {
            schema: Self::SCHEMA,
            activation_id: activation_id.into(),
            invocation_id: invocation_id.into(),
            provider,
            session_id: event.session_id.clone(),
            event_id: event.event_id.clone(),
            event_type: event.event_type,
            current_operation,
            session_context,
            matching_guards,
            input_fingerprint,
            absolute_deadline_unix_ms,
        }
    }

    pub fn validate(&self) -> Result<(), GuardEvaluationContractError> {
        if self.schema != Self::SCHEMA {
            return Err(GuardEvaluationContractError::Schema {
                expected: Self::SCHEMA,
                actual: self.schema.to_string(),
            });
        }
        validate_text("activation_id", &self.activation_id, MAX_ID_CHARS)?;
        validate_text("invocation_id", &self.invocation_id, MAX_ID_CHARS)?;
        validate_text("session_id", &self.session_id, MAX_ID_CHARS)?;
        validate_text("event_id", &self.event_id, MAX_ID_CHARS)?;
        validate_text("input_fingerprint", &self.input_fingerprint, MAX_ID_CHARS)?;
        if self.absolute_deadline_unix_ms < 0 {
            return Err(GuardEvaluationContractError::InvalidField {
                field: "absolute_deadline_unix_ms",
                reason: "must not be negative",
            });
        }
        let mut seen = BTreeSet::new();
        for g in &self.matching_guards {
            validate_text("matching_guards.guard_id", &g.guard_id, MAX_ID_CHARS)?;
            if !seen.insert(g.guard_id.as_str()) {
                return Err(GuardEvaluationContractError::DuplicateId {
                    field: "matching_guards.guard_id",
                    value: g.guard_id.clone(),
                });
            }
            validate_matcher_evidence(&g.matcher_evidence)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LeafOccurrence {
    pub occurrence_id: String,
    pub guard_id: String,
    pub expression_path: Vec<ExpressionPathSegment>,
    pub evaluation_key: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProbeOccurrence {
    pub occurrence: LeafOccurrence,
    pub expected_in: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum DecisionTaskResult {
    Satisfied {
        physical_evaluation_id: String,
        evaluation_key: String,
        findings: Option<String>,
        provider_receipt: ProviderEvaluationReceipt,
    },
    Violated {
        physical_evaluation_id: String,
        evaluation_key: String,
        findings: String,
        provider_receipt: ProviderEvaluationReceipt,
    },
    Faulted {
        physical_evaluation_id: String,
        evaluation_key: String,
        fault: DecisionTaskFault,
        provider_receipt: Option<ProviderEvaluationReceipt>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecisionTaskRequest {
    pub schema: String,
    pub physical_evaluation_id: String,
    pub activation_id: String,
    pub invocation_id: String,
    pub evaluation_key: String,
    pub profile: DecisionExecutionProfile,
    pub input: DecisionEvaluationInput,
    pub absolute_deadline_unix_ms: i64,
}

impl DecisionTaskRequest {
    pub fn validate(&self) -> Result<(), GuardEvaluationContractError> {
        if self.schema != DECISION_TASK_REQUEST_SCHEMA {
            return Err(GuardEvaluationContractError::Schema {
                expected: DECISION_TASK_REQUEST_SCHEMA,
                actual: self.schema.clone(),
            });
        }
        validate_text(
            "physical_evaluation_id",
            &self.physical_evaluation_id,
            MAX_ID_CHARS,
        )?;
        validate_text("activation_id", &self.activation_id, MAX_ID_CHARS)?;
        validate_text("invocation_id", &self.invocation_id, MAX_ID_CHARS)?;
        validate_text("evaluation_key", &self.evaluation_key, MAX_ID_CHARS)?;
        if self.absolute_deadline_unix_ms < 0 {
            return Err(GuardEvaluationContractError::InvalidField {
                field: "absolute_deadline_unix_ms",
                reason: "must not be negative",
            });
        }
        self.profile.validate()?;
        self.input.validate()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProbeObservation {
    pub physical_evaluation_id: String,
    pub evaluation_key: String,
    pub bounded_stdout_private: String,
    pub observed_sha256: String,
    pub observed_bytes: u64,
    pub started_unix_ms: i64,
    pub completed_unix_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum ProbeTaskResult {
    Observed {
        observation: ProbeObservation,
    },
    Faulted {
        physical_evaluation_id: String,
        evaluation_key: String,
        fault: ProbeTaskFault,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ProbeTaskFault {
    DeadlineExceeded,
    SpawnFailed,
    ProcessFailed {
        exit_code: Option<i32>,
        stdout_sha256: String,
        stderr_sha256: String,
    },
    OutputLimitExceeded,
    CacheKeyCollision,
    CanceledNoConsumers,
    CanceledByShutdown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CacheResolutionProvenance {
    Executed,
    CoalescedInFlight,
    ReusedCompleted,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LeafOccurrenceResolution<T> {
    pub occurrence_id: String,
    pub physical_evaluation_id: String,
    pub evaluation_key: String,
    pub provenance: CacheResolutionProvenance,
    pub result: T,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LeafEvaluationKind {
    Decision,
    Probe,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ActivationCacheError {
    #[error("activation evaluation cache is closed")]
    Closed,
    #[error("cache key collision for {kind:?} key '{evaluation_key}'")]
    KeyCollision {
        kind: LeafEvaluationKind,
        evaluation_key: String,
    },
    #[error("activation evaluation cache synchronization was poisoned")]
    Poisoned,
    #[error("physical activation evaluation panicked")]
    ExecutionPanicked,
}

pub struct TypedCacheEntry<T> {
    pub canonical_bytes: Vec<u8>,
    pub physical_evaluation_id: String,
    pub state: Mutex<TypedCacheEntryState<T>>,
    pub completed: Condvar,
}

impl<T> TypedCacheEntry<T> {
    pub fn new(canonical_bytes: Vec<u8>, physical_evaluation_id: String) -> Self {
        Self {
            canonical_bytes,
            physical_evaluation_id,
            state: Mutex::new(TypedCacheEntryState::Running),
            completed: Condvar::new(),
        }
    }
}

pub enum TypedCacheEntryState<T> {
    Running,
    Ready(Arc<T>),
    Faulted(ActivationCacheError),
    Closed,
}

struct ActivationCacheInner {
    probes: BTreeMap<String, Arc<TypedCacheEntry<Result<String, String>>>>,
    decisions: BTreeMap<String, Arc<TypedCacheEntry<DecisionTaskResult>>>,
}

enum TypedResolutionRole<T> {
    Leader(Arc<TypedCacheEntry<T>>),
    Follower(Arc<TypedCacheEntry<T>>),
    Ready(Arc<TypedCacheEntry<T>>),
}

/// Singleflight memoization whose lifetime is exactly one hook activation.
///
/// The map never holds its lock while a caller executes provider or probe
/// work. Results are statically strongly typed without `dyn Any` or runtime downcasting.
pub struct ActivationEvaluationCache {
    activation_id: String,
    closed: AtomicBool,
    inner: Mutex<ActivationCacheInner>,
    physical_fault_keys: Mutex<BTreeSet<(LeafEvaluationKind, String)>>,
    logical_occurrences: AtomicU64,
    coalesced_in_flight: AtomicU64,
    reused_completed: AtomicU64,
    physical_faults: AtomicU64,
}

impl std::fmt::Debug for ActivationEvaluationCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ActivationEvaluationCache")
            .field("activation_id", &self.activation_id)
            .field("closed", &self.closed.load(Ordering::Relaxed))
            .field(
                "logical_occurrences",
                &self.logical_occurrences.load(Ordering::Relaxed),
            )
            .field(
                "coalesced_in_flight",
                &self.coalesced_in_flight.load(Ordering::Relaxed),
            )
            .field(
                "reused_completed",
                &self.reused_completed.load(Ordering::Relaxed),
            )
            .field(
                "physical_faults",
                &self.physical_faults.load(Ordering::Relaxed),
            )
            .finish()
    }
}

impl ActivationEvaluationCache {
    pub fn new(activation_id: impl Into<String>) -> Self {
        Self {
            activation_id: activation_id.into(),
            closed: AtomicBool::new(false),
            inner: Mutex::new(ActivationCacheInner {
                probes: BTreeMap::new(),
                decisions: BTreeMap::new(),
            }),
            physical_fault_keys: Mutex::new(BTreeSet::new()),
            logical_occurrences: AtomicU64::new(0),
            coalesced_in_flight: AtomicU64::new(0),
            reused_completed: AtomicU64::new(0),
            physical_faults: AtomicU64::new(0),
        }
    }

    pub fn activation_id(&self) -> &str {
        &self.activation_id
    }

    pub fn logical_occurrences(&self) -> u64 {
        self.logical_occurrences.load(Ordering::Acquire)
    }

    pub fn coalesced_in_flight(&self) -> u64 {
        self.coalesced_in_flight.load(Ordering::Acquire)
    }

    pub fn resolve_probe<F>(
        &self,
        evaluation_key: &str,
        canonical_bytes: Vec<u8>,
        occurrence_id: &str,
        execute: F,
    ) -> Result<LeafOccurrenceResolution<Result<String, String>>, ActivationCacheError>
    where
        F: FnOnce() -> Result<String, String>,
    {
        self.resolve_typed(
            |inner| &mut inner.probes,
            LeafEvaluationKind::Probe,
            evaluation_key,
            canonical_bytes,
            occurrence_id,
            execute,
        )
    }

    pub fn resolve_decision<F>(
        &self,
        evaluation_key: &str,
        canonical_bytes: Vec<u8>,
        occurrence_id: &str,
        execute: F,
    ) -> Result<LeafOccurrenceResolution<DecisionTaskResult>, ActivationCacheError>
    where
        F: FnOnce() -> DecisionTaskResult,
    {
        self.resolve_typed(
            |inner| &mut inner.decisions,
            LeafEvaluationKind::Decision,
            evaluation_key,
            canonical_bytes,
            occurrence_id,
            execute,
        )
    }

    fn resolve_typed<T, F>(
        &self,
        get_map: impl FnOnce(
            &mut ActivationCacheInner,
        ) -> &mut BTreeMap<String, Arc<TypedCacheEntry<T>>>,
        kind: LeafEvaluationKind,
        evaluation_key: &str,
        canonical_bytes: Vec<u8>,
        occurrence_id: &str,
        execute: F,
    ) -> Result<LeafOccurrenceResolution<T>, ActivationCacheError>
    where
        T: Clone + Send + Sync + 'static,
        F: FnOnce() -> T,
    {
        if self.closed.load(Ordering::Acquire) {
            return Err(ActivationCacheError::Closed);
        }
        self.logical_occurrences.fetch_add(1, Ordering::Relaxed);
        let physical_id = physical_evaluation_id(&self.activation_id, evaluation_key);
        let entry = Arc::new(TypedCacheEntry::new(canonical_bytes.clone(), physical_id));

        let role = {
            let mut inner = lock_mutex(&self.inner)?;
            if self.closed.load(Ordering::Acquire) {
                return Err(ActivationCacheError::Closed);
            }
            let map = get_map(&mut inner);
            match map.get(evaluation_key) {
                None => {
                    map.insert(evaluation_key.to_string(), Arc::clone(&entry));
                    TypedResolutionRole::Leader(entry)
                }
                Some(existing) => {
                    if existing.canonical_bytes != canonical_bytes {
                        return Err(ActivationCacheError::KeyCollision {
                            kind,
                            evaluation_key: evaluation_key.to_string(),
                        });
                    }
                    let state = lock_mutex(&existing.state)?;
                    let role = match &*state {
                        TypedCacheEntryState::Running => {
                            TypedResolutionRole::Follower(Arc::clone(existing))
                        }
                        TypedCacheEntryState::Ready(_) => {
                            TypedResolutionRole::Ready(Arc::clone(existing))
                        }
                        TypedCacheEntryState::Faulted(error) => return Err(error.clone()),
                        TypedCacheEntryState::Closed => return Err(ActivationCacheError::Closed),
                    };
                    drop(state);
                    role
                }
            }
        };

        match role {
            TypedResolutionRole::Leader(entry) => {
                let result = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(execute)) {
                    Ok(result) => Arc::new(result),
                    Err(_) => {
                        let fault = ActivationCacheError::ExecutionPanicked;
                        self.note_physical_fault(kind, evaluation_key)?;
                        let mut state = lock_mutex(&entry.state)?;
                        *state = TypedCacheEntryState::Faulted(fault.clone());
                        entry.completed.notify_all();
                        return Err(fault);
                    }
                };
                let mut state = lock_mutex(&entry.state)?;
                if matches!(*state, TypedCacheEntryState::Closed) {
                    return Err(ActivationCacheError::Closed);
                }
                *state = TypedCacheEntryState::Ready(Arc::clone(&result));
                entry.completed.notify_all();
                Ok(LeafOccurrenceResolution {
                    occurrence_id: occurrence_id.to_string(),
                    physical_evaluation_id: entry.physical_evaluation_id.clone(),
                    evaluation_key: evaluation_key.to_string(),
                    provenance: CacheResolutionProvenance::Executed,
                    result: (*result).clone(),
                })
            }
            TypedResolutionRole::Follower(entry) => {
                self.coalesced_in_flight.fetch_add(1, Ordering::Relaxed);
                self.wait_for_result_typed(
                    &entry,
                    evaluation_key,
                    occurrence_id,
                    CacheResolutionProvenance::CoalescedInFlight,
                )
            }
            TypedResolutionRole::Ready(entry) => {
                self.reused_completed.fetch_add(1, Ordering::Relaxed);
                self.wait_for_result_typed(
                    &entry,
                    evaluation_key,
                    occurrence_id,
                    CacheResolutionProvenance::ReusedCompleted,
                )
            }
        }
    }

    pub fn note_physical_fault(
        &self,
        kind: LeafEvaluationKind,
        evaluation_key: &str,
    ) -> Result<(), ActivationCacheError> {
        let mut keys = lock_mutex(&self.physical_fault_keys)?;
        if keys.insert((kind, evaluation_key.to_owned())) {
            self.physical_faults.fetch_add(1, Ordering::Relaxed);
        }
        Ok(())
    }

    fn wait_for_result_typed<T: Clone + Send + Sync + 'static>(
        &self,
        entry: &Arc<TypedCacheEntry<T>>,
        evaluation_key: &str,
        occurrence_id: &str,
        provenance: CacheResolutionProvenance,
    ) -> Result<LeafOccurrenceResolution<T>, ActivationCacheError> {
        let mut state = lock_mutex(&entry.state)?;
        loop {
            match &*state {
                TypedCacheEntryState::Running => {
                    state = entry
                        .completed
                        .wait(state)
                        .map_err(|_| ActivationCacheError::Poisoned)?;
                }
                TypedCacheEntryState::Ready(result) => {
                    return Ok(LeafOccurrenceResolution {
                        occurrence_id: occurrence_id.to_string(),
                        physical_evaluation_id: entry.physical_evaluation_id.clone(),
                        evaluation_key: evaluation_key.to_string(),
                        provenance,
                        result: (**result).clone(),
                    });
                }
                TypedCacheEntryState::Faulted(error) => return Err(error.clone()),
                TypedCacheEntryState::Closed => return Err(ActivationCacheError::Closed),
            }
        }
    }

    pub fn summary(&self) -> ActivationCacheSummary {
        let (unique_probe_evaluations, unique_decision_evaluations) = lock_mutex(&self.inner)
            .map(|inner| (inner.probes.len() as u64, inner.decisions.len() as u64))
            .unwrap_or((0, 0));
        ActivationCacheSummary {
            logical_occurrences: self.logical_occurrences.load(Ordering::Relaxed),
            unique_probe_evaluations,
            unique_decision_evaluations,
            coalesced_in_flight: self.coalesced_in_flight.load(Ordering::Relaxed),
            reused_completed: self.reused_completed.load(Ordering::Relaxed),
            physical_faults: self.physical_faults.load(Ordering::Relaxed),
        }
    }

    pub fn close(&self) {
        if self.closed.swap(true, Ordering::AcqRel) {
            return;
        }
        if let Ok(mut inner) = self.inner.lock() {
            for entry in inner.probes.values() {
                if let Ok(mut state) = entry.state.lock() {
                    *state = TypedCacheEntryState::Closed;
                    entry.completed.notify_all();
                }
            }
            for entry in inner.decisions.values() {
                if let Ok(mut state) = entry.state.lock() {
                    *state = TypedCacheEntryState::Closed;
                    entry.completed.notify_all();
                }
            }
            inner.probes.clear();
            inner.decisions.clear();
        }
    }

    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }
}

impl Drop for ActivationEvaluationCache {
    fn drop(&mut self) {
        self.close();
    }
}

fn lock_mutex<T>(mutex: &Mutex<T>) -> Result<MutexGuard<'_, T>, ActivationCacheError> {
    mutex.lock().map_err(|_| ActivationCacheError::Poisoned)
}

pub trait PhysicalDecisionExecutor: Send + Sync {
    fn execute(&self, request: DecisionTaskRequest) -> DecisionTaskResult;
}

/// Adapter from Arc's provider-neutral decision trait to one physical
/// scheduler task. Each request receives an isolated conversation fingerprint
/// derived from its physical evaluation ID; no continuation or shared thread
/// state is introduced here.
pub struct DecisionProviderExecutor {
    provider: Arc<dyn DecisionProvider>,
    transport: String,
}

impl DecisionProviderExecutor {
    pub fn new(provider: Arc<dyn DecisionProvider>, transport: impl Into<String>) -> Self {
        Self {
            provider,
            transport: transport.into(),
        }
    }
}

impl PhysicalDecisionExecutor for DecisionProviderExecutor {
    fn execute(&self, request: DecisionTaskRequest) -> DecisionTaskResult {
        if request.schema != DECISION_TASK_REQUEST_SCHEMA
            || request.profile.sandbox_mode != "read_only"
            || request.profile.approval_policy != "never"
        {
            return DecisionTaskResult::Faulted {
                physical_evaluation_id: request.physical_evaluation_id,
                evaluation_key: request.evaluation_key,
                fault: DecisionTaskFault::IsolationViolation,
                provider_receipt: None,
            };
        }
        let started_unix_ms = unix_timestamp_ms();
        let evidence = GuardDecisionEvidence {
            guard_id: String::new(),
            event: request.input.attested_evidence.event_type.to_string(),
            event_id: request.input.attested_evidence.event_id.clone(),
            scope: request.input.attested_evidence.scope.clone(),
            matcher_evidence: request.input.attested_evidence.matcher_evidence.clone(),
            matcher_evidence_truncated: request.input.attested_evidence.matcher_evidence_truncated,
            deterministic_evidence: request
                .input
                .attested_evidence
                .deterministic_evidence
                .clone(),
            deterministic_evidence_truncated: request
                .input
                .attested_evidence
                .deterministic_evidence_truncated,
        };
        let result = self.provider.decide(
            &request.input.goal,
            Some(&request.input.session_context),
            Some(&request.input.current_operation),
            &evidence,
        );
        let completed_unix_ms = unix_timestamp_ms();
        let physical_evaluation_id = request.physical_evaluation_id.clone();
        let provider = request.profile.provider;
        let adapter_contract_fingerprint = request.profile.adapter_contract_fingerprint.clone();
        let transport = self.transport.clone();
        let receipt = move || ProviderEvaluationReceipt {
            provider,
            transport: transport.clone(),
            isolated_conversation_fingerprint: fingerprint(
                format!(
                    "{}\0{}",
                    physical_evaluation_id, adapter_contract_fingerprint
                )
                .as_bytes(),
            ),
            started_unix_ms,
            completed_unix_ms,
            queue_duration_ms: 0,
            inference_duration_ms: completed_unix_ms
                .saturating_sub(started_unix_ms)
                .try_into()
                .unwrap_or(u64::MAX),
        };
        match result {
            Ok(verdict) if verdict.decision => {
                let normalized_findings = verdict.findings.and_then(|f| {
                    let trimmed = f.trim();
                    (!trimmed.is_empty()).then(|| bounded_summary(trimmed))
                });
                DecisionTaskResult::Satisfied {
                    physical_evaluation_id: request.physical_evaluation_id,
                    evaluation_key: request.evaluation_key,
                    findings: normalized_findings,
                    provider_receipt: receipt(),
                }
            }
            Ok(verdict) => {
                let normalized_findings = verdict.findings.as_deref().and_then(|f| {
                    let trimmed = f.trim();
                    (!trimmed.is_empty()).then(|| bounded_summary(trimmed))
                });
                DecisionTaskResult::Violated {
                    physical_evaluation_id: request.physical_evaluation_id,
                    evaluation_key: request.evaluation_key,
                    findings: normalized_findings
                        .unwrap_or_else(|| "decision provider rejected the goal".into()),
                    provider_receipt: receipt(),
                }
            }
            Err(DecisionError::UnparseableResponse { response, .. }) => {
                DecisionTaskResult::Faulted {
                    physical_evaluation_id: request.physical_evaluation_id,
                    evaluation_key: request.evaluation_key,
                    fault: DecisionTaskFault::ProtocolViolation {
                        response_sha256: fingerprint(response.as_bytes()),
                    },
                    provider_receipt: None,
                }
            }
            Err(DecisionError::ExecutionFailed {
                exit_code,
                stderr_summary,
                stdout_summary,
                ..
            }) => DecisionTaskResult::Faulted {
                physical_evaluation_id: request.physical_evaluation_id,
                evaluation_key: request.evaluation_key,
                fault: DecisionTaskFault::ProcessFailed {
                    exit_code,
                    stdout_sha256: fingerprint(stdout_summary.as_bytes()),
                    stderr_sha256: fingerprint(stderr_summary.as_bytes()),
                },
                provider_receipt: None,
            },
            Err(DecisionError::IsolationViolation { .. }) => DecisionTaskResult::Faulted {
                physical_evaluation_id: request.physical_evaluation_id,
                evaluation_key: request.evaluation_key,
                fault: DecisionTaskFault::IsolationViolation,
                provider_receipt: None,
            },
            Err(DecisionError::ToolUseAttempted { .. }) => DecisionTaskResult::Faulted {
                physical_evaluation_id: request.physical_evaluation_id,
                evaluation_key: request.evaluation_key,
                fault: DecisionTaskFault::ToolUseAttempted,
                provider_receipt: None,
            },
            Err(DecisionError::AuthenticationUnavailable { .. }) => DecisionTaskResult::Faulted {
                physical_evaluation_id: request.physical_evaluation_id,
                evaluation_key: request.evaluation_key,
                fault: DecisionTaskFault::AuthenticationUnavailable,
                provider_receipt: None,
            },
            Err(DecisionError::SessionIntentUnavailable) => DecisionTaskResult::Faulted {
                physical_evaluation_id: request.physical_evaluation_id,
                evaluation_key: request.evaluation_key,
                fault: DecisionTaskFault::SessionIntentUnavailable,
                provider_receipt: None,
            },
            Err(_) => DecisionTaskResult::Faulted {
                physical_evaluation_id: request.physical_evaluation_id,
                evaluation_key: request.evaluation_key,
                fault: DecisionTaskFault::ProviderUnavailable,
                provider_receipt: None,
            },
        }
    }
}

#[derive(Debug, Error)]
pub enum SchedulerError {
    #[error("decision scheduler concurrency must be greater than zero")]
    InvalidConcurrency,
    #[error("decision scheduler worker channel closed before all tasks were submitted")]
    WorkerChannelClosed,
    #[error("decision scheduler worker result channel closed")]
    ResultChannelClosed,
    #[error("decision scheduler worker panicked")]
    WorkerPanicked,
    #[error(
        "decision scheduler received duplicate physical evaluation id '{physical_evaluation_id}'"
    )]
    DuplicatePhysicalEvaluationId { physical_evaluation_id: String },
    #[error(
        "decision executor returned an unexpected identity for physical evaluation '{physical_evaluation_id}'"
    )]
    ResultIdentityMismatch {
        physical_evaluation_id: String,
        evaluation_key: String,
    },
    #[error("failed to spawn decision scheduler worker: {source}")]
    WorkerSpawn {
        #[source]
        source: std::io::Error,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecisionBatchResult {
    pub results: Vec<DecisionTaskResult>,
    pub peak_concurrency: usize,
}

pub struct DecisionScheduler {
    max_concurrency: usize,
}

impl DecisionScheduler {
    pub fn new(max_concurrency: usize) -> Result<Self, SchedulerError> {
        if max_concurrency == 0 {
            return Err(SchedulerError::InvalidConcurrency);
        }
        Ok(Self { max_concurrency })
    }

    pub fn max_concurrency(&self) -> usize {
        self.max_concurrency
    }

    pub fn run<F>(
        &self,
        tasks: Vec<DecisionTaskRequest>,
        executor: Arc<dyn PhysicalDecisionExecutor>,
        now_unix_ms: F,
    ) -> Result<DecisionBatchResult, SchedulerError>
    where
        F: Fn() -> i64 + Send + Sync + 'static,
    {
        if tasks.is_empty() {
            return Ok(DecisionBatchResult {
                results: Vec::new(),
                peak_concurrency: 0,
            });
        }
        let task_count = tasks.len();
        let worker_count = self.max_concurrency.min(task_count);
        let expected_identities: BTreeMap<_, _> = tasks
            .iter()
            .map(|task| {
                (
                    task.physical_evaluation_id.clone(),
                    task.evaluation_key.clone(),
                )
            })
            .collect();
        let (task_tx, task_rx) = std::sync::mpsc::channel::<DecisionTaskRequest>();
        let task_rx = Arc::new(Mutex::new(task_rx));
        let (result_tx, result_rx) = std::sync::mpsc::channel::<DecisionTaskResult>();
        let active = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let now_unix_ms = Arc::new(now_unix_ms);
        let mut workers = Vec::with_capacity(worker_count);

        for _ in 0..worker_count {
            let task_rx = Arc::clone(&task_rx);
            let result_tx = result_tx.clone();
            let executor = Arc::clone(&executor);
            let active = Arc::clone(&active);
            let peak = Arc::clone(&peak);
            let now_unix_ms = Arc::clone(&now_unix_ms);
            let worker = std::thread::Builder::new()
                .name("arc-decision-worker".into())
                .spawn(move || {
                    loop {
                        let task = match task_rx.lock() {
                            Ok(receiver) => receiver.recv(),
                            Err(_) => return,
                        };
                        let Ok(task) = task else {
                            return;
                        };
                        let result = if task.absolute_deadline_unix_ms <= now_unix_ms() {
                            DecisionTaskResult::Faulted {
                                physical_evaluation_id: task.physical_evaluation_id,
                                evaluation_key: task.evaluation_key,
                                fault: DecisionTaskFault::QueueDeadlineExceeded,
                                provider_receipt: None,
                            }
                        } else {
                            let active_now = active.fetch_add(1, Ordering::AcqRel) + 1;
                            peak.fetch_max(active_now, Ordering::AcqRel);
                            let result =
                                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                                    executor.execute(task.clone())
                                }))
                                .unwrap_or_else(|_| {
                                    DecisionTaskResult::Faulted {
                                        physical_evaluation_id: task.physical_evaluation_id.clone(),
                                        evaluation_key: task.evaluation_key.clone(),
                                        fault: DecisionTaskFault::ProtocolViolation {
                                            response_sha256: fingerprint(
                                                b"decision executor panicked",
                                            ),
                                        },
                                        provider_receipt: None,
                                    }
                                });
                            active.fetch_sub(1, Ordering::AcqRel);
                            if task.absolute_deadline_unix_ms <= now_unix_ms() {
                                DecisionTaskResult::Faulted {
                                    physical_evaluation_id: task.physical_evaluation_id,
                                    evaluation_key: task.evaluation_key,
                                    fault: DecisionTaskFault::DeadlineExceeded,
                                    provider_receipt: None,
                                }
                            } else {
                                result
                            }
                        };
                        if result_tx.send(result).is_err() {
                            return;
                        }
                    }
                })
                .map_err(|source| SchedulerError::WorkerSpawn { source })?;
            workers.push(worker);
        }
        drop(result_tx);

        for task in tasks {
            task_tx
                .send(task)
                .map_err(|_| SchedulerError::WorkerChannelClosed)?;
        }
        drop(task_tx);

        let mut results = Vec::with_capacity(task_count);
        for _ in 0..task_count {
            results.push(
                result_rx
                    .recv()
                    .map_err(|_| SchedulerError::ResultChannelClosed)?,
            );
        }
        for worker in workers {
            worker.join().map_err(|_| SchedulerError::WorkerPanicked)?;
        }
        let mut physical_ids = BTreeSet::new();
        for result in &results {
            let physical_evaluation_id = decision_result_id(result);
            if !physical_ids.insert(physical_evaluation_id.to_string()) {
                return Err(SchedulerError::DuplicatePhysicalEvaluationId {
                    physical_evaluation_id: physical_evaluation_id.to_string(),
                });
            }
        }
        for result in &results {
            let physical_evaluation_id = decision_result_id(result);
            let actual_evaluation_key = decision_result_key(result);
            let identity_matches = expected_identities
                .get(physical_evaluation_id)
                .is_some_and(|expected| expected == actual_evaluation_key);
            if !identity_matches {
                return Err(SchedulerError::ResultIdentityMismatch {
                    physical_evaluation_id: physical_evaluation_id.to_string(),
                    evaluation_key: actual_evaluation_key.to_string(),
                });
            }
        }
        results.sort_by(|left, right| decision_result_id(left).cmp(decision_result_id(right)));
        Ok(DecisionBatchResult {
            results,
            peak_concurrency: peak.load(Ordering::Acquire),
        })
    }
}

fn decision_result_id(result: &DecisionTaskResult) -> &str {
    match result {
        DecisionTaskResult::Satisfied {
            physical_evaluation_id,
            ..
        }
        | DecisionTaskResult::Violated {
            physical_evaluation_id,
            ..
        }
        | DecisionTaskResult::Faulted {
            physical_evaluation_id,
            ..
        } => physical_evaluation_id,
    }
}

fn decision_result_key(result: &DecisionTaskResult) -> &str {
    match result {
        DecisionTaskResult::Satisfied { evaluation_key, .. }
        | DecisionTaskResult::Violated { evaluation_key, .. }
        | DecisionTaskResult::Faulted { evaluation_key, .. } => evaluation_key,
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderEvaluationReceipt {
    pub provider: ProviderTarget,
    pub transport: String,
    pub isolated_conversation_fingerprint: String,
    pub started_unix_ms: i64,
    pub completed_unix_ms: i64,
    pub queue_duration_ms: u64,
    pub inference_duration_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum DecisionTaskFault {
    DeadlineExceeded,
    QueueDeadlineExceeded,
    ProviderUnavailable,
    SessionIntentUnavailable,
    AuthenticationUnavailable,
    RateLimited,
    ProcessFailed {
        exit_code: Option<i32>,
        stdout_sha256: String,
        stderr_sha256: String,
    },
    ProtocolViolation {
        response_sha256: String,
    },
    ToolUseAttempted,
    IsolationViolation,
    CacheKeyCollision,
    CanceledNoConsumers,
    CanceledByShutdown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FailureCause {
    pub occurrence_id: String,
    pub physical_evaluation_id: String,
    pub cache_provenance: CacheResolutionProvenance,
    pub expression_path: Vec<ExpressionPathSegment>,
    pub kind: FailureCauseKind,
    pub summary: String,
    pub auditor_findings: Option<String>,
    pub deterministic_evidence: Vec<DeterministicEvidence>,
}

impl FailureCause {
    pub fn validate(&self) -> Result<(), GuardEvaluationContractError> {
        validate_text("occurrence_id", &self.occurrence_id, MAX_ID_CHARS)?;
        validate_text(
            "physical_evaluation_id",
            &self.physical_evaluation_id,
            MAX_ID_CHARS,
        )?;
        validate_summary("summary", &self.summary)?;
        if let Some(findings) = &self.auditor_findings {
            validate_text("auditor_findings", findings, MAX_SUMMARY_CHARS)?;
        }
        if self.expression_path.len() > MAX_RULE_PATH_SEGMENTS {
            return Err(GuardEvaluationContractError::CollectionTooLarge {
                field: "expression_path",
                max: MAX_RULE_PATH_SEGMENTS,
                actual: self.expression_path.len(),
            });
        }
        validate_deterministic_evidence(&self.deterministic_evidence)?;
        Ok(())
    }
}

fn validate_evaluation_fault(fault: &EvaluationFault) -> Result<(), GuardEvaluationContractError> {
    match fault {
        EvaluationFault::MissingLeaf { expression_path } => validate_text(
            "fault.expression_path",
            expression_path,
            MAX_OPERATION_CHARS,
        ),
        EvaluationFault::RuleCycle { rule_name } | EvaluationFault::MissingRule { rule_name } => {
            validate_text("fault.rule_name", rule_name, MAX_ID_CHARS)
        }
        EvaluationFault::Probe { summary }
        | EvaluationFault::Decision { summary }
        | EvaluationFault::InvalidPlan { summary } => validate_summary("fault.summary", summary),
        EvaluationFault::Canceled { reason } => validate_summary("fault.reason", reason),
        EvaluationFault::DeadlineExceeded
        | EvaluationFault::ProviderUnavailable
        | EvaluationFault::CacheKeyCollision => Ok(()),
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LeafAttribution {
    pub occurrence_id: String,
    pub physical_evaluation_id: String,
    pub cache_provenance: CacheResolutionProvenance,
    pub expression_path: Vec<ExpressionPathSegment>,
    pub summary: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auditor_findings: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub deterministic_evidence: Vec<DeterministicEvidence>,
}

impl LeafAttribution {
    pub fn validate(&self) -> Result<(), GuardEvaluationContractError> {
        validate_text("occurrence_id", &self.occurrence_id, MAX_ID_CHARS)?;
        validate_text(
            "physical_evaluation_id",
            &self.physical_evaluation_id,
            MAX_ID_CHARS,
        )?;
        validate_summary("summary", &self.summary)?;
        if let Some(findings) = &self.auditor_findings {
            validate_text("auditor_findings", findings, MAX_SUMMARY_CHARS)?;
        }
        if self.expression_path.len() > MAX_RULE_PATH_SEGMENTS {
            return Err(GuardEvaluationContractError::CollectionTooLarge {
                field: "expression_path",
                max: MAX_RULE_PATH_SEGMENTS,
                actual: self.expression_path.len(),
            });
        }
        validate_deterministic_evidence(&self.deterministic_evidence)?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum LeafResult {
    Satisfied {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        attribution: Option<LeafAttribution>,
    },
    Violated {
        cause: FailureCause,
    },
    Faulted {
        fault: EvaluationFault,
    },
    SkippedNonCausal {
        occurrence_id: String,
        expression_path: Vec<ExpressionPathSegment>,
        summary: String,
    },
    SkippedUnsafeToSpeculate {
        occurrence_id: String,
        expression_path: Vec<ExpressionPathSegment>,
        summary: String,
    },
}

impl LeafResult {
    pub fn satisfied() -> Self {
        Self::Satisfied { attribution: None }
    }

    pub fn satisfied_with(attribution: LeafAttribution) -> Self {
        Self::Satisfied {
            attribution: Some(attribution),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleReduction {
    pub decision: Option<bool>,
    pub causes: Vec<FailureCause>,
    pub faults: Vec<EvaluationFault>,
    pub completeness: EvaluationCompleteness,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub satisfied_attributions: Vec<LeafAttribution>,
}

impl RuleReduction {
    pub fn satisfied() -> Self {
        Self {
            decision: Some(true),
            causes: Vec::new(),
            faults: Vec::new(),
            completeness: EvaluationCompleteness::Complete,
            satisfied_attributions: Vec::new(),
        }
    }

    fn from_decision(decision: bool) -> Self {
        Self {
            decision: Some(decision),
            causes: Vec::new(),
            faults: Vec::new(),
            completeness: EvaluationCompleteness::Complete,
            satisfied_attributions: Vec::new(),
        }
    }

    fn faulted(fault: EvaluationFault) -> Self {
        Self {
            decision: None,
            causes: Vec::new(),
            faults: vec![fault],
            completeness: EvaluationCompleteness::IncompleteDueToFault,
            satisfied_attributions: Vec::new(),
        }
    }

    fn merge_completeness(&mut self, other: EvaluationCompleteness) {
        if self.completeness == EvaluationCompleteness::IncompleteDueToFault
            || other == EvaluationCompleteness::IncompleteDueToFault
        {
            self.completeness = EvaluationCompleteness::IncompleteDueToFault;
        } else if self.completeness
            == EvaluationCompleteness::CompleteForGuardResultWithNonCausalSkips
            || other == EvaluationCompleteness::CompleteForGuardResultWithNonCausalSkips
        {
            self.completeness = EvaluationCompleteness::CompleteForGuardResultWithNonCausalSkips;
        }
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ReductionError {
    #[error("missing leaf result at expression path '{expression_path}'")]
    MissingLeaf { expression_path: String },
    #[error("runtime cyclic rule evaluation detected for rule '{rule_name}'")]
    RuleCycle { rule_name: String },
    #[error("reusable rule '{rule_name}' not found in compiled rules catalog")]
    MissingRule { rule_name: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuardResult {
    pub guard_id: String,
    pub order: u32,
    pub declaration_order: usize,
    pub configured_action: ActionType,
    pub state: GuardResultState,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub satisfied_attributions: Vec<LeafAttribution>,
    pub evidence_fingerprint: String,
    pub completeness: EvaluationCompleteness,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum GuardResultState {
    Satisfied,
    Violated {
        causes: Vec<FailureCause>,
    },
    Faulted {
        faults: Vec<EvaluationFault>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        causes: Vec<FailureCause>,
    },
}

impl GuardResult {
    pub fn validate(&self) -> Result<(), GuardEvaluationContractError> {
        validate_text("guard_id", &self.guard_id, MAX_ID_CHARS)?;
        validate_text(
            "evidence_fingerprint",
            &self.evidence_fingerprint,
            MAX_ID_CHARS,
        )?;
        for attribution in &self.satisfied_attributions {
            attribution.validate()?;
        }
        match &self.state {
            GuardResultState::Satisfied => {
                if self.completeness == EvaluationCompleteness::IncompleteDueToFault {
                    return Err(GuardEvaluationContractError::InvalidField {
                        field: "completeness",
                        reason: "satisfied state cannot have completeness incomplete_due_to_fault",
                    });
                }
                Ok(())
            }
            GuardResultState::Violated { causes } => {
                if self.completeness == EvaluationCompleteness::IncompleteDueToFault {
                    return Err(GuardEvaluationContractError::InvalidField {
                        field: "completeness",
                        reason: "violated state cannot have completeness incomplete_due_to_fault",
                    });
                }
                for cause in causes {
                    cause.validate()?;
                }
                Ok(())
            }
            GuardResultState::Faulted { faults, causes } => {
                if faults.is_empty() {
                    return Err(GuardEvaluationContractError::InvalidField {
                        field: "faults",
                        reason: "faulted state must contain at least one fault",
                    });
                }
                if self.completeness != EvaluationCompleteness::IncompleteDueToFault {
                    return Err(GuardEvaluationContractError::InvalidField {
                        field: "completeness",
                        reason: "faulted state must have completeness incomplete_due_to_fault",
                    });
                }
                for fault in faults {
                    validate_evaluation_fault(fault)?;
                }
                for cause in causes {
                    cause.validate()?;
                }
                Ok(())
            }
        }
    }

    #[doc(hidden)]
    pub fn test_result(
        guard_id: impl Into<String>,
        order: u32,
        declaration_order: usize,
        configured_action: ActionType,
        satisfied: bool,
    ) -> Self {
        let guard_id = guard_id.into();
        let state = if satisfied {
            GuardResultState::Satisfied
        } else {
            GuardResultState::Violated { causes: Vec::new() }
        };
        Self {
            evidence_fingerprint: fingerprint(guard_id.as_bytes()),
            guard_id,
            order,
            declaration_order,
            configured_action,
            state,
            satisfied_attributions: Vec::new(),
            completeness: EvaluationCompleteness::Complete,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventEvaluationReport {
    pub schema: String,
    pub invocation_id: String,
    pub provider: ProviderTarget,
    pub event_id: String,
    pub event_type: ArcEventType,
    pub input_fingerprint: String,
    pub guard_results: Vec<GuardResult>,
    pub effective_disposition: EffectiveDisposition,
    pub authorization_requirements: Vec<ExactOperationAuthorization>,
    pub activation_cache_summary: ActivationCacheSummary,
    pub report_fingerprint: String,
    pub started_unix_ms: i64,
    pub completed_unix_ms: i64,
}

impl EventEvaluationReport {
    pub fn validate(&self) -> Result<(), GuardEvaluationContractError> {
        if self.schema != EVENT_EVALUATION_REPORT_SCHEMA {
            return Err(GuardEvaluationContractError::Schema {
                expected: EVENT_EVALUATION_REPORT_SCHEMA,
                actual: self.schema.clone(),
            });
        }
        validate_text("invocation_id", &self.invocation_id, MAX_ID_CHARS)?;
        validate_text("event_id", &self.event_id, MAX_ID_CHARS)?;
        validate_text("input_fingerprint", &self.input_fingerprint, MAX_ID_CHARS)?;
        validate_text("report_fingerprint", &self.report_fingerprint, MAX_ID_CHARS)?;
        let mut ids = BTreeSet::new();
        for result in &self.guard_results {
            result.validate()?;
            if !ids.insert(result.guard_id.as_str()) {
                return Err(GuardEvaluationContractError::DuplicateId {
                    field: "guard_results.guard_id",
                    value: result.guard_id.clone(),
                });
            }
        }
        let mut canonical_guard_results = self.guard_results.clone();
        sort_guard_results(&mut canonical_guard_results);
        if self.guard_results != canonical_guard_results {
            return Err(GuardEvaluationContractError::InvalidField {
                field: "guard_results",
                reason: "must use canonical order by order, declaration_order, and guard_id",
            });
        }
        let mut previous_auth: Option<&ExactOperationAuthorization> = None;
        for auth in &self.authorization_requirements {
            auth.validate()?;
            if !ids.contains(auth.guard_id.as_str()) {
                return Err(GuardEvaluationContractError::InvalidField {
                    field: "authorization_requirements.guard_id",
                    reason: "must match a guard_results.guard_id",
                });
            }
            if let Some(previous) = previous_auth
                && compare_authorization_requirements(previous, auth, &self.guard_results)
                    == std::cmp::Ordering::Greater
            {
                return Err(GuardEvaluationContractError::InvalidField {
                    field: "authorization_requirements",
                    reason: "must use canonical Guard order and exact-operation tie-breakers",
                });
            }
            previous_auth = Some(auth);
        }
        let expected_report_fingerprint = serde_json::to_vec(&self.guard_results)
            .map(|bytes| fingerprint(&bytes))
            .map_err(|_| GuardEvaluationContractError::InvalidField {
                field: "report_fingerprint",
                reason: "failed to serialize guard results for fingerprint calculation",
            })?;
        if self.report_fingerprint != expected_report_fingerprint {
            return Err(GuardEvaluationContractError::CorrelationMismatch {
                field: "report_fingerprint",
            });
        }
        let expected_disposition = reduce_effective_disposition(&self.guard_results);
        if self.effective_disposition != expected_disposition {
            return Err(GuardEvaluationContractError::InvalidField {
                field: "effective_disposition",
                reason: "does not match the reduced guard results precedence (INV-012)",
            });
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActivationCacheSummary {
    pub logical_occurrences: u64,
    pub unique_probe_evaluations: u64,
    pub unique_decision_evaluations: u64,
    pub coalesced_in_flight: u64,
    pub reused_completed: u64,
    pub physical_faults: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExactOperationAuthorization {
    pub guard_id: String,
    pub operation_fingerprint: String,
    pub event_id: String,
    pub tool: String,
    pub normalized_arguments_fingerprint: String,
}

impl ExactOperationAuthorization {
    pub fn validate(&self) -> Result<(), GuardEvaluationContractError> {
        validate_text("guard_id", &self.guard_id, MAX_ID_CHARS)?;
        validate_text(
            "operation_fingerprint",
            &self.operation_fingerprint,
            MAX_ID_CHARS,
        )?;
        validate_text("event_id", &self.event_id, MAX_ID_CHARS)?;
        validate_text("tool", &self.tool, MAX_ID_CHARS)?;
        validate_text(
            "normalized_arguments_fingerprint",
            &self.normalized_arguments_fingerprint,
            MAX_ID_CHARS,
        )?;
        Ok(())
    }
}

fn compare_authorization_requirements(
    left: &ExactOperationAuthorization,
    right: &ExactOperationAuthorization,
    guard_results: &[GuardResult],
) -> std::cmp::Ordering {
    let structural_order = match (
        guard_results
            .iter()
            .find(|guard| guard.guard_id == left.guard_id),
        guard_results
            .iter()
            .find(|guard| guard.guard_id == right.guard_id),
    ) {
        (Some(left_guard), Some(right_guard)) => (
            left_guard.order,
            left_guard.declaration_order,
            left_guard.guard_id.as_str(),
        )
            .cmp(&(
                right_guard.order,
                right_guard.declaration_order,
                right_guard.guard_id.as_str(),
            )),
        (Some(_), None) => std::cmp::Ordering::Less,
        (None, Some(_)) => std::cmp::Ordering::Greater,
        (None, None) => left.guard_id.cmp(&right.guard_id),
    };

    structural_order.then_with(|| {
        (
            left.operation_fingerprint.as_str(),
            left.event_id.as_str(),
            left.tool.as_str(),
            left.normalized_arguments_fingerprint.as_str(),
        )
            .cmp(&(
                right.operation_fingerprint.as_str(),
                right.event_id.as_str(),
                right.tool.as_str(),
                right.normalized_arguments_fingerprint.as_str(),
            ))
    })
}

fn sort_authorization_requirements(
    requirements: &mut [ExactOperationAuthorization],
    guard_results: &[GuardResult],
) {
    requirements
        .sort_by(|left, right| compare_authorization_requirements(left, right, guard_results));
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PresentationKind {
    GuardFailures,
    ExactOperationAuthorization,
    AggregateDecision,
}

/// A probe that ran and failed, as the decision dialog names it. It never
/// carries expected values or observed output.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DialogFailedProbe {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule_name: Option<String>,
    pub command: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DialogViolationItem {
    pub guard_id: String,
    pub summary: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub configured_feedback: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auditor_findings: Option<String>,
    pub scope: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub failed_probes: Vec<DialogFailedProbe>,
}

const NEGATED_TRUE_REASON: &str = "negated expression evaluated to true";

/// Builds the dialog entries for the probes that ran and failed in `causes`.
/// Only causes carrying probe evidence are listed; `decide` causes have none.
pub(crate) fn dialog_failed_probes_from_causes(causes: &[FailureCause]) -> Vec<DialogFailedProbe> {
    causes
        .iter()
        .filter_map(|cause| {
            let evidence = cause.deterministic_evidence.first()?;
            let rule_name = cause
                .expression_path
                .iter()
                .rev()
                .find_map(|segment| match segment {
                    ExpressionPathSegment::RuleRef { name } => {
                        Some(name.chars().take(MAX_ID_CHARS).collect::<String>())
                    }
                    _ => None,
                });
            let reason = matches!(cause.kind, FailureCauseKind::NegatedTrue)
                .then(|| NEGATED_TRUE_REASON.to_owned());
            Some(DialogFailedProbe {
                rule_name,
                command: evidence.operation.clone(),
                reason,
            })
        })
        .take(MAX_DIALOG_FAILED_PROBES)
        .collect()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DialogAuthorizationItem {
    pub guard_id: String,
    pub summary: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auditor_findings: Option<String>,
    pub operation_fingerprint: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DialogRequest {
    pub schema: String,
    pub request_id: String,
    pub presentation_kind: PresentationKind,
    pub title: String,
    pub scope: String,
    pub violations: Vec<DialogViolationItem>,
    pub authorizations: Vec<DialogAuthorizationItem>,
    pub operation: Option<String>,
    pub bundle_fingerprint: String,
    pub expires_at_unix_ms: i64,
}

impl DialogRequest {
    pub fn guard_failures(
        request_id: impl Into<String>,
        title: impl Into<String>,
        scope: impl Into<String>,
        violations: Vec<DialogViolationItem>,
        bundle_fingerprint: impl Into<String>,
        expires_at_unix_ms: i64,
    ) -> Self {
        Self {
            schema: DIALOG_REQUEST_SCHEMA.into(),
            request_id: request_id.into(),
            presentation_kind: PresentationKind::GuardFailures,
            title: title.into(),
            scope: scope.into(),
            violations,
            authorizations: Vec::new(),
            operation: None,
            bundle_fingerprint: bundle_fingerprint.into(),
            expires_at_unix_ms,
        }
    }

    pub fn exact_authorizations(
        request_id: impl Into<String>,
        title: impl Into<String>,
        scope: impl Into<String>,
        authorizations: Vec<DialogAuthorizationItem>,
        operation: impl Into<String>,
        bundle_fingerprint: impl Into<String>,
        expires_at_unix_ms: i64,
    ) -> Self {
        Self {
            schema: DIALOG_REQUEST_SCHEMA.into(),
            request_id: request_id.into(),
            presentation_kind: PresentationKind::ExactOperationAuthorization,
            title: title.into(),
            scope: scope.into(),
            violations: Vec::new(),
            authorizations,
            operation: Some(operation.into()),
            bundle_fingerprint: bundle_fingerprint.into(),
            expires_at_unix_ms,
        }
    }

    pub fn aggregate_decision(
        request_id: impl Into<String>,
        title: impl Into<String>,
        scope: impl Into<String>,
        violations: Vec<DialogViolationItem>,
        authorizations: Vec<DialogAuthorizationItem>,
        operation: Option<String>,
        bundle_fingerprint: impl Into<String>,
        expires_at_unix_ms: i64,
    ) -> Self {
        Self {
            schema: DIALOG_REQUEST_SCHEMA.into(),
            request_id: request_id.into(),
            presentation_kind: PresentationKind::AggregateDecision,
            title: title.into(),
            scope: scope.into(),
            violations,
            authorizations,
            operation,
            bundle_fingerprint: bundle_fingerprint.into(),
            expires_at_unix_ms,
        }
    }

    pub fn validate(&self) -> Result<(), GuardEvaluationContractError> {
        if self.schema != DIALOG_REQUEST_SCHEMA {
            return Err(GuardEvaluationContractError::Schema {
                expected: DIALOG_REQUEST_SCHEMA,
                actual: self.schema.clone(),
            });
        }
        validate_text("request_id", &self.request_id, MAX_ID_CHARS)?;
        validate_text("title", &self.title, MAX_TITLE_CHARS)?;
        validate_text("scope", &self.scope, MAX_SCOPE_CHARS)?;
        validate_text("bundle_fingerprint", &self.bundle_fingerprint, MAX_ID_CHARS)?;
        if self.expires_at_unix_ms < 0 {
            return Err(GuardEvaluationContractError::InvalidField {
                field: "expires_at_unix_ms",
                reason: "must not be negative",
            });
        }
        let mut ids = BTreeSet::new();
        for item in &self.violations {
            validate_text("violations.guard_id", &item.guard_id, MAX_ID_CHARS)?;
            validate_summary("violations.summary", &item.summary)?;
            if let Some(feedback) = &item.configured_feedback {
                validate_dialog_configured_feedback(feedback)?;
            }
            if let Some(findings) = &item.auditor_findings {
                validate_dialog_findings(findings)?;
            }
            validate_text("violations.scope", &item.scope, MAX_SCOPE_CHARS)?;
            validate_dialog_failed_probes(&item.failed_probes)?;
            if !ids.insert(item.guard_id.clone()) {
                return Err(GuardEvaluationContractError::DuplicateId {
                    field: "violations.guard_id",
                    value: item.guard_id.clone(),
                });
            }
        }
        if let Some(operation) = &self.operation {
            validate_text("operation", operation, MAX_OPERATION_CHARS)?;
        }
        match self.presentation_kind {
            PresentationKind::GuardFailures => {
                if self.violations.is_empty() {
                    return Err(GuardEvaluationContractError::InvalidField {
                        field: "violations",
                        reason: "GuardFailures requires at least one item",
                    });
                }
                if !self.authorizations.is_empty() {
                    return Err(GuardEvaluationContractError::InvalidField {
                        field: "authorizations",
                        reason: "GuardFailures cannot contain authorizations",
                    });
                }
            }
            PresentationKind::ExactOperationAuthorization => {
                if !self.violations.is_empty() || self.authorizations.is_empty() {
                    return Err(GuardEvaluationContractError::InvalidField {
                        field: "presentation_kind",
                        reason: "authorization presentations cannot contain violations and require authorizations",
                    });
                }
                for auth in &self.authorizations {
                    validate_text("authorizations.guard_id", &auth.guard_id, MAX_ID_CHARS)?;
                    validate_summary("authorizations.summary", &auth.summary)?;
                    if let Some(findings) = &auth.auditor_findings {
                        validate_dialog_findings(findings)?;
                    }
                    validate_text(
                        "authorizations.operation_fingerprint",
                        &auth.operation_fingerprint,
                        MAX_ID_CHARS,
                    )?;
                }
                if self.operation.is_none() {
                    return Err(GuardEvaluationContractError::InvalidField {
                        field: "operation",
                        reason: "authorization requires an exact operation",
                    });
                }
            }
            PresentationKind::AggregateDecision => {
                if self.violations.is_empty() && self.authorizations.is_empty() {
                    return Err(GuardEvaluationContractError::InvalidField {
                        field: "presentation_kind",
                        reason: "aggregate decision requires at least one violation or authorization",
                    });
                }
                for auth in &self.authorizations {
                    validate_text("authorizations.guard_id", &auth.guard_id, MAX_ID_CHARS)?;
                    validate_summary("authorizations.summary", &auth.summary)?;
                    if let Some(findings) = &auth.auditor_findings {
                        validate_dialog_findings(findings)?;
                    }
                    validate_text(
                        "authorizations.operation_fingerprint",
                        &auth.operation_fingerprint,
                        MAX_ID_CHARS,
                    )?;
                }
                if !self.authorizations.is_empty() && self.operation.is_none() {
                    return Err(GuardEvaluationContractError::InvalidField {
                        field: "operation",
                        reason: "authorization requires an exact operation",
                    });
                }
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DialogResponse {
    pub schema: String,
    pub request_id: String,
    pub bundle_fingerprint: String,
    pub decision: PortableDecision,
    pub transport: String,
    pub theme: String,
    pub message: Option<String>,
}

impl DialogResponse {
    pub fn validate_for(
        &self,
        request: &DialogRequest,
    ) -> Result<(), GuardEvaluationContractError> {
        request.validate()?;
        if self.schema != DIALOG_RESPONSE_SCHEMA {
            return Err(GuardEvaluationContractError::Schema {
                expected: DIALOG_RESPONSE_SCHEMA,
                actual: self.schema.clone(),
            });
        }
        if self.request_id != request.request_id {
            return Err(GuardEvaluationContractError::CorrelationMismatch {
                field: "request_id",
            });
        }
        if self.bundle_fingerprint != request.bundle_fingerprint {
            return Err(GuardEvaluationContractError::CorrelationMismatch {
                field: "bundle_fingerprint",
            });
        }
        validate_text("transport", &self.transport, MAX_ID_CHARS)?;
        validate_text("theme", &self.theme, MAX_ID_CHARS)?;
        if let Some(message) = &self.message {
            validate_dialog_message("message", message)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FailureBundle {
    pub schema: String,
    pub bundle_id: String,
    pub invocation_id: String,
    pub event_id: String,
    pub event_type: ArcEventType,
    pub effective_disposition: EffectiveDisposition,
    pub failed_guards: Vec<FailedGuardFeedback>,
    pub evaluation_faults: Vec<EvaluationFault>,
    pub completeness: EvaluationCompleteness,
    pub input_fingerprint: String,
    pub bundle_fingerprint: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FailedGuardFeedback {
    pub guard_id: String,
    pub configured_action: ActionType,
    #[serde(default)]
    pub faulted: bool,
    pub configured_feedback: Option<String>,
    pub causes: Vec<FailureCause>,
    pub evidence_fingerprint: String,
}

#[derive(Debug, Error)]
pub enum FailureBundleError {
    #[error("failure bundle serialization failed")]
    Serialization(#[source] serde_json::Error),
    #[error("invalid failure bundle: {0}")]
    InvalidBundle(String),
    #[error("inline provider feedback is too large: {bytes} bytes exceeds {max} bytes")]
    InlineTooLarge { bytes: usize, max: usize },
}

/// An opaque trust anchor verifying that a `BehaviorIR` matches an externally authenticated digest
/// (e.g. from the SQLite `trusted_irs` store).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TrustedIrAnchor {
    digest: String,
}

impl TrustedIrAnchor {
    /// Package-internal constructor: creates an anchor from an authenticated digest verified
    /// by a trusted state store (such as `SqliteStateStore`).
    pub(crate) fn from_authenticated_store_digest(digest: impl Into<String>) -> Self {
        Self {
            digest: digest.into().to_ascii_lowercase(),
        }
    }

    /// Returns the authenticated digest string.
    pub fn digest(&self) -> &str {
        &self.digest
    }
}

impl FailureBundle {
    /// Builds a deterministic bundle without dropping any violated or
    /// faulted Guard. Configured feedback is left unpopulated (`None`)
    /// because this constructor does not verify an external trust anchor.
    pub fn from_report(report: &EventEvaluationReport) -> Result<Self, FailureBundleError> {
        Self::from_report_with_feedback(report, &BTreeMap::new())
    }

    /// Builds a bundle whose configured feedback is read from a BehaviorIR
    /// verified against an opaque external trust anchor.
    pub fn from_report_with_trusted_anchor(
        report: &EventEvaluationReport,
        ir: &BehaviorIR,
        anchor: &TrustedIrAnchor,
    ) -> Result<Self, FailureBundleError> {
        if !ir.matches_digest(anchor.digest()) {
            return Err(FailureBundleError::InvalidBundle(format!(
                "BehaviorIR external digest mismatch: expected authentic digest '{}', got raw bytes digest '{}'",
                anchor.digest(),
                ir.compute_raw_bytes_digest()
            )));
        }
        let configured_feedback = configured_feedback_from_behavior_ir(report, ir)?;
        Self::from_report_with_feedback(report, &configured_feedback)
    }

    pub(crate) fn from_report_with_feedback(
        report: &EventEvaluationReport,
        configured_feedback: &BTreeMap<String, Option<String>>,
    ) -> Result<Self, FailureBundleError> {
        let report_guard_ids = report
            .guard_results
            .iter()
            .map(|guard| guard.guard_id.as_str())
            .collect::<BTreeSet<_>>();
        if let Some(unexpected_guard_id) = configured_feedback
            .keys()
            .find(|guard_id| !report_guard_ids.contains(guard_id.as_str()))
        {
            return Err(FailureBundleError::InvalidBundle(format!(
                "configured feedback contains Guard '{}' absent from report",
                unexpected_guard_id
            )));
        }
        let expected_disposition = reduce_effective_disposition(&report.guard_results);
        if report.effective_disposition != expected_disposition {
            return Err(FailureBundleError::InvalidBundle(format!(
                "report effective disposition {:?} does not match reduced guard results precedence {:?}",
                report.effective_disposition, expected_disposition
            )));
        }
        let mut failed_guards = Vec::new();
        let mut evaluation_faults = Vec::new();
        let mut completeness = EvaluationCompleteness::Complete;
        for result in &report.guard_results {
            match &result.state {
                GuardResultState::Satisfied => {}
                GuardResultState::Violated { causes } => failed_guards.push(FailedGuardFeedback {
                    guard_id: result.guard_id.clone(),
                    configured_action: result.configured_action,
                    faulted: false,
                    configured_feedback: configured_feedback
                        .get(result.guard_id.as_str())
                        .cloned()
                        .flatten(),
                    causes: causes.clone(),
                    evidence_fingerprint: result.evidence_fingerprint.clone(),
                }),
                GuardResultState::Faulted { faults, causes } => {
                    failed_guards.push(FailedGuardFeedback {
                        guard_id: result.guard_id.clone(),
                        configured_action: result.configured_action,
                        faulted: true,
                        configured_feedback: configured_feedback
                            .get(result.guard_id.as_str())
                            .cloned()
                            .flatten(),
                        causes: causes.clone(),
                        evidence_fingerprint: result.evidence_fingerprint.clone(),
                    });
                    evaluation_faults.extend(faults.clone());
                }
            }
            completeness = merge_completeness(completeness, result.completeness);
        }
        let identity = serde_json::to_vec(&(
            &report.invocation_id,
            &report.event_id,
            report.event_type,
            report.effective_disposition,
            &failed_guards,
            &evaluation_faults,
            completeness,
            &report.input_fingerprint,
        ))
        .map_err(FailureBundleError::Serialization)?;
        let mut bundle = Self {
            schema: FAILURE_BUNDLE_SCHEMA.into(),
            bundle_id: format!("bundle-{}", fingerprint(&identity)),
            invocation_id: report.invocation_id.clone(),
            event_id: report.event_id.clone(),
            event_type: report.event_type,
            effective_disposition: report.effective_disposition,
            failed_guards,
            evaluation_faults,
            completeness,
            input_fingerprint: report.input_fingerprint.clone(),
            bundle_fingerprint: String::new(),
        };
        bundle.bundle_fingerprint = calculate_bundle_fingerprint(&bundle)?;
        Ok(bundle)
    }

    pub fn validate(&self) -> Result<(), FailureBundleError> {
        if self.schema != FAILURE_BUNDLE_SCHEMA {
            return Err(FailureBundleError::InvalidBundle(format!(
                "schema must be '{FAILURE_BUNDLE_SCHEMA}'"
            )));
        }
        validate_text("bundle_id", &self.bundle_id, MAX_ID_CHARS)
            .map_err(|error| FailureBundleError::InvalidBundle(error.to_string()))?;
        validate_text("invocation_id", &self.invocation_id, MAX_ID_CHARS)
            .map_err(|error| FailureBundleError::InvalidBundle(error.to_string()))?;
        validate_text("event_id", &self.event_id, MAX_ID_CHARS)
            .map_err(|error| FailureBundleError::InvalidBundle(error.to_string()))?;
        validate_text("input_fingerprint", &self.input_fingerprint, MAX_ID_CHARS)
            .map_err(|error| FailureBundleError::InvalidBundle(error.to_string()))?;
        validate_text("bundle_fingerprint", &self.bundle_fingerprint, MAX_ID_CHARS)
            .map_err(|error| FailureBundleError::InvalidBundle(error.to_string()))?;

        let mut guard_ids = BTreeSet::new();
        for guard in &self.failed_guards {
            if !guard_ids.insert(guard.guard_id.as_str()) {
                return Err(FailureBundleError::InvalidBundle(format!(
                    "duplicate failed guard id '{}'",
                    guard.guard_id
                )));
            }
            validate_text("failed_guards.guard_id", &guard.guard_id, MAX_ID_CHARS)
                .map_err(|error| FailureBundleError::InvalidBundle(error.to_string()))?;
            validate_text(
                "failed_guards.evidence_fingerprint",
                &guard.evidence_fingerprint,
                MAX_ID_CHARS,
            )
            .map_err(|error| FailureBundleError::InvalidBundle(error.to_string()))?;
            if let Some(feedback) = &guard.configured_feedback {
                if contains_unsupported_markup(feedback) {
                    return Err(FailureBundleError::InvalidBundle(
                        "failed_guards.configured_feedback contains unsupported markup".into(),
                    ));
                }
            }
            for cause in &guard.causes {
                cause
                    .validate()
                    .map_err(|error| FailureBundleError::InvalidBundle(error.to_string()))?;
            }
        }
        for fault in &self.evaluation_faults {
            validate_evaluation_fault(fault)
                .map_err(|error| FailureBundleError::InvalidBundle(error.to_string()))?;
        }
        let expected_fingerprint = calculate_bundle_fingerprint(self)?;
        if self.bundle_fingerprint != expected_fingerprint {
            return Err(FailureBundleError::InvalidBundle(format!(
                "bundle fingerprint mismatch: expected {expected_fingerprint}, got {}",
                self.bundle_fingerprint
            )));
        }
        Ok(())
    }
}

fn configured_feedback_from_behavior_ir(
    report: &EventEvaluationReport,
    ir: &BehaviorIR,
) -> Result<BTreeMap<String, Option<String>>, FailureBundleError> {
    report
        .validate()
        .map_err(|error| FailureBundleError::InvalidBundle(format!("invalid report: {error}")))?;
    if ir.content_hash.is_none() {
        return Err(FailureBundleError::InvalidBundle(
            "BehaviorIR content_hash is required to establish configured feedback provenance"
                .into(),
        ));
    }
    ir.validate_integrity().map_err(|error| {
        FailureBundleError::InvalidBundle(format!(
            "BehaviorIR integrity validation failed: {error}"
        ))
    })?;

    let mut guards = BTreeMap::<String, (u32, usize, ActionType, Option<String>)>::new();
    for guard in &ir.lifecycle_guards {
        if guards
            .insert(
                guard.id.clone(),
                (
                    guard.order,
                    guard.declaration_order,
                    guard.on_failure.action,
                    guard.on_failure.feedback.clone(),
                ),
            )
            .is_some()
        {
            return Err(FailureBundleError::InvalidBundle(format!(
                "BehaviorIR contains duplicate Guard '{}'",
                guard.id
            )));
        }
    }
    for guard in &ir.tool_guards {
        if guards
            .insert(
                guard.id.clone(),
                (
                    guard.order,
                    guard.declaration_order,
                    guard.on_failure.action,
                    guard.on_failure.feedback.clone(),
                ),
            )
            .is_some()
        {
            return Err(FailureBundleError::InvalidBundle(format!(
                "BehaviorIR contains duplicate Guard '{}'",
                guard.id
            )));
        }
    }

    let mut configured_feedback = BTreeMap::new();
    for result in &report.guard_results {
        let Some((order, declaration_order, action, feedback)) = guards.get(&result.guard_id)
        else {
            return Err(FailureBundleError::InvalidBundle(format!(
                "report Guard '{}' is absent from BehaviorIR",
                result.guard_id
            )));
        };
        if (*order, *declaration_order, *action)
            != (
                result.order,
                result.declaration_order,
                result.configured_action,
            )
        {
            return Err(FailureBundleError::InvalidBundle(format!(
                "BehaviorIR configuration for Guard '{}' does not match report identity",
                result.guard_id
            )));
        }
        configured_feedback.insert(result.guard_id.clone(), feedback.clone());
    }
    Ok(configured_feedback)
}

fn calculate_bundle_fingerprint(bundle: &FailureBundle) -> Result<String, FailureBundleError> {
    let mut unsigned = bundle.clone();
    unsigned.bundle_fingerprint.clear();
    let bytes = serde_json::to_vec(&unsigned).map_err(FailureBundleError::Serialization)?;
    Ok(fingerprint(&bytes))
}

/// Canonical aggregate evaluation result representing the lossless projection of an activation.
/// Retains the complete underlying report, dominant disposition, all exact authorization requirements,
/// and the comprehensive failure bundle across all evaluated guards.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArcEvaluationResult {
    pub report: EventEvaluationReport,
    pub effective_disposition: EffectiveDisposition,
    pub authorization_requirements: Vec<ExactOperationAuthorization>,
    pub failure_bundle: FailureBundle,
}

/// Strongly typed errors produced during canonical aggregate projection, validation, or coordination.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ArcEvaluationError {
    #[error(
        "Unsupported simultaneous interactive domains: GuardFailures ({guard_failures:?}) and ExactOperationAuthorization ({authorizations:?}) cannot be combined"
    )]
    SimultaneousInteractiveDomains {
        guard_failures: Vec<String>,
        authorizations: Vec<String>,
    },
    #[error("Evaluation report invariant violation: {reason}")]
    InvalidReport { reason: String },
    #[error("Durable state store error: {0}")]
    StoreError(String),
    #[error("Runtime evaluation fault: {0}")]
    RuntimeFault(String),
}

impl ArcEvaluationResult {
    /// Builds an aggregate result directly from an evaluation report by deriving its failure bundle
    /// without unverified configured feedback.
    pub fn from_report(report: EventEvaluationReport) -> Result<Self, ArcEvaluationError> {
        let bundle =
            FailureBundle::from_report(&report).map_err(|e| ArcEvaluationError::InvalidReport {
                reason: e.to_string(),
            })?;
        Self::from_report_and_bundle(report, bundle)
    }

    /// Builds an aggregate result using configured feedback from a BehaviorIR
    /// verified against an opaque external trust anchor.
    pub fn from_report_with_trusted_anchor(
        report: EventEvaluationReport,
        ir: &BehaviorIR,
        anchor: &TrustedIrAnchor,
    ) -> Result<Self, ArcEvaluationError> {
        let bundle =
            FailureBundle::from_report_with_trusted_anchor(&report, ir, anchor).map_err(|e| {
                ArcEvaluationError::InvalidReport {
                    reason: e.to_string(),
                }
            })?;
        Self::from_report_and_bundle(report, bundle)
    }

    /// Builds an aggregate result from an evaluation report and an existing failure bundle,
    /// validating all projection, correlation, and domain invariants atomically.
    pub fn from_report_and_bundle(
        report: EventEvaluationReport,
        failure_bundle: FailureBundle,
    ) -> Result<Self, ArcEvaluationError> {
        let result = Self {
            effective_disposition: report.effective_disposition,
            authorization_requirements: report.authorization_requirements.clone(),
            failure_bundle,
            report,
        };
        result.validate()?;
        Ok(result)
    }

    /// Enforces the aggregate contract invariants (§4.2, §4.3, §4.4, INV-006, INV-012):
    /// 1. Report and FailureBundle internal validity.
    /// 2. Effective disposition and authorization requirements match the report exactly.
    /// 3. Activation contextual identity matches between report and failure bundle.
    /// 4. Failed guards in the bundle match the violated/faulted guards in the report.
    /// 5. Authorization requirements correlate to the report's event and have no duplicate guard IDs.
    /// 6. Defensive rejection: simultaneous interactive domains (Ask violations + ExactOperationAuthorization)
    ///    must fail closed rather than silently dropping either requirement or synthesizing grants.
    pub fn validate(&self) -> Result<(), ArcEvaluationError> {
        self.report
            .validate()
            .map_err(|error| ArcEvaluationError::InvalidReport {
                reason: format!("report validation failed: {error}"),
            })?;
        self.failure_bundle
            .validate()
            .map_err(|error| ArcEvaluationError::InvalidReport {
                reason: format!("failure bundle validation failed: {error}"),
            })?;

        if self.effective_disposition != self.report.effective_disposition {
            return Err(ArcEvaluationError::InvalidReport {
                reason: format!(
                    "effective_disposition {:?} does not match report effective_disposition {:?}",
                    self.effective_disposition, self.report.effective_disposition
                ),
            });
        }

        if self.authorization_requirements != self.report.authorization_requirements {
            return Err(ArcEvaluationError::InvalidReport {
                reason: "authorization_requirements do not match report authorization_requirements"
                    .into(),
            });
        }

        if self.failure_bundle.invocation_id != self.report.invocation_id {
            return Err(ArcEvaluationError::InvalidReport {
                reason: format!(
                    "failure bundle invocation_id '{}' does not match report invocation_id '{}'",
                    self.failure_bundle.invocation_id, self.report.invocation_id
                ),
            });
        }
        if self.failure_bundle.event_id != self.report.event_id {
            return Err(ArcEvaluationError::InvalidReport {
                reason: format!(
                    "failure bundle event_id '{}' does not match report event_id '{}'",
                    self.failure_bundle.event_id, self.report.event_id
                ),
            });
        }
        if self.failure_bundle.event_type != self.report.event_type {
            return Err(ArcEvaluationError::InvalidReport {
                reason: format!(
                    "failure bundle event_type {:?} does not match report event_type {:?}",
                    self.failure_bundle.event_type, self.report.event_type
                ),
            });
        }
        if self.failure_bundle.input_fingerprint != self.report.input_fingerprint {
            return Err(ArcEvaluationError::InvalidReport {
                reason: format!(
                    "failure bundle input_fingerprint '{}' does not match report input_fingerprint '{}'",
                    self.failure_bundle.input_fingerprint, self.report.input_fingerprint
                ),
            });
        }
        if self.failure_bundle.effective_disposition != self.report.effective_disposition {
            return Err(ArcEvaluationError::InvalidReport {
                reason: format!(
                    "failure bundle effective_disposition {:?} does not match report effective_disposition {:?}",
                    self.failure_bundle.effective_disposition, self.report.effective_disposition
                ),
            });
        }

        let report_failed_ids: BTreeSet<&str> = self
            .report
            .guard_results
            .iter()
            .filter(|g| {
                matches!(
                    g.state,
                    GuardResultState::Violated { .. } | GuardResultState::Faulted { .. }
                )
            })
            .map(|g| g.guard_id.as_str())
            .collect();
        let bundle_failed_ids: BTreeSet<&str> = self
            .failure_bundle
            .failed_guards
            .iter()
            .map(|g| g.guard_id.as_str())
            .collect();
        if report_failed_ids != bundle_failed_ids {
            return Err(ArcEvaluationError::InvalidReport {
                reason: format!(
                    "failed guards mismatch between report ({:?}) and failure bundle ({:?})",
                    report_failed_ids, bundle_failed_ids
                ),
            });
        }

        let report_failed_results: Vec<&GuardResult> = self
            .report
            .guard_results
            .iter()
            .filter(|guard| {
                matches!(
                    guard.state,
                    GuardResultState::Violated { .. } | GuardResultState::Faulted { .. }
                )
            })
            .collect();
        if report_failed_results.len() != self.failure_bundle.failed_guards.len() {
            return Err(ArcEvaluationError::InvalidReport {
                reason: format!(
                    "failed guard projection length mismatch: report has {}, failure bundle has {}",
                    report_failed_results.len(),
                    self.failure_bundle.failed_guards.len()
                ),
            });
        }

        let mut expected_evaluation_faults = Vec::new();
        let mut expected_completeness = EvaluationCompleteness::Complete;
        for result in &self.report.guard_results {
            expected_completeness = merge_completeness(expected_completeness, result.completeness);
            if let GuardResultState::Faulted { faults, .. } = &result.state {
                expected_evaluation_faults.extend(faults.clone());
            }
        }
        if self.failure_bundle.evaluation_faults != expected_evaluation_faults {
            return Err(ArcEvaluationError::InvalidReport {
                reason: "failure bundle evaluation_faults do not match the report projection"
                    .into(),
            });
        }
        if self.failure_bundle.completeness != expected_completeness {
            return Err(ArcEvaluationError::InvalidReport {
                reason: format!(
                    "failure bundle completeness {:?} does not match report projection {:?}",
                    self.failure_bundle.completeness, expected_completeness
                ),
            });
        }

        for (index, (result, feedback)) in report_failed_results
            .iter()
            .zip(&self.failure_bundle.failed_guards)
            .enumerate()
        {
            let (expected_faulted, expected_causes) = match &result.state {
                GuardResultState::Violated { causes } => (false, causes),
                GuardResultState::Faulted { causes, .. } => (true, causes),
                GuardResultState::Satisfied => {
                    return Err(ArcEvaluationError::InvalidReport {
                        reason: format!(
                            "internal failed Guard projection contains satisfied Guard '{}'",
                            result.guard_id
                        ),
                    });
                }
            };
            if feedback.guard_id != result.guard_id {
                return Err(ArcEvaluationError::InvalidReport {
                    reason: format!(
                        "failure bundle failed_guards[{index}].guard_id '{}' does not match report guard_id '{}'",
                        feedback.guard_id, result.guard_id
                    ),
                });
            }
            if feedback.configured_action != result.configured_action {
                return Err(ArcEvaluationError::InvalidReport {
                    reason: format!(
                        "failure bundle configured_action for Guard '{}' does not match report",
                        result.guard_id
                    ),
                });
            }
            if feedback.faulted != expected_faulted {
                return Err(ArcEvaluationError::InvalidReport {
                    reason: format!(
                        "failure bundle faulted for Guard '{}' does not match report",
                        result.guard_id
                    ),
                });
            }
            if feedback.causes.as_slice() != expected_causes.as_slice() {
                return Err(ArcEvaluationError::InvalidReport {
                    reason: format!(
                        "failure bundle causes for Guard '{}' do not match report",
                        result.guard_id
                    ),
                });
            }
            if feedback.evidence_fingerprint != result.evidence_fingerprint {
                return Err(ArcEvaluationError::InvalidReport {
                    reason: format!(
                        "failure bundle evidence_fingerprint for Guard '{}' does not match report",
                        result.guard_id
                    ),
                });
            }
        }

        let mut seen_auth_guards = BTreeSet::new();
        for auth in &self.authorization_requirements {
            if auth.event_id != self.report.event_id {
                return Err(ArcEvaluationError::InvalidReport {
                    reason: format!(
                        "authorization requirement event_id '{}' does not match report event_id '{}'",
                        auth.event_id, self.report.event_id
                    ),
                });
            }
            if !seen_auth_guards.insert(auth.guard_id.as_str()) {
                return Err(ArcEvaluationError::InvalidReport {
                    reason: format!(
                        "duplicate guard_id '{}' in authorization_requirements",
                        auth.guard_id
                    ),
                });
            }
        }

        Ok(())
    }
}

fn merge_completeness(
    left: EvaluationCompleteness,
    right: EvaluationCompleteness,
) -> EvaluationCompleteness {
    if left == EvaluationCompleteness::IncompleteDueToFault
        || right == EvaluationCompleteness::IncompleteDueToFault
    {
        EvaluationCompleteness::IncompleteDueToFault
    } else if left == EvaluationCompleteness::CompleteForGuardResultWithNonCausalSkips
        || right == EvaluationCompleteness::CompleteForGuardResultWithNonCausalSkips
    {
        EvaluationCompleteness::CompleteForGuardResultWithNonCausalSkips
    } else {
        EvaluationCompleteness::Complete
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum GuardEvaluationContractError {
    #[error("{field} must not be empty")]
    EmptyField { field: &'static str },
    #[error("{field} exceeds the {max} character limit (got {actual})")]
    FieldTooLong {
        field: &'static str,
        max: usize,
        actual: usize,
    },
    #[error("{field} exceeds the {max} item limit (got {actual})")]
    CollectionTooLarge {
        field: &'static str,
        max: usize,
        actual: usize,
    },
    #[error("{field} contains unsupported markup")]
    UnsupportedMarkup { field: &'static str },
    #[error("invalid {field}: {reason}")]
    InvalidField {
        field: &'static str,
        reason: &'static str,
    },
    #[error("{field} contains duplicate value '{value}'")]
    DuplicateId { field: &'static str, value: String },
    #[error("schema mismatch: expected '{expected}', got '{actual}'")]
    Schema {
        expected: &'static str,
        actual: String,
    },
    #[error("correlation field '{field}' does not match the request")]
    CorrelationMismatch { field: &'static str },
}

fn validate_text(
    field: &'static str,
    value: &str,
    max: usize,
) -> Result<(), GuardEvaluationContractError> {
    if value.trim().is_empty() {
        return Err(GuardEvaluationContractError::EmptyField { field });
    }
    validate_text_allow_empty(field, value, max)
}

fn validate_text_allow_empty(
    field: &'static str,
    value: &str,
    max: usize,
) -> Result<(), GuardEvaluationContractError> {
    let actual = value.chars().count();
    if actual > max {
        return Err(GuardEvaluationContractError::FieldTooLong { field, max, actual });
    }
    Ok(())
}

fn contains_unsupported_markup(value: &str) -> bool {
    let bytes = value.as_bytes();
    let len = bytes.len();
    for i in 0..len {
        if bytes[i] == b'<' {
            let mut j = i + 1;
            if j < len && (bytes[j] == b'/' || bytes[j] == b'!') {
                j += 1;
            }
            if j < len && (bytes[j].is_ascii_alphabetic() || bytes[j] == b'-') {
                if bytes[j..].contains(&b'>') {
                    return true;
                }
            }
        }
    }
    false
}

fn validate_summary(field: &'static str, value: &str) -> Result<(), GuardEvaluationContractError> {
    validate_text(field, value, MAX_SUMMARY_CHARS)?;
    if contains_unsupported_markup(value) {
        return Err(GuardEvaluationContractError::UnsupportedMarkup { field });
    }
    Ok(())
}

fn validate_dialog_failed_probes(
    probes: &[DialogFailedProbe],
) -> Result<(), GuardEvaluationContractError> {
    if probes.len() > MAX_DIALOG_FAILED_PROBES {
        return Err(GuardEvaluationContractError::CollectionTooLarge {
            field: "violations.failed_probes",
            max: MAX_DIALOG_FAILED_PROBES,
            actual: probes.len(),
        });
    }
    for probe in probes {
        validate_text(
            "violations.failed_probes.command",
            &probe.command,
            MAX_ID_CHARS,
        )?;
        if let Some(rule_name) = &probe.rule_name {
            validate_text(
                "violations.failed_probes.rule_name",
                rule_name,
                MAX_ID_CHARS,
            )?;
        }
        if let Some(reason) = &probe.reason {
            validate_summary("violations.failed_probes.reason", reason)?;
        }
    }
    Ok(())
}

fn validate_dialog_findings(value: &str) -> Result<(), GuardEvaluationContractError> {
    const FIELD: &str = "violations.auditor_findings";
    validate_text(FIELD, value, MAX_DIALOG_AUDITOR_FINDINGS_CHARS)?;
    if value.contains('<') || value.contains('>') {
        return Err(GuardEvaluationContractError::UnsupportedMarkup { field: FIELD });
    }
    Ok(())
}

fn validate_dialog_configured_feedback(value: &str) -> Result<(), GuardEvaluationContractError> {
    const FIELD: &str = "violations.configured_feedback";
    validate_text(FIELD, value, MAX_DIALOG_CONFIGURED_FEEDBACK_CHARS)?;
    if value.contains('<') || value.contains('>') {
        return Err(GuardEvaluationContractError::UnsupportedMarkup { field: FIELD });
    }
    Ok(())
}

fn validate_dialog_message(
    field: &'static str,
    value: &str,
) -> Result<(), GuardEvaluationContractError> {
    validate_text(field, value, MAX_DIALOG_USER_MESSAGE_CHARS)?;
    if value.contains('<') || value.contains('>') {
        return Err(GuardEvaluationContractError::UnsupportedMarkup { field });
    }
    Ok(())
}

fn validate_matcher_evidence(
    items: &[MatcherEvidence],
) -> Result<(), GuardEvaluationContractError> {
    if items.len() > MAX_MATCHER_EVIDENCE_ITEMS {
        return Err(GuardEvaluationContractError::CollectionTooLarge {
            field: "matcher_evidence",
            max: MAX_MATCHER_EVIDENCE_ITEMS,
            actual: items.len(),
        });
    }
    for item in items {
        validate_text("matcher_evidence.kind", &item.kind, MAX_ID_CHARS)?;
        validate_text("matcher_evidence.matcher", &item.matcher, MAX_SCOPE_CHARS)?;
    }
    Ok(())
}

fn validate_deterministic_evidence(
    items: &[DeterministicEvidence],
) -> Result<(), GuardEvaluationContractError> {
    if items.len() > MAX_DETERMINISTIC_EVIDENCE_ITEMS {
        return Err(GuardEvaluationContractError::CollectionTooLarge {
            field: "deterministic_evidence",
            max: MAX_DETERMINISTIC_EVIDENCE_ITEMS,
            actual: items.len(),
        });
    }
    for item in items {
        validate_text(
            "deterministic_evidence.operation",
            &item.operation,
            MAX_ID_CHARS,
        )?;
        validate_text(
            "deterministic_evidence.observed_sha256",
            &item.observed_sha256,
            MAX_ID_CHARS,
        )?;
        if item.rule_path.len() > MAX_RULE_PATH_SEGMENTS {
            return Err(GuardEvaluationContractError::CollectionTooLarge {
                field: "deterministic_evidence.rule_path",
                max: MAX_RULE_PATH_SEGMENTS,
                actual: item.rule_path.len(),
            });
        }
        for path in &item.rule_path {
            validate_text("deterministic_evidence.rule_path", path, MAX_ID_CHARS)?;
        }
        if item.expected_values.len() > MAX_EXPECTED_VALUES_ITEMS {
            return Err(GuardEvaluationContractError::CollectionTooLarge {
                field: "deterministic_evidence.expected_values",
                max: MAX_EXPECTED_VALUES_ITEMS,
                actual: item.expected_values.len(),
            });
        }
        for expected in &item.expected_values {
            validate_text_allow_empty(
                "deterministic_evidence.expected_values",
                expected,
                MAX_SUMMARY_CHARS,
            )?;
        }
    }
    Ok(())
}

/// Returns a framed, deterministic key for the complete semantic decision input.
pub fn decision_evaluation_key(
    profile: &DecisionExecutionProfile,
    input: &DecisionEvaluationInput,
) -> String {
    fingerprint(&canonical_decision_evaluation_bytes(profile, input))
}

pub fn canonical_decision_evaluation_bytes(
    profile: &DecisionExecutionProfile,
    input: &DecisionEvaluationInput,
) -> Vec<u8> {
    let mut bytes = Vec::new();
    encode_str(&mut bytes, "profile.provider", profile.provider.as_str());
    encode_str(&mut bytes, "profile.transport", &profile.transport);
    encode_optional_str(&mut bytes, "profile.model", profile.model.as_deref());
    encode_str(
        &mut bytes,
        "profile.adapter_contract_fingerprint",
        &profile.adapter_contract_fingerprint,
    );
    encode_str(
        &mut bytes,
        "profile.output_schema_fingerprint",
        &profile.output_schema_fingerprint,
    );
    encode_str(&mut bytes, "profile.sandbox_mode", &profile.sandbox_mode);
    encode_str(
        &mut bytes,
        "profile.approval_policy",
        &profile.approval_policy,
    );
    encode_str(&mut bytes, "input.goal", &input.goal);
    encode_str(&mut bytes, "input.role", &input.role);
    encode_current_operation(&mut bytes, &input.current_operation);
    encode_session_context(&mut bytes, &input.session_context);
    encode_semantic_evidence(&mut bytes, &input.attested_evidence);
    bytes
}

/// Returns the stable identity of the exact tool operation associated with a
/// ToolCall. This fingerprint is separate from the decision key so a model
/// verdict can never be mistaken for authorization of a different operation.
pub fn exact_operation_fingerprint(operation: &CurrentOperation) -> String {
    let mut bytes = Vec::new();
    encode_current_operation(&mut bytes, operation);
    fingerprint(&bytes)
}

/// Returns the stable identity of normalized tool arguments only. The
/// operation fingerprint remains the stronger binding because it also covers
/// event type, tool name, and command text.
pub fn normalized_arguments_fingerprint(operation: &CurrentOperation) -> String {
    let mut bytes = Vec::new();
    match &operation.input {
        Some(input) => {
            bytes.push(1);
            encode_json_value(&mut bytes, input);
        }
        None => bytes.push(0),
    }
    fingerprint(&bytes)
}

pub fn probe_evaluation_key(input: &ProbeEvaluationInput) -> String {
    fingerprint(&canonical_probe_evaluation_bytes(input))
}

pub fn canonical_probe_evaluation_bytes(input: &ProbeEvaluationInput) -> Vec<u8> {
    let mut bytes = Vec::new();
    encode_str(
        &mut bytes,
        "probe.resolved_command",
        &input.resolved_command,
    );
    encode_str(
        &mut bytes,
        "probe.canonical_workspace_root",
        &input.canonical_workspace_root.to_string_lossy(),
    );
    encode_str(
        &mut bytes,
        "probe.effective_environment_fingerprint",
        &input.effective_environment_fingerprint,
    );
    encode_str(
        &mut bytes,
        "probe.runner_contract_fingerprint",
        &input.runner_contract_fingerprint,
    );
    encode_u64(&mut bytes, "probe.timeout_ms", input.timeout_ms);
    encode_u64(&mut bytes, "probe.max_output_bytes", input.max_output_bytes);
    bytes
}

pub fn occurrence_id(
    schema_version: &str,
    invocation_id: &str,
    guard_id: &str,
    expression_path: &[ExpressionPathSegment],
    normalized_consumer_contract: &str,
) -> String {
    let mut bytes = Vec::new();
    encode_str(&mut bytes, "schema_version", schema_version);
    encode_str(&mut bytes, "invocation_id", invocation_id);
    encode_str(&mut bytes, "guard_id", guard_id);
    encode_path(&mut bytes, expression_path);
    encode_str(
        &mut bytes,
        "normalized_consumer_contract",
        normalized_consumer_contract,
    );
    fingerprint(&bytes)
}

pub fn physical_evaluation_id(activation_id: &str, evaluation_key: &str) -> String {
    let mut bytes = Vec::new();
    encode_str(&mut bytes, "activation_id", activation_id);
    encode_str(&mut bytes, "evaluation_key", evaluation_key);
    fingerprint(&bytes)
}

pub fn expression_path_key(path: &[ExpressionPathSegment]) -> String {
    let mut bytes = Vec::new();
    encode_path(&mut bytes, path);
    fingerprint(&bytes)
}

pub fn reduce_rule_expression(
    expression: &BoundRuleExpression,
    rules_catalog: &BTreeMap<String, BoundRuleExpression>,
    leaf_results: &BTreeMap<String, LeafResult>,
) -> Result<RuleReduction, ReductionError> {
    reduce_expression(
        expression,
        rules_catalog,
        leaf_results,
        &mut Vec::new(),
        &mut Vec::new(),
    )
}

#[allow(clippy::too_many_arguments)]
pub fn reduce_guard_result(
    guard_id: impl Into<String>,
    order: u32,
    declaration_order: usize,
    configured_action: ActionType,
    evidence_fingerprint: impl Into<String>,
    expression: &BoundRuleExpression,
    rules_catalog: &BTreeMap<String, BoundRuleExpression>,
    leaf_results: &BTreeMap<String, LeafResult>,
) -> Result<GuardResult, ReductionError> {
    let reduction = reduce_rule_expression(expression, rules_catalog, leaf_results)?;
    let state = if reduction.faults.is_empty() {
        match reduction.decision {
            Some(true) => GuardResultState::Satisfied,
            Some(false) => GuardResultState::Violated {
                causes: reduction.causes,
            },
            None => GuardResultState::Faulted {
                faults: vec![EvaluationFault::InvalidPlan {
                    summary: "reducer produced no decision and no fault".into(),
                }],
                causes: reduction.causes,
            },
        }
    } else {
        GuardResultState::Faulted {
            faults: reduction.faults,
            causes: reduction.causes,
        }
    };
    Ok(GuardResult {
        guard_id: guard_id.into(),
        order,
        declaration_order,
        configured_action,
        state,
        satisfied_attributions: reduction.satisfied_attributions,
        evidence_fingerprint: evidence_fingerprint.into(),
        completeness: reduction.completeness,
    })
}

pub fn sort_guard_results(results: &mut [GuardResult]) {
    results.sort_by(|left, right| {
        (left.order, left.declaration_order, left.guard_id.as_str()).cmp(&(
            right.order,
            right.declaration_order,
            right.guard_id.as_str(),
        ))
    });
}

pub fn reduce_effective_disposition(results: &[GuardResult]) -> EffectiveDisposition {
    if results
        .iter()
        .any(|result| matches!(result.state, GuardResultState::Faulted { .. }))
    {
        return EffectiveDisposition::RuntimeFault;
    }
    if results.iter().any(|result| {
        matches!(
            (&result.configured_action, &result.state),
            (ActionType::Deny, GuardResultState::Violated { .. })
        )
    }) {
        return EffectiveDisposition::Deny;
    }
    if results.iter().any(|result| {
        matches!(
            (&result.configured_action, &result.state),
            (ActionType::Ask, GuardResultState::Violated { .. })
        )
    }) {
        return EffectiveDisposition::Ask;
    }
    if results.iter().any(|result| {
        matches!(
            (&result.configured_action, &result.state),
            (ActionType::Message, GuardResultState::Violated { .. })
        )
    }) {
        return EffectiveDisposition::Message;
    }
    EffectiveDisposition::Continue
}

#[derive(Debug, Clone)]
pub enum ExecutionPlanNode {
    Probe {
        path: Vec<ExpressionPathSegment>,
        occurrence_id: String,
        evaluation_key: String,
        canonical_bytes: Vec<u8>,
        resolved_command: Result<String, String>,
        expected_in: Vec<String>,
    },
    Decide {
        path: Vec<ExpressionPathSegment>,
        occurrence_id: String,
        prompt: String,
    },
    Not {
        path: Vec<ExpressionPathSegment>,
        child: Box<ExecutionPlanNode>,
    },
    All {
        path: Vec<ExpressionPathSegment>,
        children: Vec<ExecutionPlanNode>,
    },
    Any {
        path: Vec<ExpressionPathSegment>,
        children: Vec<ExecutionPlanNode>,
    },
}

#[derive(Debug, Clone)]
struct PendingDecision {
    expression_path: Vec<ExpressionPathSegment>,
    occurrence_id: String,
    evaluation_key: String,
    canonical_bytes: Vec<u8>,
    request: DecisionTaskRequest,
}

#[derive(Debug, Clone)]
struct GuardEvaluationWork {
    spec: GuardEvaluationSpec,
    plan: Option<ExecutionPlanNode>,
    planning_fault: Option<EvaluationFault>,
    leaf_results: BTreeMap<String, LeafResult>,
    deterministic_evidence: Vec<DeterministicEvidence>,
    deterministic_evidence_truncated: bool,
    pending_decisions: Vec<PendingDecision>,
}

/// Evaluates all physical leaves in a batch while preserving one logical
/// result for every guard occurrence. The cache is supplied by the hook
/// activation owner and is never persisted by this function.
#[allow(clippy::too_many_arguments)]
pub fn evaluate_all_guards_with_cache_concurrency(
    snapshot: &ActivationSnapshot,
    guards: &[GuardEvaluationSpec],
    rules_catalog: &BTreeMap<String, BoundRuleExpression>,
    workspace_root: &Path,
    effective_environment_fingerprint: &str,
    runner_contract_fingerprint: &str,
    decision_profile: &DecisionExecutionProfile,
    cache: &ActivationEvaluationCache,
    probe_runner: Arc<dyn ProbeRunner>,
    decision_provider: Option<Arc<dyn DecisionProvider>>,
    scheduler_concurrency: usize,
) -> Result<EventEvaluationReport, GuardEvaluationBatchError> {
    evaluate_all_guards_with_cache_sequential(
        snapshot,
        guards,
        rules_catalog,
        workspace_root,
        effective_environment_fingerprint,
        runner_contract_fingerprint,
        decision_profile,
        cache,
        probe_runner,
        decision_provider,
        scheduler_concurrency,
    )
}

#[allow(clippy::too_many_arguments)]
fn evaluate_all_guards_with_cache_sequential(
    snapshot: &ActivationSnapshot,
    guards: &[GuardEvaluationSpec],
    rules_catalog: &BTreeMap<String, BoundRuleExpression>,
    workspace_root: &Path,
    effective_environment_fingerprint: &str,
    runner_contract_fingerprint: &str,
    decision_profile: &DecisionExecutionProfile,
    cache: &ActivationEvaluationCache,
    probe_runner: Arc<dyn ProbeRunner>,
    decision_provider: Option<Arc<dyn DecisionProvider>>,
    scheduler_concurrency: usize,
) -> Result<EventEvaluationReport, GuardEvaluationBatchError> {
    validate_guard_ids_unique(guards)?;
    if snapshot.event_type == ArcEventType::Start {
        for guard in guards {
            if guard.action == ActionType::Ask {
                return Err(GuardEvaluationBatchError::Planning {
                    guard_id: guard.guard_id.clone(),
                    message: "lifecycle start guard cannot use action ask".into(),
                });
            }
        }
    }
    // Without a provider, a profile defect is reported only after we know whether decision
    // tasks exist, so the missing provider (a configuration error) takes precedence.
    let profile_error =
        decision_profile
            .validate()
            .err()
            .map(|error| GuardEvaluationBatchError::Planning {
                guard_id: String::new(),
                message: format!("invalid decision execution profile: {error}"),
            });
    if let Some(error) = profile_error.clone()
        && decision_provider.is_some()
    {
        return Err(error);
    }
    if decision_profile.provider != snapshot.provider {
        return Err(GuardEvaluationBatchError::Planning {
            guard_id: String::new(),
            message: "decision execution profile provider does not match the evaluation snapshot"
                .into(),
        });
    }
    let canonical_workspace_root =
        std::fs::canonicalize(workspace_root).unwrap_or_else(|_| workspace_root.to_path_buf());

    let mut work = Vec::with_capacity(guards.len());
    for guard in guards {
        let mut path = Vec::new();
        let mut active_rules = Vec::new();
        let (plan, planning_fault) = match plan_guard_expression(
            &guard.expression,
            rules_catalog,
            snapshot,
            guard,
            &canonical_workspace_root,
            effective_environment_fingerprint,
            runner_contract_fingerprint,
            &mut path,
            &mut active_rules,
        ) {
            Ok(p) => (Some(p), None),
            Err(fault) => (None, Some(fault)),
        };
        work.push(GuardEvaluationWork {
            spec: guard.clone(),
            plan,
            planning_fault,
            leaf_results: BTreeMap::new(),
            deterministic_evidence: Vec::new(),
            deterministic_evidence_truncated: false,
            pending_decisions: Vec::new(),
        });
    }

    // Probe observations are established lazily (without speculative execution across
    // branches that have already failed in All or succeeded in Any, per INV-010, EC-037).
    for guard_work in &mut work {
        if guard_work.planning_fault.is_some() {
            continue;
        }
        if let Some(plan) = &guard_work.plan {
            let _ = evaluate_plan_lazily(
                plan,
                snapshot,
                &guard_work.spec.scope,
                &guard_work.spec.matcher_evidence,
                guard_work.spec.matcher_evidence_truncated,
                decision_profile,
                cache.activation_id(),
                cache,
                probe_runner.as_ref(),
                &mut guard_work.leaf_results,
                &mut guard_work.deterministic_evidence,
                &mut guard_work.deterministic_evidence_truncated,
                &mut guard_work.pending_decisions,
            );
        }
    }

    let mut decision_tasks: BTreeMap<String, DecisionTaskRequest> = BTreeMap::new();
    for guard_work in &work {
        for pending in &guard_work.pending_decisions {
            if let Some(existing) = decision_tasks.get(&pending.evaluation_key) {
                if existing.input != pending.request.input
                    || existing.profile != pending.request.profile
                {
                    return Err(GuardEvaluationBatchError::Planning {
                        guard_id: guard_work.spec.guard_id.clone(),
                        message: "decision evaluation key collision with different semantic input"
                            .into(),
                    });
                }
            } else {
                decision_tasks.insert(pending.evaluation_key.clone(), pending.request.clone());
            }
        }
    }

    if decision_tasks.is_empty()
        && let Some(error) = profile_error
    {
        return Err(error);
    }

    let scheduled_results = if decision_tasks.is_empty() {
        Vec::new()
    } else {
        let executor: Arc<dyn PhysicalDecisionExecutor> = match decision_provider {
            Some(provider) => Arc::new(DecisionProviderExecutor::new(
                provider,
                decision_profile.transport.clone(),
            )),
            None => {
                return Err(GuardEvaluationBatchError::MissingDecisionProvider {
                    transport: decision_profile.transport.clone(),
                });
            }
        };
        DecisionScheduler::new(scheduler_concurrency.max(1))
            .map_err(|error| GuardEvaluationBatchError::Planning {
                guard_id: String::new(),
                message: format!("decision scheduler could not start: {error}"),
            })?
            .run(
                decision_tasks.into_values().collect(),
                executor,
                unix_timestamp_ms,
            )
            .map_err(|error| GuardEvaluationBatchError::Planning {
                guard_id: String::new(),
                message: format!("decision scheduler failed: {error}"),
            })?
            .results
    };
    for result in &scheduled_results {
        if matches!(result, DecisionTaskResult::Faulted { .. }) {
            cache.note_physical_fault(LeafEvaluationKind::Decision, decision_result_key(result))?;
        }
    }
    let scheduled_by_key: BTreeMap<_, _> = scheduled_results
        .into_iter()
        .map(|result| (decision_result_key(&result).to_owned(), result))
        .collect();

    let mut guard_results = Vec::with_capacity(guards.len());
    let mut authorization_requirements = BTreeMap::new();
    for guard_work in &mut work {
        if let Some(fault) = &guard_work.planning_fault {
            let evidence_fingerprint = fingerprint(
                format!(
                    "{}\0{}",
                    guard_work.spec.guard_id, snapshot.input_fingerprint
                )
                .as_bytes(),
            );
            guard_results.push(GuardResult {
                guard_id: guard_work.spec.guard_id.clone(),
                order: guard_work.spec.order,
                declaration_order: guard_work.spec.declaration_order,
                configured_action: guard_work.spec.action,
                state: GuardResultState::Faulted {
                    faults: vec![fault.clone()],
                    causes: Vec::new(),
                },
                satisfied_attributions: Vec::new(),
                evidence_fingerprint,
                completeness: EvaluationCompleteness::IncompleteDueToFault,
            });
            continue;
        }

        for pending in &guard_work.pending_decisions {
            let scheduled = scheduled_by_key
                .get(&pending.evaluation_key)
                .ok_or_else(|| GuardEvaluationBatchError::Planning {
                    guard_id: guard_work.spec.guard_id.clone(),
                    message: "decision scheduler omitted a requested evaluation".into(),
                })?;
            let scheduled = scheduled.clone();
            let resolution = cache.resolve_decision(
                &pending.evaluation_key,
                pending.canonical_bytes.clone(),
                &pending.occurrence_id,
                || scheduled,
            )?;
            let leaf_result = match resolution.result {
                DecisionTaskResult::Satisfied { findings, .. } => {
                    if snapshot.event_type == ArcEventType::ToolCall
                        && let Some(tool) = snapshot.current_operation.tool.as_deref()
                    {
                        let operation_fingerprint =
                            exact_operation_fingerprint(&snapshot.current_operation);
                        authorization_requirements
                            .entry((
                                guard_work.spec.guard_id.clone(),
                                operation_fingerprint.clone(),
                            ))
                            .or_insert_with(|| ExactOperationAuthorization {
                                guard_id: guard_work.spec.guard_id.clone(),
                                operation_fingerprint,
                                event_id: snapshot.event_id.clone(),
                                tool: tool.to_owned(),
                                normalized_arguments_fingerprint: normalized_arguments_fingerprint(
                                    &snapshot.current_operation,
                                ),
                            });
                    }
                    let normalized_findings = findings.and_then(|f| {
                        let trimmed = f.trim();
                        (!trimmed.is_empty()).then(|| bounded_summary(trimmed))
                    });
                    LeafResult::Satisfied {
                        attribution: Some(LeafAttribution {
                            occurrence_id: resolution.occurrence_id,
                            physical_evaluation_id: resolution.physical_evaluation_id,
                            cache_provenance: resolution.provenance,
                            expression_path: pending.expression_path.clone(),
                            summary: normalized_findings
                                .clone()
                                .unwrap_or_else(|| "decision evaluated to satisfied".into()),
                            auditor_findings: normalized_findings,
                            deterministic_evidence: Vec::new(),
                        }),
                    }
                }
                DecisionTaskResult::Violated { findings, .. } => {
                    let trimmed = findings.trim();
                    let (summary, auditor_findings) = if trimmed.is_empty() {
                        ("decision provider rejected the goal".to_string(), None)
                    } else if trimmed == "decision provider rejected the goal" {
                        (trimmed.to_string(), None)
                    } else {
                        (bounded_summary(trimmed), Some(bounded_summary(trimmed)))
                    };
                    LeafResult::Violated {
                        cause: FailureCause {
                            occurrence_id: resolution.occurrence_id,
                            physical_evaluation_id: resolution.physical_evaluation_id,
                            cache_provenance: resolution.provenance,
                            expression_path: pending.expression_path.clone(),
                            kind: FailureCauseKind::DecisionViolated,
                            summary,
                            auditor_findings,
                            deterministic_evidence: Vec::new(),
                        },
                    }
                }
                DecisionTaskResult::Faulted { fault, .. } => LeafResult::Faulted {
                    fault: EvaluationFault::Decision {
                        summary: bounded_summary(&format!("decision task fault: {fault:?}")),
                    },
                },
            };
            guard_work
                .leaf_results
                .insert(expression_path_key(&pending.expression_path), leaf_result);
        }

        let evidence_fingerprint = fingerprint(
            serde_json::to_vec(&guard_work.deterministic_evidence)
                .map_err(|_| GuardEvaluationBatchError::ReportSerialization)?
                .as_slice(),
        );
        let result = match reduce_guard_result(
            guard_work.spec.guard_id.clone(),
            guard_work.spec.order,
            guard_work.spec.declaration_order,
            guard_work.spec.action,
            evidence_fingerprint.clone(),
            &guard_work.spec.expression,
            rules_catalog,
            &guard_work.leaf_results,
        ) {
            Ok(res) => res,
            Err(error) => {
                let fault = match error {
                    ReductionError::RuleCycle { rule_name } => {
                        EvaluationFault::RuleCycle { rule_name }
                    }
                    ReductionError::MissingRule { rule_name } => {
                        EvaluationFault::MissingRule { rule_name }
                    }
                    ReductionError::MissingLeaf { expression_path } => {
                        EvaluationFault::MissingLeaf { expression_path }
                    }
                };
                GuardResult {
                    guard_id: guard_work.spec.guard_id.clone(),
                    order: guard_work.spec.order,
                    declaration_order: guard_work.spec.declaration_order,
                    configured_action: guard_work.spec.action,
                    state: GuardResultState::Faulted {
                        faults: vec![fault],
                        causes: Vec::new(),
                    },
                    satisfied_attributions: Vec::new(),
                    evidence_fingerprint,
                    completeness: EvaluationCompleteness::IncompleteDueToFault,
                }
            }
        };
        guard_results.push(result);
    }

    sort_guard_results(&mut guard_results);
    let effective_disposition = reduce_effective_disposition(&guard_results);
    let report_fingerprint = serde_json::to_vec(&guard_results)
        .map(|bytes| fingerprint(&bytes))
        .map_err(|_| GuardEvaluationBatchError::ReportSerialization)?;
    let mut authorization_requirements =
        authorization_requirements.into_values().collect::<Vec<_>>();
    sort_authorization_requirements(&mut authorization_requirements, &guard_results);
    let activation_cache_summary = cache.summary();
    Ok(EventEvaluationReport {
        schema: EVENT_EVALUATION_REPORT_SCHEMA.into(),
        invocation_id: snapshot.invocation_id.clone(),
        provider: snapshot.provider,
        event_id: snapshot.event_id.clone(),
        event_type: snapshot.event_type,
        input_fingerprint: snapshot.input_fingerprint.clone(),
        guard_results,
        effective_disposition,
        authorization_requirements,
        activation_cache_summary,
        report_fingerprint,
        started_unix_ms: 0,
        completed_unix_ms: 0,
    })
}

fn plan_guard_expression(
    expression: &BoundRuleExpression,
    rules_catalog: &BTreeMap<String, BoundRuleExpression>,
    snapshot: &ActivationSnapshot,
    guard: &GuardEvaluationSpec,
    canonical_workspace_root: &Path,
    effective_environment_fingerprint: &str,
    runner_contract_fingerprint: &str,
    path: &mut Vec<ExpressionPathSegment>,
    active_rules: &mut Vec<String>,
) -> Result<ExecutionPlanNode, EvaluationFault> {
    match expression {
        BoundRuleExpression::Probe {
            command,
            expected_in,
        } => {
            let occurrence_id = occurrence_id(
                "arc.guard_evaluation.v1",
                &snapshot.invocation_id,
                &guard.guard_id,
                path,
                "normalized_guard_leaf",
            );
            let (resolved_command, evaluation_key, canonical_bytes) = match command
                .resolve_for_host()
            {
                Ok(cmd) => {
                    let cmd_str = cmd.to_string();
                    let input = ProbeEvaluationInput {
                        resolved_command: cmd_str.clone(),
                        canonical_workspace_root: canonical_workspace_root.to_path_buf(),
                        effective_environment_fingerprint: effective_environment_fingerprint.into(),
                        runner_contract_fingerprint: runner_contract_fingerprint.into(),
                        timeout_ms: 30_000,
                        max_output_bytes: MAX_PROBE_OUTPUT_BYTES as u64,
                    };
                    (
                        Ok(cmd_str),
                        probe_evaluation_key(&input),
                        canonical_probe_evaluation_bytes(&input),
                    )
                }
                Err(err) => (Err(err.to_string()), String::new(), Vec::new()),
            };
            Ok(ExecutionPlanNode::Probe {
                path: path.clone(),
                occurrence_id,
                evaluation_key,
                canonical_bytes,
                resolved_command,
                expected_in: expected_in.clone(),
            })
        }
        BoundRuleExpression::Decide { prompt } => {
            let occurrence_id = occurrence_id(
                "arc.guard_evaluation.v1",
                &snapshot.invocation_id,
                &guard.guard_id,
                path,
                "normalized_guard_leaf",
            );
            Ok(ExecutionPlanNode::Decide {
                path: path.clone(),
                occurrence_id,
                prompt: prompt.clone(),
            })
        }
        BoundRuleExpression::RuleRef { name } => {
            if active_rules.iter().any(|active| active == name) {
                return Err(EvaluationFault::RuleCycle {
                    rule_name: name.clone(),
                });
            }
            let target = rules_catalog
                .get(name)
                .ok_or_else(|| EvaluationFault::MissingRule {
                    rule_name: name.clone(),
                })?;
            active_rules.push(name.clone());
            path.push(ExpressionPathSegment::RuleRef { name: name.clone() });
            let result = plan_guard_expression(
                target,
                rules_catalog,
                snapshot,
                guard,
                canonical_workspace_root,
                effective_environment_fingerprint,
                runner_contract_fingerprint,
                path,
                active_rules,
            );
            path.pop();
            active_rules.pop();
            result
        }
        BoundRuleExpression::Not(child) => {
            path.push(ExpressionPathSegment::Not);
            let planned_child = plan_guard_expression(
                child,
                rules_catalog,
                snapshot,
                guard,
                canonical_workspace_root,
                effective_environment_fingerprint,
                runner_contract_fingerprint,
                path,
                active_rules,
            )?;
            path.pop();
            Ok(ExecutionPlanNode::Not {
                path: path.clone(),
                child: Box::new(planned_child),
            })
        }
        BoundRuleExpression::All(children) => {
            let mut planned_children = Vec::with_capacity(children.len());
            for (index, child) in children.iter().enumerate() {
                path.push(ExpressionPathSegment::All { index });
                let planned = plan_guard_expression(
                    child,
                    rules_catalog,
                    snapshot,
                    guard,
                    canonical_workspace_root,
                    effective_environment_fingerprint,
                    runner_contract_fingerprint,
                    path,
                    active_rules,
                )?;
                path.pop();
                planned_children.push(planned);
            }
            Ok(ExecutionPlanNode::All {
                path: path.clone(),
                children: planned_children,
            })
        }
        BoundRuleExpression::Any(children) => {
            let mut planned_children = Vec::with_capacity(children.len());
            for (index, child) in children.iter().enumerate() {
                path.push(ExpressionPathSegment::Any { index });
                let planned = plan_guard_expression(
                    child,
                    rules_catalog,
                    snapshot,
                    guard,
                    canonical_workspace_root,
                    effective_environment_fingerprint,
                    runner_contract_fingerprint,
                    path,
                    active_rules,
                )?;
                path.pop();
                planned_children.push(planned);
            }
            Ok(ExecutionPlanNode::Any {
                path: path.clone(),
                children: planned_children,
            })
        }
    }
}

fn mark_skipped_plan_leaves(
    node: &ExecutionPlanNode,
    leaf_results: &mut BTreeMap<String, LeafResult>,
) {
    match node {
        ExecutionPlanNode::Probe {
            path,
            occurrence_id,
            resolved_command,
            ..
        } => {
            let key = expression_path_key(path);
            if !leaf_results.contains_key(&key) {
                let cmd_summary = match resolved_command {
                    Ok(cmd) => bounded_summary(cmd),
                    Err(err) => bounded_summary(err),
                };
                leaf_results.insert(
                    key,
                    LeafResult::SkippedNonCausal {
                        occurrence_id: occurrence_id.clone(),
                        expression_path: path.clone(),
                        summary: format!("probe '{cmd_summary}' skipped non-causal"),
                    },
                );
            }
        }
        ExecutionPlanNode::Decide {
            path,
            occurrence_id,
            prompt,
        } => {
            let key = expression_path_key(path);
            if !leaf_results.contains_key(&key) {
                leaf_results.insert(
                    key,
                    LeafResult::SkippedNonCausal {
                        occurrence_id: occurrence_id.clone(),
                        expression_path: path.clone(),
                        summary: format!(
                            "decision '{}' skipped non-causal",
                            bounded_summary(prompt)
                        ),
                    },
                );
            }
        }
        ExecutionPlanNode::Not { child, .. } => {
            mark_skipped_plan_leaves(child, leaf_results);
        }
        ExecutionPlanNode::All { children, .. } | ExecutionPlanNode::Any { children, .. } => {
            for child in children {
                mark_skipped_plan_leaves(child, leaf_results);
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn evaluate_plan_lazily(
    node: &ExecutionPlanNode,
    snapshot: &ActivationSnapshot,
    guard_scope: &str,
    matcher_evidence: &[MatcherEvidence],
    matcher_evidence_truncated: bool,
    decision_profile: &DecisionExecutionProfile,
    activation_id: &str,
    cache: &ActivationEvaluationCache,
    probe_runner: &dyn ProbeRunner,
    leaf_results: &mut BTreeMap<String, LeafResult>,
    deterministic_evidence: &mut Vec<DeterministicEvidence>,
    deterministic_evidence_truncated: &mut bool,
    pending_decisions: &mut Vec<PendingDecision>,
) -> Result<Option<bool>, GuardEvaluationBatchError> {
    match node {
        ExecutionPlanNode::Probe {
            path,
            occurrence_id,
            evaluation_key,
            canonical_bytes,
            resolved_command,
            expected_in,
        } => {
            let cmd_str = match resolved_command {
                Ok(cmd) => cmd.clone(),
                Err(error) => {
                    let leaf_result = LeafResult::Faulted {
                        fault: EvaluationFault::Probe {
                            summary: bounded_summary(&format!(
                                "probe command cannot be resolved: {error}"
                            )),
                        },
                    };
                    leaf_results.insert(expression_path_key(path), leaf_result);
                    return Ok(Some(false));
                }
            };

            let cmd_for_closure = cmd_str.clone();
            let resolution = cache.resolve_probe(
                evaluation_key,
                canonical_bytes.clone(),
                occurrence_id,
                || match probe_runner.run_probe(&cmd_for_closure) {
                    Ok(output) if output.len() > MAX_PROBE_OUTPUT_BYTES => {
                        Err("probe output exceeded the configured byte limit".into())
                    }
                    Ok(output) => Ok(output),
                    Err(error) => Err(error.to_string()),
                },
            )?;
            if resolution.result.is_err() {
                cache.note_physical_fault(LeafEvaluationKind::Probe, evaluation_key)?;
            }
            let (leaf_result, outcome) = match resolution.result {
                Ok(output) => {
                    let trimmed = output.trim();
                    let matched = expected_in
                        .iter()
                        .any(|expected| expected.trim() == trimmed);
                    let leaf_evidence = DeterministicEvidence {
                        rule_path: path_segments(path),
                        operation: cmd_str.chars().take(MAX_ID_CHARS).collect(),
                        expected_values: expected_in
                            .iter()
                            .take(MAX_EXPECTED_VALUES_ITEMS)
                            .map(|value| value.chars().take(MAX_SUMMARY_CHARS).collect())
                            .collect(),
                        result: matched,
                        observed_sha256: fingerprint(trimmed.as_bytes()),
                    };
                    if deterministic_evidence.len() < MAX_DETERMINISTIC_EVIDENCE_ITEMS {
                        deterministic_evidence.push(leaf_evidence.clone());
                    } else {
                        *deterministic_evidence_truncated = true;
                    }
                    if matched {
                        (
                            LeafResult::Satisfied {
                                attribution: Some(LeafAttribution {
                                    occurrence_id: resolution.occurrence_id,
                                    physical_evaluation_id: resolution.physical_evaluation_id,
                                    cache_provenance: resolution.provenance,
                                    expression_path: path.clone(),
                                    summary: format!(
                                        "probe '{}' matched expected value",
                                        bounded_summary(&cmd_str)
                                    ),
                                    auditor_findings: None,
                                    deterministic_evidence: vec![leaf_evidence],
                                }),
                            },
                            Some(true),
                        )
                    } else {
                        (
                            LeafResult::Violated {
                                cause: FailureCause {
                                    occurrence_id: resolution.occurrence_id,
                                    physical_evaluation_id: resolution.physical_evaluation_id,
                                    cache_provenance: resolution.provenance,
                                    expression_path: path.clone(),
                                    kind: FailureCauseKind::ProbeMismatch,
                                    summary: format!(
                                        "probe '{}' did not match an expected value",
                                        bounded_summary(&cmd_str)
                                    ),
                                    auditor_findings: None,
                                    deterministic_evidence: vec![leaf_evidence],
                                },
                            },
                            Some(false),
                        )
                    }
                }
                Err(summary) => (
                    LeafResult::Faulted {
                        fault: EvaluationFault::Probe {
                            summary: bounded_summary(&summary),
                        },
                    },
                    Some(false),
                ),
            };
            leaf_results.insert(expression_path_key(path), leaf_result);
            Ok(outcome)
        }
        ExecutionPlanNode::Decide {
            path,
            occurrence_id,
            prompt,
        } => {
            let key = expression_path_key(path);
            if !leaf_results.contains_key(&key) {
                let evidence = SemanticDecisionEvidence {
                    event_type: snapshot.event_type,
                    event_id: snapshot.event_id.clone(),
                    scope: guard_scope.to_string(),
                    matcher_evidence: matcher_evidence.to_vec(),
                    matcher_evidence_truncated,
                    deterministic_evidence: deterministic_evidence.clone(),
                    deterministic_evidence_truncated: *deterministic_evidence_truncated,
                };
                let input = DecisionEvaluationInput {
                    goal: prompt.clone(),
                    role: "read_only_compliance_auditor".into(),
                    current_operation: snapshot.current_operation.clone(),
                    session_context: snapshot.session_context.clone(),
                    attested_evidence: evidence,
                };
                let evaluation_key = decision_evaluation_key(decision_profile, &input);
                let canonical_bytes = canonical_decision_evaluation_bytes(decision_profile, &input);
                let request = DecisionTaskRequest {
                    schema: DECISION_TASK_REQUEST_SCHEMA.into(),
                    physical_evaluation_id: physical_evaluation_id(activation_id, &evaluation_key),
                    activation_id: activation_id.into(),
                    invocation_id: snapshot.invocation_id.clone(),
                    evaluation_key: evaluation_key.clone(),
                    profile: decision_profile.clone(),
                    input,
                    absolute_deadline_unix_ms: snapshot.absolute_deadline_unix_ms,
                };
                pending_decisions.push(PendingDecision {
                    expression_path: path.clone(),
                    occurrence_id: occurrence_id.clone(),
                    evaluation_key,
                    canonical_bytes,
                    request,
                });
            }
            Ok(None)
        }
        ExecutionPlanNode::Not { child, .. } => {
            let child_res = evaluate_plan_lazily(
                child,
                snapshot,
                guard_scope,
                matcher_evidence,
                matcher_evidence_truncated,
                decision_profile,
                activation_id,
                cache,
                probe_runner,
                leaf_results,
                deterministic_evidence,
                deterministic_evidence_truncated,
                pending_decisions,
            )?;
            Ok(child_res.map(|val| !val))
        }
        ExecutionPlanNode::All { children, .. } => {
            let mut all_true = true;
            let mut has_none = false;
            for (index, child) in children.iter().enumerate() {
                let child_res = evaluate_plan_lazily(
                    child,
                    snapshot,
                    guard_scope,
                    matcher_evidence,
                    matcher_evidence_truncated,
                    decision_profile,
                    activation_id,
                    cache,
                    probe_runner,
                    leaf_results,
                    deterministic_evidence,
                    deterministic_evidence_truncated,
                    pending_decisions,
                )?;
                match child_res {
                    Some(false) => {
                        for remaining_child in children.iter().skip(index + 1) {
                            mark_skipped_plan_leaves(remaining_child, leaf_results);
                        }
                        return Ok(Some(false));
                    }
                    Some(true) => {}
                    None => {
                        has_none = true;
                        all_true = false;
                    }
                }
            }
            if all_true {
                Ok(Some(true))
            } else if has_none {
                Ok(None)
            } else {
                Ok(Some(false))
            }
        }
        ExecutionPlanNode::Any { children, .. } => {
            let mut has_none = false;
            for (index, child) in children.iter().enumerate() {
                let child_res = evaluate_plan_lazily(
                    child,
                    snapshot,
                    guard_scope,
                    matcher_evidence,
                    matcher_evidence_truncated,
                    decision_profile,
                    activation_id,
                    cache,
                    probe_runner,
                    leaf_results,
                    deterministic_evidence,
                    deterministic_evidence_truncated,
                    pending_decisions,
                )?;
                match child_res {
                    Some(true) => {
                        for remaining_child in children.iter().skip(index + 1) {
                            mark_skipped_plan_leaves(remaining_child, leaf_results);
                        }
                        return Ok(Some(true));
                    }
                    Some(false) => {}
                    None => {
                        has_none = true;
                    }
                }
            }
            if has_none { Ok(None) } else { Ok(Some(false)) }
        }
    }
}

fn validate_guard_ids_unique(
    guards: &[GuardEvaluationSpec],
) -> Result<(), GuardEvaluationBatchError> {
    let mut seen = BTreeSet::new();
    for guard in guards {
        if guard.guard_id.trim().is_empty() {
            return Err(GuardEvaluationBatchError::Planning {
                guard_id: guard.guard_id.clone(),
                message: "guard id must not be empty".into(),
            });
        }
        if !seen.insert(guard.guard_id.as_str()) {
            return Err(GuardEvaluationBatchError::DuplicateGuardId {
                guard_id: guard.guard_id.clone(),
            });
        }
    }
    Ok(())
}

fn path_segments(path: &[ExpressionPathSegment]) -> Vec<String> {
    path.iter()
        .map(|segment| match segment {
            ExpressionPathSegment::All { index } => format!("all[{index}]"),
            ExpressionPathSegment::Any { index } => format!("any[{index}]"),
            ExpressionPathSegment::Not => "not".into(),
            ExpressionPathSegment::RuleRef { name } => format!("rule:{name}"),
        })
        .collect()
}

fn bounded_summary(value: &str) -> String {
    value.chars().take(MAX_SUMMARY_CHARS).collect()
}

fn unix_timestamp_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis().min(i64::MAX as u128) as i64)
        .unwrap_or(0)
}

fn reduce_expression(
    expression: &BoundRuleExpression,
    rules_catalog: &BTreeMap<String, BoundRuleExpression>,
    leaf_results: &BTreeMap<String, LeafResult>,
    path: &mut Vec<ExpressionPathSegment>,
    active_rule_refs: &mut Vec<String>,
) -> Result<RuleReduction, ReductionError> {
    match expression {
        BoundRuleExpression::Probe { .. } | BoundRuleExpression::Decide { .. } => {
            let key = expression_path_key(path);
            let result = leaf_results.get(&key).ok_or(ReductionError::MissingLeaf {
                expression_path: key,
            })?;
            Ok(match result {
                LeafResult::Satisfied { attribution } => {
                    let mut reduction = RuleReduction::from_decision(true);
                    if let Some(attr) = attribution {
                        reduction.satisfied_attributions.push(attr.clone());
                    }
                    reduction
                }
                LeafResult::Violated { cause } => {
                    let mut reduction = RuleReduction::from_decision(false);
                    reduction.causes.push(cause.clone());
                    reduction
                }
                LeafResult::Faulted { fault } => RuleReduction::faulted(fault.clone()),
                LeafResult::SkippedNonCausal { .. }
                | LeafResult::SkippedUnsafeToSpeculate { .. } => {
                    let mut reduction = RuleReduction::from_decision(false);
                    reduction.decision = None;
                    reduction.completeness =
                        EvaluationCompleteness::CompleteForGuardResultWithNonCausalSkips;
                    reduction
                }
            })
        }
        BoundRuleExpression::RuleRef { name } => {
            if active_rule_refs.iter().any(|active| active == name) {
                return Err(ReductionError::RuleCycle {
                    rule_name: name.clone(),
                });
            }
            let target = rules_catalog
                .get(name)
                .ok_or_else(|| ReductionError::MissingRule {
                    rule_name: name.clone(),
                })?;
            active_rule_refs.push(name.clone());
            path.push(ExpressionPathSegment::RuleRef { name: name.clone() });
            let result =
                reduce_expression(target, rules_catalog, leaf_results, path, active_rule_refs);
            path.pop();
            active_rule_refs.pop();
            result
        }
        BoundRuleExpression::All(children) => {
            if children.is_empty() {
                return Ok(RuleReduction::satisfied());
            }
            let mut reductions = Vec::with_capacity(children.len());
            for (index, child) in children.iter().enumerate() {
                path.push(ExpressionPathSegment::All { index });
                let result =
                    reduce_expression(child, rules_catalog, leaf_results, path, active_rule_refs);
                path.pop();
                reductions.push(result?);
            }
            let mut combined = RuleReduction::from_decision(true);
            for reduction in reductions {
                let child_decision = reduction.decision;
                combined.causes.extend(reduction.causes);
                combined.faults.extend(reduction.faults);
                combined
                    .satisfied_attributions
                    .extend(reduction.satisfied_attributions);
                combined.merge_completeness(reduction.completeness);
                if child_decision != Some(true) {
                    combined.decision = Some(false);
                }
            }
            if !combined.faults.is_empty() {
                combined.decision = None;
            }
            if combined.decision != Some(true) {
                combined.satisfied_attributions.clear();
            }
            sort_causes(&mut combined.causes);
            Ok(combined)
        }
        BoundRuleExpression::Any(children) => {
            if children.is_empty() {
                return Ok(RuleReduction::from_decision(false));
            }
            let mut reductions = Vec::with_capacity(children.len());
            for (index, child) in children.iter().enumerate() {
                path.push(ExpressionPathSegment::Any { index });
                let result =
                    reduce_expression(child, rules_catalog, leaf_results, path, active_rule_refs);
                path.pop();
                reductions.push(result?);
            }
            let has_fault = reductions
                .iter()
                .any(|reduction| !reduction.faults.is_empty());
            let has_true = reductions
                .iter()
                .any(|reduction| reduction.decision == Some(true));
            let mut combined = RuleReduction::from_decision(has_true);
            for reduction in reductions {
                combined.faults.extend(reduction.faults);
                combined.merge_completeness(reduction.completeness);
                if has_true {
                    if reduction.decision == Some(true) {
                        combined
                            .satisfied_attributions
                            .extend(reduction.satisfied_attributions);
                    }
                } else {
                    combined.causes.extend(reduction.causes);
                }
            }
            if has_fault {
                combined.decision = None;
            }
            sort_causes(&mut combined.causes);
            Ok(combined)
        }
        BoundRuleExpression::Not(child) => {
            path.push(ExpressionPathSegment::Not);
            let child_reduction =
                reduce_expression(child, rules_catalog, leaf_results, path, active_rule_refs)?;
            path.pop();
            if !child_reduction.faults.is_empty() {
                return Ok(child_reduction);
            }
            let mut reduction = match child_reduction.decision {
                Some(true) => {
                    let mut red = RuleReduction::from_decision(false);
                    for attribution in child_reduction.satisfied_attributions {
                        let occurrence_id = if attribution.occurrence_id.trim().is_empty() {
                            occurrence_id(
                                "arc.guard_evaluation.v1",
                                "reducer",
                                "not",
                                &attribution.expression_path,
                                "synthetic_negated_true",
                            )
                        } else {
                            attribution.occurrence_id
                        };
                        let physical_evaluation_id =
                            if attribution.physical_evaluation_id.trim().is_empty() {
                                physical_evaluation_id("reducer", &occurrence_id)
                            } else {
                                attribution.physical_evaluation_id
                            };
                        red.causes.push(FailureCause {
                            occurrence_id,
                            physical_evaluation_id,
                            cache_provenance: attribution.cache_provenance,
                            expression_path: attribution.expression_path,
                            kind: FailureCauseKind::NegatedTrue,
                            summary: format!(
                                "negated expression evaluated to true: {}",
                                attribution.summary
                            ),
                            auditor_findings: attribution.auditor_findings,
                            deterministic_evidence: attribution.deterministic_evidence,
                        });
                    }
                    if red.causes.is_empty() {
                        let mut not_path = path.clone();
                        not_path.push(ExpressionPathSegment::Not);
                        let occurrence_id = occurrence_id(
                            "arc.guard_evaluation.v1",
                            "reducer",
                            "not",
                            &not_path,
                            "synthetic_negated_true",
                        );
                        let physical_evaluation_id =
                            physical_evaluation_id("reducer", &occurrence_id);
                        red.causes.push(FailureCause {
                            occurrence_id,
                            physical_evaluation_id,
                            cache_provenance: CacheResolutionProvenance::Executed,
                            expression_path: not_path,
                            kind: FailureCauseKind::NegatedTrue,
                            summary: "negated expression evaluated to true".into(),
                            auditor_findings: None,
                            deterministic_evidence: Vec::new(),
                        });
                    }
                    sort_causes(&mut red.causes);
                    red
                }
                Some(false) => {
                    let mut red = RuleReduction::from_decision(true);
                    for cause in child_reduction.causes {
                        red.satisfied_attributions.push(LeafAttribution {
                            occurrence_id: cause.occurrence_id,
                            physical_evaluation_id: cause.physical_evaluation_id,
                            cache_provenance: cause.cache_provenance,
                            expression_path: cause.expression_path,
                            summary: format!("negated cause: {}", cause.summary),
                            auditor_findings: cause.auditor_findings,
                            deterministic_evidence: cause.deterministic_evidence,
                        });
                    }
                    red
                }
                None => {
                    let mut red = RuleReduction::from_decision(false);
                    red.decision = None;
                    red
                }
            };
            reduction.merge_completeness(child_reduction.completeness);
            Ok(reduction)
        }
    }
}

fn sort_causes(causes: &mut [FailureCause]) {
    causes.sort_by(|left, right| {
        (
            expression_path_key(&left.expression_path),
            left.occurrence_id.as_str(),
        )
            .cmp(&(
                expression_path_key(&right.expression_path),
                right.occurrence_id.as_str(),
            ))
    });
}

pub fn fingerprint(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

fn encode_str(bytes: &mut Vec<u8>, field: &str, value: &str) {
    encode_bytes(bytes, field.as_bytes());
    encode_bytes(bytes, value.as_bytes());
}

fn encode_optional_str(bytes: &mut Vec<u8>, field: &str, value: Option<&str>) {
    encode_bytes(bytes, field.as_bytes());
    match value {
        Some(value) => {
            bytes.push(1);
            encode_bytes(bytes, value.as_bytes());
        }
        None => bytes.push(0),
    }
}

fn encode_u64(bytes: &mut Vec<u8>, field: &str, value: u64) {
    encode_bytes(bytes, field.as_bytes());
    bytes.extend_from_slice(&value.to_be_bytes());
}

fn encode_bytes(bytes: &mut Vec<u8>, value: &[u8]) {
    bytes.extend_from_slice(&(value.len() as u64).to_be_bytes());
    bytes.extend_from_slice(value);
}

fn encode_path(bytes: &mut Vec<u8>, path: &[ExpressionPathSegment]) {
    encode_u64(bytes, "path.length", path.len() as u64);
    for segment in path {
        match segment {
            ExpressionPathSegment::All { index } => {
                encode_str(bytes, "path.segment", "all");
                encode_u64(bytes, "path.index", *index as u64);
            }
            ExpressionPathSegment::Any { index } => {
                encode_str(bytes, "path.segment", "any");
                encode_u64(bytes, "path.index", *index as u64);
            }
            ExpressionPathSegment::Not => encode_str(bytes, "path.segment", "not"),
            ExpressionPathSegment::RuleRef { name } => {
                encode_str(bytes, "path.segment", "rule_ref");
                encode_str(bytes, "path.rule_name", name);
            }
        }
    }
}

fn encode_current_operation(bytes: &mut Vec<u8>, operation: &CurrentOperation) {
    encode_str(
        bytes,
        "operation.event_type",
        &operation.event_type.to_string(),
    );
    encode_optional_str(bytes, "operation.tool", operation.tool.as_deref());
    match &operation.input {
        Some(input) => {
            bytes.push(1);
            encode_json_value(bytes, input);
        }
        None => bytes.push(0),
    }
    encode_optional_str(
        bytes,
        "operation.command_text",
        operation.command_text.as_deref(),
    );
}

fn encode_session_context(bytes: &mut Vec<u8>, context: &SessionContext) {
    encode_str(bytes, "context.user_intent", &context.user_intent);
    encode_string_list(
        bytes,
        "context.files_created_or_modified",
        &context.files_created_or_modified,
    );
    encode_u64(
        bytes,
        "context.tools_executed_count",
        context.tools_executed_count as u64,
    );
    encode_optional_str(
        bytes,
        "context.agent_final_response",
        context.agent_final_response.as_deref(),
    );
    encode_u64(
        bytes,
        "context.test_commands_run.length",
        context.test_commands_run.len() as u64,
    );
    for command in &context.test_commands_run {
        encode_command_telemetry(bytes, command);
    }
}

fn encode_command_telemetry(bytes: &mut Vec<u8>, telemetry: &CommandTelemetry) {
    encode_optional_str(bytes, "telemetry.call_id", telemetry.call_id.as_deref());
    encode_str(bytes, "telemetry.command", &telemetry.command);
    match telemetry.exit_code {
        Some(code) => {
            bytes.push(1);
            bytes.extend_from_slice(&code.to_be_bytes());
        }
        None => bytes.push(0),
    }
    encode_str(bytes, "telemetry.status", &telemetry.status);
}

fn encode_semantic_evidence(bytes: &mut Vec<u8>, evidence: &SemanticDecisionEvidence) {
    encode_str(
        bytes,
        "evidence.event_type",
        &evidence.event_type.to_string(),
    );
    encode_str(bytes, "evidence.event_id", &evidence.event_id);
    encode_str(bytes, "evidence.scope", &evidence.scope);
    encode_matcher_evidence(bytes, &evidence.matcher_evidence);
    bytes.push(u8::from(evidence.matcher_evidence_truncated));
    encode_u64(
        bytes,
        "evidence.deterministic.length",
        evidence.deterministic_evidence.len() as u64,
    );
    for item in &evidence.deterministic_evidence {
        encode_string_list(bytes, "deterministic.rule_path", &item.rule_path);
        encode_str(bytes, "deterministic.operation", &item.operation);
        encode_string_list(
            bytes,
            "deterministic.expected_values",
            &item.expected_values,
        );
        bytes.push(u8::from(item.result));
        encode_str(
            bytes,
            "deterministic.observed_sha256",
            &item.observed_sha256,
        );
    }
    bytes.push(u8::from(evidence.deterministic_evidence_truncated));
}

fn encode_matching_guards(bytes: &mut Vec<u8>, guards: &[MatchingGuardSnapshot]) {
    encode_u64(bytes, "matching_guards.length", guards.len() as u64);
    for guard in guards {
        encode_str(bytes, "matching_guard.id", &guard.guard_id);
        encode_u64(bytes, "matching_guard.order", guard.order as u64);
        encode_u64(
            bytes,
            "matching_guard.declaration_order",
            guard.declaration_order as u64,
        );
        encode_str(bytes, "matching_guard.action", &guard.action.to_string());
        encode_optional_str(
            bytes,
            "matching_guard.configured_feedback",
            guard.configured_feedback.as_deref(),
        );
        encode_matcher_evidence(bytes, &guard.matcher_evidence);
        bytes.push(u8::from(guard.matcher_evidence_truncated));
    }
}

fn encode_matcher_evidence(bytes: &mut Vec<u8>, evidence: &[MatcherEvidence]) {
    encode_u64(bytes, "evidence.matcher.length", evidence.len() as u64);
    for item in evidence {
        encode_str(bytes, "matcher.kind", &item.kind);
        encode_str(bytes, "matcher.matcher", &item.matcher);
        bytes.push(u8::from(item.matched));
    }
}

fn encode_string_list(bytes: &mut Vec<u8>, field: &str, values: &[String]) {
    encode_u64(bytes, &format!("{field}.length"), values.len() as u64);
    for value in values {
        encode_str(bytes, field, value);
    }
}

fn encode_json_value(bytes: &mut Vec<u8>, value: &serde_json::Value) {
    match value {
        serde_json::Value::Null => bytes.push(0),
        serde_json::Value::Bool(value) => {
            bytes.extend_from_slice(if *value { b"b1" } else { b"b0" })
        }
        serde_json::Value::Number(value) => {
            bytes.push(2);
            encode_bytes(bytes, value.to_string().as_bytes());
        }
        serde_json::Value::String(value) => {
            bytes.push(3);
            encode_bytes(bytes, value.as_bytes());
        }
        serde_json::Value::Array(values) => {
            bytes.push(4);
            encode_u64(bytes, "array.length", values.len() as u64);
            for value in values {
                encode_json_value(bytes, value);
            }
        }
        serde_json::Value::Object(values) => {
            bytes.push(5);
            let sorted: BTreeMap<&str, &serde_json::Value> = values
                .iter()
                .map(|(key, value)| (key.as_str(), value))
                .collect();
            encode_u64(bytes, "object.length", sorted.len() as u64);
            for (key, value) in sorted {
                encode_bytes(bytes, key.as_bytes());
                encode_json_value(bytes, value);
            }
        }
    }
}
