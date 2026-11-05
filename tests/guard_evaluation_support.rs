//! Shared fixture preparation for tests that evaluate guards through the
//! explicit engine entry (`evaluate_all_guards_with_cache_concurrency`) and
//! the canonical session entry (`ArcRuntimeSession::evaluate_event_aggregate`).
//!
//! The fixture fingerprints `env-v1` and `runner-v1` and the generic decision
//! profile live here, in test code only (AC-004.2). Consumers include this
//! file with `#[path = "guard_evaluation_support.rs"] mod guard_evaluation_support;`.
//! Cargo also builds it as its own empty test target; that is accepted.
#![allow(dead_code)]

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use arc::ir::BoundRuleExpression;
use arc::manifest::schema::DECISION_EVALUATION_TIMEOUT_SECONDS;
use arc::{
    ActivationEvaluationCache, ActivationSnapshot, ArcEvaluationError, ArcEvaluationResult,
    ArcEvent, ArcRuntimeSession, DecisionExecutionProfile, DecisionProvider, EventEvaluationReport,
    GuardEvaluationBatchError, GuardEvaluationSpec, ProbeRunner, ProviderTarget,
    evaluate_all_guards_with_cache_concurrency,
};

/// Environment fingerprint used by fixtures (not a production value).
pub const FIXTURE_ENVIRONMENT_FINGERPRINT: &str = "env-v1";
/// Probe runner contract fingerprint used by fixtures (not a production value).
pub const FIXTURE_RUNNER_FINGERPRINT: &str = "runner-v1";
/// Scheduler concurrency used by fixtures.
pub const FIXTURE_SCHEDULER_CONCURRENCY: usize = 4;

/// Generic decision profile for fixtures: `cli_native`, no model,
/// `contract-v1`/`schema-v1`, `read_only` sandbox and `never` approvals.
pub fn fixture_decision_profile(provider: ProviderTarget) -> DecisionExecutionProfile {
    DecisionExecutionProfile {
        provider,
        transport: "cli_native".into(),
        model: None,
        adapter_contract_fingerprint: "contract-v1".into(),
        output_schema_fingerprint: "schema-v1".into(),
        sandbox_mode: "read_only".into(),
        approval_policy: "never".into(),
    }
}

/// Evaluates a batch through the engine entry with the fixture configuration:
/// workspace `.`, `env-v1`, `runner-v1`, a fresh cache for the snapshot's
/// activation, and concurrency 4.
pub fn evaluate_with_fixture_config(
    snapshot: &ActivationSnapshot,
    guards: &[GuardEvaluationSpec],
    rules_catalog: &BTreeMap<String, BoundRuleExpression>,
    probe_runner: Arc<dyn ProbeRunner>,
    decision_provider: Option<Arc<dyn DecisionProvider>>,
) -> Result<EventEvaluationReport, GuardEvaluationBatchError> {
    let cache = ActivationEvaluationCache::new(&snapshot.activation_id);
    let decision_profile = fixture_decision_profile(snapshot.provider);
    evaluate_all_guards_with_cache_concurrency(
        snapshot,
        guards,
        rules_catalog,
        Path::new("."),
        FIXTURE_ENVIRONMENT_FINGERPRINT,
        FIXTURE_RUNNER_FINGERPRINT,
        &decision_profile,
        &cache,
        probe_runner,
        decision_provider,
        FIXTURE_SCHEDULER_CONCURRENCY,
    )
}

/// Evaluates one event through the canonical aggregate entry, using the
/// session's own decision profile and workspace root and a deadline of now
/// plus `DECISION_EVALUATION_TIMEOUT_SECONDS`.
pub fn evaluate_session_event(
    session: &mut ArcRuntimeSession,
    event: ArcEvent,
) -> Result<ArcEvaluationResult, ArcEvaluationError> {
    let workspace_root = session.workspace_root.clone();
    let decision_profile = session.decision_profile.clone();
    let now_unix_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(i64::MAX as u128) as i64;
    let budget_ms = i64::try_from(DECISION_EVALUATION_TIMEOUT_SECONDS * 1_000).unwrap_or(i64::MAX);
    session.evaluate_event_aggregate(
        event,
        decision_profile,
        &workspace_root,
        now_unix_ms.saturating_add(budget_ms),
    )
}
