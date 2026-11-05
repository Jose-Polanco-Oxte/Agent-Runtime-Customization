use anyhow::Result;
use regex::Regex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fmt;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

use crate::ir::{BehaviorIR, BoundMatcher};
use crate::manifest::schema::{ActionType, DECISION_EVALUATION_TIMEOUT_SECONDS};
use crate::runtime::context::SessionContextExtractor;
use crate::runtime::evaluator::{
    DecisionProvider, DefaultProbeRunner, MatcherEvidence, ProbeRunner,
};
use crate::runtime::events::{
    ActivationKind, ArcEvent, ArcEventPayload, ArcEventType, EvaluationState, GuardEvaluation,
};
#[cfg(test)]
use crate::runtime::guard_evaluation::EffectiveDisposition;
use crate::runtime::guard_evaluation::{
    ActivationEvaluationCache, ActivationSnapshot, ArcEvaluationError, ArcEvaluationResult,
    DecisionExecutionProfile, EventEvaluationReport, FailureBundle, GuardEvaluationSpec,
    GuardResultState, TrustedIrAnchor, evaluate_all_guards_with_cache_concurrency,
};
use crate::runtime::state_store::{GuardExecutionStateStore, TrustedIrSnapshot};

/// Error returned when a tool call has unrecognized or malformed arguments that fail closed.
#[derive(thiserror::Error)]
#[error(
    "Preventive security fault: Unrecognized or malformed arguments for tool '{tool_name}': {reason}. Fails closed. Arguments: {arguments}",
    arguments = self.argument_summary()
)]
pub struct PreventiveSecurityFaultError {
    pub tool_name: String,
    pub reason: String,
    /// Sensitive input retained for explicit programmatic inspection only.
    /// Display and Debug must both use the redacted summary.
    pub raw: serde_json::Value,
}

impl PreventiveSecurityFaultError {
    fn argument_summary(&self) -> RedactedArguments<'_> {
        RedactedArguments(&self.raw)
    }
}

impl fmt::Debug for PreventiveSecurityFaultError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreventiveSecurityFaultError")
            .field("tool_name", &self.tool_name)
            .field("reason", &self.reason)
            .field("arguments", &self.argument_summary())
            .finish()
    }
}

struct RedactedArguments<'a>(&'a serde_json::Value);

impl fmt::Display for RedactedArguments<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Stream compact JSON into the digest: do not allocate another copy of
        // potentially large, sensitive arguments just to format an error.
        let mut summary = ArgumentSummaryWriter::default();
        serde_json::to_writer(&mut summary, self.0).map_err(|_| fmt::Error)?;
        let json_type = match self.0 {
            serde_json::Value::Null => "null",
            serde_json::Value::Bool(_) => "boolean",
            serde_json::Value::Number(_) => "number",
            serde_json::Value::String(_) => "string",
            serde_json::Value::Array(_) => "array",
            serde_json::Value::Object(_) => "object",
        };
        write!(
            formatter,
            "type={json_type}, bytes={}, sha256={}",
            summary.bytes,
            hex::encode(summary.hasher.finalize())
        )
    }
}

impl fmt::Debug for RedactedArguments<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

#[derive(Default)]
struct ArgumentSummaryWriter {
    hasher: Sha256,
    bytes: usize,
}

impl Write for ArgumentSummaryWriter {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.hasher.update(buffer);
        self.bytes = self.bytes.saturating_add(buffer.len());
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Persistent session state and coordinator for Arc Runtime Architecture v2.
pub struct ArcRuntimeSession {
    pub session_id: String,
    pub ir: BehaviorIR,
    pub sequence: u64,
    pub event_buffer: Vec<ArcEvent>,
    pub active_evaluations: Vec<GuardEvaluation>,
    pub probe_runner: Arc<dyn ProbeRunner>,
    pub decision_provider: Option<Arc<dyn DecisionProvider>>,
    pub workspace_root: PathBuf,
    pub decision_profile: DecisionExecutionProfile,
    pub scheduler_concurrency: usize,
    pub state_store: Option<Arc<dyn GuardExecutionStateStore>>,
    pub active_activation_cache: Option<ActivationEvaluationCache>,
    pub trust_anchor: Option<TrustedIrAnchor>,
}

impl Drop for ArcRuntimeSession {
    fn drop(&mut self) {
        if let Some(cache) = self.active_activation_cache.take() {
            cache.close();
        }
    }
}

impl ArcRuntimeSession {
    /// Creates a new Arc session for a given BehaviorIR with the default probe runner.
    /// By default, an unanchored session does not produce authenticated configured feedback
    /// bundles. Trust can be established via `with_trusted_anchor`, `with_trusted_digest`,
    /// or `from_trusted_snapshot`.
    pub fn new(session_id: impl Into<String>, ir: BehaviorIR) -> Self {
        Self {
            session_id: session_id.into(),
            ir,
            sequence: 0,
            event_buffer: Vec::new(),
            active_evaluations: Vec::new(),
            probe_runner: Arc::new(DefaultProbeRunner),
            decision_provider: None,
            workspace_root: std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
            decision_profile: DecisionExecutionProfile::default(),
            scheduler_concurrency: 4,
            state_store: None,
            active_activation_cache: None,
            trust_anchor: None,
        }
    }

    /// Creates an Arc session from an immutable, verified `TrustedIrSnapshot` loaded from disk
    /// and verified against the SQLite trust store.
    pub fn from_trusted_snapshot(
        session_id: impl Into<String>,
        snapshot: TrustedIrSnapshot,
    ) -> Self {
        let trust_anchor = snapshot.anchor().clone();
        Self {
            session_id: session_id.into(),
            ir: snapshot.into_ir(),
            sequence: 0,
            event_buffer: Vec::new(),
            active_evaluations: Vec::new(),
            probe_runner: Arc::new(DefaultProbeRunner),
            decision_provider: None,
            workspace_root: std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
            decision_profile: DecisionExecutionProfile::default(),
            scheduler_concurrency: 4,
            state_store: None,
            active_activation_cache: None,
            trust_anchor: Some(trust_anchor),
        }
    }

    /// Creates an Arc session anchored to an explicit external `TrustedIrAnchor`.
    /// Validates that the IR's raw byte digest matches the anchor's authenticated digest.
    pub fn new_with_trust(
        session_id: impl Into<String>,
        ir: BehaviorIR,
        anchor: TrustedIrAnchor,
    ) -> std::result::Result<Self, ArcEvaluationError> {
        if !ir.matches_digest(anchor.digest()) {
            return Err(ArcEvaluationError::InvalidReport {
                reason: format!(
                    "BehaviorIR external digest mismatch: expected authentic digest '{}', got raw bytes digest '{}'",
                    anchor.digest(),
                    ir.compute_raw_bytes_digest()
                ),
            });
        }
        let mut session = Self::new(session_id, ir);
        session.trust_anchor = Some(anchor);
        Ok(session)
    }

    /// Attaches an opaque verified `TrustedIrAnchor` to this session after confirming
    /// that the session's BehaviorIR matches the anchor's authenticated digest.
    pub fn with_trusted_anchor(
        mut self,
        anchor: TrustedIrAnchor,
    ) -> std::result::Result<Self, ArcEvaluationError> {
        if !self.ir.matches_digest(anchor.digest()) {
            return Err(ArcEvaluationError::InvalidReport {
                reason: format!(
                    "BehaviorIR external digest mismatch: expected authentic digest '{}', got raw bytes digest '{}'",
                    anchor.digest(),
                    self.ir.compute_raw_bytes_digest()
                ),
            });
        }
        self.trust_anchor = Some(anchor);
        Ok(self)
    }

    /// Returns a reference to the active `TrustedIrAnchor`, if configured.
    pub fn trust_anchor(&self) -> Option<&TrustedIrAnchor> {
        self.trust_anchor.as_ref()
    }

    /// Returns the verified external digest string, if an anchor is configured.
    pub fn trusted_ir_digest(&self) -> Option<&str> {
        self.trust_anchor.as_ref().map(|a| a.digest())
    }

    /// Configures a custom probe runner (e.g. for testing or mock environments).
    pub fn with_probe_runner(mut self, runner: Arc<dyn ProbeRunner>) -> Self {
        self.probe_runner = runner;
        self
    }

    /// Configures a custom decision provider (e.g. for auto-resolving decisions in tests).
    pub fn with_decision_provider(mut self, provider: Arc<dyn DecisionProvider>) -> Self {
        self.decision_provider = Some(provider);
        self
    }

    /// Configures the workspace root for probe and evaluation contexts.
    pub fn with_workspace_root(mut self, root: impl Into<PathBuf>) -> Self {
        self.workspace_root = root.into();
        self
    }

    /// Configures the decision execution profile.
    pub fn with_decision_profile(mut self, profile: DecisionExecutionProfile) -> Self {
        self.decision_profile = profile;
        self
    }

    /// Configures scheduler concurrency for parallel decision evaluation.
    pub fn with_scheduler_concurrency(mut self, concurrency: usize) -> Self {
        self.scheduler_concurrency = concurrency.max(1);
        self
    }

    /// Configures the durable state store for claims, authorizations, and receipts.
    pub fn with_state_store(mut self, store: Arc<dyn GuardExecutionStateStore>) -> Self {
        self.state_store = Some(store);
        self
    }

    /// Evaluates one event through the batch contract. Every matching guard is
    /// reduced before the effective disposition is selected; callers that need
    /// interactive UI must consume the returned report and create the v2
    /// presentation from its failed guards.
    pub fn evaluate_event_report(
        &mut self,
        event: ArcEvent,
        decision_profile: DecisionExecutionProfile,
        workspace_root: &Path,
        absolute_deadline_unix_ms: i64,
    ) -> Result<EventEvaluationReport> {
        let activation_id = format!("activation-{}", Uuid::new_v4());
        let invocation_id = format!("invocation-{}", Uuid::new_v4());
        self.evaluate_event_report_with_identity(
            event,
            decision_profile,
            workspace_root,
            absolute_deadline_unix_ms,
            activation_id,
            invocation_id,
        )
    }

    fn evaluate_event_report_with_identity(
        &mut self,
        mut event: ArcEvent,
        decision_profile: DecisionExecutionProfile,
        workspace_root: &Path,
        absolute_deadline_unix_ms: i64,
        activation_id: String,
        invocation_id: String,
    ) -> Result<EventEvaluationReport> {
        if event.sequence == 0 {
            event.sequence = self.next_sequence();
        }
        self.event_buffer.push(event.clone());

        let provider = decision_profile.provider;
        let session_context = SessionContextExtractor::extract_from_session_id_with_provider_path(
            &event.session_id,
            event.provider.or(Some(provider)),
            event.transcript_path.as_deref(),
        );
        let mut guards = Vec::new();
        match event.event_type {
            ArcEventType::Start | ArcEventType::End => {
                let trigger = event
                    .event_type
                    .to_lifecycle_trigger()
                    .ok_or_else(|| anyhow::anyhow!("event is not a lifecycle trigger"))?;
                for guard in &self.ir.lifecycle_guards {
                    if guard.triggers.contains(&trigger) {
                        if event.event_type == ArcEventType::Start
                            && guard.on_failure.action == ActionType::Ask
                        {
                            return Err(anyhow::anyhow!(
                                "Arc rejected invalid compiled policy: lifecycle start guard '{}' cannot use action ask.",
                                guard.id
                            ));
                        }
                        guards.push(GuardEvaluationSpec {
                            guard_id: guard.id.clone(),
                            order: guard.order,
                            declaration_order: guard.declaration_order,
                            action: guard.on_failure.action,
                            configured_feedback: guard.on_failure.feedback.clone(),
                            scope: format!("lifecycle:{trigger}"),
                            expression: guard.require.clone(),
                            matcher_evidence: Vec::new(),
                            matcher_evidence_truncated: false,
                        });
                    }
                }
            }
            ArcEventType::ToolCall => {
                let (tool_name, argument_extraction) = match &event.payload {
                    ArcEventPayload::ToolCall {
                        tool,
                        argument_extraction,
                        ..
                    } => (tool.as_str(), argument_extraction),
                    ArcEventPayload::Empty => (
                        "",
                        &crate::runtime::events::ToolArgumentExtraction::NonCommand,
                    ),
                };
                if !self.ir.tool_guards.is_empty() {
                    match argument_extraction {
                        crate::runtime::events::ToolArgumentExtraction::MalformedOrUnrecognized {
                            raw,
                            reason,
                        } => {
                            return Err(PreventiveSecurityFaultError {
                                tool_name: tool_name.to_string(),
                                reason: reason.clone(),
                                raw: raw.clone(),
                            }.into());
                        }
                        crate::runtime::events::ToolArgumentExtraction::NonCommand => {
                            // Non-command tool calls have no command execution semantics;
                            // command matchers are not applicable. Zero tool guards match (EC-001).
                        }
                        crate::runtime::events::ToolArgumentExtraction::Command { command } => {
                            let tool_guards = self.ir.tool_guards.clone();
                            for guard in &tool_guards {
                                if let Some((matcher_evidence, matcher_evidence_truncated)) =
                                    self.matcher_evidence(&guard.matcher, command)?
                                {
                                    guards.push(GuardEvaluationSpec {
                                        guard_id: guard.id.clone(),
                                        order: guard.order,
                                        declaration_order: guard.declaration_order,
                                        action: guard.on_failure.action,
                                        configured_feedback: guard.on_failure.feedback.clone(),
                                        scope: format!("tool:{tool_name}"),
                                        expression: guard.require.clone(),
                                        matcher_evidence,
                                        matcher_evidence_truncated,
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }
        guards.sort_by_key(|guard| (guard.order, guard.declaration_order));
        let matching_guards = guards
            .iter()
            .map(
                |guard| crate::runtime::guard_evaluation::MatchingGuardSnapshot {
                    guard_id: guard.guard_id.clone(),
                    order: guard.order,
                    declaration_order: guard.declaration_order,
                    action: guard.action,
                    configured_feedback: guard.configured_feedback.clone(),
                    matcher_evidence: guard.matcher_evidence.clone(),
                    matcher_evidence_truncated: guard.matcher_evidence_truncated,
                },
            )
            .collect();
        let snapshot = ActivationSnapshot::from_event(
            activation_id.clone(),
            invocation_id,
            provider,
            &event,
            session_context,
            matching_guards,
            absolute_deadline_unix_ms,
        );
        let cache = ActivationEvaluationCache::new(activation_id);
        let report = evaluate_all_guards_with_cache_concurrency(
            &snapshot,
            &guards,
            &self.ir.rules,
            workspace_root,
            "runtime-environment-v1",
            "probe-runner-v1",
            &decision_profile,
            &cache,
            Arc::clone(&self.probe_runner),
            self.decision_provider.clone(),
            self.scheduler_concurrency,
        )?;
        if let Some(old_cache) = self.active_activation_cache.take() {
            old_cache.close();
        }
        self.active_activation_cache = Some(cache);

        let activation_kind = match event.event_type {
            ArcEventType::Start => ActivationKind::Lifecycle(
                event
                    .event_type
                    .to_lifecycle_trigger()
                    .ok_or_else(|| anyhow::anyhow!("start is not a lifecycle trigger"))?,
            ),
            ArcEventType::End => ActivationKind::Lifecycle(
                event
                    .event_type
                    .to_lifecycle_trigger()
                    .ok_or_else(|| anyhow::anyhow!("end is not a lifecycle trigger"))?,
            ),
            ArcEventType::ToolCall => {
                let matched_pattern = match &event.payload {
                    ArcEventPayload::ToolCall {
                        argument_extraction:
                            crate::runtime::events::ToolArgumentExtraction::Command { command },
                        ..
                    } => Some(command.clone()),
                    _ => None,
                };
                ActivationKind::Tool { matched_pattern }
            }
        };
        for result in &report.guard_results {
            let state = match &result.state {
                GuardResultState::Satisfied => EvaluationState::Satisfied,
                GuardResultState::Violated { .. } => EvaluationState::Failed,
                GuardResultState::Faulted { faults, .. } => EvaluationState::Errored {
                    error: format!("guard evaluation fault: {faults:?}"),
                },
            };
            self.record_guard_evaluation(
                format!("batch-{}-{}", report.invocation_id, result.guard_id),
                &result.guard_id,
                &event,
                activation_kind.clone(),
                state,
            );
        }
        Ok(report)
    }

    /// Returns the aggregate report together with the provider-facing bundle.
    /// Feedback is resolved from the matched IR Guards after evaluation so it
    /// remains separate from causal findings and GuardResult state.
    fn configured_feedback_for_report(
        &self,
        report: &EventEvaluationReport,
    ) -> BTreeMap<String, Option<String>> {
        // Configured feedback is only projected for sessions anchored to a
        // trusted IR; unanchored sessions expose none.
        if self.trust_anchor.is_none() {
            return BTreeMap::new();
        }
        let mut configured_feedback = self
            .ir
            .lifecycle_guards
            .iter()
            .map(|guard| (guard.id.clone(), guard.on_failure.feedback.clone()))
            .chain(
                self.ir
                    .tool_guards
                    .iter()
                    .map(|guard| (guard.id.clone(), guard.on_failure.feedback.clone())),
            )
            .collect::<BTreeMap<_, _>>();
        configured_feedback.retain(|guard_id, _| {
            report
                .guard_results
                .iter()
                .any(|result| result.guard_id == *guard_id)
        });
        configured_feedback
    }

    pub fn evaluate_event_with_bundle(
        &mut self,
        event: ArcEvent,
        decision_profile: DecisionExecutionProfile,
        workspace_root: &Path,
        absolute_deadline_unix_ms: i64,
    ) -> Result<(EventEvaluationReport, FailureBundle)> {
        let report = self.evaluate_event_report(
            event,
            decision_profile,
            workspace_root,
            absolute_deadline_unix_ms,
        )?;
        let configured_feedback = self.configured_feedback_for_report(&report);
        let bundle = FailureBundle::from_report_with_feedback(&report, &configured_feedback)?;
        Ok((report, bundle))
    }

    /// Returns the canonical aggregate evaluation result (`ArcEvaluationResult`) directly from the engine.
    /// The aggregate result atomically bundles the complete report, effective disposition, all exact
    /// authorization requirements, and the verified failure bundle across all evaluated guards.
    pub fn evaluate_event_aggregate(
        &mut self,
        event: ArcEvent,
        decision_profile: DecisionExecutionProfile,
        workspace_root: &Path,
        absolute_deadline_unix_ms: i64,
    ) -> std::result::Result<ArcEvaluationResult, ArcEvaluationError> {
        let (report, bundle) = self
            .evaluate_event_with_bundle(
                event,
                decision_profile,
                workspace_root,
                absolute_deadline_unix_ms,
            )
            .map_err(|e| ArcEvaluationError::RuntimeFault(e.to_string()))?;
        ArcEvaluationResult::from_report_and_bundle(report, bundle)
    }

    fn next_sequence(&mut self) -> u64 {
        self.sequence += 1;
        self.sequence
    }

    fn record_guard_evaluation(
        &mut self,
        evaluation_id: String,
        guard_id: &str,
        event: &ArcEvent,
        activation_kind: ActivationKind,
        state: EvaluationState,
    ) {
        self.active_evaluations.push(GuardEvaluation {
            evaluation_id,
            session_id: self.session_id.clone(),
            guard_id: guard_id.to_string(),
            originating_event_id: event.event_id.clone(),
            activation_kind,
            state,
        });
    }

    /// Returns the configured ActionType for a guard identifier if present in the IR.
    pub fn guard_action(&self, guard_id: &str) -> Option<ActionType> {
        self.ir
            .lifecycle_guards
            .iter()
            .find(|g| g.id == guard_id)
            .map(|g| g.on_failure.action)
            .or_else(|| {
                self.ir
                    .tool_guards
                    .iter()
                    .find(|g| g.id == guard_id)
                    .map(|g| g.on_failure.action)
            })
    }

    fn matcher_evidence(
        &self,
        matcher: &BoundMatcher,
        command_text: &str,
    ) -> Result<Option<(Vec<MatcherEvidence>, bool)>> {
        let mut evidence = Vec::new();
        let mut truncated = false;
        // 1. Exact matches
        for exact_pattern in &matcher.exact_patterns {
            let matched = command_text == exact_pattern;
            let item = MatcherEvidence {
                kind: "exact".into(),
                matcher: exact_pattern.chars().take(512).collect(),
                matched,
            };
            if evidence.len() < 64 {
                evidence.push(item);
            } else {
                truncated = true;
                if matched {
                    evidence[63] = item;
                }
            }
            if matched {
                return Ok(Some((evidence, truncated)));
            }
        }

        // 2. Regex matches (RE2 / Rust regex search semantics)
        for regex_pattern in &matcher.regex_patterns {
            let re = Regex::new(regex_pattern)?;
            let matched = re.is_match(command_text);
            let item = MatcherEvidence {
                kind: "regex".into(),
                matcher: regex_pattern.chars().take(512).collect(),
                matched,
            };
            if evidence.len() < 64 {
                evidence.push(item);
            } else {
                truncated = true;
                if matched {
                    evidence[63] = item;
                }
            }
            if matched {
                return Ok(Some((evidence, truncated)));
            }
        }

        Ok(None)
    }

    /// Emits `ProviderFeedbackPrepared` while the activation evaluation cache is still open/active.
    pub fn record_feedback_prepared(
        &self,
        journal: &Option<crate::runtime::observability::ObservabilityJournal>,
        observed: &HookObservationContext,
        failure_bundle: &FailureBundle,
    ) -> Result<()> {
        let cache_active = self
            .active_activation_cache
            .as_ref()
            .is_some_and(|c| !c.is_closed());
        if let Some(j) = journal {
            let _ = j.append(crate::runtime::observability::NewObservabilityEvent {
                event_type: "ProviderFeedbackPrepared".into(),
                level: "info".into(),
                provider: Some(observed.provider.clone()),
                workspace_id: observed.workspace_id.clone(),
                session_id: Some(observed.session_id.clone()),
                turn_id: observed.turn_id.clone(),
                invocation_id: Some(observed.invocation_id.clone()),
                details: serde_json::json!({
                    "failed_guards": failure_bundle.failed_guards.len(),
                    "bundle_fingerprint": failure_bundle.bundle_fingerprint,
                    "cache_active": cache_active,
                }),
                ..Default::default()
            });
        }
        Ok(())
    }

    /// Closes and releases the active activation evaluation cache, emitting `ActivationEvaluationCacheDropped`.
    pub fn release_activation_cache(
        &mut self,
        journal: &Option<crate::runtime::observability::ObservabilityJournal>,
        observed: &HookObservationContext,
    ) -> Result<()> {
        if let Some(cache) = self.active_activation_cache.take() {
            cache.close();
        }
        if let Some(j) = journal {
            let _ = j.append(crate::runtime::observability::NewObservabilityEvent {
                event_type: "ActivationEvaluationCacheDropped".into(),
                level: "info".into(),
                provider: Some(observed.provider.clone()),
                workspace_id: observed.workspace_id.clone(),
                session_id: Some(observed.session_id.clone()),
                turn_id: observed.turn_id.clone(),
                invocation_id: Some(observed.invocation_id.clone()),
                details: serde_json::json!({}),
                ..Default::default()
            });
        }
        Ok(())
    }
}

/// Canonical observation context for hook evaluations across providers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HookObservationContext {
    pub provider: String,
    pub workspace_id: Option<String>,
    pub session_id: String,
    pub turn_id: Option<String>,
    pub invocation_id: String,
}

impl HookObservationContext {
    pub fn new(
        provider: impl Into<String>,
        session_id: impl Into<String>,
        invocation_id: impl Into<String>,
    ) -> Self {
        Self {
            provider: provider.into(),
            workspace_id: None,
            session_id: session_id.into(),
            turn_id: None,
            invocation_id: invocation_id.into(),
        }
    }

    pub fn with_workspace(mut self, workspace_id: impl Into<String>) -> Self {
        self.workspace_id = Some(workspace_id.into());
        self
    }

    pub fn with_turn(mut self, turn_id: impl Into<String>) -> Self {
        self.turn_id = Some(turn_id.into());
        self
    }
}

/// Evaluates guards for an event with end-to-end telemetry and observability recorded to the journal.
pub fn evaluate_guard_with_observability(
    session: &mut ArcRuntimeSession,
    event: ArcEvent,
    journal: &Option<crate::runtime::observability::ObservabilityJournal>,
    observed: &HookObservationContext,
) -> Result<ArcEvaluationResult> {
    evaluate_guard_with_default_deadline(
        session,
        event,
        journal,
        observed,
        evaluate_guard_with_observability_until,
    )
}

/// Seam: computes the default deadline and hands it to `evaluate_until`.
fn evaluate_guard_with_default_deadline<F>(
    session: &mut ArcRuntimeSession,
    event: ArcEvent,
    journal: &Option<crate::runtime::observability::ObservabilityJournal>,
    observed: &HookObservationContext,
    evaluate_until: F,
) -> Result<ArcEvaluationResult>
where
    F: FnOnce(
        &mut ArcRuntimeSession,
        ArcEvent,
        &Option<crate::runtime::observability::ObservabilityJournal>,
        &HookObservationContext,
        i64,
    ) -> Result<ArcEvaluationResult>,
{
    evaluate_until(
        session,
        event,
        journal,
        observed,
        default_evaluation_deadline_unix_ms(),
    )
}

fn evaluate_guard_with_observability_until(
    session: &mut ArcRuntimeSession,
    event: ArcEvent,
    journal: &Option<crate::runtime::observability::ObservabilityJournal>,
    observed: &HookObservationContext,
    absolute_deadline_unix_ms: i64,
) -> Result<ArcEvaluationResult> {
    let evaluation_started = std::time::Instant::now();
    let event_type = event.event_type.to_string();
    let transport = session
        .decision_provider
        .as_ref()
        .map(|p| p.dispatcher_label())
        .unwrap_or_else(|| "none".to_string());
    if let Some(j) = journal {
        let _ = j.append(crate::runtime::observability::NewObservabilityEvent {
            event_type: "GuardEvaluationStarted".into(),
            level: "info".into(),
            provider: Some(observed.provider.clone()),
            workspace_id: observed.workspace_id.clone(),
            session_id: Some(observed.session_id.clone()),
            turn_id: observed.turn_id.clone(),
            invocation_id: Some(observed.invocation_id.clone()),
            details: serde_json::json!({
                "event": event_type,
                "decision_transport": transport,
            }),
            ..Default::default()
        });
    }

    let provider = event
        .provider
        .unwrap_or(crate::target::ProviderTarget::Codex);
    let decision_profile = DecisionExecutionProfile {
        provider,
        transport,
        model: None,
        adapter_contract_fingerprint: "contract-v1".into(),
        output_schema_fingerprint: "schema-v1".into(),
        sandbox_mode: "read_only".into(),
        approval_policy: "never".into(),
    };
    let workspace_root = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));

    match session.evaluate_event_aggregate(
        event,
        decision_profile,
        &workspace_root,
        absolute_deadline_unix_ms,
    ) {
        Ok(eval_result) => {
            if let Some(j) = journal {
                for res in &eval_result.report.guard_results {
                    let _ = j.append(crate::runtime::observability::NewObservabilityEvent {
                        event_type: "GuardResultRecorded".into(),
                        level: "info".into(),
                        provider: Some(observed.provider.clone()),
                        workspace_id: observed.workspace_id.clone(),
                        session_id: Some(observed.session_id.clone()),
                        turn_id: observed.turn_id.clone(),
                        invocation_id: Some(observed.invocation_id.clone()),
                        guard_id: Some(res.guard_id.clone()),
                        details: serde_json::json!({
                            "guard_id": res.guard_id,
                            "state": serde_json::to_value(&res.state).unwrap_or_default(),
                            "completeness": serde_json::to_value(res.completeness).unwrap_or_default(),
                        }),
                        ..Default::default()
                    });
                }
                let _ = j.append(crate::runtime::observability::NewObservabilityEvent {
                    event_type: "GuardEvaluationCompleted".into(),
                    level: "info".into(),
                    provider: Some(observed.provider.clone()),
                    workspace_id: observed.workspace_id.clone(),
                    session_id: Some(observed.session_id.clone()),
                    turn_id: observed.turn_id.clone(),
                    invocation_id: Some(observed.invocation_id.clone()),
                    duration_ms: Some(evaluation_started.elapsed().as_millis() as i64),
                    details: serde_json::json!({
                        "event": event_type,
                        "effective_disposition": serde_json::to_value(eval_result.effective_disposition).unwrap_or_default(),
                        "authorization_requirements": eval_result.authorization_requirements.len(),
                        "authorization_requirement_items": &eval_result.authorization_requirements,
                        "failed_guards": eval_result.failure_bundle.failed_guards.len(),
                    }),
                    ..Default::default()
                });
            }
            Ok(eval_result)
        }
        Err(error) => {
            if let Some(j) = journal {
                let _ = j.append(crate::runtime::observability::NewObservabilityEvent {
                    event_type: "GuardEvaluationFailed".into(),
                    level: "error".into(),
                    provider: Some(observed.provider.clone()),
                    workspace_id: observed.workspace_id.clone(),
                    session_id: Some(observed.session_id.clone()),
                    turn_id: observed.turn_id.clone(),
                    invocation_id: Some(observed.invocation_id.clone()),
                    reason_code: Some("guard_evaluation_error".into()),
                    duration_ms: Some(evaluation_started.elapsed().as_millis() as i64),
                    details: serde_json::json!({ "event": event_type }),
                    ..Default::default()
                });
            }
            Err(anyhow::anyhow!(
                "Guard evaluation aggregate failed: {error}"
            ))
        }
    }
}

fn default_evaluation_deadline_unix_ms() -> i64 {
    let now_unix_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(i64::MAX as u128) as i64;
    evaluation_deadline_from(now_unix_ms)
}

fn evaluation_deadline_from(now_unix_ms: i64) -> i64 {
    let evaluation_budget_ms =
        i64::try_from(DECISION_EVALUATION_TIMEOUT_SECONDS * 1_000).unwrap_or(i64::MAX);
    now_unix_ms.saturating_add(evaluation_budget_ms)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ExactOperationAuthorization;
    use crate::ir::{BoundLifecycleGuard, BoundRuleExpression, BoundToolGuard, WorkspaceContext};
    use crate::manifest::schema::{LifecycleTrigger, OnFailureConfig};
    use crate::{CurrentOperation, exact_operation_fingerprint};

    use crate::runtime::evaluator::{DecisionVerdict, MockDecisionProvider, MockProbeRunner};

    /// Test-only helper: aggregate evaluation with the session's own profile and
    /// workspace root and the default deadline.
    trait AggregateWithSessionDefaults {
        fn aggregate_with_session_defaults(
            &mut self,
            event: ArcEvent,
        ) -> std::result::Result<ArcEvaluationResult, ArcEvaluationError>;
    }

    impl AggregateWithSessionDefaults for ArcRuntimeSession {
        fn aggregate_with_session_defaults(
            &mut self,
            event: ArcEvent,
        ) -> std::result::Result<ArcEvaluationResult, ArcEvaluationError> {
            let workspace_root = self.workspace_root.clone();
            let decision_profile = self.decision_profile.clone();
            self.evaluate_event_aggregate(
                event,
                decision_profile,
                &workspace_root,
                default_evaluation_deadline_unix_ms(),
            )
        }
    }

    fn test_ir() -> BehaviorIR {
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
            lifecycle_guards: vec![BoundLifecycleGuard {
                id: "safe_start".into(),
                triggers: vec![LifecycleTrigger::Start],
                require: BoundRuleExpression::Not(Box::new(BoundRuleExpression::Probe {
                    command: "git branch".into(),
                    expected_in: vec!["main".into()],
                })),
                on_failure: OnFailureConfig {
                    action: ActionType::Deny,
                    feedback: Some("Cannot start from main".into()),
                },
                order: 0,
                declaration_order: 0,
            }],
            tool_guards: vec![BoundToolGuard {
                id: "deny_force_push".into(),
                matcher: BoundMatcher {
                    exact_patterns: vec![],
                    regex_patterns: vec!["^git push .*--force.*$".into()],
                },
                require: BoundRuleExpression::Not(Box::new(BoundRuleExpression::Probe {
                    command: "git branch".into(),
                    expected_in: vec!["main".into()],
                })),
                on_failure: OnFailureConfig {
                    action: ActionType::Deny,
                    feedback: Some("Force push to main blocked".into()),
                },
                order: 0,
                declaration_order: 0,
            }],
            rules: BTreeMap::new(),
        };
        ir.content_hash = Some(ir.compute_content_hash());
        ir
    }

    #[test]
    fn tool_decide_true_requires_exact_authorization_in_aggregate_result() {
        let ir = BehaviorIR {
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
            lifecycle_guards: Vec::new(),
            tool_guards: vec![BoundToolGuard {
                id: "guard-auth".into(),
                matcher: BoundMatcher {
                    exact_patterns: vec!["git status".into()],
                    regex_patterns: Vec::new(),
                },
                require: BoundRuleExpression::Decide {
                    prompt: "audit this exact operation".into(),
                },
                on_failure: OnFailureConfig {
                    action: ActionType::Ask,
                    feedback: None,
                },
                order: 1,
                declaration_order: 0,
            }],
            rules: BTreeMap::new(),
        };
        let provider =
            Arc::new(MockDecisionProvider::new().with_decision("audit this exact operation", true));
        let mut session =
            ArcRuntimeSession::new("session-auth", ir).with_decision_provider(provider);
        let event = ArcEvent::tool_call("session-auth", "event-auth", 1, "Bash", "git status");

        let result = session
            .aggregate_with_session_defaults(event)
            .expect("tool evaluation should succeed");
        assert_eq!(result.effective_disposition, EffectiveDisposition::Continue);
        assert_eq!(result.authorization_requirements.len(), 1);
        let authorization = &result.authorization_requirements[0];
        authorization
            .validate()
            .expect("exact authorization must be valid");
        assert_eq!(authorization.guard_id, "guard-auth");
        assert_eq!(authorization.event_id, "event-auth");
        assert_eq!(authorization.tool, "Bash");
        assert_eq!(
            result.report.authorization_requirements,
            result.authorization_requirements
        );
    }

    #[test]
    fn matcher_evidence_is_bounded_and_retains_the_terminal_match() {
        let session = ArcRuntimeSession::new("matcher-evidence", test_ir());
        let matcher = BoundMatcher {
            exact_patterns: (0..70).map(|index| format!("command-{index}")).collect(),
            regex_patterns: Vec::new(),
        };

        let (evidence, truncated) = session
            .matcher_evidence(&matcher, "command-69")
            .unwrap()
            .expect("last matcher must select the guard");

        assert!(truncated);
        assert_eq!(evidence.len(), 64);
        assert_eq!(evidence.last().unwrap().matcher, "command-69");
        assert!(evidence.last().unwrap().matched);
    }

    #[test]
    fn test_evaluate_event_strictly_delegates_to_evaluate_event_report_and_supports_multiple_authorizations()
     {
        let ir = BehaviorIR {
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
            lifecycle_guards: Vec::new(),
            tool_guards: vec![
                BoundToolGuard {
                    id: "guard-auth-1".into(),
                    matcher: BoundMatcher {
                        exact_patterns: vec!["git commit".into()],
                        regex_patterns: Vec::new(),
                    },
                    require: BoundRuleExpression::Decide {
                        prompt: "First decide prompt".into(),
                    },
                    on_failure: OnFailureConfig {
                        action: ActionType::Ask,
                        feedback: None,
                    },
                    order: 0,
                    declaration_order: 0,
                },
                BoundToolGuard {
                    id: "guard-auth-2".into(),
                    matcher: BoundMatcher {
                        exact_patterns: vec!["git commit".into()],
                        regex_patterns: Vec::new(),
                    },
                    require: BoundRuleExpression::Decide {
                        prompt: "Second decide prompt".into(),
                    },
                    on_failure: OnFailureConfig {
                        action: ActionType::Ask,
                        feedback: None,
                    },
                    order: 0,
                    declaration_order: 1,
                },
            ],
            rules: BTreeMap::new(),
        };

        let provider = Arc::new(
            MockDecisionProvider::new()
                .with_decision("First decide prompt", true)
                .with_decision("Second decide prompt", true),
        );
        let mut session =
            ArcRuntimeSession::new("session-multi-auth", ir).with_decision_provider(provider);
        let event = ArcEvent::tool_call(
            "session-multi-auth",
            "event-commit",
            1,
            "Bash",
            "git commit",
        );

        let eval_result = session
            .aggregate_with_session_defaults(event)
            .expect("evaluate_event strictly succeeds");

        assert_eq!(eval_result.authorization_requirements.len(), 2);
        assert_eq!(
            eval_result.authorization_requirements[0].guard_id,
            "guard-auth-1"
        );
        assert_eq!(
            eval_result.authorization_requirements[0].event_id,
            "event-commit"
        );
        assert_eq!(eval_result.authorization_requirements[0].tool, "Bash");
        assert_eq!(
            eval_result.authorization_requirements[1].guard_id,
            "guard-auth-2"
        );
        assert_eq!(
            eval_result.authorization_requirements[1].event_id,
            "event-commit"
        );
        assert_eq!(eval_result.authorization_requirements[1].tool, "Bash");

        assert_eq!(
            eval_result.report.authorization_requirements,
            eval_result.authorization_requirements
        );
        assert!(eval_result.failure_bundle.failed_guards.is_empty());

        assert_eq!(session.active_evaluations.len(), 2);
        assert_eq!(session.active_evaluations[0].guard_id, "guard-auth-1");
        assert_eq!(
            session.active_evaluations[0].state,
            EvaluationState::Satisfied
        );
        assert_eq!(session.active_evaluations[1].guard_id, "guard-auth-2");
        assert_eq!(
            session.active_evaluations[1].state,
            EvaluationState::Satisfied
        );
    }

    #[test]
    fn test_lifecycle_start_denial_and_success() {
        let ir = test_ir();

        // 1. Repository is on main -> start denied
        let probe_runner = Arc::new(MockProbeRunner::new().with_output("git branch", "main"));
        let mut session = ArcRuntimeSession::new("test-session", ir.clone())
            .with_probe_runner(probe_runner)
            .with_trusted_anchor(TrustedIrAnchor::from_authenticated_store_digest(
                ir.compute_raw_bytes_digest(),
            ))
            .unwrap();

        let event = ArcEvent::lifecycle("test-session", "ev-1", ArcEventType::Start, 1);
        let eval_result = session.aggregate_with_session_defaults(event).unwrap();
        assert_eq!(
            eval_result.effective_disposition,
            EffectiveDisposition::Deny
        );
        assert_eq!(
            eval_result.failure_bundle.failed_guards[0].guard_id,
            "safe_start"
        );
        assert_eq!(
            eval_result.failure_bundle.failed_guards[0]
                .configured_feedback
                .as_deref(),
            Some("Cannot start from main")
        );

        // 2. Repository is on dev -> start allowed
        let probe_runner_dev = Arc::new(MockProbeRunner::new().with_output("git branch", "dev"));
        let mut session_dev =
            ArcRuntimeSession::new("test-session-dev", ir).with_probe_runner(probe_runner_dev);

        let event_dev = ArcEvent::lifecycle("test-session-dev", "ev-1", ArcEventType::Start, 1);
        let eval_result_dev = session_dev
            .aggregate_with_session_defaults(event_dev)
            .unwrap();
        assert_eq!(
            eval_result_dev.effective_disposition,
            EffectiveDisposition::Continue
        );
    }

    #[test]
    fn test_tool_guard_and_remediation() {
        let ir = test_ir();
        let probe_runner = Arc::new(MockProbeRunner::new().with_output("git branch", "main"));
        let mut session = ArcRuntimeSession::new("test-session", ir.clone())
            .with_probe_runner(probe_runner)
            .with_trusted_anchor(TrustedIrAnchor::from_authenticated_store_digest(
                ir.compute_raw_bytes_digest(),
            ))
            .unwrap();

        // 1. Attempt force push on main -> Denied
        let ev1 = ArcEvent::tool_call(
            "test-session",
            "ev-1",
            1,
            "bash",
            "git push --force origin main",
        );
        let res1 = session.aggregate_with_session_defaults(ev1).unwrap();
        assert_eq!(res1.effective_disposition, EffectiveDisposition::Deny);
        assert_eq!(
            res1.failure_bundle.failed_guards[0]
                .configured_feedback
                .as_deref(),
            Some("Force push to main blocked")
        );

        // 2. Agent remediates state: switches branch (different tool call) -> Allowed!
        let ev2 = ArcEvent::tool_call("test-session", "ev-2", 2, "bash", "git switch dev");
        let res2 = session.aggregate_with_session_defaults(ev2).unwrap();
        assert_eq!(res2.effective_disposition, EffectiveDisposition::Continue);
    }

    #[test]
    fn test_lifecycle_probe_runtime_error() {
        let ir = test_ir();
        // Unconfigured mock probe runner will return Err
        let probe_runner = Arc::new(MockProbeRunner::new());
        let mut session =
            ArcRuntimeSession::new("test-session", ir).with_probe_runner(probe_runner);

        let event = ArcEvent::lifecycle("test-session", "ev-1", ArcEventType::Start, 1);
        let eval_result = session.aggregate_with_session_defaults(event).unwrap();
        assert_eq!(
            eval_result.effective_disposition,
            EffectiveDisposition::RuntimeFault
        );

        assert_eq!(session.active_evaluations.len(), 1);
        match &session.active_evaluations[0].state {
            EvaluationState::Errored { error } => {
                assert!(error.contains("No mock output configured"));
            }
            _ => panic!("Expected Errored state"),
        }
    }

    #[test]
    fn test_lifecycle_guard_action_ask() {
        let mut ir = test_ir();
        ir.lifecycle_guards[0].triggers = vec![LifecycleTrigger::End];
        ir.lifecycle_guards[0].on_failure.action = ActionType::Ask;
        ir.lifecycle_guards[0].on_failure.feedback = Some("Confirm session policy override".into());

        let probe_runner = Arc::new(MockProbeRunner::new().with_output("git branch", "main"));
        let mut session = ArcRuntimeSession::new("test-lifecycle-ask", ir.clone())
            .with_probe_runner(probe_runner)
            .with_trusted_anchor(TrustedIrAnchor::from_authenticated_store_digest(
                ir.compute_raw_bytes_digest(),
            ))
            .unwrap();

        let event = ArcEvent::lifecycle("test-lifecycle-ask", "ev-ask", ArcEventType::End, 1);
        let eval_result = session.aggregate_with_session_defaults(event).unwrap();
        assert_eq!(eval_result.effective_disposition, EffectiveDisposition::Ask);
        assert_ask_failure_bundle(
            &eval_result,
            "safe_start",
            Some("Confirm session policy override"),
            None,
        );
    }

    #[test]
    fn test_tool_guard_action_ask() {
        let mut ir = test_ir();
        // Set action on tool guard to Ask
        ir.tool_guards[0].on_failure.action = ActionType::Ask;
        ir.tool_guards[0].on_failure.feedback = Some("Please confirm force push".into());

        let probe_runner = Arc::new(MockProbeRunner::new().with_output("git branch", "main"));
        let mut session = ArcRuntimeSession::new("test-session-ask", ir.clone())
            .with_probe_runner(probe_runner)
            .with_trusted_anchor(TrustedIrAnchor::from_authenticated_store_digest(
                ir.compute_raw_bytes_digest(),
            ))
            .unwrap();

        let ev = ArcEvent::tool_call(
            "test-session-ask",
            "ev-1",
            1,
            "bash",
            "git push --force origin main",
        );
        let eval_result = session.aggregate_with_session_defaults(ev).unwrap();
        assert_eq!(eval_result.effective_disposition, EffectiveDisposition::Ask);
        assert_ask_failure_bundle(
            &eval_result,
            "deny_force_push",
            Some("Please confirm force push"),
            None,
        );
    }

    #[test]
    fn failure_bundle_preserves_feedback_and_findings_for_lifecycle_and_tool_asks() {
        let mut lifecycle_ir = test_ir();
        lifecycle_ir.lifecycle_guards[0].triggers = vec![LifecycleTrigger::End];
        lifecycle_ir.lifecycle_guards[0].require = BoundRuleExpression::Decide {
            prompt: "Review lifecycle operation".into(),
        };
        lifecycle_ir.lifecycle_guards[0].on_failure.action = ActionType::Ask;
        lifecycle_ir.lifecycle_guards[0].on_failure.feedback =
            Some("Configured lifecycle feedback".into());
        let lifecycle_provider = Arc::new(MockDecisionProvider::new().with_verdict(
            "Review lifecycle operation",
            DecisionVerdict::deny("Lifecycle auditor finding"),
        ));
        let mut lifecycle_session =
            ArcRuntimeSession::new("context-lifecycle", lifecycle_ir.clone())
                .with_decision_provider(lifecycle_provider)
                .with_trusted_anchor(TrustedIrAnchor::from_authenticated_store_digest(
                    lifecycle_ir.compute_raw_bytes_digest(),
                ))
                .unwrap();

        let lifecycle_eval = lifecycle_session
            .aggregate_with_session_defaults(ArcEvent::lifecycle(
                "context-lifecycle",
                "ev-lifecycle",
                ArcEventType::End,
                1,
            ))
            .unwrap();
        assert_ask_failure_bundle(
            &lifecycle_eval,
            "safe_start",
            Some("Configured lifecycle feedback"),
            Some("Lifecycle auditor finding"),
        );

        let mut tool_ir = test_ir();
        tool_ir.tool_guards[0].require = BoundRuleExpression::Decide {
            prompt: "Review tool operation".into(),
        };
        tool_ir.tool_guards[0].on_failure.action = ActionType::Ask;
        tool_ir.tool_guards[0].on_failure.feedback = Some("Configured tool feedback".into());
        let tool_provider = Arc::new(MockDecisionProvider::new().with_verdict(
            "Review tool operation",
            DecisionVerdict::deny("Tool auditor finding"),
        ));
        let mut tool_session = ArcRuntimeSession::new("context-tool", tool_ir.clone())
            .with_decision_provider(tool_provider)
            .with_trusted_anchor(TrustedIrAnchor::from_authenticated_store_digest(
                tool_ir.compute_raw_bytes_digest(),
            ))
            .unwrap();

        let tool_eval = tool_session
            .aggregate_with_session_defaults(ArcEvent::tool_call(
                "context-tool",
                "ev-tool",
                1,
                "bash",
                "git push --force origin main",
            ))
            .unwrap();
        assert_ask_failure_bundle(
            &tool_eval,
            "deny_force_push",
            Some("Configured tool feedback"),
            Some("Tool auditor finding"),
        );
    }

    #[test]
    fn failure_bundle_keeps_findings_when_configured_feedback_is_absent() {
        let mut ir = test_ir();
        ir.lifecycle_guards[0].triggers = vec![LifecycleTrigger::End];
        ir.lifecycle_guards[0].require = BoundRuleExpression::Decide {
            prompt: "Review without configured feedback".into(),
        };
        ir.lifecycle_guards[0].on_failure.action = ActionType::Ask;
        ir.lifecycle_guards[0].on_failure.feedback = None;
        let provider = Arc::new(MockDecisionProvider::new().with_verdict(
            "Review without configured feedback",
            DecisionVerdict::deny("Only auditor finding"),
        ));
        let mut session =
            ArcRuntimeSession::new("context-no-feedback", ir).with_decision_provider(provider);

        let eval_res = session
            .aggregate_with_session_defaults(ArcEvent::lifecycle(
                "context-no-feedback",
                "ev-no-feedback",
                ArcEventType::End,
                1,
            ))
            .unwrap();

        assert_ask_failure_bundle(&eval_res, "safe_start", None, Some("Only auditor finding"));
    }

    fn assert_ask_failure_bundle(
        result: &ArcEvaluationResult,
        expected_guard_id: &str,
        expected_feedback: Option<&str>,
        expected_findings: Option<&str>,
    ) {
        result
            .validate()
            .expect("aggregate result must remain valid");
        assert_eq!(result.effective_disposition, EffectiveDisposition::Ask);
        assert_eq!(result.failure_bundle.failed_guards.len(), 1);
        let failure = &result.failure_bundle.failed_guards[0];
        assert_eq!(failure.guard_id, expected_guard_id);
        assert_eq!(failure.configured_feedback.as_deref(), expected_feedback);
        let findings: Vec<_> = failure
            .causes
            .iter()
            .filter_map(|cause| cause.auditor_findings.as_deref())
            .collect();
        assert_eq!(findings, expected_findings.into_iter().collect::<Vec<_>>());
    }

    #[test]
    fn session_exact_operation_authorization_and_durable_waiver() {
        let mut ir = test_ir();
        ir.tool_guards[0].on_failure.action = ActionType::Deny;
        ir.tool_guards[0].on_failure.feedback = Some("Force push is forbidden".into());

        // Probe returns "main", so the rule requiring "feature" would normally fail!
        let probe_runner = Arc::new(MockProbeRunner::new().with_output("git branch", "main"));
        let state_store = Arc::new(crate::runtime::state_store::InMemoryStateStore::default());

        let ev = ArcEvent::tool_call(
            "test-auth-session",
            "ev-tool-1",
            1,
            "bash",
            "git push --force origin main",
        );

        let current_op = CurrentOperation::from(&ev);
        let op_fp = exact_operation_fingerprint(&current_op);
        let args_fp =
            crate::runtime::guard_evaluation::normalized_arguments_fingerprint(&current_op);

        // Pre-record exact operation authorization for 1 use with TTL in future
        let auth = ExactOperationAuthorization {
            guard_id: "deny_force_push".into(),
            operation_fingerprint: op_fp.clone(),
            event_id: "ev-tool-1".into(),
            tool: "bash".into(),
            normalized_arguments_fingerprint: args_fp,
        };
        let auth_context =
            crate::runtime::state_store::ExactAuthorizationContext::for_authorizations(
                "ev-tool-1",
                "bash",
                "workspace-test",
                "codex",
                "test-auth-session",
                "invocation-auth-1",
                "policy-test",
                "evidence-test",
                std::slice::from_ref(&auth),
            )
            .unwrap();
        state_store
            .record_exact_authorization(&auth, &auth_context, Some("waiver-1"), i64::MAX, 1)
            .unwrap();

        let mut session = ArcRuntimeSession::new("test-auth-session", ir)
            .with_probe_runner(probe_runner.clone())
            .with_state_store(state_store.clone());

        // Evaluation is strictly semantic (C-08/F-03): probe fails against "feature", producing Deny.
        // No fake All([]) AST rewrite fabricates Continue during evaluation.
        let first_result = session.aggregate_with_session_defaults(ev).unwrap();
        assert_eq!(
            first_result.effective_disposition,
            EffectiveDisposition::Deny
        );

        // The authorization in the store was NOT consumed during matching/evaluation
        assert!(
            state_store
                .consume_exact_authorization(&auth, &auth_context, 1000)
                .unwrap(),
            "Authorization must not be consumed prematurely during matching/evaluation phase"
        );
    }

    #[test]
    fn session_activation_cache_ephemerality() {
        let mut ir = test_ir();
        // Two lifecycle start guards that use the same probe
        ir.lifecycle_guards = vec![
            BoundLifecycleGuard {
                id: "guard_1".into(),
                triggers: vec![LifecycleTrigger::Start],
                require: BoundRuleExpression::Probe {
                    command: "git branch".into(),
                    expected_in: vec!["main".into()],
                },
                on_failure: OnFailureConfig {
                    action: ActionType::Deny,
                    feedback: None,
                },
                order: 0,
                declaration_order: 0,
            },
            BoundLifecycleGuard {
                id: "guard_2".into(),
                triggers: vec![LifecycleTrigger::Start],
                require: BoundRuleExpression::Probe {
                    command: "git branch".into(),
                    expected_in: vec!["main".into()],
                },
                on_failure: OnFailureConfig {
                    action: ActionType::Deny,
                    feedback: None,
                },
                order: 1,
                declaration_order: 1,
            },
        ];

        let probe_runner = Arc::new(MockProbeRunner::new().with_output("git branch", "main"));
        let mut session = ArcRuntimeSession::new("test-ephemeral-session", ir)
            .with_probe_runner(probe_runner.clone());

        // Event 1: Evaluates both guards. In the first activation, probe should be cached across guards in that activation
        let ev1 = ArcEvent::lifecycle("test-ephemeral-session", "ev-1", ArcEventType::Start, 1);
        let res1 = session.aggregate_with_session_defaults(ev1).unwrap();
        assert_eq!(res1.effective_disposition, EffectiveDisposition::Continue);
        assert_eq!(probe_runner.calls().len(), 1);

        // Event 2: A separate activation MUST run probes fresh (INV-022: no cross-activation reuse)
        let ev2 = ArcEvent::lifecycle("test-ephemeral-session", "ev-2", ArcEventType::Start, 2);
        let res2 = session.aggregate_with_session_defaults(ev2).unwrap();
        assert_eq!(res2.effective_disposition, EffectiveDisposition::Continue);
        assert_eq!(probe_runner.calls().len(), 2);
    }

    #[test]
    fn aggregate_result_preserves_all_guard_identities_in_contract_order() {
        let mut ir = test_ir();
        let template = ir.lifecycle_guards[0].clone();
        ir.lifecycle_guards = [
            ("guard-message", ActionType::Message, false),
            ("guard-deny", ActionType::Deny, false),
            ("guard-satisfied", ActionType::Ask, true),
        ]
        .into_iter()
        .enumerate()
        .map(|(index, (id, action, satisfied))| {
            let mut guard = template.clone();
            guard.id = id.into();
            guard.triggers = vec![LifecycleTrigger::End];
            guard.on_failure.action = action;
            guard.declaration_order = index;
            if satisfied {
                guard.require = BoundRuleExpression::Probe {
                    command: "git branch".into(),
                    expected_in: vec!["main".into()],
                };
            }
            guard
        })
        .collect();
        let mut session = ArcRuntimeSession::new("aggregate-identities", ir).with_probe_runner(
            Arc::new(MockProbeRunner::new().with_output("git branch", "main")),
        );
        let result = session
            .aggregate_with_session_defaults(ArcEvent::lifecycle(
                "aggregate-identities",
                "event-identities",
                ArcEventType::End,
                1,
            ))
            .expect("all guards must be evaluated");

        assert_eq!(result.effective_disposition, EffectiveDisposition::Deny);
        assert_eq!(
            result
                .report
                .guard_results
                .iter()
                .map(|guard| guard.guard_id.as_str())
                .collect::<Vec<_>>(),
            ["guard-message", "guard-deny", "guard-satisfied"]
        );
        assert_eq!(
            result
                .failure_bundle
                .failed_guards
                .iter()
                .map(|guard| guard.guard_id.as_str())
                .collect::<Vec<_>>(),
            ["guard-message", "guard-deny"]
        );
        assert_eq!(session.active_evaluations.len(), 3);
        assert_eq!(
            session.active_evaluations[2].state,
            EvaluationState::Satisfied
        );
    }

    #[test]
    fn test_evaluate_event_single_sequence_assignment_and_buffer_invariants() {
        let ir = test_ir();
        let probe_runner = Arc::new(MockProbeRunner::new().with_output("git branch", "dev"));
        let mut session =
            ArcRuntimeSession::new("test-seq-session", ir).with_probe_runner(probe_runner);

        assert_eq!(session.sequence, 0);
        assert_eq!(session.event_buffer.len(), 0);

        let event = ArcEvent::lifecycle("test-seq-session", "ev-seq-1", ArcEventType::Start, 0);
        let eval_result = session
            .aggregate_with_session_defaults(event)
            .expect("evaluate_event succeeds");
        assert_eq!(
            eval_result.effective_disposition,
            EffectiveDisposition::Continue
        );

        assert_eq!(session.sequence, 1);
        assert_eq!(session.event_buffer.len(), 1);
        assert_eq!(session.event_buffer[0].sequence, 1);
        assert_eq!(session.event_buffer[0].event_id, "ev-seq-1");
    }

    fn deadline_session() -> ArcRuntimeSession {
        let mut ir = test_ir();
        ir.tool_guards.clear();
        ir.lifecycle_guards = vec![BoundLifecycleGuard {
            id: "deadline-guard".into(),
            triggers: vec![LifecycleTrigger::End],
            require: BoundRuleExpression::Decide {
                prompt: "approve end".into(),
            },
            on_failure: OnFailureConfig {
                action: ActionType::Deny,
                feedback: None,
            },
            order: 1,
            declaration_order: 0,
        }];
        ir.content_hash = Some(ir.compute_content_hash());
        ArcRuntimeSession::new("deadline-session", ir)
            .with_decision_provider(Arc::new(
                MockDecisionProvider::new().with_decision("approve end", true),
            ))
            .with_probe_runner(Arc::new(MockProbeRunner::new()))
    }

    fn run_hook_with_deadline(deadline_unix_ms: i64) -> ArcEvaluationResult {
        let mut session = deadline_session();
        let observed = HookObservationContext::new("codex", "deadline-session", "inv-deadline");
        evaluate_guard_with_observability_until(
            &mut session,
            ArcEvent::lifecycle("deadline-session", "deadline-hook", ArcEventType::End, 1),
            &None,
            &observed,
            deadline_unix_ms,
        )
        .expect("hook evaluation returns a result")
    }

    #[test]
    fn hook_wrapper_passes_bounded_default_deadline_to_until() {
        let now_ms = |t: SystemTime| t.duration_since(UNIX_EPOCH).unwrap().as_millis() as i64;
        let window_ms = (DECISION_EVALUATION_TIMEOUT_SECONDS * 1_000) as i64;
        let mut session = deadline_session();
        let observed = HookObservationContext::new("codex", "deadline-session", "inv-deadline");
        let event = ArcEvent::lifecycle("deadline-session", "deadline-hook", ArcEventType::End, 1);
        let before = now_ms(SystemTime::now());
        let mut seen = None;
        let _ = evaluate_guard_with_default_deadline(
            &mut session,
            event,
            &None,
            &observed,
            |_, _, _, _, deadline| {
                seen = Some(deadline);
                Err(anyhow::anyhow!("captured"))
            },
        );
        let after = now_ms(SystemTime::now());
        let deadline = seen.expect("until fn called");
        assert!(deadline < i64::MAX);
        assert!(deadline >= before + window_ms, "deadline below now+budget");
        assert!(deadline <= after + window_ms, "deadline above now+budget");
    }

    #[test]
    fn evaluation_deadline_from_adds_the_decision_window_and_saturates() {
        let window_ms = (DECISION_EVALUATION_TIMEOUT_SECONDS * 1_000) as i64;
        assert_eq!(evaluation_deadline_from(1_000), 1_000 + window_ms);
        assert_eq!(evaluation_deadline_from(i64::MAX), i64::MAX);
    }

    #[test]
    fn hook_entry_with_expired_deadline_is_a_runtime_fault_not_continue() {
        let result = run_hook_with_deadline(1);
        assert_eq!(
            result.effective_disposition,
            EffectiveDisposition::RuntimeFault
        );
        match &result.report.guard_results[0].state {
            GuardResultState::Faulted { faults, .. } => assert!(
                faults.iter().any(|fault| matches!(
                    fault,
                    crate::runtime::guard_evaluation::EvaluationFault::Decision { summary }
                        if summary.contains("DeadlineExceeded")
                )),
                "expected DeadlineExceeded decision fault, got: {faults:?}"
            ),
            other => panic!("expected Faulted guard, got: {other:?}"),
        }
    }

    #[test]
    fn hook_entry_with_maximum_deadline_continues() {
        let result = run_hook_with_deadline(i64::MAX);
        assert_eq!(result.effective_disposition, EffectiveDisposition::Continue);
    }
}
