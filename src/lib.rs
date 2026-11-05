// src/lib.rs

pub mod catalog;
pub mod compiler;
pub mod decision_ui;
pub mod emitters;
pub mod ir;
pub mod manifest;
pub mod mcp;
pub mod runtime;
pub mod target;

// Re-exports
pub use compiler::lower;
pub use emitters::{
    BuildArtifactRecord, BuildManifest, CodexEmitter, CollisionDetector, EmissionContext,
    EmitterRegistry, GeminiEmitter, GeneratedArtifact, TargetEmitter, recover_pending_build,
    write_artifacts, write_artifacts_with_trust,
};
pub use ir::{
    BehaviorIR, BoundLifecycleGuard, BoundMatcher, BoundProbeCommand, BoundRuleExpression,
    BoundToolGuard, ProbeCommandError, WorkspaceContext,
};
pub use manifest::{
    ActionType, AliasesManifest, ArcManifest, GuardsConfig, LifecycleTrigger, LoadedArcProject,
    OnFailureConfig, RuleExpression, RulesManifest, RuntimeConfig, discover_arc_root,
    load_manifest, load_project, read_contained_file, resolve_explicit_manifest_file,
};
pub use runtime::{
    ARC_RECURSION_INTERNAL_TOKEN, ARC_RECURSION_MARKER_ENV, ActivationKind,
    AggregateGuardResolutionApplyRequest, AggregateGuardResolutionTarget,
    AggregateResolutionApplyOutcome, AggregateResolutionApplyRequest, AgyAdapter,
    AgyPreInvocationInput, AgyPreInvocationOutput, AgyPreToolUseInput, AgyPreToolUseOutput,
    AgyStopInput, AgyStopOutput, AgyToolCallDetail, AppliedDecisionDirective, ArcEvent,
    ArcEventPayload, ArcEventType, ArcRuntimeSession, AuditRequestDetails, AuditorInputPayload,
    AuditorOutputPayload, CliDecisionProvider, CodexAdapter, CodexPreToolUseInput,
    CodexPreToolUseOutput, CodexSessionStartInput, CodexSessionStartOutput, CodexStopInput,
    CodexStopOutput, CommandTelemetry, CoordinationInput, CurrentOperation, DecisionActor,
    DecisionApplyResult, DecisionChoice, DecisionContractError, DecisionCorrelation, DecisionError,
    DecisionIntegrity, DecisionPresentationClaimStore, DecisionPresentationRegistry,
    DecisionPresenter, DecisionProvider, DecisionReceipt, DecisionRequest, DecisionVerdict,
    DefaultProbeRunner, DeterministicEvidence, EmbeddedDecisionPresenter, EvaluationSnapshot,
    EvaluationState, EventQuery, ExactAuthorizationContext, ExecutionPolicy, GuardActivation,
    GuardDecisionEvidence, GuardEvaluation, GuardExecutionCoordinator, GuardExecutionKey,
    GuardExecutionRecord, GuardExecutionState, GuardExecutionStateStore, GuardFailureContext,
    GuardWaiver, HookObservationContext, InteractiveDecisionDispatch, InteractiveDecisionMetadata,
    InteractiveDecisionOrchestrator, InteractiveDecisionOutcome, InteractiveDecisionRequest,
    InteractiveDecisionResolution, InteractivePendingTarget, InteractiveResolutionContext,
    MatcherEvidence, NewObservabilityEvent, ObservabilityEvent, ObservabilityJournal,
    OpenedTranscript, PreventiveSecurityFaultError, ProbeError, ProbeRunner, ProviderSignals,
    ReasonCode, ReentryKind, RuntimeDirective, RuntimeDisposition, SessionContext,
    SessionContextExtractor, SqliteStateStore, ToolArgumentExtraction, TranscriptResolutionError,
    TrustedIrSnapshot, ViolationHandling, WorkspaceProbeRunner, WriteOutcome,
    apply_interactive_resolution, build_auditor_payload, canonical_workspace_root,
    compose_failure_feedback, default_state_database_path, evaluate_guard_with_observability,
    format_bundle_feedback_for_provider, interactive_decision_request_from_evaluation_result,
    is_auditor_session_intent, new_invocation_id, run_command_bounded,
    run_command_bounded_with_input,
};

#[cfg(any(test, feature = "test-support"))]
pub use runtime::{InMemoryStateStore, MockDecisionProvider, MockProbeRunner};

pub use runtime::guard_evaluation::{
    ActivationCacheError, ActivationCacheSummary, ActivationEvaluationCache, ActivationSnapshot,
    ArcEvaluationError, ArcEvaluationResult, CacheResolutionProvenance,
    DECISION_TASK_REQUEST_SCHEMA, DIALOG_REQUEST_SCHEMA, DIALOG_RESPONSE_SCHEMA,
    DecisionBatchResult, DecisionEvaluationInput, DecisionExecutionProfile,
    DecisionProviderExecutor, DecisionScheduler, DecisionTaskFault, DecisionTaskRequest,
    DecisionTaskResult, DialogAuthorizationItem, DialogFailedProbe, DialogRequest, DialogResponse,
    DialogViolationItem, EVENT_EVALUATION_REPORT_SCHEMA, EffectiveDisposition,
    EvaluationCompleteness, EvaluationFault, EventEvaluationReport, ExactOperationAuthorization,
    ExpressionPathSegment, FAILURE_BUNDLE_SCHEMA, FailedGuardFeedback, FailureBundle,
    FailureBundleError, FailureCause, FailureCauseKind, GuardEvaluationBatchError,
    GuardEvaluationContractError, GuardEvaluationSpec, GuardResult, GuardResultState,
    LeafAttribution, LeafEvaluationKind, LeafOccurrence, LeafOccurrenceResolution, LeafResult,
    MAX_DETERMINISTIC_EVIDENCE_ITEMS, MAX_DIALOG_FAILED_PROBES, MAX_DIALOG_USER_MESSAGE_CHARS,
    MAX_EXPECTED_VALUES_ITEMS, MAX_MATCHER_EVIDENCE_ITEMS, MAX_RULE_PATH_SEGMENTS,
    MatchingGuardSnapshot, PhysicalDecisionExecutor, PresentationKind, ProbeEvaluationInput,
    ProbeObservation, ProbeOccurrence, ProbeTaskFault, ProbeTaskResult, ProviderEvaluationReceipt,
    ReductionError, RuleReduction, SchedulerError, SemanticDecisionEvidence, TrustedIrAnchor,
    canonical_decision_evaluation_bytes, canonical_probe_evaluation_bytes, decision_evaluation_key,
    evaluate_all_guards_with_cache_concurrency, exact_operation_fingerprint, expression_path_key,
    fingerprint, normalized_arguments_fingerprint, occurrence_id, physical_evaluation_id,
    probe_evaluation_key, reduce_effective_disposition, reduce_guard_result,
    reduce_rule_expression, sort_guard_results,
};

pub use target::{
    CapabilityContext, CapabilityDiagnostic, CapabilityEvent, CapabilityLevel,
    CapabilityResolution, CompilationMatrix, CoverageSurface, DecisionEnvironment,
    DecisionTransport, DecisionUiMode, OsTarget, ProviderCapabilities, ProviderEnvironment,
    ProviderTarget, TargetSelector, TransportResolution, check_project_compatibility,
    generate_capabilities_table, resolve_capability, resolve_decision_transport,
    resolve_decision_transport_for,
};

pub use decision_ui::{PortableDecision, UnresolvedReason};
