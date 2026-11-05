pub mod adapter;
pub mod context;
pub(crate) mod decision;
pub mod evaluator;
pub mod events;
pub mod execution;
pub mod guard_evaluation;
pub mod observability;
pub mod session;
pub mod state_store;

pub use adapter::{
    AgyAdapter, AgyPreInvocationInput, AgyPreInvocationOutput, AgyPreToolUseInput,
    AgyPreToolUseOutput, AgyStopInput, AgyStopOutput, AgyToolCallDetail, CodexAdapter,
    CodexPreToolUseInput, CodexPreToolUseOutput, CodexSessionStartInput, CodexSessionStartOutput,
    CodexStopInput, CodexStopOutput, format_bundle_feedback_for_provider,
};
pub use context::{
    CommandTelemetry, OpenedTranscript, SessionContext, SessionContextExtractor,
    TranscriptResolutionError,
};
pub use decision::GuardFailureContext;
pub use decision::{
    AppliedDecisionDirective, DecisionApplyResult, DecisionContractError, DecisionCorrelation,
    DecisionPresentationClaimStore, DecisionPresentationRegistry, DecisionPresenter,
    EmbeddedDecisionPresenter, InteractiveDecisionDispatch, InteractiveDecisionMetadata,
    InteractiveDecisionOrchestrator, InteractiveDecisionOutcome, InteractiveDecisionRequest,
    InteractiveDecisionResolution, InteractivePendingTarget, InteractiveResolutionContext,
    apply_interactive_resolution, compose_failure_feedback,
    interactive_decision_request_from_evaluation_result, validate_interactive_request,
};

pub use evaluator::{
    ARC_RECURSION_INTERNAL_TOKEN, ARC_RECURSION_MARKER_ENV, AuditRequestDetails,
    AuditorInputPayload, AuditorOutputPayload, CliDecisionProvider, CurrentOperation,
    DecisionError, DecisionProvider, DecisionVerdict, DefaultProbeRunner, DeterministicEvidence,
    GuardDecisionEvidence, MatcherEvidence, ProbeError, ProbeRunner, WorkspaceProbeRunner,
    build_auditor_payload, is_auditor_session_intent, run_command_bounded,
    run_command_bounded_with_input,
};
#[cfg(any(test, feature = "test-support"))]
pub use evaluator::{MockDecisionProvider, MockProbeRunner};
pub use events::{
    ActivationKind, ArcEvent, ArcEventPayload, ArcEventType, EvaluationState, GuardEvaluation,
    ToolArgumentExtraction,
};
pub use execution::{
    CoordinationInput, DecisionActor, DecisionChoice, DecisionIntegrity, DecisionReceipt,
    DecisionRequest, EvaluationSnapshot, ExecutionPolicy, GuardActivation,
    GuardExecutionCoordinator, GuardExecutionKey, GuardExecutionRecord, GuardExecutionState,
    GuardWaiver, ProviderSignals, ReasonCode, ReentryKind, RuntimeDirective, RuntimeDisposition,
    ViolationHandling,
};
pub use guard_evaluation::{
    ActivationCacheError, ActivationCacheSummary, ActivationEvaluationCache, ActivationSnapshot,
    ArcEvaluationError, ArcEvaluationResult, CacheResolutionProvenance, DecisionBatchResult,
    DecisionEvaluationInput, DecisionExecutionProfile, DecisionProviderExecutor, DecisionScheduler,
    DecisionTaskFault, DecisionTaskRequest, DecisionTaskResult, DialogAuthorizationItem,
    DialogRequest, DialogResponse, DialogViolationItem, EffectiveDisposition,
    EvaluationCompleteness, EvaluationFault, EventEvaluationReport, ExactOperationAuthorization,
    ExpressionPathSegment, FailedGuardFeedback, FailureBundle, FailureBundleError, FailureCause,
    FailureCauseKind, GuardEvaluationBatchError, GuardEvaluationContractError, GuardEvaluationSpec,
    GuardResult, GuardResultState, LeafAttribution, LeafEvaluationKind, LeafOccurrence,
    LeafOccurrenceResolution, LeafResult, MAX_DETERMINISTIC_EVIDENCE_ITEMS,
    MAX_DIALOG_USER_MESSAGE_CHARS, MAX_EXPECTED_VALUES_ITEMS, MAX_MATCHER_EVIDENCE_ITEMS,
    MAX_RULE_PATH_SEGMENTS, MatchingGuardSnapshot, PhysicalDecisionExecutor, PresentationKind,
    ProbeEvaluationInput, ProbeObservation, ProbeOccurrence, ProbeTaskFault, ProbeTaskResult,
    ProviderEvaluationReceipt, ReductionError, RuleReduction, SchedulerError,
    SemanticDecisionEvidence, TrustedIrAnchor, canonical_decision_evaluation_bytes,
    canonical_probe_evaluation_bytes, decision_evaluation_key,
    evaluate_all_guards_with_cache_concurrency, exact_operation_fingerprint, expression_path_key,
    normalized_arguments_fingerprint, occurrence_id, physical_evaluation_id, probe_evaluation_key,
    reduce_effective_disposition, reduce_guard_result, reduce_rule_expression, sort_guard_results,
};
pub use observability::{
    EventQuery, NewObservabilityEvent, ObservabilityEvent, ObservabilityJournal, new_invocation_id,
};
pub use session::{
    ArcRuntimeSession, HookObservationContext, PreventiveSecurityFaultError,
    evaluate_guard_with_observability,
};
#[cfg(any(test, feature = "test-support"))]
pub use state_store::InMemoryStateStore;
pub use state_store::{
    AggregateGuardResolutionApplyRequest, AggregateGuardResolutionTarget,
    AggregateResolutionApplyOutcome, AggregateResolutionApplyRequest, ExactAuthorizationContext,
    GuardExecutionStateStore, SqliteStateStore, TrustedIrSnapshot, WriteOutcome,
    canonical_workspace_root, default_state_database_path,
};
