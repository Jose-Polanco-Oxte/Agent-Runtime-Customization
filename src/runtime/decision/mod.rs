mod context;
mod messages;
mod orchestrator;
mod resolution;

pub use context::GuardFailureContext;
pub use context::{
    DecisionCorrelation, InteractiveDecisionRequest, compose_failure_feedback,
    interactive_decision_request_from_evaluation_result,
};
pub use messages::DecisionContractError;
pub use orchestrator::{
    AppliedDecisionDirective, DecisionApplyResult, DecisionPresentationClaimStore,
    DecisionPresentationRegistry, DecisionPresenter, EmbeddedDecisionPresenter,
    InteractiveDecisionDispatch, InteractiveDecisionOrchestrator, InteractivePendingTarget,
    InteractiveResolutionContext, apply_interactive_resolution, validate_interactive_request,
};
pub use resolution::{
    InteractiveDecisionMetadata, InteractiveDecisionOutcome, InteractiveDecisionResolution,
};
