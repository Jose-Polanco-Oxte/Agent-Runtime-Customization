mod coordinator;
mod decision;
mod directive;
mod identity;
mod lifecycle;
mod observation;
mod policy;
mod state;

pub use coordinator::{CoordinationInput, GuardExecutionCoordinator, ViolationHandling};
pub use decision::{
    DecisionActor, DecisionChoice, DecisionIntegrity, DecisionReceipt, DecisionRequest, GuardWaiver,
};
pub use directive::{ReasonCode, RuntimeDirective, RuntimeDisposition};
pub use identity::{GuardActivation, GuardExecutionKey, ProviderSignals, ReentryKind};
pub use observation::EvaluationSnapshot;
pub use policy::ExecutionPolicy;
pub use state::{AttemptSnapshot, GuardExecutionRecord, GuardExecutionState, unix_ms_to_iso8601};

pub use lifecycle::{
    LifecycleStopActivation, LifecycleStopContext, LifecycleStopDecision,
    LifecycleStopDecisionRequest, LifecycleStopOutcome, coordinate_lifecycle_stop,
};
