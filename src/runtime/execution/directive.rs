use serde::{Deserialize, Serialize};

use super::DecisionRequest;
use super::state::AttemptSnapshot;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeDisposition {
    Proceed,
    Prevent,
    ContinueForRemediation,
    RequestDecision,
    RequestAuthorization,
    Suspend,
    Abort,
    ReportOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReasonCode {
    GuardSatisfied,
    GuardDenied,
    MessageFeedback,
    FirstRemediation,
    ProgressObserved,
    UserDecisionRequired,
    AuthorizationRequired,
    EvaluationFault,
    CircuitBreakerExhausted,
    DuplicateInvocation,
    WaiverAccepted,
    RemediationAttemptIncomplete,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeDirective {
    pub disposition: RuntimeDisposition,
    pub execution_id: String,
    pub message: Option<String>,
    pub attempts: AttemptSnapshot,
    pub evidence_fingerprint: Option<String>,
    pub reason_code: ReasonCode,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decision_request: Option<DecisionRequest>,
}
