use serde::{Deserialize, Serialize};

use crate::decision_ui::{ARC_EMBEDDED_UI_TRANSPORT_LABEL, PortableDecision, UnresolvedReason};
use crate::runtime::execution::DecisionChoice;
use crate::runtime::guard_evaluation::{DIALOG_RESPONSE_SCHEMA, DialogResponse};
use crate::target::{DecisionTransport, ProviderTarget};

use super::context::InteractiveDecisionRequest;
use super::messages::{
    DecisionContractError, MAX_MESSAGE_CHARS, MAX_THEME_CHARS, MAX_TRANSPORT_LABEL_CHARS,
    validate_optional, validate_required,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum InteractiveDecisionOutcome {
    Allow,
    Deny,
    Retry { reason: UnresolvedReason },
}

impl From<PortableDecision> for InteractiveDecisionOutcome {
    fn from(decision: PortableDecision) -> Self {
        match decision {
            PortableDecision::Allow => Self::Allow,
            PortableDecision::Deny => Self::Deny,
            PortableDecision::Unresolved(reason) => Self::Retry { reason },
        }
    }
}

impl InteractiveDecisionOutcome {
    /// Converts only explicit user choices to durable choices. Retry has no
    /// durable equivalent and therefore cannot become Deny by accident.
    pub(crate) fn explicit_decision_choice(self) -> Option<DecisionChoice> {
        match self {
            Self::Allow => Some(DecisionChoice::Allow),
            Self::Deny => Some(DecisionChoice::Deny),
            Self::Retry { .. } => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InteractiveDecisionResolution {
    request: InteractiveDecisionRequest,
    outcome: InteractiveDecisionOutcome,
    user_message: Option<String>,
    transport: DecisionTransport,
    transport_label: String,
    theme: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct InteractiveDecisionMetadata {
    presentation_id: String,
    provider: ProviderTarget,
    event: crate::runtime::events::ArcEventType,
    outcome: InteractiveDecisionOutcome,
    transport: DecisionTransport,
    transport_label: String,
    theme: String,
}

impl InteractiveDecisionResolution {
    fn new(
        request: InteractiveDecisionRequest,
        outcome: InteractiveDecisionOutcome,
        user_message: Option<String>,
        transport: DecisionTransport,
        transport_label: impl Into<String>,
        theme: impl Into<String>,
    ) -> Result<Self, DecisionContractError> {
        let transport_label = transport_label.into();
        let theme = theme.into();
        validate_optional("user_message", user_message.as_deref(), MAX_MESSAGE_CHARS)?;
        validate_required(
            "transport_label",
            &transport_label,
            MAX_TRANSPORT_LABEL_CHARS,
        )?;
        validate_required("theme", &theme, MAX_THEME_CHARS)?;
        validate_transport_label(transport, &transport_label)?;
        Ok(Self {
            request,
            outcome,
            user_message,
            transport,
            transport_label,
            theme,
        })
    }

    pub fn from_dialog_response(
        request: InteractiveDecisionRequest,
        response: DialogResponse,
        transport: DecisionTransport,
    ) -> Result<Self, DecisionContractError> {
        let expected_bundle_fingerprint = request
            .failure_bundle()
            .map(|bundle| bundle.bundle_fingerprint.as_str())
            .or_else(|| {
                request
                    .correlation()
                    .map(|correlation| correlation.decision_id())
            })
            .or_else(|| {
                request
                    .exact_authorizations()
                    .and_then(<[_]>::first)
                    .map(|a| a.operation_fingerprint.as_str())
            })
            .unwrap_or(request.presentation_id());
        validate_dialog_response(
            request.presentation_id(),
            expected_bundle_fingerprint,
            &response,
            transport,
        )?;
        Self::new(
            request,
            response.decision.into(),
            response.message,
            transport,
            response.transport,
            response.theme,
        )
    }

    pub fn request(&self) -> &InteractiveDecisionRequest {
        &self.request
    }

    pub fn outcome(&self) -> InteractiveDecisionOutcome {
        self.outcome
    }

    pub fn user_message(&self) -> Option<&str> {
        self.user_message.as_deref()
    }

    pub fn transport(&self) -> DecisionTransport {
        self.transport
    }

    pub fn transport_label(&self) -> &str {
        &self.transport_label
    }

    pub fn theme(&self) -> &str {
        &self.theme
    }

    pub fn decision_id(&self) -> Option<&str> {
        self.request
            .correlation()
            .map(|correlation| correlation.decision_id())
    }

    pub fn provider(&self) -> ProviderTarget {
        self.request.provider()
    }

    pub fn metadata(&self) -> InteractiveDecisionMetadata {
        InteractiveDecisionMetadata {
            presentation_id: self.request.presentation_id().to_owned(),
            provider: self.request.provider(),
            event: self.request.event(),
            outcome: self.outcome,
            transport: self.transport,
            transport_label: self.transport_label.clone(),
            theme: self.theme.clone(),
        }
    }

    pub fn portable_decision(&self) -> PortableDecision {
        match self.outcome {
            InteractiveDecisionOutcome::Allow => PortableDecision::Allow,
            InteractiveDecisionOutcome::Deny => PortableDecision::Deny,
            InteractiveDecisionOutcome::Retry { reason } => PortableDecision::Unresolved(reason),
        }
    }

    pub fn to_dialog_response(&self) -> DialogResponse {
        let bundle_fingerprint = self
            .request
            .failure_bundle()
            .map(|bundle| bundle.bundle_fingerprint.clone())
            .or_else(|| {
                self.request
                    .correlation()
                    .map(|correlation| correlation.decision_id().to_owned())
            })
            .or_else(|| {
                self.request
                    .exact_authorizations()
                    .and_then(<[_]>::first)
                    .map(|a| a.operation_fingerprint.clone())
            })
            .unwrap_or_else(|| self.request.presentation_id().to_owned());
        DialogResponse {
            schema: DIALOG_RESPONSE_SCHEMA.into(),
            request_id: self.request.presentation_id().to_owned(),
            bundle_fingerprint,
            decision: self.portable_decision(),
            transport: self.transport_label.clone(),
            theme: self.theme.clone(),
            message: self.user_message.clone(),
        }
    }
}

pub(crate) fn validate_dialog_response(
    expected_request_id: &str,
    expected_bundle_fingerprint: &str,
    response: &DialogResponse,
    transport: DecisionTransport,
) -> Result<(), DecisionContractError> {
    if response.schema != DIALOG_RESPONSE_SCHEMA {
        return Err(DecisionContractError::Schema {
            expected: DIALOG_RESPONSE_SCHEMA,
            actual: response.schema.clone(),
        });
    }
    if response.request_id != expected_request_id {
        return Err(DecisionContractError::ResponseRequestMismatch {
            expected: expected_request_id.to_owned(),
            received: response.request_id.clone(),
        });
    }
    if response.bundle_fingerprint != expected_bundle_fingerprint {
        return Err(DecisionContractError::CorrelationMismatch {
            field: "bundle_fingerprint",
        });
    }
    validate_optional(
        "user_message",
        response.message.as_deref(),
        MAX_MESSAGE_CHARS,
    )?;
    validate_required(
        "transport_label",
        &response.transport,
        MAX_TRANSPORT_LABEL_CHARS,
    )?;
    validate_required("theme", &response.theme, MAX_THEME_CHARS)?;
    validate_transport_label(transport, &response.transport)
}

fn validate_transport_label(
    transport: DecisionTransport,
    label: &str,
) -> Result<(), DecisionContractError> {
    let expected = match transport {
        DecisionTransport::ProviderNative => "provider_native",
        DecisionTransport::ArcEmbeddedUi => ARC_EMBEDDED_UI_TRANSPORT_LABEL,
        DecisionTransport::CodexAppServer => "codex_app_server",
        DecisionTransport::DirectMcp => "direct_mcp",
    };
    if label != expected {
        return Err(DecisionContractError::TransportLabelMismatch {
            transport: expected,
            label: label.to_owned(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::decision::{DecisionCorrelation, GuardFailureContext};
    use crate::runtime::events::ArcEventType;

    fn request() -> InteractiveDecisionRequest {
        let guard = GuardFailureContext::new(
            "guard-1",
            Some("Configured feedback".into()),
            Some("Finding: operation requires review".into()),
        )
        .expect("valid guard");
        InteractiveDecisionRequest::new(
            ProviderTarget::Codex,
            ArcEventType::ToolCall,
            crate::manifest::schema::ActionType::Ask,
            "presentation-1",
            "invocation-1",
            guard,
            "Approve the exact operation",
            None,
            Some("Bash git status".into()),
            "exact pending operation once",
            Some(
                DecisionCorrelation::new(
                    "decision-1",
                    "execution-1",
                    Some("invocation-owner".into()),
                )
                .expect("valid correlation"),
            ),
        )
        .expect("valid request")
    }

    #[test]
    fn serde_distinguishes_allow_deny_and_retry() {
        assert_eq!(
            serde_json::to_value(InteractiveDecisionOutcome::Allow).unwrap(),
            serde_json::json!({"outcome": "allow"})
        );
        assert_eq!(
            serde_json::to_value(InteractiveDecisionOutcome::Deny).unwrap(),
            serde_json::json!({"outcome": "deny"})
        );
        assert_eq!(
            serde_json::to_value(InteractiveDecisionOutcome::Retry {
                reason: UnresolvedReason::TimedOut,
            })
            .unwrap(),
            serde_json::json!({"outcome": "retry", "reason": "timed_out"})
        );
    }

    #[test]
    fn portable_unresolved_decisions_become_retry() {
        let outcome = InteractiveDecisionOutcome::from(PortableDecision::Unresolved(
            UnresolvedReason::Closed,
        ));
        assert_eq!(
            outcome,
            InteractiveDecisionOutcome::Retry {
                reason: UnresolvedReason::Closed
            }
        );
        assert!(matches!(outcome, InteractiveDecisionOutcome::Retry { .. }));
        assert_eq!(outcome.explicit_decision_choice(), None);
    }

    #[test]
    fn retry_never_serializes_or_maps_to_deny() {
        let retry = InteractiveDecisionOutcome::Retry {
            reason: UnresolvedReason::TransportFailed,
        };
        assert_eq!(retry.explicit_decision_choice(), None);
        assert_ne!(
            serde_json::to_value(retry).unwrap(),
            serde_json::to_value(DecisionChoice::Deny).unwrap()
        );
    }

    #[test]
    fn resolution_preserves_user_message_and_transport_metadata() {
        let response = DialogResponse {
            schema: DIALOG_RESPONSE_SCHEMA.into(),
            request_id: "presentation-1".into(),
            bundle_fingerprint: "decision-1".into(),
            decision: PortableDecision::Allow,
            transport: ARC_EMBEDDED_UI_TRANSPORT_LABEL.into(),
            theme: "dark".into(),
            message: Some("Run the focused tests first".into()),
        };
        let resolution = InteractiveDecisionResolution::from_dialog_response(
            request(),
            response,
            DecisionTransport::ArcEmbeddedUi,
        )
        .expect("valid resolution");
        assert_eq!(resolution.outcome(), InteractiveDecisionOutcome::Allow);
        assert_eq!(
            resolution.user_message(),
            Some("Run the focused tests first")
        );
        assert_eq!(
            resolution.transport_label(),
            ARC_EMBEDDED_UI_TRANSPORT_LABEL
        );
        assert_eq!(resolution.theme(), "dark");
    }

    #[test]
    fn metadata_serialization_excludes_sensitive_request_context() {
        let resolution = InteractiveDecisionResolution::new(
            request(),
            InteractiveDecisionOutcome::Retry {
                reason: UnresolvedReason::Closed,
            },
            Some("The dialog was closed".into()),
            DecisionTransport::ArcEmbeddedUi,
            "arc_embedded_ui",
            "dark",
        )
        .expect("valid resolution");
        let encoded = serde_json::to_value(resolution.metadata()).expect("serialize metadata");
        assert_eq!(encoded["presentation_id"], "presentation-1");
        assert_eq!(encoded["outcome"]["outcome"], "retry");
        assert!(encoded.get("prompt").is_none());
        assert!(encoded.get("auditor_findings").is_none());
        assert!(encoded.get("operation").is_none());
        assert!(encoded.get("user_message").is_none());
    }

    #[test]
    fn response_for_another_request_is_rejected() {
        let response = DialogResponse {
            schema: DIALOG_RESPONSE_SCHEMA.into(),
            request_id: "presentation-other".into(),
            bundle_fingerprint: "decision-1".into(),
            decision: PortableDecision::Allow,
            transport: "arc_embedded_ui".into(),
            theme: "dark".into(),
            message: None,
        };
        let error = InteractiveDecisionResolution::from_dialog_response(
            request(),
            response,
            DecisionTransport::ArcEmbeddedUi,
        )
        .expect_err("response/request correlation must be enforced");
        assert!(matches!(
            error,
            DecisionContractError::ResponseRequestMismatch { .. }
        ));
    }

    #[test]
    fn transport_label_must_match_transport_metadata() {
        let response = DialogResponse {
            schema: DIALOG_RESPONSE_SCHEMA.into(),
            request_id: "presentation-1".into(),
            bundle_fingerprint: "decision-1".into(),
            decision: PortableDecision::Allow,
            transport: "provider_native".into(),
            theme: "dark".into(),
            message: None,
        };
        let error = InteractiveDecisionResolution::from_dialog_response(
            request(),
            response,
            DecisionTransport::ArcEmbeddedUi,
        )
        .expect_err("transport metadata cannot contradict the selected transport");
        assert!(matches!(
            error,
            DecisionContractError::TransportLabelMismatch { .. }
        ));
    }
}
