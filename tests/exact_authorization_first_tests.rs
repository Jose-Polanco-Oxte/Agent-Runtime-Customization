//! REQ-008 (AC-008.1, AC-012): pins the `.first()` semantics of the inlined
//! `exact_authorizations().and_then(<[_]>::first)` sites in
//! `runtime/decision/resolution.rs` (`from_dialog_response`, `to_dialog_response`)
//! and `runtime/decision/context.rs` (`to_dialog_request`).
//!
//! The three sites fall back to the first exact authorization's operation
//! fingerprint only when the request has no failure bundle and no correlation.
//! An `aggregate_decision` request is the only public way to hold several
//! authorizations with different fingerprints without a bundle.

use arc::{
    ActionType, ArcEventType, DIALOG_RESPONSE_SCHEMA, DecisionContractError, DecisionTransport,
    DialogResponse, ExactOperationAuthorization, GuardFailureContext, InteractiveDecisionRequest,
    InteractiveDecisionResolution, PortableDecision, ProviderTarget,
};

const FIRST_FP: &str = "sha256:first-authorization";
const SECOND_FP: &str = "sha256:second-authorization";

fn authorization(guard_id: &str, fingerprint: &str) -> ExactOperationAuthorization {
    ExactOperationAuthorization {
        guard_id: guard_id.into(),
        operation_fingerprint: fingerprint.into(),
        event_id: "event-1".into(),
        tool: "Bash".into(),
        normalized_arguments_fingerprint: format!("args-{guard_id}"),
    }
}

/// Aggregate request: no failure bundle, no correlation, two authorizations
/// with different operation fingerprints, FIRST_FP listed first.
fn aggregate_request() -> InteractiveDecisionRequest {
    let guards = vec![
        GuardFailureContext::new("guard-a", None, None).expect("guard a"),
        GuardFailureContext::new("guard-b", None, None).expect("guard b"),
    ];
    let request = InteractiveDecisionRequest::aggregate_decision(
        ProviderTarget::Codex,
        ArcEventType::ToolCall,
        ActionType::Ask,
        "presentation-two-auth",
        "invocation-1",
        guards,
        vec![
            authorization("guard-a", FIRST_FP),
            authorization("guard-b", SECOND_FP),
        ],
        "Arc policy requires your decision.",
        None,
        Some("Bash git status".into()),
        "this exact tool call once",
        None,
    )
    .expect("valid aggregate request");
    let authorizations = request.exact_authorizations().expect("authorizations");
    assert_eq!(
        authorizations.len(),
        2,
        "fixture must hold two authorizations"
    );
    assert_eq!(authorizations[0].operation_fingerprint, FIRST_FP);
    assert_eq!(authorizations[1].operation_fingerprint, SECOND_FP);
    assert!(request.correlation().is_none());
    assert!(request.failure_bundle().is_none());
    request
}

fn allow_response(bundle_fingerprint: &str) -> DialogResponse {
    DialogResponse {
        schema: DIALOG_RESPONSE_SCHEMA.into(),
        request_id: "presentation-two-auth".into(),
        bundle_fingerprint: bundle_fingerprint.into(),
        decision: PortableDecision::Allow,
        transport: "provider_native".into(),
        theme: "dark".into(),
        message: None,
    }
}

#[test]
fn dialog_request_bundle_fingerprint_is_the_first_authorization_fingerprint() {
    // context.rs `to_dialog_request` fallback.
    let dialog = aggregate_request().to_dialog_request("Arc policy decision");
    assert_eq!(dialog.bundle_fingerprint, FIRST_FP);
}

#[test]
fn dialog_response_bundle_fingerprint_is_the_first_authorization_fingerprint() {
    // resolution.rs `to_dialog_response` fallback (second site).
    let resolution = InteractiveDecisionResolution::from_dialog_response(
        aggregate_request(),
        allow_response(FIRST_FP),
        DecisionTransport::ProviderNative,
    )
    .expect("response carrying the first fingerprint is accepted");
    assert_eq!(resolution.to_dialog_response().bundle_fingerprint, FIRST_FP);
}

#[test]
fn response_validation_expects_the_first_authorization_fingerprint() {
    // resolution.rs `from_dialog_response` expected fingerprint (first site).
    let accepted = InteractiveDecisionResolution::from_dialog_response(
        aggregate_request(),
        allow_response(FIRST_FP),
        DecisionTransport::ProviderNative,
    );
    assert!(accepted.is_ok(), "first fingerprint must be accepted");

    let rejected = InteractiveDecisionResolution::from_dialog_response(
        aggregate_request(),
        allow_response(SECOND_FP),
        DecisionTransport::ProviderNative,
    )
    .expect_err("a response bound to the second authorization must be rejected");
    assert_eq!(
        rejected,
        DecisionContractError::CorrelationMismatch {
            field: "bundle_fingerprint"
        }
    );
}
