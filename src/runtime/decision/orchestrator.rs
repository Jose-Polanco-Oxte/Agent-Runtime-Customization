use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Result, anyhow, bail};

use crate::decision_ui::request_embedded_decision;
use crate::runtime::events::ArcEventType;
use crate::runtime::guard_evaluation::{DialogRequest, DialogResponse};
use crate::target::capabilities::expected_ask_effective_action;
use crate::target::{
    CapabilityContext, CapabilityEvent, CapabilityLevel, CapabilityResolution, DecisionTransport,
    DecisionUiMode, OsTarget, resolve_capability,
};

use crate::runtime::execution::{DecisionActor, DecisionIntegrity, DecisionReceipt};
use crate::runtime::execution::{GuardExecutionCoordinator, GuardExecutionKey};
use crate::runtime::guard_evaluation::{ArcEvaluationResult, EffectiveDisposition};
use crate::runtime::state_store::{AggregateResolutionApplyOutcome, ExactAuthorizationContext};

use super::context::InteractiveDecisionRequest;
use super::messages::DecisionContractError;
use super::resolution::InteractiveDecisionResolution;

/// Presentation boundary for one interactive decision.
pub trait DecisionPresenter: Send + Sync {
    fn present(&self, request: &DialogRequest, timeout: Duration) -> Result<DialogResponse>;
}

/// Atomic durable claim used to prevent duplicate dialogs across hook
/// processes. The store must make the invocation and optional decision claim
/// one transaction, and return `false` when either identifier was already
/// claimed.
pub trait DecisionPresentationClaimStore: Send + Sync {
    fn claim_presentation(&self, invocation_id: &str, decision_id: Option<&str>) -> Result<bool>;
}

/// Production presenter backed by Arc's bounded embedded UI sidecar.
#[derive(Debug, Default, Clone, Copy)]
pub struct EmbeddedDecisionPresenter;

impl DecisionPresenter for EmbeddedDecisionPresenter {
    fn present(&self, request: &DialogRequest, timeout: Duration) -> Result<DialogResponse> {
        request_embedded_decision(request, timeout)
    }
}

#[derive(Debug, Default)]
struct PresentationClaims {
    invocation_ids: HashSet<String>,
    decision_ids: HashSet<String>,
}

/// Shared claim registry preventing duplicate presentation for one invocation
/// or one correlated decision. Callers that span multiple dispatches must
/// share the same registry instance.
#[derive(Default)]
pub struct DecisionPresentationRegistry {
    claims: Mutex<PresentationClaims>,
    durable_claim_store: Option<Arc<dyn DecisionPresentationClaimStore>>,
}

impl std::fmt::Debug for DecisionPresentationRegistry {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DecisionPresentationRegistry")
            .field("claims", &self.claims)
            .field(
                "has_durable_claim_store",
                &self.durable_claim_store.is_some(),
            )
            .finish()
    }
}

impl DecisionPresentationRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_durable_claim_store(
        durable_claim_store: Arc<dyn DecisionPresentationClaimStore>,
    ) -> Self {
        Self {
            claims: Mutex::new(PresentationClaims::default()),
            durable_claim_store: Some(durable_claim_store),
        }
    }

    fn claim(&self, request: &InteractiveDecisionRequest) -> Result<()> {
        let decision_id = request
            .correlation()
            .map(|correlation| correlation.decision_id().to_owned());
        let mut claims = self
            .claims
            .lock()
            .map_err(|_| anyhow!("interactive presentation claim registry is poisoned"))?;
        if claims.invocation_ids.contains(request.invocation_id())
            || decision_id
                .as_ref()
                .is_some_and(|id| claims.decision_ids.contains(id))
        {
            return Err(DecisionContractError::DuplicatePresentation {
                invocation_id: request.invocation_id().to_owned(),
                decision_id,
            }
            .into());
        }
        if let Some(store) = &self.durable_claim_store
            && !store.claim_presentation(request.invocation_id(), decision_id.as_deref())?
        {
            return Err(DecisionContractError::DuplicatePresentation {
                invocation_id: request.invocation_id().to_owned(),
                decision_id,
            }
            .into());
        }
        claims
            .invocation_ids
            .insert(request.invocation_id().to_owned());
        if let Some(decision_id) = decision_id {
            claims.decision_ids.insert(decision_id);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InteractiveDecisionDispatch {
    Presented {
        capability: CapabilityResolution,
        resolution: Box<InteractiveDecisionResolution>,
    },
    CapabilityOnly {
        capability: CapabilityResolution,
    },
}

impl InteractiveDecisionDispatch {
    pub fn capability(&self) -> &CapabilityResolution {
        match self {
            Self::Presented { capability, .. } | Self::CapabilityOnly { capability } => capability,
        }
    }

    pub fn resolution(&self) -> Option<&InteractiveDecisionResolution> {
        match self {
            Self::Presented { resolution, .. } => Some(resolution.as_ref()),
            Self::CapabilityOnly { .. } => None,
        }
    }
}

pub struct InteractiveDecisionOrchestrator {
    target_os: OsTarget,
    decision_ui: DecisionUiMode,
    timeout: Duration,
    presenter: Arc<dyn DecisionPresenter>,
    presentation_registry: Arc<DecisionPresentationRegistry>,
}

impl InteractiveDecisionOrchestrator {
    pub fn new(target_os: OsTarget, decision_ui: DecisionUiMode, timeout: Duration) -> Self {
        Self {
            target_os,
            decision_ui,
            timeout,
            presenter: Arc::new(EmbeddedDecisionPresenter),
            presentation_registry: Arc::new(DecisionPresentationRegistry::new()),
        }
    }

    pub fn with_registry(
        target_os: OsTarget,
        decision_ui: DecisionUiMode,
        timeout: Duration,
        presentation_registry: Arc<DecisionPresentationRegistry>,
    ) -> Self {
        Self {
            target_os,
            decision_ui,
            timeout,
            presenter: Arc::new(EmbeddedDecisionPresenter),
            presentation_registry,
        }
    }

    pub fn with_presenter(
        target_os: OsTarget,
        decision_ui: DecisionUiMode,
        timeout: Duration,
        presenter: Arc<dyn DecisionPresenter>,
    ) -> Self {
        Self::with_presenter_and_registry(
            target_os,
            decision_ui,
            timeout,
            presenter,
            Arc::new(DecisionPresentationRegistry::new()),
        )
    }

    pub fn with_presenter_and_registry(
        target_os: OsTarget,
        decision_ui: DecisionUiMode,
        timeout: Duration,
        presenter: Arc<dyn DecisionPresenter>,
        presentation_registry: Arc<DecisionPresentationRegistry>,
    ) -> Self {
        Self {
            target_os,
            decision_ui,
            timeout,
            presenter,
            presentation_registry,
        }
    }

    /// Resolves capability once and presents only when Arc owns the selected
    /// embedded UI transport. Provider-owned or unsupported capabilities remain
    /// capability-only so the adapter can preserve its provider contract.
    pub fn dispatch(
        &self,
        request: InteractiveDecisionRequest,
    ) -> Result<InteractiveDecisionDispatch> {
        validate_interactive_request(&request).map_err(anyhow::Error::new)?;
        let capability = resolve_capability(CapabilityContext::cli(
            request.provider(),
            self.target_os.clone(),
            capability_event(request.event()),
            request.requested_action(),
            self.decision_ui,
        ));
        validate_capability(&request, &capability)?;

        if capability.decision_transport != Some(DecisionTransport::ArcEmbeddedUi) {
            return Ok(InteractiveDecisionDispatch::CapabilityOnly { capability });
        }

        self.presentation_registry.claim(&request)?;
        let dialog = request.to_dialog_request("Arc policy decision");
        let response = self.presenter.present(&dialog, self.timeout)?;
        let resolution = InteractiveDecisionResolution::from_dialog_response(
            request,
            response,
            DecisionTransport::ArcEmbeddedUi,
        )
        .map_err(anyhow::Error::new)?;
        Ok(InteractiveDecisionDispatch::Presented {
            capability,
            resolution: Box::new(resolution),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AppliedDecisionDirective {
    Allow {
        user_message: Option<String>,
        authorized_guards: Vec<String>,
    },
    Deny {
        user_message: Option<String>,
    },
    Retry {
        reason: crate::decision_ui::UnresolvedReason,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecisionApplyResult {
    pub directive: AppliedDecisionDirective,
    pub outcome: AggregateResolutionApplyOutcome,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InteractiveResolutionContext {
    pub keys: Vec<GuardExecutionKey>,
    pub pending_targets: Vec<InteractivePendingTarget>,
    pub owner_invocation_id: String,
    pub resolution_invocation_id: String,
    pub expires_at_unix_ms: i64,
    pub receipt_received_at_unix_ms: i64,
    pub authorization_context: Option<ExactAuthorizationContext>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InteractivePendingTarget {
    pub key: GuardExecutionKey,
    pub decision_id: String,
    pub execution_id: String,
}

pub fn apply_interactive_resolution(
    resolution: &InteractiveDecisionResolution,
    eval_result: &ArcEvaluationResult,
    coordinator: &GuardExecutionCoordinator,
    context: &InteractiveResolutionContext,
) -> Result<DecisionApplyResult> {
    let portable = resolution.portable_decision();

    if portable == crate::decision_ui::PortableDecision::Allow
        && matches!(
            eval_result.effective_disposition,
            EffectiveDisposition::Deny | EffectiveDisposition::RuntimeFault
        )
    {
        anyhow::bail!(
            "Cannot apply Allow: aggregate evaluation resulted in non-overridable disposition {:?}",
            eval_result.effective_disposition
        );
    }

    let auths = resolution
        .request()
        .exact_authorizations()
        .unwrap_or(&eval_result.authorization_requirements);
    if context.keys.is_empty() || context.pending_targets.len() != context.keys.len() {
        bail!("interactive resolution requires durable guard execution targets");
    }
    if context.pending_targets.iter().any(|target| {
        target.decision_id.is_empty()
            || target.execution_id.is_empty()
            || !context.keys.iter().any(|key| key == &target.key)
    }) || context.keys.iter().any(|key| {
        context
            .pending_targets
            .iter()
            .filter(|target| &target.key == key)
            .count()
            != 1
    }) {
        bail!("interactive resolution contains an invalid durable pending target");
    }
    let request_invocation_id = resolution.request().invocation_id();
    if request_invocation_id != context.owner_invocation_id
        || request_invocation_id != context.resolution_invocation_id
    {
        bail!("interactive resolution request does not match the durable invocation");
    }
    let correlation = resolution
        .request()
        .correlation()
        .ok_or_else(|| anyhow!("interactive resolution has no durable pending correlation"))?;
    if correlation.owner_invocation_id() != Some(context.owner_invocation_id.as_str()) {
        bail!("interactive resolution owner does not match the durable pending request");
    }
    if !context.pending_targets.iter().any(|target| {
        target.decision_id == correlation.decision_id()
            && target.execution_id == correlation.execution_id()
    }) {
        bail!("interactive resolution correlation does not match a durable pending target");
    }

    let store_outcome = match resolution.outcome().explicit_decision_choice() {
        Some(choice) => {
            let receipt = DecisionReceipt {
                decision_id: correlation.decision_id().to_string(),
                execution_id: correlation.execution_id().to_string(),
                selected_choice: choice,
                actor: DecisionActor::User,
                provider: format!("{}", resolution.provider()),
                received_at_unix_ms: context.receipt_received_at_unix_ms,
                integrity: DecisionIntegrity {
                    transport: resolution.transport_label().to_string(),
                    native_interaction_id: None,
                },
            };
            let (_, outcome) = coordinator.apply_aggregate_decision_with_authorizations_outcome(
                &context.keys,
                &format!("res:{}", correlation.decision_id()),
                request_invocation_id,
                &context.owner_invocation_id,
                &receipt,
                auths,
                context.authorization_context.clone(),
                Some(context.expires_at_unix_ms),
            )?;
            outcome
        }
        None => {
            for pending_target in &context.pending_targets {
                coordinator.abandon_decision(
                    &pending_target.key,
                    &context.owner_invocation_id,
                    &pending_target.decision_id,
                    &pending_target.execution_id,
                )?;
            }
            AggregateResolutionApplyOutcome::Applied
        }
    };

    let directive = match portable {
        crate::decision_ui::PortableDecision::Allow => {
            let authorized_guards = auths.iter().map(|a| a.guard_id.clone()).collect();
            AppliedDecisionDirective::Allow {
                user_message: resolution.user_message().map(str::to_string),
                authorized_guards,
            }
        }
        crate::decision_ui::PortableDecision::Deny => AppliedDecisionDirective::Deny {
            user_message: resolution.user_message().map(str::to_string),
        },
        crate::decision_ui::PortableDecision::Unresolved(reason) => {
            AppliedDecisionDirective::Retry { reason }
        }
    };

    Ok(DecisionApplyResult {
        directive,
        outcome: store_outcome,
    })
}

fn capability_event(event: ArcEventType) -> CapabilityEvent {
    match event {
        ArcEventType::Start => CapabilityEvent::Start,
        ArcEventType::End => CapabilityEvent::End,
        ArcEventType::ToolCall => CapabilityEvent::ToolCall,
    }
}

fn validate_capability(
    request: &InteractiveDecisionRequest,
    capability: &CapabilityResolution,
) -> Result<()> {
    if capability.context.provider != request.provider() {
        return Err(DecisionContractError::CapabilityMismatch {
            field: "provider",
            expected: format!("{}", request.provider()),
            actual: format!("{}", capability.context.provider),
        }
        .into());
    }

    let expected_event = capability_event(request.event());
    if capability.context.event != expected_event {
        return Err(DecisionContractError::CapabilityMismatch {
            field: "event",
            expected: expected_event.to_string(),
            actual: capability.context.event.to_string(),
        }
        .into());
    }

    if capability.context.requested_action != request.requested_action() {
        return Err(DecisionContractError::CapabilityMismatch {
            field: "requested_action",
            expected: format!("{:?}", request.requested_action()),
            actual: format!("{:?}", capability.context.requested_action),
        }
        .into());
    }

    let expected_effective_action = expected_ask_effective_action(
        request.provider(),
        expected_event,
        capability.decision_transport,
    );
    if capability.effective_action != expected_effective_action {
        return Err(DecisionContractError::CapabilityMismatch {
            field: "effective_action",
            expected: expected_effective_action.to_owned(),
            actual: capability.effective_action.clone(),
        }
        .into());
    }
    if capability.capability == CapabilityLevel::Unsupported
        && capability.decision_transport.is_some()
    {
        bail!("unsupported capability cannot expose a decision transport");
    }
    Ok(())
}

/// Validates the request immediately before capability resolution and
/// presentation. This remains a second guard after request construction so a
/// future deserialization or transport boundary cannot bypass Start rejection.
pub fn validate_interactive_request(
    request: &InteractiveDecisionRequest,
) -> Result<(), DecisionContractError> {
    if request.event() == ArcEventType::Start {
        return Err(DecisionContractError::StartAskNotSupported);
    }
    if request.requested_action() != crate::manifest::schema::ActionType::Ask {
        return Err(DecisionContractError::InvalidRequestedAction {
            actual: format!("{:?}", request.requested_action()),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decision_ui::{PortableDecision, UnresolvedReason};
    use crate::runtime::decision::{
        DecisionCorrelation, GuardFailureContext, InteractiveDecisionOutcome,
    };
    use crate::runtime::guard_evaluation::DIALOG_RESPONSE_SCHEMA;
    use crate::target::ProviderTarget;
    use std::collections::VecDeque;
    use std::sync::Mutex;

    struct FakePresenter {
        responses: Mutex<VecDeque<DialogResponse>>,
        calls: Mutex<Vec<DialogRequest>>,
    }

    impl FakePresenter {
        fn new(response: DialogResponse) -> Self {
            Self {
                responses: Mutex::new(VecDeque::from([response])),
                calls: Mutex::new(Vec::new()),
            }
        }

        fn calls(&self) -> usize {
            self.calls.lock().expect("fake presenter lock").len()
        }
    }

    impl DecisionPresenter for FakePresenter {
        fn present(&self, request: &DialogRequest, _timeout: Duration) -> Result<DialogResponse> {
            self.calls
                .lock()
                .expect("fake presenter lock")
                .push(request.clone());
            self.responses
                .lock()
                .expect("fake presenter lock")
                .pop_front()
                .ok_or_else(|| anyhow::anyhow!("fake presenter response exhausted"))
        }
    }

    fn request(provider: ProviderTarget, event: ArcEventType) -> InteractiveDecisionRequest {
        request_with_ids(
            provider,
            event,
            "presentation-1",
            "invocation-1",
            "decision-1",
        )
    }

    fn request_with_ids(
        provider: ProviderTarget,
        event: ArcEventType,
        presentation_id: &str,
        invocation_id: &str,
        decision_id: &str,
    ) -> InteractiveDecisionRequest {
        InteractiveDecisionRequest::new(
            provider,
            event,
            crate::manifest::schema::ActionType::Ask,
            presentation_id,
            invocation_id,
            GuardFailureContext::new(
                "guard-1",
                Some("Configured feedback".into()),
                Some("Finding".into()),
            )
            .expect("valid guard"),
            "Approve the exact operation",
            None,
            Some("Bash git status".into()),
            "exact operation once",
            Some(
                DecisionCorrelation::new(decision_id, "execution-1", Some("owner-1".into()))
                    .expect("valid correlation"),
            ),
        )
        .expect("valid request")
    }

    fn orchestrator(
        presenter: Arc<dyn DecisionPresenter>,
        mode: DecisionUiMode,
    ) -> InteractiveDecisionOrchestrator {
        InteractiveDecisionOrchestrator::with_presenter(
            OsTarget::host().expect("supported host"),
            mode,
            Duration::from_secs(10),
            presenter,
        )
    }

    #[test]
    fn fake_presenter_preserves_allow_message() {
        let fake = Arc::new(FakePresenter::new(DialogResponse {
            schema: DIALOG_RESPONSE_SCHEMA.into(),
            request_id: "presentation-1".into(),
            bundle_fingerprint: "decision-1".into(),
            decision: PortableDecision::Allow,
            transport: "arc_embedded_ui".into(),
            theme: "dark".into(),
            message: Some("Proceed with the exact operation".into()),
        }));
        let dispatch = orchestrator(fake.clone(), DecisionUiMode::Native)
            .dispatch(request(ProviderTarget::Codex, ArcEventType::ToolCall))
            .expect("fake allow should resolve");
        let resolution = dispatch.resolution().expect("presented resolution");
        assert_eq!(resolution.portable_decision(), PortableDecision::Allow);
        assert_eq!(
            resolution.user_message(),
            Some("Proceed with the exact operation")
        );
        assert_eq!(resolution.request().provider(), ProviderTarget::Codex);
        assert_eq!(resolution.request().event(), ArcEventType::ToolCall);
        assert_eq!(
            resolution.request().requested_action(),
            crate::manifest::schema::ActionType::Ask
        );
        assert_eq!(resolution.request().invocation_id(), "invocation-1");
        assert_eq!(resolution.request().guard().guard_id(), "guard-1");
        assert_eq!(
            resolution.request().guard().configured_feedback(),
            Some("Configured feedback")
        );
        assert_eq!(
            resolution.request().guard().auditor_findings(),
            Some("Finding")
        );
        assert_eq!(resolution.request().scope(), "exact operation once");
        let correlation = resolution
            .request()
            .correlation()
            .expect("correlation preserved");
        assert_eq!(correlation.decision_id(), "decision-1");
        assert_eq!(correlation.execution_id(), "execution-1");
        assert_eq!(correlation.owner_invocation_id(), Some("owner-1"));
        assert_eq!(fake.calls(), 1);
    }

    #[test]
    fn fake_presenter_maps_deny_to_explicit_deny() {
        let fake = Arc::new(FakePresenter::new(DialogResponse {
            schema: DIALOG_RESPONSE_SCHEMA.into(),
            request_id: "presentation-1".into(),
            bundle_fingerprint: "decision-1".into(),
            decision: PortableDecision::Deny,
            transport: "arc_embedded_ui".into(),
            theme: "dark".into(),
            message: Some("Do not continue".into()),
        }));
        let dispatch = orchestrator(fake, DecisionUiMode::Native)
            .dispatch(request(ProviderTarget::Codex, ArcEventType::ToolCall))
            .expect("fake deny should resolve");
        assert_eq!(
            dispatch
                .resolution()
                .expect("presented resolution")
                .portable_decision(),
            PortableDecision::Deny
        );
    }

    #[test]
    fn unresolved_responses_are_retry_and_never_presented_as_deny() {
        for reason in [
            UnresolvedReason::Closed,
            UnresolvedReason::TimedOut,
            UnresolvedReason::TransportFailed,
        ] {
            let fake = Arc::new(FakePresenter::new(DialogResponse {
                schema: DIALOG_RESPONSE_SCHEMA.into(),
                request_id: "presentation-1".into(),
                bundle_fingerprint: "decision-1".into(),
                decision: PortableDecision::Unresolved(reason),
                transport: "arc_embedded_ui".into(),
                theme: "dark".into(),
                message: None,
            }));
            let dispatch = orchestrator(fake, DecisionUiMode::Native)
                .dispatch(request(ProviderTarget::Codex, ArcEventType::ToolCall))
                .expect("unresolved response should be represented");
            assert!(matches!(
                dispatch.resolution().expect("presented resolution").outcome(),
                InteractiveDecisionOutcome::Retry { reason: actual } if actual == reason
            ));
        }
    }

    #[test]
    fn incompatible_capability_does_not_call_presenter() {
        let fake = Arc::new(FakePresenter::new(DialogResponse {
            schema: DIALOG_RESPONSE_SCHEMA.into(),
            request_id: "unused".into(),
            bundle_fingerprint: "unused".into(),
            decision: PortableDecision::Allow,
            transport: "arc_embedded_ui".into(),
            theme: "dark".into(),
            message: None,
        }));
        let dispatch = orchestrator(fake.clone(), DecisionUiMode::Provider)
            .dispatch(request(ProviderTarget::Codex, ArcEventType::ToolCall))
            .expect("incompatible capability is a capability-only result");
        assert!(matches!(
            dispatch,
            InteractiveDecisionDispatch::CapabilityOnly { .. }
        ));
        assert_eq!(fake.calls(), 0);
    }

    #[test]
    fn incompatible_effective_action_is_rejected_before_presentation() {
        let fake = Arc::new(FakePresenter::new(DialogResponse {
            schema: DIALOG_RESPONSE_SCHEMA.into(),
            request_id: "unused".into(),
            bundle_fingerprint: "unused".into(),
            decision: PortableDecision::Allow,
            transport: "arc_embedded_ui".into(),
            theme: "dark".into(),
            message: None,
        }));
        let request = request(ProviderTarget::Codex, ArcEventType::ToolCall);
        let mut capability = resolve_capability(CapabilityContext::cli(
            ProviderTarget::Codex,
            OsTarget::host().expect("supported host"),
            CapabilityEvent::ToolCall,
            crate::manifest::schema::ActionType::Ask,
            DecisionUiMode::Native,
        ));
        capability.effective_action = "unexpected_action".into();

        let error = validate_capability(&request, &capability)
            .expect_err("an effective action outside the transport contract must be rejected");
        assert!(error.to_string().contains("effective_action"));
        assert_eq!(fake.calls(), 0);
    }

    #[test]
    fn gemini_stop_native_uses_its_canonical_effective_action() {
        let fake = Arc::new(FakePresenter::new(DialogResponse {
            schema: DIALOG_RESPONSE_SCHEMA.into(),
            request_id: "presentation-1".into(),
            bundle_fingerprint: "decision-1".into(),
            decision: PortableDecision::Deny,
            transport: "arc_embedded_ui".into(),
            theme: "dark".into(),
            message: Some("user message".into()),
        }));

        let dispatch = orchestrator(fake.clone(), DecisionUiMode::Native)
            .dispatch(request(ProviderTarget::Gemini, ArcEventType::End))
            .expect("Gemini Stop Arc embedded UI must use its canonical action");

        match dispatch {
            InteractiveDecisionDispatch::Presented { capability, .. } => {
                assert_eq!(
                    capability.effective_action,
                    "continue_loop_with_arc_embedded_ui"
                );
                assert_eq!(
                    capability.decision_transport,
                    Some(DecisionTransport::ArcEmbeddedUi)
                );
            }
            InteractiveDecisionDispatch::CapabilityOnly { .. } => {
                panic!("Gemini Stop Arc embedded UI must reach the presenter")
            }
        }
        assert_eq!(fake.calls(), 1);
    }

    #[test]
    fn shared_registry_rejects_duplicate_presentation_before_presenter() {
        let fake = Arc::new(FakePresenter::new(DialogResponse {
            schema: DIALOG_RESPONSE_SCHEMA.into(),
            request_id: "presentation-1".into(),
            bundle_fingerprint: "decision-1".into(),
            decision: PortableDecision::Allow,
            transport: "arc_embedded_ui".into(),
            theme: "dark".into(),
            message: None,
        }));
        let registry = Arc::new(DecisionPresentationRegistry::new());
        let orchestrator = InteractiveDecisionOrchestrator::with_presenter_and_registry(
            OsTarget::host().expect("supported host"),
            DecisionUiMode::Native,
            Duration::from_secs(10),
            fake.clone(),
            registry,
        );

        orchestrator
            .dispatch(request(ProviderTarget::Codex, ArcEventType::ToolCall))
            .expect("the first presentation should be accepted");
        let error = orchestrator
            .dispatch(request(ProviderTarget::Codex, ArcEventType::ToolCall))
            .expect_err("the same invocation and decision must not open a second dialog");

        assert!(error.to_string().contains("already claimed"));
        assert_eq!(fake.calls(), 1);
    }

    #[test]
    fn durable_registry_rejects_duplicate_across_independent_state_connections() {
        let root = std::env::temp_dir().join(format!(
            "arc_presentation_claims_{}_{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&root).expect("create temporary claim store directory");
        let database = root.join("state.sqlite3");
        let first_store = Arc::new(
            crate::runtime::state_store::SqliteStateStore::open(&database)
                .expect("open first state connection"),
        );
        let second_store = Arc::new(
            crate::runtime::state_store::SqliteStateStore::open(&database)
                .expect("open second state connection"),
        );
        let first_registry = Arc::new(DecisionPresentationRegistry::with_durable_claim_store(
            first_store,
        ));
        let second_registry = Arc::new(DecisionPresentationRegistry::with_durable_claim_store(
            second_store,
        ));
        let first_fake = Arc::new(FakePresenter::new(DialogResponse {
            schema: DIALOG_RESPONSE_SCHEMA.into(),
            request_id: "presentation-1".into(),
            bundle_fingerprint: "decision-1".into(),
            decision: PortableDecision::Allow,
            transport: "arc_embedded_ui".into(),
            theme: "dark".into(),
            message: None,
        }));
        let second_fake = Arc::new(FakePresenter::new(DialogResponse {
            schema: DIALOG_RESPONSE_SCHEMA.into(),
            request_id: "presentation-2".into(),
            bundle_fingerprint: "decision-1".into(),
            decision: PortableDecision::Allow,
            transport: "arc_embedded_ui".into(),
            theme: "dark".into(),
            message: None,
        }));
        let first = InteractiveDecisionOrchestrator::with_presenter_and_registry(
            OsTarget::host().expect("supported host"),
            DecisionUiMode::Native,
            Duration::from_secs(10),
            first_fake.clone(),
            first_registry,
        );
        let second = InteractiveDecisionOrchestrator::with_presenter_and_registry(
            OsTarget::host().expect("supported host"),
            DecisionUiMode::Native,
            Duration::from_secs(10),
            second_fake.clone(),
            second_registry,
        );

        first
            .dispatch(request(ProviderTarget::Codex, ArcEventType::ToolCall))
            .expect("first process should claim presentation");
        let error = second
            .dispatch(request_with_ids(
                ProviderTarget::Codex,
                ArcEventType::ToolCall,
                "presentation-2",
                "invocation-2",
                "decision-1",
            ))
            .expect_err("decision id claim must survive a process boundary");

        assert!(error.to_string().contains("already claimed"));
        assert_eq!(first_fake.calls(), 1);
        assert_eq!(second_fake.calls(), 0);
        drop(first);
        drop(second);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn start_request_is_rejected_before_presenter() {
        let fake = Arc::new(FakePresenter::new(DialogResponse {
            schema: DIALOG_RESPONSE_SCHEMA.into(),
            request_id: "unused".into(),
            bundle_fingerprint: "unused".into(),
            decision: PortableDecision::Allow,
            transport: "arc_embedded_ui".into(),
            theme: "dark".into(),
            message: None,
        }));
        let error = InteractiveDecisionRequest::new(
            ProviderTarget::Codex,
            ArcEventType::Start,
            crate::manifest::schema::ActionType::Ask,
            "presentation-1",
            "invocation-1",
            GuardFailureContext::new("guard-1", None, None).expect("valid guard"),
            "Start must not be presented",
            None,
            None,
            "session start",
            None,
        )
        .expect_err("Start Ask must be rejected");
        assert_eq!(error, DecisionContractError::StartAskNotSupported);
        assert_eq!(fake.calls(), 0);
    }
}
