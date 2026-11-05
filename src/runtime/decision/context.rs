use crate::manifest::schema::ActionType;
use crate::runtime::evaluator::CurrentOperation;
use crate::runtime::events::ArcEventType;
use crate::runtime::guard_evaluation::{
    ArcEvaluationResult, DialogAuthorizationItem, DialogFailedProbe, DialogRequest,
    DialogViolationItem, EffectiveDisposition, ExactOperationAuthorization, FailureBundle,
    FailureCause, GuardResultState, PresentationKind, dialog_failed_probes_from_causes,
    exact_operation_fingerprint, normalized_arguments_fingerprint,
};
use crate::runtime::observability::new_invocation_id;
use crate::target::ProviderTarget;

use super::messages::{
    DecisionContractError, MAX_COMMAND_TEXT_CHARS, MAX_DECISION_ID_CHARS, MAX_EXECUTION_ID_CHARS,
    MAX_FINDINGS_CHARS, MAX_GUARD_ID_CHARS, MAX_INVOCATION_ID_CHARS, MAX_MESSAGE_CHARS,
    MAX_OPERATION_DISPLAY_CHARS, MAX_OPERATION_INPUT_BYTES, MAX_OPERATION_TOOL_CHARS,
    MAX_PRESENTATION_ID_CHARS, MAX_SCOPE_CHARS, validate_optional, validate_required,
    validate_structured_bounded,
};

#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuardFailureContext {
    guard_id: String,
    configured_feedback: Option<String>,
    auditor_findings: Option<String>,
    failed_probes: Vec<DialogFailedProbe>,
}

#[allow(dead_code)]
impl GuardFailureContext {
    pub fn new(
        guard_id: impl Into<String>,
        configured_feedback: Option<String>,
        auditor_findings: Option<String>,
    ) -> Result<Self, DecisionContractError> {
        let guard_id = guard_id.into();
        validate_required("guard_id", &guard_id, MAX_GUARD_ID_CHARS)?;
        validate_optional(
            "configured_feedback",
            configured_feedback.as_deref(),
            MAX_MESSAGE_CHARS,
        )?;
        validate_optional(
            "auditor_findings",
            auditor_findings.as_deref(),
            MAX_FINDINGS_CHARS,
        )?;
        Ok(Self {
            guard_id,
            configured_feedback,
            auditor_findings,
            failed_probes: Vec::new(),
        })
    }

    /// Builds the context of one failed guard from its failure causes: the
    /// findings of every cause and the probes that ran and failed.
    pub(crate) fn from_failure_causes(
        guard_id: impl Into<String>,
        configured_feedback: Option<String>,
        causes: &[FailureCause],
    ) -> Result<Self, DecisionContractError> {
        let findings = causes
            .iter()
            .filter_map(|cause| cause.auditor_findings.clone())
            .collect::<Vec<_>>()
            .join("\n");
        let findings = (!findings.is_empty()).then_some(findings);
        let mut context = Self::new(guard_id, configured_feedback, findings)?;
        context.failed_probes = dialog_failed_probes_from_causes(causes);
        Ok(context)
    }

    pub fn failed_probes(&self) -> &[DialogFailedProbe] {
        &self.failed_probes
    }

    pub fn guard_id(&self) -> &str {
        &self.guard_id
    }

    pub fn configured_feedback(&self) -> Option<&str> {
        self.configured_feedback.as_deref()
    }

    pub fn auditor_findings(&self) -> Option<&str> {
        self.auditor_findings.as_deref()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecisionCorrelation {
    decision_id: String,
    execution_id: String,
    owner_invocation_id: Option<String>,
}

impl DecisionCorrelation {
    pub fn new(
        decision_id: impl Into<String>,
        execution_id: impl Into<String>,
        owner_invocation_id: Option<String>,
    ) -> Result<Self, DecisionContractError> {
        let decision_id = decision_id.into();
        let execution_id = execution_id.into();
        validate_required("decision_id", &decision_id, MAX_DECISION_ID_CHARS)?;
        validate_required("execution_id", &execution_id, MAX_EXECUTION_ID_CHARS)?;
        validate_optional(
            "owner_invocation_id",
            owner_invocation_id.as_deref(),
            MAX_INVOCATION_ID_CHARS,
        )?;
        Ok(Self {
            decision_id,
            execution_id,
            owner_invocation_id,
        })
    }

    pub fn decision_id(&self) -> &str {
        &self.decision_id
    }

    pub fn execution_id(&self) -> &str {
        &self.execution_id
    }

    pub fn owner_invocation_id(&self) -> Option<&str> {
        self.owner_invocation_id.as_deref()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum InteractiveDecisionPresentation {
    GuardFailures,
    ExactOperationAuthorization(Vec<ExactOperationAuthorization>),
    AggregateDecision {
        authorizations: Vec<ExactOperationAuthorization>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InteractiveDecisionRequest {
    provider: ProviderTarget,
    event: ArcEventType,
    requested_action: ActionType,
    presentation_id: String,
    invocation_id: String,
    guards: Vec<GuardFailureContext>,
    /// Rendered context for the user. It is never an authorization source.
    prompt: String,
    operation: Option<CurrentOperation>,
    operation_display: Option<String>,
    scope: String,
    correlation: Option<DecisionCorrelation>,
    presentation: InteractiveDecisionPresentation,
    evaluation_result: Option<ArcEvaluationResult>,
}

impl InteractiveDecisionRequest {
    #[allow(clippy::too_many_arguments)]
    pub fn with_guards(
        provider: ProviderTarget,
        event: ArcEventType,
        requested_action: ActionType,
        presentation_id: impl Into<String>,
        invocation_id: impl Into<String>,
        guards: Vec<GuardFailureContext>,
        prompt: impl Into<String>,
        operation: Option<CurrentOperation>,
        operation_display: Option<String>,
        scope: impl Into<String>,
        correlation: Option<DecisionCorrelation>,
    ) -> Result<Self, DecisionContractError> {
        if event == ArcEventType::Start {
            return Err(DecisionContractError::StartAskNotSupported);
        }
        if requested_action != ActionType::Ask {
            return Err(DecisionContractError::InvalidRequestedAction {
                actual: format!("{requested_action:?}"),
            });
        }
        if guards.is_empty() {
            return Err(DecisionContractError::EmptyField { field: "guards" });
        }
        let presentation_id = presentation_id.into();
        let invocation_id = invocation_id.into();
        let prompt = prompt.into();
        let scope = scope.into();
        validate_required(
            "presentation_id",
            &presentation_id,
            MAX_PRESENTATION_ID_CHARS,
        )?;
        validate_required("invocation_id", &invocation_id, MAX_INVOCATION_ID_CHARS)?;
        validate_required("prompt", &prompt, MAX_MESSAGE_CHARS)?;
        validate_optional(
            "operation_display",
            operation_display.as_deref(),
            MAX_OPERATION_DISPLAY_CHARS,
        )?;
        validate_required("scope", &scope, MAX_SCOPE_CHARS)?;
        if let Some(operation) = &operation
            && operation.event_type != event
        {
            return Err(DecisionContractError::OperationEventMismatch {
                operation_event: operation.event_type.to_string(),
                request_event: event.to_string(),
            });
        }
        if let Some(operation) = &operation {
            validate_optional(
                "operation.tool",
                operation.tool.as_deref(),
                MAX_OPERATION_TOOL_CHARS,
            )?;
            validate_optional(
                "operation.command_text",
                operation.command_text.as_deref(),
                MAX_COMMAND_TEXT_CHARS,
            )?;
            if let Some(input) = &operation.input {
                let serialized = serde_json::to_vec(input).map_err(|_| {
                    DecisionContractError::InvalidStructuredField {
                        field: "operation.input",
                    }
                })?;
                validate_structured_bounded(
                    "operation.input",
                    serialized.len(),
                    MAX_OPERATION_INPUT_BYTES,
                )?;
            }
        }
        let mut seen = std::collections::BTreeSet::new();
        let mut unique_guards = Vec::with_capacity(guards.len());
        for g in guards {
            if seen.insert(g.guard_id().to_string()) {
                unique_guards.push(g);
            }
        }
        Ok(Self {
            provider,
            event,
            requested_action,
            presentation_id,
            invocation_id,
            guards: unique_guards,
            prompt,
            operation,
            operation_display,
            scope,
            correlation,
            presentation: InteractiveDecisionPresentation::GuardFailures,
            evaluation_result: None,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn aggregate_decision(
        provider: ProviderTarget,
        event: ArcEventType,
        requested_action: ActionType,
        presentation_id: impl Into<String>,
        invocation_id: impl Into<String>,
        guards: Vec<GuardFailureContext>,
        authorizations: Vec<ExactOperationAuthorization>,
        prompt: impl Into<String>,
        operation: Option<CurrentOperation>,
        operation_display: Option<String>,
        scope: impl Into<String>,
        correlation: Option<DecisionCorrelation>,
    ) -> Result<Self, DecisionContractError> {
        let mut request = Self::with_guards(
            provider,
            event,
            requested_action,
            presentation_id,
            invocation_id,
            guards,
            prompt,
            operation,
            operation_display,
            scope,
            correlation,
        )?;
        request.presentation =
            InteractiveDecisionPresentation::AggregateDecision { authorizations };
        Ok(request)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new(
        provider: ProviderTarget,
        event: ArcEventType,
        requested_action: ActionType,
        presentation_id: impl Into<String>,
        invocation_id: impl Into<String>,
        guard: GuardFailureContext,
        prompt: impl Into<String>,
        operation: Option<CurrentOperation>,
        operation_display: Option<String>,
        scope: impl Into<String>,
        correlation: Option<DecisionCorrelation>,
    ) -> Result<Self, DecisionContractError> {
        Self::with_guards(
            provider,
            event,
            requested_action,
            presentation_id,
            invocation_id,
            vec![guard],
            prompt,
            operation,
            operation_display,
            scope,
            correlation,
        )
    }

    pub fn from_exact_authorizations(
        provider: ProviderTarget,
        event: ArcEventType,
        presentation_id: impl Into<String>,
        invocation_id: impl Into<String>,
        authorizations: Vec<ExactOperationAuthorization>,
        prompt: impl Into<String>,
        event_id: &str,
        operation: CurrentOperation,
        operation_display: impl Into<String>,
        scope: impl Into<String>,
        correlation: Option<DecisionCorrelation>,
    ) -> Result<Self, DecisionContractError> {
        if authorizations.is_empty() {
            return Err(DecisionContractError::InvalidStructuredField {
                field: "authorizations",
            });
        }
        for authorization in &authorizations {
            authorization.validate().map_err(|_| {
                DecisionContractError::InvalidStructuredField {
                    field: "authorizations",
                }
            })?;
            if event == ArcEventType::Start {
                return Err(DecisionContractError::StartAskNotSupported);
            }
            if event != ArcEventType::ToolCall {
                return Err(DecisionContractError::InvalidStructuredField { field: "event" });
            }
            if authorization.event_id != event_id {
                return Err(DecisionContractError::CorrelationMismatch {
                    field: "authorization.event_id",
                });
            }
            if operation.tool.as_deref() != Some(authorization.tool.as_str()) {
                return Err(DecisionContractError::CorrelationMismatch {
                    field: "authorization.tool",
                });
            }
            if exact_operation_fingerprint(&operation) != authorization.operation_fingerprint {
                return Err(DecisionContractError::CorrelationMismatch {
                    field: "authorization.operation_fingerprint",
                });
            }
            if normalized_arguments_fingerprint(&operation)
                != authorization.normalized_arguments_fingerprint
            {
                return Err(DecisionContractError::CorrelationMismatch {
                    field: "authorization.normalized_arguments_fingerprint",
                });
            }
        }

        let guards: Result<Vec<_>, _> = authorizations
            .iter()
            .map(|auth| GuardFailureContext::new(auth.guard_id.clone(), None, None))
            .collect();
        let guards = guards?;
        let operation_display = operation_display.into();
        let mut request = Self::with_guards(
            provider,
            event,
            ActionType::Ask,
            presentation_id,
            invocation_id,
            guards,
            prompt,
            Some(operation),
            Some(operation_display),
            scope,
            correlation,
        )?;
        request.presentation =
            InteractiveDecisionPresentation::ExactOperationAuthorization(authorizations);
        Ok(request)
    }

    pub fn provider(&self) -> ProviderTarget {
        self.provider
    }

    pub fn event(&self) -> ArcEventType {
        self.event
    }

    pub fn requested_action(&self) -> ActionType {
        self.requested_action
    }

    pub fn invocation_id(&self) -> &str {
        &self.invocation_id
    }

    pub fn guard(&self) -> &GuardFailureContext {
        &self.guards[0]
    }

    pub fn guards(&self) -> &[GuardFailureContext] {
        &self.guards
    }

    pub fn prompt(&self) -> &str {
        &self.prompt
    }

    pub fn operation(&self) -> Option<&CurrentOperation> {
        self.operation.as_ref()
    }

    pub fn operation_display(&self) -> Option<&str> {
        self.operation_display.as_deref()
    }

    pub fn scope(&self) -> &str {
        &self.scope
    }

    pub fn correlation(&self) -> Option<&DecisionCorrelation> {
        self.correlation.as_ref()
    }

    pub fn presentation_id(&self) -> &str {
        &self.presentation_id
    }

    pub fn presentation_kind(&self) -> PresentationKind {
        match &self.presentation {
            InteractiveDecisionPresentation::GuardFailures => PresentationKind::GuardFailures,
            InteractiveDecisionPresentation::ExactOperationAuthorization(_) => {
                PresentationKind::ExactOperationAuthorization
            }
            InteractiveDecisionPresentation::AggregateDecision { .. } => {
                PresentationKind::AggregateDecision
            }
        }
    }

    pub fn set_correlation(&mut self, correlation: DecisionCorrelation) {
        self.correlation = Some(correlation);
    }

    pub fn evaluation_result(&self) -> Option<&ArcEvaluationResult> {
        self.evaluation_result.as_ref()
    }

    pub fn failure_bundle(&self) -> Option<&FailureBundle> {
        self.evaluation_result.as_ref().map(|r| &r.failure_bundle)
    }

    pub fn exact_authorizations(&self) -> Option<&[ExactOperationAuthorization]> {
        match &self.presentation {
            InteractiveDecisionPresentation::GuardFailures => {
                self.evaluation_result.as_ref().and_then(|result| {
                    if result.authorization_requirements.is_empty() {
                        None
                    } else {
                        Some(result.authorization_requirements.as_slice())
                    }
                })
            }
            InteractiveDecisionPresentation::ExactOperationAuthorization(authorizations) => {
                Some(authorizations.as_slice())
            }
            InteractiveDecisionPresentation::AggregateDecision { authorizations } => {
                Some(authorizations.as_slice())
            }
        }
    }

    pub fn to_dialog_request(&self, title: impl Into<String>) -> DialogRequest {
        let title = title.into();
        let bundle_fingerprint = self
            .failure_bundle()
            .map(|bundle| bundle.bundle_fingerprint.clone())
            .or_else(|| {
                self.correlation
                    .as_ref()
                    .map(|correlation| correlation.decision_id().to_owned())
            })
            .or_else(|| {
                if matches!(
                    self.presentation,
                    InteractiveDecisionPresentation::ExactOperationAuthorization(_)
                        | InteractiveDecisionPresentation::AggregateDecision { .. }
                ) {
                    self.exact_authorizations()
                        .and_then(<[_]>::first)
                        .map(|authorization| authorization.operation_fingerprint.clone())
                } else {
                    None
                }
            })
            .unwrap_or_else(|| self.presentation_id.clone());
        match &self.presentation {
            InteractiveDecisionPresentation::GuardFailures => {
                let violations = self.dialog_violation_items();
                DialogRequest::guard_failures(
                    self.presentation_id.clone(),
                    title,
                    self.scope.clone(),
                    violations,
                    bundle_fingerprint,
                    0,
                )
            }
            InteractiveDecisionPresentation::ExactOperationAuthorization(authorizations) => {
                let auth_items: Vec<_> = authorizations
                    .iter()
                    .map(|authorization| DialogAuthorizationItem {
                        guard_id: authorization.guard_id.clone(),
                        summary: format_dialog_summary(
                            &self.prompt,
                            "Exact operation requires confirmation",
                        ),
                        auditor_findings: self.auditor_findings_for_guard(&authorization.guard_id),
                        operation_fingerprint: authorization.operation_fingerprint.clone(),
                    })
                    .collect();
                DialogRequest::exact_authorizations(
                    self.presentation_id.clone(),
                    title,
                    self.scope.clone(),
                    auth_items,
                    self.operation_display
                        .clone()
                        .unwrap_or_else(|| self.prompt.clone()),
                    bundle_fingerprint,
                    0,
                )
            }
            InteractiveDecisionPresentation::AggregateDecision { authorizations } => {
                let violations = self.dialog_violation_items();
                let auth_items: Vec<_> = authorizations
                    .iter()
                    .map(|authorization| DialogAuthorizationItem {
                        guard_id: authorization.guard_id.clone(),
                        summary: format_dialog_summary(
                            &self.prompt,
                            "Exact operation requires confirmation",
                        ),
                        auditor_findings: self.auditor_findings_for_guard(&authorization.guard_id),
                        operation_fingerprint: authorization.operation_fingerprint.clone(),
                    })
                    .collect();
                DialogRequest::aggregate_decision(
                    self.presentation_id.clone(),
                    title,
                    self.scope.clone(),
                    violations,
                    auth_items,
                    self.operation_display.clone(),
                    bundle_fingerprint,
                    0,
                )
            }
        }
    }

    fn dialog_violation_items(&self) -> Vec<DialogViolationItem> {
        self.guards
            .iter()
            .map(|guard| {
                let summary = format_dialog_summary(
                    if self.guards.len() == 1 {
                        &self.prompt
                    } else {
                        ""
                    },
                    &format!("Guard '{}' requires confirmation", guard.guard_id()),
                );
                DialogViolationItem {
                    guard_id: guard.guard_id().to_owned(),
                    summary,
                    configured_feedback: guard.configured_feedback().map(format_dialog_findings),
                    auditor_findings: guard.auditor_findings().map(format_dialog_findings),
                    scope: self.scope.clone(),
                    failed_probes: guard.failed_probes().to_vec(),
                }
            })
            .collect()
    }

    fn auditor_findings_for_guard(&self, guard_id: &str) -> Option<String> {
        let guard_result = self
            .evaluation_result
            .as_ref()?
            .report
            .guard_results
            .iter()
            .find(|result| result.guard_id == guard_id)?;
        if !matches!(
            &guard_result.state,
            crate::runtime::guard_evaluation::GuardResultState::Satisfied
        ) {
            return None;
        }

        let mut findings: Vec<String> = Vec::new();
        for finding in guard_result
            .satisfied_attributions
            .iter()
            .filter_map(|attribution| attribution.auditor_findings.as_deref())
            .map(str::trim)
            .filter(|finding| !finding.is_empty())
        {
            if !findings.iter().any(|existing| existing.as_str() == finding) {
                findings.push(finding.to_owned());
            }
        }
        if findings.is_empty() {
            None
        } else {
            Some(format_dialog_findings(&findings.join("\n")))
        }
    }
}

fn format_dialog_summary(summary: &str, fallback: &str) -> String {
    const MAX_SUMMARY_CHARS: usize = 512;

    let body = if summary.trim().is_empty() {
        fallback.to_owned()
    } else {
        summary.replace('<', "").replace('>', "")
    };
    body.chars().take(MAX_SUMMARY_CHARS).collect::<String>()
}

fn format_dialog_findings(findings: &str) -> String {
    findings.replace('<', "").replace('>', "")
}

pub fn compose_failure_feedback(context: &GuardFailureContext) -> Option<String> {
    match (context.configured_feedback(), context.auditor_findings()) {
        (Some(feedback), Some(findings)) => Some(format!(
            "{}\nHallazgos del Auditor:\n{}",
            feedback.trim(),
            findings.trim()
        )),
        (Some(feedback), None) => Some(feedback.to_string()),
        (None, Some(findings)) => Some(format!(
            "Guard '{}' verification failed:\n{}",
            context.guard_id(),
            findings.trim()
        )),
        (None, None) => None,
    }
}

pub fn interactive_decision_request_from_evaluation_result(
    eval_result: &ArcEvaluationResult,
    provider: ProviderTarget,
    event: ArcEventType,
    event_id: &str,
    invocation_id: &str,
    operation: Option<CurrentOperation>,
    operation_display: Option<String>,
    scope: &str,
) -> anyhow::Result<Option<InteractiveDecisionRequest>> {
    let has_authorizations = !eval_result.authorization_requirements.is_empty();
    let needs_exact_authorization =
        eval_result.effective_disposition == EffectiveDisposition::Continue && has_authorizations;
    if eval_result.effective_disposition != EffectiveDisposition::Ask && !needs_exact_authorization
    {
        return Ok(None);
    }

    let mut failure_contexts = Vec::new();
    for g in &eval_result.failure_bundle.failed_guards {
        if g.configured_action == ActionType::Ask {
            let fc = GuardFailureContext::from_failure_causes(
                g.guard_id.clone(),
                g.configured_feedback.clone(),
                &g.causes,
            )?;
            failure_contexts.push(fc);
        }
    }
    if failure_contexts.is_empty() {
        for g in &eval_result.report.guard_results {
            if g.configured_action == ActionType::Ask
                && matches!(g.state, GuardResultState::Violated { .. })
            {
                let causes: &[FailureCause] = match &g.state {
                    GuardResultState::Violated { causes } => causes,
                    _ => &[],
                };
                let fc =
                    GuardFailureContext::from_failure_causes(g.guard_id.clone(), None, causes)?;
                failure_contexts.push(fc);
            }
        }
    }

    let has_failures = !failure_contexts.is_empty();
    let mut request = match (has_failures, has_authorizations) {
        (true, true) => {
            let prompt = String::from(
                "Arc policy requires your decision before this operation can continue.",
            );
            InteractiveDecisionRequest::aggregate_decision(
                provider,
                event,
                ActionType::Ask,
                new_invocation_id(),
                invocation_id,
                failure_contexts,
                eval_result.authorization_requirements.clone(),
                prompt,
                operation,
                operation_display,
                scope,
                None,
            )?
        }
        (true, false) => {
            let prompt = String::from(
                "Arc policy requires your decision before this operation can continue.",
            );
            InteractiveDecisionRequest::with_guards(
                provider,
                event,
                ActionType::Ask,
                new_invocation_id(),
                invocation_id,
                failure_contexts,
                prompt,
                operation,
                operation_display,
                scope,
                None,
            )?
        }
        (false, true) => {
            let authorizations = &eval_result.authorization_requirements;
            let guard_ids = authorizations
                .iter()
                .map(|a| a.guard_id.as_str())
                .collect::<Vec<_>>()
                .join(", ");
            let operation = operation.ok_or_else(|| {
                anyhow::anyhow!(
                    "exact authorization for Guards '{guard_ids}' has no current operation"
                )
            })?;
            let operation_display = operation_display.ok_or_else(|| {
                anyhow::anyhow!(
                    "exact authorization for Guards '{guard_ids}' has no operation display"
                )
            })?;
            let prompt = if authorizations.len() == 1 {
                format!(
                    "Arc compliance approved Guard '{}' for this exact operation; confirm execution.",
                    authorizations[0].guard_id
                )
            } else {
                format!(
                    "Arc compliance approved Guards '{guard_ids}' for this exact operation; confirm execution."
                )
            };
            InteractiveDecisionRequest::from_exact_authorizations(
                provider,
                event,
                new_invocation_id(),
                invocation_id,
                authorizations.clone(),
                prompt,
                event_id,
                operation,
                operation_display,
                scope,
                None,
            )?
        }
        (false, false) => {
            anyhow::bail!(
                "inconsistent evaluation result: disposition is Ask but neither failure contexts nor authorization requirements are present"
            );
        }
    };

    request.evaluation_result = Some(eval_result.clone());
    Ok(Some(request))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::guard_evaluation::{
        ActivationCacheSummary, EVENT_EVALUATION_REPORT_SCHEMA, EvaluationCompleteness,
        EventEvaluationReport, FAILURE_BUNDLE_SCHEMA, FailedGuardFeedback,
    };
    use crate::runtime::guard_evaluation::{FailureCause, FailureCauseKind};
    use crate::target::ProviderTarget;

    fn test_eval_result(
        event_id: &str,
        disposition: EffectiveDisposition,
        failed_guards: Vec<FailedGuardFeedback>,
        authorizations: Vec<ExactOperationAuthorization>,
    ) -> ArcEvaluationResult {
        let bundle = FailureBundle {
            schema: FAILURE_BUNDLE_SCHEMA.into(),
            bundle_id: "bundle-test".into(),
            invocation_id: "inv-test".into(),
            event_id: event_id.into(),
            event_type: ArcEventType::ToolCall,
            effective_disposition: disposition,
            failed_guards,
            evaluation_faults: vec![],
            completeness: EvaluationCompleteness::Complete,
            input_fingerprint: "input-fp".into(),
            bundle_fingerprint: "bundle-fp".into(),
        };
        let report = EventEvaluationReport {
            schema: EVENT_EVALUATION_REPORT_SCHEMA.into(),
            invocation_id: "inv-test".into(),
            provider: ProviderTarget::Codex,
            event_id: event_id.into(),
            event_type: ArcEventType::ToolCall,
            input_fingerprint: "input-fp".into(),
            guard_results: vec![],
            effective_disposition: disposition,
            authorization_requirements: authorizations.clone(),
            activation_cache_summary: ActivationCacheSummary {
                logical_occurrences: 0,
                unique_probe_evaluations: 0,
                unique_decision_evaluations: 0,
                coalesced_in_flight: 0,
                reused_completed: 0,
                physical_faults: 0,
            },
            report_fingerprint: "report-fp".into(),
            started_unix_ms: 0,
            completed_unix_ms: 0,
        };
        ArcEvaluationResult {
            report,
            effective_disposition: disposition,
            authorization_requirements: authorizations,
            failure_bundle: bundle,
        }
    }

    fn guard() -> GuardFailureContext {
        GuardFailureContext::new(
            "guard-1",
            Some("Configured feedback".into()),
            Some("Auditor finding".into()),
        )
        .expect("valid guard context")
    }

    #[test]
    fn preserves_feedback_and_findings_as_separate_fields() {
        let value = guard();
        assert_eq!(value.guard_id(), "guard-1");
        assert_eq!(value.configured_feedback(), Some("Configured feedback"));
        assert_eq!(value.auditor_findings(), Some("Auditor finding"));
    }

    #[test]
    fn rejects_start_before_a_presenter_can_be_called() {
        let error = InteractiveDecisionRequest::new(
            ProviderTarget::Codex,
            ArcEventType::Start,
            ActionType::Ask,
            "presentation-1",
            "invocation-1",
            guard(),
            "Should never render",
            None,
            None,
            "session start",
            None,
        )
        .expect_err("Start Ask must be rejected before presentation");
        assert_eq!(error, DecisionContractError::StartAskNotSupported);
    }

    #[test]
    fn rejects_operation_event_mismatch() {
        let operation = CurrentOperation {
            event_type: ArcEventType::End,
            tool: None,
            input: None,
            command_text: None,
        };
        let error = InteractiveDecisionRequest::new(
            ProviderTarget::Codex,
            ArcEventType::ToolCall,
            ActionType::Ask,
            "presentation-2",
            "invocation-1",
            guard(),
            "Approve operation",
            Some(operation),
            None,
            "exact operation",
            None,
        )
        .expect_err("operation and request event must correlate");
        assert!(matches!(
            error,
            DecisionContractError::OperationEventMismatch { .. }
        ));
    }

    #[test]
    fn dialog_projection_preserves_configured_feedback_and_auditor_findings() {
        let correlation =
            DecisionCorrelation::new("decision-1", "execution-1", Some("invocation-owner".into()))
                .expect("valid correlation");
        let request = InteractiveDecisionRequest::new(
            ProviderTarget::Gemini,
            ArcEventType::ToolCall,
            ActionType::Ask,
            "presentation-3",
            "invocation-1",
            guard(),
            "Approve this exact operation",
            None,
            Some("Bash git status".into()),
            "exact pending operation once",
            Some(correlation),
        )
        .expect("valid request");
        let dialog = request.to_dialog_request("Arc policy decision");
        assert_eq!(dialog.request_id, "presentation-3");
        assert_eq!(dialog.violations[0].guard_id, "guard-1");
        assert_eq!(dialog.violations[0].summary, "Approve this exact operation");
        assert_eq!(
            dialog.violations[0].configured_feedback.as_deref(),
            Some("Configured feedback")
        );
        assert_eq!(
            dialog.violations[0].auditor_findings.as_deref(),
            Some("Auditor finding")
        );
        assert_eq!(dialog.scope, "exact pending operation once");
        assert_eq!(dialog.bundle_fingerprint, "decision-1");
    }

    #[test]
    fn exact_authorization_projection_is_not_a_guard_failure() {
        let operation = CurrentOperation {
            event_type: ArcEventType::ToolCall,
            tool: Some("Bash".into()),
            input: Some(serde_json::json!({"command": "git status"})),
            command_text: Some("git status".into()),
        };
        let authorization = ExactOperationAuthorization {
            guard_id: "guard-auth".into(),
            operation_fingerprint: exact_operation_fingerprint(&operation),
            event_id: "event-auth".into(),
            tool: "Bash".into(),
            normalized_arguments_fingerprint: normalized_arguments_fingerprint(&operation),
        };
        let request = InteractiveDecisionRequest::from_exact_authorizations(
            ProviderTarget::Codex,
            ArcEventType::ToolCall,
            "presentation-auth",
            "invocation-auth",
            vec![authorization.clone()],
            "Arc compliance approved this exact operation; confirm execution.",
            "event-auth",
            operation,
            "Bash git status",
            "this exact tool call once",
            None,
        )
        .expect("exact authorization request should be valid");

        let dialog = request.to_dialog_request("Arc exact authorization");
        assert_eq!(
            dialog.presentation_kind,
            crate::runtime::guard_evaluation::PresentationKind::ExactOperationAuthorization
        );
        assert!(dialog.violations.is_empty());
        assert_eq!(
            dialog.authorizations,
            vec![DialogAuthorizationItem {
                guard_id: authorization.guard_id,
                summary: "Arc compliance approved this exact operation; confirm execution.".into(),
                auditor_findings: None,
                operation_fingerprint: authorization.operation_fingerprint,
            }]
        );
        assert_eq!(dialog.operation.as_deref(), Some("Bash git status"));
        dialog
            .validate()
            .expect("exact authorization dialog is valid");
    }

    #[test]
    fn rejects_oversized_prompt() {
        let error = InteractiveDecisionRequest::new(
            ProviderTarget::Codex,
            ArcEventType::ToolCall,
            ActionType::Ask,
            "presentation-4",
            "invocation-1",
            guard(),
            "x".repeat(MAX_MESSAGE_CHARS + 1),
            None,
            None,
            "exact operation",
            None,
        )
        .expect_err("oversized prompt must be rejected");
        assert!(matches!(error, DecisionContractError::FieldTooLong { .. }));
    }

    #[test]
    fn rejects_oversized_operation_input() {
        let operation = CurrentOperation {
            event_type: ArcEventType::ToolCall,
            tool: Some("run_command".into()),
            input: Some(serde_json::json!({
                "command": "x".repeat(MAX_OPERATION_INPUT_BYTES)
            })),
            command_text: Some("x".into()),
        };
        let error = InteractiveDecisionRequest::new(
            ProviderTarget::Codex,
            ArcEventType::ToolCall,
            ActionType::Ask,
            "presentation-5",
            "invocation-1",
            guard(),
            "Approve operation",
            Some(operation),
            None,
            "exact operation",
            None,
        )
        .expect_err("oversized operation input must be rejected");
        assert!(matches!(
            error,
            DecisionContractError::StructuredFieldTooLarge { .. }
        ));
    }

    #[test]
    fn rejects_empty_presentation_id() {
        let error = InteractiveDecisionRequest::new(
            ProviderTarget::Codex,
            ArcEventType::ToolCall,
            ActionType::Ask,
            " ",
            "invocation-1",
            guard(),
            "Approve operation",
            None,
            None,
            "exact operation",
            None,
        )
        .expect_err("presentation id is required for response binding");
        assert_eq!(
            error,
            DecisionContractError::EmptyField {
                field: "presentation_id"
            }
        );
    }

    #[test]
    fn multiple_guards_project_feedback_and_findings_to_separate_fields() {
        let guard1 = GuardFailureContext::new(
            "guard-1",
            Some("feedback 1".into()),
            Some("auditor finding 1".into()),
        )
        .expect("valid guard context 1");
        let guard2 = GuardFailureContext::new(
            "guard-2",
            Some("feedback 2".into()),
            Some("auditor finding 2".into()),
        )
        .expect("valid guard context 2");
        let request = InteractiveDecisionRequest::with_guards(
            ProviderTarget::Codex,
            ArcEventType::ToolCall,
            ActionType::Ask,
            "pres-multi",
            "inv-multi",
            vec![guard1, guard2],
            "combined prompt",
            None,
            None,
            "workspace",
            None,
        )
        .expect("valid multi-guard request");

        assert_eq!(request.guards().len(), 2);
        assert_eq!(request.guard().guard_id(), "guard-1");
        assert_eq!(request.guards()[0].guard_id(), "guard-1");
        assert_eq!(request.guards()[1].guard_id(), "guard-2");

        let dialog = request.to_dialog_request("Multiple Guards Violated");
        assert_eq!(dialog.presentation_kind, PresentationKind::GuardFailures);
        assert_eq!(dialog.violations.len(), 2);
        assert_eq!(dialog.violations[0].guard_id, "guard-1");
        assert_eq!(
            dialog.violations[0].summary,
            "Guard 'guard-1' requires confirmation"
        );
        assert_eq!(
            dialog.violations[0].configured_feedback.as_deref(),
            Some("feedback 1")
        );
        assert_eq!(
            dialog.violations[0].auditor_findings.as_deref(),
            Some("auditor finding 1")
        );
        assert_eq!(dialog.violations[1].guard_id, "guard-2");
        assert_eq!(
            dialog.violations[1].summary,
            "Guard 'guard-2' requires confirmation"
        );
        assert_eq!(
            dialog.violations[1].configured_feedback.as_deref(),
            Some("feedback 2")
        );
        assert_eq!(
            dialog.violations[1].auditor_findings.as_deref(),
            Some("auditor finding 2")
        );
        assert!(dialog.validate().is_ok());
    }

    #[test]
    fn interactive_decision_request_from_evaluation_result_handles_multiple_ask_guards() {
        let guard1 = FailedGuardFeedback {
            guard_id: "ask-g1".into(),
            configured_action: ActionType::Ask,
            faulted: false,
            configured_feedback: Some("check g1".into()),
            causes: vec![],
            evidence_fingerprint: "fp1".into(),
        };
        let guard2 = FailedGuardFeedback {
            guard_id: "ask-g2".into(),
            configured_action: ActionType::Ask,
            faulted: false,
            configured_feedback: Some("check g2".into()),
            causes: vec![],
            evidence_fingerprint: "fp2".into(),
        };
        let eval_result = test_eval_result(
            "ev-1",
            EffectiveDisposition::Ask,
            vec![guard1, guard2],
            vec![],
        );

        let req = interactive_decision_request_from_evaluation_result(
            &eval_result,
            ProviderTarget::Codex,
            ArcEventType::ToolCall,
            "ev-1",
            "inv-1",
            None,
            None,
            "workspace",
        )
        .expect("builds request")
        .expect("is interactive");

        assert_eq!(req.guards().len(), 2);
        assert_eq!(req.guards()[0].guard_id(), "ask-g1");
        assert_eq!(req.guards()[1].guard_id(), "ask-g2");

        let dialog = req.to_dialog_request("Decision Required");
        assert_eq!(dialog.violations.len(), 2);
        assert_eq!(dialog.violations[0].guard_id, "ask-g1");
        assert_eq!(
            dialog.violations[0].summary,
            "Guard 'ask-g1' requires confirmation"
        );
        assert_eq!(
            dialog.violations[0].configured_feedback.as_deref(),
            Some("check g1")
        );
        assert_eq!(dialog.violations[1].guard_id, "ask-g2");
        assert_eq!(
            dialog.violations[1].summary,
            "Guard 'ask-g2' requires confirmation"
        );
        assert_eq!(
            dialog.violations[1].configured_feedback.as_deref(),
            Some("check g2")
        );
        assert!(dialog.validate().is_ok());
    }

    #[test]
    fn failed_decide_feedback_and_findings_are_separate_and_no_verdict_is_shown() {
        let cause = FailureCause {
            occurrence_id: "decision-occurrence".into(),
            physical_evaluation_id: "decision-evaluation".into(),
            cache_provenance: crate::runtime::guard_evaluation::CacheResolutionProvenance::Executed,
            expression_path: Vec::new(),
            kind: FailureCauseKind::DecisionViolated,
            summary: "decision provider rejected the requested operation".into(),
            auditor_findings: Some("The request did not authorize this operation.".into()),
            deterministic_evidence: Vec::new(),
        };
        let failed_guard = FailedGuardFeedback {
            guard_id: "ask-decide".into(),
            configured_action: ActionType::Ask,
            faulted: false,
            configured_feedback: Some("Review this operation before continuing.".into()),
            causes: vec![cause],
            evidence_fingerprint: "evidence-fingerprint".into(),
        };
        let eval_result = test_eval_result(
            "event-decide-false",
            EffectiveDisposition::Ask,
            vec![failed_guard],
            Vec::new(),
        );

        let request = interactive_decision_request_from_evaluation_result(
            &eval_result,
            ProviderTarget::Codex,
            ArcEventType::ToolCall,
            "event-decide-false",
            "invocation-decide-false",
            None,
            None,
            "exact pending tool call",
        )
        .expect("evaluation request should be constructed")
        .expect("failed Ask guard should request a user decision");

        let dialog = request.to_dialog_request("Decision Required");
        assert_eq!(
            dialog.violations[0].summary,
            "Arc policy requires your decision before this operation can continue."
        );
        assert_eq!(
            dialog.violations[0].configured_feedback.as_deref(),
            Some("Review this operation before continuing.")
        );
        assert_eq!(
            dialog.violations[0].auditor_findings.as_deref(),
            Some("The request did not authorize this operation.")
        );
        let wire = serde_json::to_string(&dialog).expect("serialize dialog");
        assert!(!wire.contains("Agent verdict:"));
        assert!(!wire.contains("true"));
        assert!(!wire.contains("false"));
    }

    #[test]
    fn interactive_decision_request_from_evaluation_result_handles_multiple_authorizations() {
        let op = CurrentOperation {
            event_type: ArcEventType::ToolCall,
            tool: Some("bash".into()),
            input: Some(serde_json::json!({ "command": "git push origin main" })),
            command_text: Some("git push origin main".into()),
        };
        let op_fp = exact_operation_fingerprint(&op);
        let args_fp = normalized_arguments_fingerprint(&op);

        let auth1 = ExactOperationAuthorization {
            guard_id: "guard-auth-1".into(),
            operation_fingerprint: op_fp.clone(),
            event_id: "ev-auth".into(),
            tool: "bash".into(),
            normalized_arguments_fingerprint: args_fp.clone(),
        };
        let auth2 = ExactOperationAuthorization {
            guard_id: "guard-auth-2".into(),
            operation_fingerprint: op_fp.clone(),
            event_id: "ev-auth".into(),
            tool: "bash".into(),
            normalized_arguments_fingerprint: args_fp,
        };

        let eval_result = test_eval_result(
            "ev-auth",
            EffectiveDisposition::Ask,
            vec![],
            vec![auth1, auth2],
        );

        let req = interactive_decision_request_from_evaluation_result(
            &eval_result,
            ProviderTarget::Codex,
            ArcEventType::ToolCall,
            "ev-auth",
            "inv-auth",
            Some(op),
            Some("git push origin main".into()),
            "workspace",
        )
        .expect("builds request")
        .expect("is interactive");

        assert_eq!(req.guards().len(), 2);
        assert_eq!(req.guards()[0].guard_id(), "guard-auth-1");
        assert_eq!(req.guards()[1].guard_id(), "guard-auth-2");

        let dialog = req.to_dialog_request("Exact Authorization");
        assert_eq!(
            dialog.presentation_kind,
            PresentationKind::ExactOperationAuthorization
        );
        assert_eq!(dialog.authorizations.len(), 2);
        assert_eq!(dialog.authorizations[0].guard_id, "guard-auth-1");
        assert_eq!(dialog.authorizations[1].guard_id, "guard-auth-2");
        assert!(dialog.validate().is_ok());
    }

    #[test]
    fn interactive_decision_request_from_evaluation_result_asks_on_continue_with_authorizations() {
        let op = CurrentOperation {
            event_type: ArcEventType::ToolCall,
            tool: Some("bash".into()),
            input: Some(serde_json::json!({ "command": "git status" })),
            command_text: Some("git status".into()),
        };
        let op_fp = exact_operation_fingerprint(&op);
        let args_fp = normalized_arguments_fingerprint(&op);

        let auth = ExactOperationAuthorization {
            guard_id: "guard-auth".into(),
            operation_fingerprint: op_fp,
            event_id: "ev-auth".into(),
            tool: "bash".into(),
            normalized_arguments_fingerprint: args_fp,
        };

        let eval_result = test_eval_result(
            "ev-auth",
            EffectiveDisposition::Continue,
            vec![],
            vec![auth],
        );

        let req = interactive_decision_request_from_evaluation_result(
            &eval_result,
            ProviderTarget::Codex,
            ArcEventType::ToolCall,
            "ev-auth",
            "inv-auth",
            Some(op),
            Some("git status".into()),
            "workspace",
        )
        .expect("evaluation succeeds");

        let request = req.expect("exact authorization must open Ask before the operation runs");
        assert_eq!(request.requested_action(), ActionType::Ask);
        assert_eq!(request.guards().len(), 1);
        assert_eq!(request.guard().guard_id(), "guard-auth");
        assert_eq!(
            request.exact_authorizations().unwrap().len(),
            1,
            "the request must retain the exact authorization requirements"
        );
        assert_eq!(
            request
                .to_dialog_request("Exact Authorization")
                .presentation_kind,
            PresentationKind::ExactOperationAuthorization
        );
        let authorization_summary = request
            .to_dialog_request("Exact Authorization")
            .authorizations[0]
            .summary
            .clone();
        assert_eq!(
            authorization_summary,
            "Arc compliance approved Guard 'guard-auth' for this exact operation; confirm execution."
        );
        assert!(!authorization_summary.contains("true"));
        assert!(!authorization_summary.contains("false"));
    }

    #[test]
    fn interactive_decision_request_does_not_override_terminal_disposition_with_authorization() {
        for disposition in [
            EffectiveDisposition::Deny,
            EffectiveDisposition::RuntimeFault,
        ] {
            let op = CurrentOperation {
                event_type: ArcEventType::ToolCall,
                tool: Some("bash".into()),
                input: Some(serde_json::json!({ "command": "git push origin main" })),
                command_text: Some("git push origin main".into()),
            };
            let auth = ExactOperationAuthorization {
                guard_id: "guard-auth".into(),
                operation_fingerprint: exact_operation_fingerprint(&op),
                event_id: "ev-auth".into(),
                tool: "bash".into(),
                normalized_arguments_fingerprint: normalized_arguments_fingerprint(&op),
            };
            let eval_result = test_eval_result("ev-auth", disposition, vec![], vec![auth]);

            let request = interactive_decision_request_from_evaluation_result(
                &eval_result,
                ProviderTarget::Codex,
                ArcEventType::ToolCall,
                "ev-auth",
                "inv-auth",
                Some(op),
                Some("git push origin main".into()),
                "workspace",
            )
            .expect("terminal aggregate evaluation succeeds");

            assert!(request.is_none(), "{disposition:?} must suppress Ask UI");
        }
    }

    #[test]
    fn interactive_decision_request_from_evaluation_result_rejects_inconsistent_ask_without_failures_or_auth()
     {
        let eval_result =
            test_eval_result("ev-inconsistent", EffectiveDisposition::Ask, vec![], vec![]);

        let err = interactive_decision_request_from_evaluation_result(
            &eval_result,
            ProviderTarget::Codex,
            ArcEventType::ToolCall,
            "ev-inconsistent",
            "inv-inconsistent",
            None,
            None,
            "workspace",
        )
        .expect_err("inconsistent Ask without failures or auth must error");

        assert!(err.to_string().contains("inconsistent evaluation result"));
    }

    #[test]
    fn rejects_empty_guards() {
        let error = InteractiveDecisionRequest::with_guards(
            ProviderTarget::Codex,
            ArcEventType::ToolCall,
            ActionType::Ask,
            "pres-empty",
            "inv-empty",
            vec![],
            "prompt",
            None,
            None,
            "workspace",
            None,
        )
        .expect_err("empty guards must fail");
        assert_eq!(error, DecisionContractError::EmptyField { field: "guards" });
    }
}
