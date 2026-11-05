use crate::runtime::execution::{
    LifecycleStopActivation, LifecycleStopDecision, LifecycleStopOutcome,
};
use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::path::PathBuf;

use super::common::validate_provider_tool_call_arguments;
pub use super::common::{
    extract_command_text, format_bundle_feedback_for_provider, is_command_tool,
    normalize_tool_call_arguments,
};
use crate::runtime::events::{ArcEvent, ArcEventPayload, ArcEventType};
use crate::runtime::guard_evaluation::{ArcEvaluationResult, EffectiveDisposition};

use crate::target::capabilities::expected_ask_effective_action;
use crate::target::{
    CapabilityContext, CapabilityEvent, CapabilityResolution, DecisionUiMode, OsTarget,
    ProviderTarget, resolve_capability,
};

/// Input payload sent by AGY on PreToolUse hooks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgyToolCallDetail {
    pub name: String,
    #[serde(default)]
    pub args: Value,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgyPreToolUseInput {
    pub tool_call: AgyToolCallDetail,
    #[serde(default)]
    pub step_idx: Option<u64>,
    #[serde(default)]
    pub conversation_id: Option<String>,
    #[serde(default)]
    pub model_name: Option<String>,
    #[serde(alias = "transcript_path", default)]
    pub transcript_path: Option<String>,
}

/// Output payload expected by AGY for PreToolUse hooks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgyPreToolUseOutput {
    pub decision: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub overwrite: Option<Value>,
}

impl AgyPreToolUseOutput {
    pub fn allow() -> Self {
        Self {
            decision: "allow".to_string(),
            reason: None,
            overwrite: None,
        }
    }

    pub fn allow_with_reason(reason: Option<String>) -> Self {
        Self {
            decision: "allow".to_string(),
            reason,
            overwrite: None,
        }
    }

    pub fn deny(reason: Option<String>) -> Self {
        Self {
            decision: "deny".to_string(),
            reason,
            overwrite: None,
        }
    }
}

/// Input payload sent by AGY on Stop hooks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgyStopInput {
    #[serde(default)]
    pub execution_num: Option<u64>,
    #[serde(default)]
    pub termination_reason: Option<String>,
    #[serde(default)]
    pub error: Option<String>,
    #[serde(default)]
    pub fully_idle: Option<bool>,
    #[serde(default)]
    pub conversation_id: Option<String>,
    #[serde(alias = "transcript_path", default)]
    pub transcript_path: Option<String>,
}

/// Output payload expected by AGY for Stop hooks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgyStopOutput {
    pub decision: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl AgyStopOutput {
    pub fn stop() -> Self {
        Self {
            decision: "stop".to_string(),
            reason: None,
        }
    }

    pub fn stop_with_reason(reason: Option<String>) -> Self {
        Self {
            decision: "stop".to_string(),
            reason,
        }
    }

    pub fn continue_loop(reason: Option<String>) -> Self {
        Self {
            decision: "continue".to_string(),
            reason,
        }
    }
}

/// Input payload sent by AGY on PreInvocation hooks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgyPreInvocationInput {
    #[serde(default)]
    pub invocation_num: Option<u64>,
    #[serde(default)]
    pub conversation_id: Option<String>,
    #[serde(alias = "transcript_path", default)]
    pub transcript_path: Option<String>,
}

/// Output payload expected by AGY for PreInvocation hooks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgyPreInvocationOutput {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decision: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub inject_steps: Vec<Value>,
}

impl AgyPreInvocationOutput {
    pub fn allow() -> Self {
        Self {
            decision: None,
            reason: None,
            inject_steps: Vec::new(),
        }
    }

    pub fn abort(reason: impl Into<String>) -> Self {
        let r = reason.into();
        Self {
            decision: Some("abort".to_string()),
            reason: Some(r.clone()),
            inject_steps: vec![serde_json::json!({
                "ephemeralMessage": r,
            })],
        }
    }
}

/// Adapter converting between AGY payloads and Arc Runtime events / outcomes.
pub struct AgyAdapter;

impl AgyAdapter {
    /// Normalizes native session/turn/reentry fields for the shared runtime coordinator.
    pub fn stop_activation(input: &AgyStopInput, invocation_id: &str) -> LifecycleStopActivation {
        let turn_id = input.execution_num.map(|number| format!("step-{number}"));
        LifecycleStopActivation {
            provider: ProviderTarget::Gemini,
            session_id: input
                .conversation_id
                .clone()
                .unwrap_or_else(|| "agy-session-default".into()),
            coordination_invocation_id: format!(
                "{}:{invocation_id}",
                turn_id.as_deref().unwrap_or("step-unknown")
            ),
            turn_id,
            signals: crate::ProviderSignals {
                reentry: crate::ReentryKind::FirstInvocation,
                ..Default::default()
            },
        }
    }

    /// Projects a coordinated semantic result into this provider's Stop wire contract.
    pub fn lifecycle_stop_to_output(
        outcome: LifecycleStopOutcome,
        result: &ArcEvaluationResult,
        invocation_id: &str,
    ) -> Result<AgyStopOutput> {
        match outcome {
            LifecycleStopOutcome::ProjectEvaluation => {
                Self::evaluation_result_to_stop_output(result)
            }
            LifecycleStopOutcome::Completed { feedback }
            | LifecycleStopOutcome::Blocked { feedback } => {
                Ok(AgyStopOutput::stop_with_reason(Some(feedback)))
            }
            LifecycleStopOutcome::Decision(decision) => {
                let LifecycleStopDecision {
                    response,
                    resolution,
                    guard_id,
                    configured_feedback,
                    aggregate_feedback,
                } = *decision;
                let mut output = Self::embedded_decision_to_stop_output(
                    &resolution,
                    response.decision,
                    &guard_id,
                    invocation_id,
                    configured_feedback.as_deref(),
                    response.message.as_deref(),
                )?;
                output.reason = Some(super::common::append_aggregate_feedback(
                    output.reason.take(),
                    &aggregate_feedback,
                ));
                Ok(output)
            }
        }
    }

    /// Rejects malformed provider wire input before a hook can evaluate guards.
    pub fn validate_pre_tool_use_input(input: &AgyPreToolUseInput) -> Result<()> {
        validate_provider_tool_call_arguments(&input.tool_call.name, &input.tool_call.args)
    }

    /// Translates an AGY PreToolUse input payload into a normalized ArcEvent.
    pub fn pre_tool_use_to_event(input: &AgyPreToolUseInput, sequence: u64) -> ArcEvent {
        let session_id = input
            .conversation_id
            .clone()
            .unwrap_or_else(|| "session-default".to_string());
        let event_id = format!("ev-tool-{}", input.step_idx.unwrap_or(sequence));

        // Extract command text with robust multi-field / JSON-string / array support (H1)
        let (command_text, argument_extraction) =
            normalize_tool_call_arguments(&input.tool_call.name, &input.tool_call.args);

        ArcEvent {
            provider: Some(ProviderTarget::Gemini),
            session_id,
            event_id,
            event_type: ArcEventType::ToolCall,
            sequence,
            correlation_id: None,
            transcript_path: input.transcript_path.as_deref().map(PathBuf::from),
            payload: ArcEventPayload::ToolCall {
                tool: input.tool_call.name.clone(),
                input: input.tool_call.args.clone(),
                command_text,
                argument_extraction,
            },
        }
    }

    pub fn evaluation_result_to_pre_tool_use_output(
        eval_result: &ArcEvaluationResult,
    ) -> Result<AgyPreToolUseOutput> {
        if matches!(
            eval_result.effective_disposition,
            EffectiveDisposition::Continue
        ) && !eval_result.authorization_requirements.is_empty()
        {
            return Ok(AgyPreToolUseOutput::deny(Some(
                "Arc exact operation authorization is unresolved; the tool call was blocked without user confirmation."
                    .into(),
            )));
        }
        if matches!(
            eval_result.effective_disposition,
            EffectiveDisposition::Continue
        ) && eval_result.failure_bundle.failed_guards.is_empty()
        {
            return Ok(AgyPreToolUseOutput::allow());
        }
        if matches!(
            eval_result.effective_disposition,
            EffectiveDisposition::RuntimeFault
        ) {
            let reason = format_bundle_feedback_for_provider(
                &eval_result.failure_bundle,
                "[ARC PROBE ERROR] Guard evaluation failed; see local Arc diagnostics.",
            )?;
            return Ok(AgyPreToolUseOutput::deny(Some(reason)));
        }
        let action = match eval_result.effective_disposition {
            EffectiveDisposition::Continue => crate::manifest::schema::ActionType::Message,
            EffectiveDisposition::Message => crate::manifest::schema::ActionType::Message,
            EffectiveDisposition::Deny | EffectiveDisposition::RuntimeFault => {
                crate::manifest::schema::ActionType::Deny
            }
            EffectiveDisposition::Ask => crate::manifest::schema::ActionType::Ask,
        };
        let resolution = resolve_capability(CapabilityContext::cli(
            ProviderTarget::Gemini,
            OsTarget::host().expect("Arc only runs on a supported host OS"),
            CapabilityEvent::ToolCall,
            action,
            DecisionUiMode::Auto,
        ));
        Self::evaluation_result_to_pre_tool_use_output_with_resolution(eval_result, &resolution)
    }

    pub fn evaluation_result_to_pre_tool_use_output_with_resolution(
        eval_result: &ArcEvaluationResult,
        resolution: &CapabilityResolution,
    ) -> Result<AgyPreToolUseOutput> {
        if matches!(
            eval_result.effective_disposition,
            EffectiveDisposition::Continue
        ) && !eval_result.authorization_requirements.is_empty()
        {
            return Ok(AgyPreToolUseOutput::deny(Some(
                "Arc exact operation authorization is unresolved; the tool call was blocked without user confirmation."
                    .into(),
            )));
        }
        let action = match eval_result.effective_disposition {
            EffectiveDisposition::Continue => None,
            EffectiveDisposition::Message => Some(crate::manifest::schema::ActionType::Message),
            EffectiveDisposition::Deny | EffectiveDisposition::RuntimeFault => {
                Some(crate::manifest::schema::ActionType::Deny)
            }
            EffectiveDisposition::Ask => Some(crate::manifest::schema::ActionType::Ask),
        };
        validate_agy_resolution_action(resolution, CapabilityEvent::ToolCall, action)?;
        match eval_result.effective_disposition {
            EffectiveDisposition::Continue => Ok(AgyPreToolUseOutput::allow()),
            EffectiveDisposition::Deny => {
                let reason = format_bundle_feedback_for_provider(
                    &eval_result.failure_bundle,
                    "Arc policy denied the tool call.",
                )?;
                Ok(AgyPreToolUseOutput::deny(Some(reason)))
            }
            EffectiveDisposition::Ask => {
                if resolution.effective_action != "decision_force_ask" {
                    bail!("AGY ask requires the native PreToolUse force_ask resolution");
                }
                let reason = format_bundle_feedback_for_provider(
                    &eval_result.failure_bundle,
                    "Confirmation required before allowing the tool.",
                )?;
                Ok(AgyPreToolUseOutput {
                    decision: "force_ask".to_string(),
                    reason: Some(reason),
                    overwrite: None,
                })
            }
            EffectiveDisposition::Message => {
                let reason = if !eval_result.failure_bundle.failed_guards.is_empty() {
                    Some(format_bundle_feedback_for_provider(
                        &eval_result.failure_bundle,
                        "Arc policy message.",
                    )?)
                } else {
                    None
                };
                Ok(AgyPreToolUseOutput::allow_with_reason(reason))
            }
            EffectiveDisposition::RuntimeFault => {
                let reason = format_bundle_feedback_for_provider(
                    &eval_result.failure_bundle,
                    "[ARC PROBE ERROR] Guard evaluation failed; see local Arc diagnostics.",
                )?;
                Ok(AgyPreToolUseOutput::deny(Some(reason)))
            }
        }
    }

    pub fn embedded_decision_to_pre_tool_use_output(
        resolution: &CapabilityResolution,
        decision: crate::decision_ui::PortableDecision,
        reason: String,
    ) -> Result<AgyPreToolUseOutput> {
        if resolution.context.provider != ProviderTarget::Gemini
            || resolution.context.event != CapabilityEvent::ToolCall
            || resolution.context.requested_action != crate::manifest::schema::ActionType::Ask
            || resolution.decision_transport
                != Some(crate::target::DecisionTransport::ArcEmbeddedUi)
            || resolution.effective_action != "arc_embedded_ui_ask"
        {
            bail!("Gemini embedded UI decision does not match the supplied capability resolution");
        }
        Ok(match decision {
            crate::decision_ui::PortableDecision::Allow => {
                AgyPreToolUseOutput::allow_with_reason(Some(reason))
            }
            crate::decision_ui::PortableDecision::Deny
            | crate::decision_ui::PortableDecision::Unresolved(_) => {
                AgyPreToolUseOutput::deny(Some(reason))
            }
        })
    }

    pub fn embedded_decision_to_stop_output(
        resolution: &CapabilityResolution,
        decision: crate::decision_ui::PortableDecision,
        guard_id: &str,
        invocation_id: &str,
        failure_context: Option<&str>,
        user_message: Option<&str>,
    ) -> Result<AgyStopOutput> {
        if resolution.context.provider != ProviderTarget::Gemini
            || resolution.context.event != CapabilityEvent::End
            || resolution.context.requested_action != crate::manifest::schema::ActionType::Ask
            || resolution.decision_transport
                != Some(crate::target::DecisionTransport::ArcEmbeddedUi)
            || resolution.capability != crate::target::CapabilityLevel::Emulated
            || resolution.effective_action
                != expected_ask_effective_action(
                    ProviderTarget::Gemini,
                    CapabilityEvent::End,
                    resolution.decision_transport,
                )
        {
            bail!("Gemini Stop embedded UI output contradicts the supplied capability resolution");
        }
        Ok(match decision {
            crate::decision_ui::PortableDecision::Allow => {
                AgyStopOutput::continue_loop(Some(super::stop_remediation_reason(
                    guard_id,
                    invocation_id,
                    failure_context,
                    user_message,
                )))
            }
            crate::decision_ui::PortableDecision::Deny => AgyStopOutput::stop(),
            crate::decision_ui::PortableDecision::Unresolved(reason) => {
                AgyStopOutput::continue_loop(Some(format!(
                    "Arc's decision remained unresolved ({reason:?}) for guard '{guard_id}' on stop attempt ({invocation_id}). Keep the session active, re-evaluate the guard, and ask the user again before stopping."
                )))
            }
        })
    }

    /// Translates an AGY Stop input payload into a normalized ArcEvent (trigger: end).
    pub fn stop_to_event(input: &AgyStopInput, sequence: u64) -> ArcEvent {
        let session_id = input
            .conversation_id
            .clone()
            .unwrap_or_else(|| "session-default".to_string());
        let event_id = format!("ev-stop-{}", input.execution_num.unwrap_or(sequence));

        ArcEvent {
            provider: Some(ProviderTarget::Gemini),
            session_id,
            event_id,
            event_type: ArcEventType::End,
            sequence,
            correlation_id: None,
            transcript_path: input.transcript_path.as_deref().map(PathBuf::from),
            payload: ArcEventPayload::Empty,
        }
    }

    pub fn evaluation_result_to_stop_output(
        eval_result: &ArcEvaluationResult,
    ) -> Result<AgyStopOutput> {
        if matches!(
            eval_result.effective_disposition,
            EffectiveDisposition::Continue
        ) && eval_result.failure_bundle.failed_guards.is_empty()
        {
            return Ok(AgyStopOutput::stop());
        }
        let action = match eval_result.effective_disposition {
            EffectiveDisposition::Continue => crate::manifest::schema::ActionType::Message,
            EffectiveDisposition::Message => crate::manifest::schema::ActionType::Message,
            EffectiveDisposition::Deny | EffectiveDisposition::RuntimeFault => {
                crate::manifest::schema::ActionType::Deny
            }
            EffectiveDisposition::Ask => crate::manifest::schema::ActionType::Ask,
        };
        let resolution = resolve_capability(CapabilityContext::cli(
            ProviderTarget::Gemini,
            OsTarget::host().expect("Arc only runs on a supported host OS"),
            CapabilityEvent::End,
            action,
            DecisionUiMode::Auto,
        ));
        Self::evaluation_result_to_stop_output_with_resolution(eval_result, &resolution)
    }

    pub fn evaluation_result_to_stop_output_with_resolution(
        eval_result: &ArcEvaluationResult,
        resolution: &CapabilityResolution,
    ) -> Result<AgyStopOutput> {
        let action = match eval_result.effective_disposition {
            EffectiveDisposition::Continue => None,
            EffectiveDisposition::Message => Some(crate::manifest::schema::ActionType::Message),
            EffectiveDisposition::Deny | EffectiveDisposition::RuntimeFault => {
                Some(crate::manifest::schema::ActionType::Deny)
            }
            EffectiveDisposition::Ask => Some(crate::manifest::schema::ActionType::Ask),
        };
        validate_agy_resolution_action(resolution, CapabilityEvent::End, action)?;
        Ok(match eval_result.effective_disposition {
            EffectiveDisposition::Continue => AgyStopOutput::stop(),
            EffectiveDisposition::Message => {
                let prompt = if !eval_result.failure_bundle.failed_guards.is_empty() {
                    Some(format_bundle_feedback_for_provider(
                        &eval_result.failure_bundle,
                        "Arc policy message.",
                    )?)
                } else {
                    None
                };
                AgyStopOutput::stop_with_reason(prompt)
            }
            EffectiveDisposition::Deny => {
                let prompt = format_bundle_feedback_for_provider(
                    &eval_result.failure_bundle,
                    "Session cannot end: Arc guard requirements unmet.",
                )?;
                AgyStopOutput::stop_with_reason(Some(prompt))
            }
            EffectiveDisposition::Ask => {
                let prompt = format_bundle_feedback_for_provider(
                    &eval_result.failure_bundle,
                    "Confirmation required before finishing.",
                )?;
                AgyStopOutput::continue_loop(Some(prompt))
            }
            EffectiveDisposition::RuntimeFault => {
                let prompt = format_bundle_feedback_for_provider(
                    &eval_result.failure_bundle,
                    "[ARC PROBE ERROR] Guard evaluation failed; see local Arc diagnostics.",
                )?;
                AgyStopOutput::stop_with_reason(Some(prompt))
            }
        })
    }

    /// Translates an AGY PreInvocation input payload into a normalized ArcEvent (Start on turn 1).
    pub fn pre_invocation_to_event(
        input: &AgyPreInvocationInput,
        sequence: u64,
    ) -> Option<ArcEvent> {
        // PreInvocation only maps to LifecycleTrigger::Start on the first invocation (turn 1)
        if input.invocation_num.unwrap_or(1) > 1 {
            return None;
        }

        let session_id = input
            .conversation_id
            .clone()
            .unwrap_or_else(|| "session-default".to_string());
        let event_id = format!("ev-pre-invoc-{}", input.invocation_num.unwrap_or(sequence));

        Some(ArcEvent {
            provider: Some(ProviderTarget::Gemini),
            session_id,
            event_id,
            event_type: ArcEventType::Start,
            sequence,
            correlation_id: None,
            transcript_path: input.transcript_path.as_deref().map(PathBuf::from),
            payload: ArcEventPayload::Empty,
        })
    }

    pub fn evaluation_result_to_pre_invocation_output(
        eval_result: &ArcEvaluationResult,
    ) -> Result<AgyPreInvocationOutput> {
        if matches!(
            eval_result.effective_disposition,
            EffectiveDisposition::Continue
        ) && eval_result.failure_bundle.failed_guards.is_empty()
        {
            return Ok(AgyPreInvocationOutput::allow());
        }
        let action = match eval_result.effective_disposition {
            EffectiveDisposition::Continue => crate::manifest::schema::ActionType::Message,
            EffectiveDisposition::Message => crate::manifest::schema::ActionType::Message,
            EffectiveDisposition::Deny | EffectiveDisposition::RuntimeFault => {
                crate::manifest::schema::ActionType::Deny
            }
            EffectiveDisposition::Ask => crate::manifest::schema::ActionType::Ask,
        };
        let resolution = resolve_capability(CapabilityContext::cli(
            ProviderTarget::Gemini,
            OsTarget::host().expect("Arc only runs on a supported host OS"),
            CapabilityEvent::Start,
            action,
            DecisionUiMode::Auto,
        ));
        Self::evaluation_result_to_pre_invocation_output_with_resolution(eval_result, &resolution)
    }

    pub fn evaluation_result_to_pre_invocation_output_with_resolution(
        eval_result: &ArcEvaluationResult,
        resolution: &CapabilityResolution,
    ) -> Result<AgyPreInvocationOutput> {
        let action = match eval_result.effective_disposition {
            EffectiveDisposition::Continue => None,
            EffectiveDisposition::Message => Some(crate::manifest::schema::ActionType::Message),
            EffectiveDisposition::Deny | EffectiveDisposition::RuntimeFault => {
                Some(crate::manifest::schema::ActionType::Deny)
            }
            EffectiveDisposition::Ask => Some(crate::manifest::schema::ActionType::Ask),
        };
        validate_agy_resolution_action(resolution, CapabilityEvent::Start, action)?;
        Ok(match eval_result.effective_disposition {
            EffectiveDisposition::Continue => AgyPreInvocationOutput::allow(),
            EffectiveDisposition::Message => {
                let reason = if !eval_result.failure_bundle.failed_guards.is_empty() {
                    Some(format_bundle_feedback_for_provider(
                        &eval_result.failure_bundle,
                        "Arc policy message.",
                    )?)
                } else {
                    None
                };
                if let Some(msg) = reason {
                    AgyPreInvocationOutput {
                        decision: None,
                        reason: None,
                        inject_steps: vec![serde_json::json!({
                            "ephemeralMessage": msg,
                        })],
                    }
                } else {
                    AgyPreInvocationOutput::allow()
                }
            }
            EffectiveDisposition::Deny => {
                let prompt = format_bundle_feedback_for_provider(
                    &eval_result.failure_bundle,
                    "Arc policy denied session start.",
                )?;
                AgyPreInvocationOutput::abort(prompt)
            }
            EffectiveDisposition::Ask => {
                let prompt = format_bundle_feedback_for_provider(
                    &eval_result.failure_bundle,
                    "Confirmation required before session start.",
                )?;
                AgyPreInvocationOutput::abort(prompt)
            }
            EffectiveDisposition::RuntimeFault => {
                let prompt = format_bundle_feedback_for_provider(
                    &eval_result.failure_bundle,
                    "[ARC RUNTIME ERROR] Guard evaluation failed; see local Arc diagnostics.",
                )?;
                AgyPreInvocationOutput::abort(prompt)
            }
        })
    }
}

fn validate_agy_resolution_action(
    resolution: &CapabilityResolution,
    event: CapabilityEvent,
    action: Option<crate::manifest::schema::ActionType>,
) -> Result<()> {
    if resolution.context.provider != ProviderTarget::Gemini || resolution.context.event != event {
        bail!(
            "capability resolution targets {}/{}, AGY adapter requires gemini/{}",
            resolution.context.provider,
            resolution.context.event,
            event
        );
    }
    if let Some(action) = action
        && action != resolution.context.requested_action
    {
        bail!(
            "runtime outcome action {} contradicts capability action {}",
            action,
            resolution.context.requested_action
        );
    }
    if resolution.context.requested_action == crate::manifest::schema::ActionType::Ask
        && resolution.effective_action
            != expected_ask_effective_action(
                ProviderTarget::Gemini,
                event,
                resolution.decision_transport,
            )
    {
        bail!(
            "ask resolution action '{}' contradicts Gemini event/transport contract",
            resolution.effective_action
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::test_support::evaluate_result;
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_pre_tool_use_translation() {
        let raw_json = r#"{
            "toolCall": {
                "name": "run_command",
                "args": {
                    "CommandLine": "git push origin main --force"
                }
            },
            "stepIdx": 42,
            "conversationId": "conv-123",
            "modelName": "gemini-2.5-pro",
            "transcriptPath": "C:/agy/conversations/conv-123.jsonl"
        }"#;

        let input: AgyPreToolUseInput = serde_json::from_str(raw_json).unwrap();
        let event = AgyAdapter::pre_tool_use_to_event(&input, 1);

        assert_eq!(event.session_id, "conv-123");
        assert_eq!(event.event_type, ArcEventType::ToolCall);
        assert_eq!(
            event.transcript_path,
            Some(PathBuf::from("C:/agy/conversations/conv-123.jsonl"))
        );
        match event.payload {
            ArcEventPayload::ToolCall {
                tool, command_text, ..
            } => {
                assert_eq!(tool, "run_command");
                assert_eq!(command_text, Some("git push origin main --force".into()));
            }
            _ => panic!("Expected ToolCall payload"),
        }

        // Test output conversion
        let deny_result = evaluate_result(
            EffectiveDisposition::Deny,
            ArcEventType::ToolCall,
            "Blocked by Arc guard",
        );
        let output = AgyAdapter::evaluation_result_to_pre_tool_use_output(&deny_result).unwrap();
        assert_eq!(output.decision, "deny");
        assert!(output.reason.unwrap().contains("Blocked by Arc guard"));
    }

    #[test]
    fn test_stop_translation() {
        let raw_json = r#"{
            "executionNum": 5,
            "terminationReason": "model_stop",
            "error": "",
            "fullyIdle": true,
            "conversationId": "conv-456"
        }"#;

        let input: AgyStopInput = serde_json::from_str(raw_json).unwrap();
        let event = AgyAdapter::stop_to_event(&input, 1);

        assert_eq!(event.session_id, "conv-456");
        assert_eq!(event.event_type, ArcEventType::End);

        let deny_result = evaluate_result(
            EffectiveDisposition::Deny,
            ArcEventType::End,
            "Pending tests must pass",
        );
        let output = AgyAdapter::evaluation_result_to_stop_output(&deny_result).unwrap();
        assert_eq!(output.decision, "stop");
        assert!(output.reason.unwrap().contains("Pending tests must pass"));
    }

    #[test]
    fn stop_preserves_provider_transcript_path() {
        let input: AgyStopInput = serde_json::from_value(serde_json::json!({
            "conversationId": "conv-path",
            "transcriptPath": "C:/agy/conversations/conv-path.json"
        }))
        .unwrap();

        assert_eq!(
            AgyAdapter::stop_to_event(&input, 1).transcript_path,
            Some(PathBuf::from("C:/agy/conversations/conv-path.json"))
        );
    }

    #[test]
    fn pre_invocation_preserves_provider_transcript_path() {
        let input: AgyPreInvocationInput = serde_json::from_value(serde_json::json!({
            "invocationNum": 0,
            "conversationId": "conv-pre-path",
            "transcriptPath": "C:/Users/user/.gemini/antigravity-cli/brain/conv-pre-path/.system_generated/logs/transcript_full.jsonl"
        }))
        .unwrap();

        let event = AgyAdapter::pre_invocation_to_event(&input, 1).expect("turn 0 maps to Start");
        assert_eq!(
            event.transcript_path,
            Some(PathBuf::from(
                "C:/Users/user/.gemini/antigravity-cli/brain/conv-pre-path/.system_generated/logs/transcript_full.jsonl"
            ))
        );
    }

    #[test]
    fn stop_timeout_keeps_session_active() {
        let resolution = resolve_capability(CapabilityContext::cli(
            ProviderTarget::Gemini,
            OsTarget::host().unwrap(),
            CapabilityEvent::End,
            crate::manifest::schema::ActionType::Ask,
            DecisionUiMode::Native,
        ));
        let output = AgyAdapter::embedded_decision_to_stop_output(
            &resolution,
            crate::decision_ui::PortableDecision::Unresolved(
                crate::decision_ui::UnresolvedReason::TimedOut,
            ),
            "ensure_clean_completion",
            "stop-timeout-1",
            None,
            None,
        )
        .unwrap();
        assert_eq!(output.decision, "continue");
        assert!(output.reason.unwrap().contains("ask the user again"));
    }

    #[test]
    fn stop_remediation_preserves_guard_context_and_user_message() {
        let resolution = resolve_capability(CapabilityContext::cli(
            ProviderTarget::Gemini,
            OsTarget::host().unwrap(),
            CapabilityEvent::End,
            crate::manifest::schema::ActionType::Ask,
            DecisionUiMode::Native,
        ));
        let output = AgyAdapter::embedded_decision_to_stop_output(
            &resolution,
            crate::decision_ui::PortableDecision::Allow,
            "ensure_clean_completion",
            "stop-remediation-1",
            Some("Git is dirty and the test suite has not been verified."),
            Some("Commit only the generated fixture."),
        )
        .unwrap();

        let reason = output.reason.expect("allow must carry remediation context");
        assert!(reason.contains("Git is dirty and the test suite has not been verified."));
        assert!(reason.contains("Commit only the generated fixture."));
    }

    #[test]
    fn stop_decisions_have_the_same_allow_deny_retry_contract_as_codex() {
        let resolution = resolve_capability(CapabilityContext::cli(
            ProviderTarget::Gemini,
            OsTarget::host().unwrap(),
            CapabilityEvent::End,
            crate::manifest::schema::ActionType::Ask,
            DecisionUiMode::Native,
        ));

        let allowed = AgyAdapter::embedded_decision_to_stop_output(
            &resolution,
            crate::decision_ui::PortableDecision::Allow,
            "ensure_clean_completion",
            "stop-allow-1",
            Some("workspace remains dirty"),
            None,
        )
        .unwrap();
        assert_eq!(allowed.decision, "continue");

        let denied = AgyAdapter::embedded_decision_to_stop_output(
            &resolution,
            crate::decision_ui::PortableDecision::Deny,
            "ensure_clean_completion",
            "stop-deny-1",
            Some("workspace remains dirty"),
            None,
        )
        .unwrap();
        assert_eq!(denied.decision, "stop");

        let unresolved = AgyAdapter::embedded_decision_to_stop_output(
            &resolution,
            crate::decision_ui::PortableDecision::Unresolved(
                crate::decision_ui::UnresolvedReason::Closed,
            ),
            "ensure_clean_completion",
            "stop-retry-1",
            Some("workspace remains dirty"),
            None,
        )
        .unwrap();
        assert_eq!(unresolved.decision, "continue");
        assert!(unresolved.reason.unwrap().contains("ask the user again"));
    }

    #[test]
    fn message_is_advisory_on_tool_and_end_hooks() {
        let message = evaluate_result(
            EffectiveDisposition::Message,
            ArcEventType::ToolCall,
            "Review completed",
        );
        let message_end = evaluate_result(
            EffectiveDisposition::Message,
            ArcEventType::End,
            "Review completed",
        );
        let pre_tool = AgyAdapter::evaluation_result_to_pre_tool_use_output(&message).unwrap();
        assert_eq!(pre_tool.decision, "allow");
        assert!(pre_tool.reason.unwrap().contains("Review completed"));

        let stop = AgyAdapter::evaluation_result_to_stop_output(&message_end).unwrap();
        assert_eq!(stop.decision, "stop");
        assert!(stop.reason.unwrap().contains("Review completed"));
    }

    #[test]
    fn test_pre_tool_use_quoted_command_normalization() {
        let raw_json = r#"{
            "toolCall": {
                "name": "run_command",
                "args": {
                    "CommandLine": "\"git push --force origin main\""
                }
            },
            "stepIdx": 10
        }"#;

        let input: AgyPreToolUseInput = serde_json::from_str(raw_json).unwrap();
        let event = AgyAdapter::pre_tool_use_to_event(&input, 1);

        match event.payload {
            ArcEventPayload::ToolCall { command_text, .. } => {
                assert_eq!(command_text, Some("git push --force origin main".into()));
            }
            _ => panic!("Expected ToolCall payload"),
        }
    }

    #[test]
    fn malformed_command_shapes_fail_closed() {
        assert_eq!(
            extract_command_text(&serde_json::json!({"args": ["git", 42]})),
            None
        );
        assert_eq!(
            extract_command_text(&serde_json::json!({
                "command": "safe",
                "script": "dangerous"
            })),
            None
        );
        assert_eq!(
            extract_command_text(&serde_json::json!(r#"{"args":["git",42]}"#)),
            None
        );
    }

    #[test]
    fn test_agy_runtime_error_translation() {
        let fault_result = evaluate_result(
            EffectiveDisposition::RuntimeFault,
            ArcEventType::ToolCall,
            "Probe failed",
        );
        let fault_result_end = evaluate_result(
            EffectiveDisposition::RuntimeFault,
            ArcEventType::End,
            "Probe failed",
        );

        let pre_tool = AgyAdapter::evaluation_result_to_pre_tool_use_output(&fault_result).unwrap();
        assert_eq!(pre_tool.decision, "deny");
        assert!(pre_tool.reason.unwrap().contains("[ARC PROBE ERROR]"));

        let stop = AgyAdapter::evaluation_result_to_stop_output(&fault_result_end).unwrap();
        assert_eq!(stop.decision, "stop");
        assert!(stop.reason.unwrap().contains("[ARC PROBE ERROR]"));
    }

    #[test]
    fn provider_native_ask_requires_explicit_provider_mode() {
        let ask_result = evaluate_result(
            EffectiveDisposition::Ask,
            ArcEventType::ToolCall,
            "Confirm deleting prueba.txt?",
        );

        assert!(AgyAdapter::evaluation_result_to_pre_tool_use_output(&ask_result).is_err());

        let resolution = resolve_capability(CapabilityContext::cli(
            ProviderTarget::Gemini,
            OsTarget::host().unwrap(),
            CapabilityEvent::ToolCall,
            crate::manifest::schema::ActionType::Ask,
            DecisionUiMode::Provider,
        ));
        let pre_tool = AgyAdapter::evaluation_result_to_pre_tool_use_output_with_resolution(
            &ask_result,
            &resolution,
        )
        .unwrap();
        assert_eq!(pre_tool.decision, "force_ask");
        assert!(
            pre_tool
                .reason
                .unwrap()
                .contains("Confirm deleting prueba.txt?")
        );
    }

    #[test]
    fn alternative_codex_transports_are_rejected_by_the_gemini_adapter() {
        let ask_result = evaluate_result(
            EffectiveDisposition::Ask,
            ArcEventType::End,
            "Confirm the protected operation",
        );

        for transport in [
            crate::target::DecisionTransport::CodexAppServer,
            crate::target::DecisionTransport::DirectMcp,
        ] {
            let mut context = CapabilityContext::cli(
                ProviderTarget::Gemini,
                OsTarget::host().unwrap(),
                CapabilityEvent::End,
                crate::manifest::schema::ActionType::Ask,
                DecisionUiMode::Auto,
            );
            context.decision_environment = crate::target::DecisionEnvironment {
                provider_native: false,
                arc_embedded_ui: false,
                arc_owns_app_server_session: transport
                    == crate::target::DecisionTransport::CodexAppServer,
                direct_mcp_channel: transport == crate::target::DecisionTransport::DirectMcp,
            };
            let mut resolution = resolve_capability(context);
            resolution.decision_transport = Some(transport);
            resolution.effective_action = match transport {
                crate::target::DecisionTransport::CodexAppServer => {
                    "decision_block_with_codex_app_server".into()
                }
                crate::target::DecisionTransport::DirectMcp => {
                    "decision_block_with_direct_mcp".into()
                }
                _ => unreachable!(),
            };

            assert!(
                AgyAdapter::evaluation_result_to_stop_output_with_resolution(
                    &ask_result,
                    &resolution,
                )
                .is_err(),
                "AGY must fail closed for a Codex-only ask transport"
            );
        }
    }
}
