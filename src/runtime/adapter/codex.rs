use crate::runtime::execution::{
    LifecycleStopActivation, LifecycleStopDecision, LifecycleStopOutcome,
};
use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::path::{Path, PathBuf};

pub use super::common::{extract_command_text, is_command_tool, normalize_tool_call_arguments};
use super::common::{format_bundle_feedback_for_provider, validate_provider_tool_call_arguments};
use crate::runtime::events::{ArcEvent, ArcEventPayload, ArcEventType};
use crate::runtime::guard_evaluation::{ArcEvaluationResult, EffectiveDisposition};
use crate::target::capabilities::expected_ask_effective_action;
use crate::target::{
    CapabilityContext, CapabilityEvent, CapabilityResolution, DecisionTransport, DecisionUiMode,
    OsTarget, ProviderTarget, resolve_capability,
};

/// Input payload sent by OpenAI Codex on PreToolUse hooks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CodexPreToolUseInput {
    #[serde(alias = "hook_event_name", default)]
    pub hook_event_name: Option<String>,
    #[serde(alias = "tool_name")]
    pub tool_name: String,
    #[serde(alias = "tool_input", default)]
    pub tool_input: Value,
    #[serde(alias = "session_id", default)]
    pub session_id: Option<String>,
    #[serde(alias = "turn_id", default)]
    pub turn_id: Option<String>,
    #[serde(alias = "tool_use_id", default)]
    pub tool_use_id: Option<String>,
    #[serde(alias = "cwd", default)]
    pub cwd: Option<String>,
    #[serde(alias = "model", default)]
    pub model: Option<String>,
    /// Optional absolute transcript/rollout path supplied by the provider.
    #[serde(
        alias = "transcript_path",
        alias = "rollout_path",
        alias = "rolloutPath",
        default
    )]
    pub transcript_path: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CodexPreToolUseSpecificOutput {
    pub hook_event_name: String,
    pub permission_decision: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub permission_decision_reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_input: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub additional_context: Option<String>,
}

/// Output payload expected by Codex for PreToolUse hooks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CodexPreToolUseOutput {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hook_specific_output: Option<CodexPreToolUseSpecificOutput>,
}

impl CodexPreToolUseOutput {
    pub fn allow() -> Self {
        Self {
            hook_specific_output: None,
        }
    }

    pub fn deny(reason: Option<String>) -> Self {
        Self {
            hook_specific_output: Some(CodexPreToolUseSpecificOutput {
                hook_event_name: "PreToolUse".to_string(),
                permission_decision: "deny".to_string(),
                permission_decision_reason: reason,
                updated_input: None,
                additional_context: None,
            }),
        }
    }

    pub fn allow_with_context(context: impl Into<String>) -> Self {
        Self {
            hook_specific_output: Some(CodexPreToolUseSpecificOutput {
                hook_event_name: "PreToolUse".to_string(),
                permission_decision: "allow".to_string(),
                permission_decision_reason: None,
                updated_input: None,
                additional_context: Some(context.into()),
            }),
        }
    }
}

/// Input payload sent by Codex on Stop / SubagentStop hooks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CodexStopInput {
    #[serde(alias = "hook_event_name", default)]
    pub hook_event_name: Option<String>,
    #[serde(alias = "session_id", default)]
    pub session_id: Option<String>,
    #[serde(alias = "turn_id", default)]
    pub turn_id: Option<String>,
    #[serde(alias = "cwd", default)]
    pub cwd: Option<String>,
    #[serde(alias = "model", default)]
    pub model: Option<String>,
    #[serde(
        alias = "transcript_path",
        alias = "rollout_path",
        alias = "rolloutPath",
        default
    )]
    pub transcript_path: Option<String>,
    /// Codex sets this after a Stop hook has already continued the turn.
    /// Blocking again would create an unbounded Stop continuation loop.
    #[serde(alias = "stop_hook_active", default)]
    pub stop_hook_active: bool,
}

/// Output payload expected by Codex for Stop hooks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CodexStopOutput {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub r#continue: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stop_reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decision: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub system_message: Option<String>,
}

impl CodexStopOutput {
    pub fn allow() -> Self {
        Self {
            r#continue: None,
            stop_reason: None,
            decision: None,
            reason: None,
            system_message: None,
        }
    }

    pub fn allow_with_context(context: impl Into<String>) -> Self {
        Self {
            system_message: Some(context.into()),
            ..Self::allow()
        }
    }

    pub fn continue_loop(prompt: String) -> Self {
        Self {
            r#continue: None,
            stop_reason: None,
            decision: Some("block".to_string()),
            reason: Some(prompt),
            system_message: None,
        }
    }

    pub fn abort(reason: String) -> Self {
        Self {
            r#continue: Some(false),
            stop_reason: Some(reason),
            decision: None,
            reason: None,
            system_message: None,
        }
    }
}

/// Input payload sent by Codex on SessionStart hooks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CodexSessionStartInput {
    #[serde(alias = "hook_event_name", default)]
    pub hook_event_name: Option<String>,
    #[serde(alias = "session_id", default)]
    pub session_id: Option<String>,
    #[serde(alias = "cwd", default)]
    pub cwd: Option<String>,
    #[serde(
        alias = "transcript_path",
        alias = "rollout_path",
        alias = "rolloutPath",
        default
    )]
    pub transcript_path: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CodexSessionStartSpecificOutput {
    pub hook_event_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub additional_context: Option<String>,
}

/// Output payload expected by Codex for SessionStart hooks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CodexSessionStartOutput {
    pub r#continue: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stop_reason: Option<String>,
    pub hook_specific_output: CodexSessionStartSpecificOutput,
}

impl CodexSessionStartOutput {
    pub fn allow() -> Self {
        Self {
            r#continue: true,
            stop_reason: None,
            hook_specific_output: CodexSessionStartSpecificOutput {
                hook_event_name: "SessionStart".to_string(),
                additional_context: None,
            },
        }
    }

    pub fn allow_with_context(context: impl Into<String>) -> Self {
        Self {
            r#continue: true,
            stop_reason: None,
            hook_specific_output: CodexSessionStartSpecificOutput {
                hook_event_name: "SessionStart".to_string(),
                additional_context: Some(context.into()),
            },
        }
    }

    pub fn abort(reason: Option<String>) -> Self {
        Self {
            r#continue: false,
            stop_reason: reason.clone(),
            hook_specific_output: CodexSessionStartSpecificOutput {
                hook_event_name: "SessionStart".to_string(),
                additional_context: reason,
            },
        }
    }
}

/// Adapter converting between OpenAI Codex hook payloads and Arc Runtime events / outcomes.
pub struct CodexAdapter;

impl CodexAdapter {
    /// Normalizes native session/turn/reentry fields for the shared runtime coordinator.
    pub fn stop_activation(
        input: &CodexStopInput,
        _invocation_id: &str,
    ) -> LifecycleStopActivation {
        let turn_id = input.turn_id.clone();
        LifecycleStopActivation {
            provider: ProviderTarget::Codex,
            session_id: input
                .session_id
                .clone()
                .unwrap_or_else(|| "codex-session-default".into()),
            coordination_invocation_id: format!(
                "{}:{}",
                turn_id.as_deref().unwrap_or("turn-unknown"),
                if input.stop_hook_active {
                    "continued"
                } else {
                    "initial"
                }
            ),
            turn_id,
            signals: crate::ProviderSignals {
                reentry: if input.stop_hook_active {
                    crate::ReentryKind::ContinuedByHook
                } else {
                    crate::ReentryKind::FirstInvocation
                },
                ..Default::default()
            },
        }
    }

    /// Projects a coordinated semantic result into this provider's Stop wire contract.
    pub fn lifecycle_stop_to_output(
        outcome: LifecycleStopOutcome,
        result: &ArcEvaluationResult,
        invocation_id: &str,
    ) -> Result<CodexStopOutput> {
        match outcome {
            LifecycleStopOutcome::ProjectEvaluation => {
                Self::evaluation_result_to_stop_output(result)
            }
            LifecycleStopOutcome::Completed { feedback } => {
                Ok(CodexStopOutput::allow_with_context(feedback))
            }
            LifecycleStopOutcome::Blocked { feedback } => Ok(CodexStopOutput::abort(feedback)),
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
                let mut appended = false;
                for field in [
                    &mut output.reason,
                    &mut output.stop_reason,
                    &mut output.system_message,
                ] {
                    if let Some(reason) = field.take() {
                        *field = Some(super::common::append_aggregate_feedback(
                            Some(reason),
                            &aggregate_feedback,
                        ));
                        appended = true;
                    }
                }
                if !appended {
                    output.system_message = Some(aggregate_feedback);
                }
                Ok(output)
            }
        }
    }

    /// Rejects malformed provider wire input before a hook can evaluate guards.
    pub fn validate_pre_tool_use_input(input: &CodexPreToolUseInput) -> Result<()> {
        validate_provider_tool_call_arguments(&input.tool_name, &input.tool_input)
    }

    /// Translates a Codex PreToolUse input payload into a normalized ArcEvent.
    pub fn pre_tool_use_to_event(input: &CodexPreToolUseInput, sequence: u64) -> ArcEvent {
        let session_id = input
            .session_id
            .clone()
            .unwrap_or_else(|| "codex-session-default".to_string());
        let event_id = format!(
            "ev-codex-tool-{}",
            input
                .tool_use_id
                .as_deref()
                .unwrap_or(&sequence.to_string())
        );

        // Extract command text with robust multi-field / JSON-string / array support (H1)
        let (command_text, argument_extraction) =
            normalize_tool_call_arguments(&input.tool_name, &input.tool_input);

        ArcEvent {
            provider: Some(ProviderTarget::Codex),
            session_id,
            event_id,
            event_type: ArcEventType::ToolCall,
            sequence,
            correlation_id: input.turn_id.clone(),
            transcript_path: provider_transcript_path(
                input.transcript_path.as_deref(),
                input.cwd.as_deref(),
            ),
            payload: ArcEventPayload::ToolCall {
                tool: input.tool_name.clone(),
                input: input.tool_input.clone(),
                command_text,
                argument_extraction,
            },
        }
    }

    /// Converts an ArcEvaluationResult to the Codex PreToolUse output payload without loss of aggregate context.
    pub fn evaluation_result_to_pre_tool_use_output(
        eval_result: &ArcEvaluationResult,
    ) -> Result<CodexPreToolUseOutput> {
        if matches!(
            eval_result.effective_disposition,
            EffectiveDisposition::Continue
        ) && !eval_result.authorization_requirements.is_empty()
        {
            return Ok(CodexPreToolUseOutput::deny(Some(
                "Arc exact operation authorization is unresolved; the tool call was blocked without user confirmation."
                    .into(),
            )));
        }
        if matches!(
            eval_result.effective_disposition,
            EffectiveDisposition::Continue
        ) && eval_result.failure_bundle.failed_guards.is_empty()
        {
            return Ok(CodexPreToolUseOutput::allow());
        }
        if matches!(
            eval_result.effective_disposition,
            EffectiveDisposition::RuntimeFault
        ) {
            let reason = format_bundle_feedback_for_provider(
                &eval_result.failure_bundle,
                "[ARC PROBE ERROR] Guard evaluation failed; see local Arc diagnostics.",
            )?;
            return Ok(CodexPreToolUseOutput::deny(Some(reason)));
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
            ProviderTarget::Codex,
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
    ) -> Result<CodexPreToolUseOutput> {
        if matches!(
            eval_result.effective_disposition,
            EffectiveDisposition::Continue
        ) && !eval_result.authorization_requirements.is_empty()
        {
            return Ok(CodexPreToolUseOutput::deny(Some(
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
        validate_resolution_action(
            resolution,
            ProviderTarget::Codex,
            CapabilityEvent::ToolCall,
            action,
        )?;
        match eval_result.effective_disposition {
            EffectiveDisposition::Continue => Ok(CodexPreToolUseOutput::allow()),
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
                    Ok(CodexPreToolUseOutput::allow_with_context(msg))
                } else {
                    Ok(CodexPreToolUseOutput::allow())
                }
            }
            EffectiveDisposition::Deny => {
                let reason = format_bundle_feedback_for_provider(
                    &eval_result.failure_bundle,
                    "Arc policy denied the tool call.",
                )?;
                Ok(CodexPreToolUseOutput::deny(Some(reason)))
            }
            EffectiveDisposition::Ask => {
                let base = format!(
                    "Arc must resolve this ask through {:?} before allowing the tool.",
                    resolution.decision_transport,
                );
                let reason =
                    format_bundle_feedback_for_provider(&eval_result.failure_bundle, &base)?;
                Ok(CodexPreToolUseOutput::deny(Some(reason)))
            }
            EffectiveDisposition::RuntimeFault => {
                let reason = format_bundle_feedback_for_provider(
                    &eval_result.failure_bundle,
                    "[ARC PROBE ERROR] Guard evaluation failed; see local Arc diagnostics.",
                )?;
                Ok(CodexPreToolUseOutput::deny(Some(reason)))
            }
        }
    }

    pub fn embedded_decision_to_pre_tool_use_output(
        resolution: &CapabilityResolution,
        decision: crate::decision_ui::PortableDecision,
        allow_context: String,
        deny_reason: String,
    ) -> Result<CodexPreToolUseOutput> {
        if resolution.context.provider != ProviderTarget::Codex
            || resolution.context.event != CapabilityEvent::ToolCall
            || resolution.context.requested_action != crate::manifest::schema::ActionType::Ask
            || resolution.decision_transport != Some(DecisionTransport::ArcEmbeddedUi)
            || resolution.effective_action != "arc_embedded_ui_ask"
        {
            bail!("Codex embedded UI decision does not match the supplied capability resolution");
        }
        Ok(match decision {
            crate::decision_ui::PortableDecision::Allow => {
                CodexPreToolUseOutput::allow_with_context(allow_context)
            }
            crate::decision_ui::PortableDecision::Deny
            | crate::decision_ui::PortableDecision::Unresolved(_) => {
                CodexPreToolUseOutput::deny(Some(deny_reason))
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
    ) -> Result<CodexStopOutput> {
        validate_native_resolution(resolution, CapabilityEvent::End)?;
        Ok(match decision {
            crate::decision_ui::PortableDecision::Allow => {
                CodexStopOutput::continue_loop(super::stop_remediation_reason(
                    guard_id,
                    invocation_id,
                    failure_context,
                    user_message,
                ))
            }
            crate::decision_ui::PortableDecision::Deny => {
                CodexStopOutput::allow_with_context(format!(
                    "The user declined remediation for Arc guard '{guard_id}'. Finish the current turn without performing additional remediation for this guard."
                ))
            }
            crate::decision_ui::PortableDecision::Unresolved(reason) => {
                CodexStopOutput::continue_loop(format!(
                    "Arc's decision remained unresolved ({reason:?}) for guard '{guard_id}' on stop attempt ({invocation_id}). Keep the session active, re-evaluate the guard, and ask the user again before stopping."
                ))
            }
        })
    }

    /// Translates a Codex Stop input payload into a normalized ArcEvent (trigger: end).
    pub fn stop_to_event(input: &CodexStopInput, sequence: u64) -> ArcEvent {
        let session_id = input
            .session_id
            .clone()
            .unwrap_or_else(|| "codex-session-default".to_string());
        let event_id = format!("ev-codex-stop-{}", sequence);

        ArcEvent {
            provider: Some(ProviderTarget::Codex),
            session_id,
            event_id,
            event_type: ArcEventType::End,
            sequence,
            correlation_id: input.turn_id.clone(),
            transcript_path: provider_transcript_path(
                input.transcript_path.as_deref(),
                input.cwd.as_deref(),
            ),
            payload: ArcEventPayload::Empty,
        }
    }

    pub fn evaluation_result_to_stop_output(
        eval_result: &ArcEvaluationResult,
    ) -> Result<CodexStopOutput> {
        if matches!(
            eval_result.effective_disposition,
            EffectiveDisposition::Continue
        ) && eval_result.authorization_requirements.is_empty()
            && eval_result.failure_bundle.failed_guards.is_empty()
        {
            return Ok(CodexStopOutput::allow());
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
            ProviderTarget::Codex,
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
    ) -> Result<CodexStopOutput> {
        let action = match eval_result.effective_disposition {
            EffectiveDisposition::Continue => None,
            EffectiveDisposition::Message => Some(crate::manifest::schema::ActionType::Message),
            EffectiveDisposition::Deny | EffectiveDisposition::RuntimeFault => {
                Some(crate::manifest::schema::ActionType::Deny)
            }
            EffectiveDisposition::Ask => Some(crate::manifest::schema::ActionType::Ask),
        };
        validate_resolution_action(
            resolution,
            ProviderTarget::Codex,
            CapabilityEvent::End,
            action,
        )?;
        Ok(match eval_result.effective_disposition {
            EffectiveDisposition::Continue => CodexStopOutput::allow(),
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
                    CodexStopOutput::allow_with_context(msg)
                } else {
                    CodexStopOutput::allow()
                }
            }
            EffectiveDisposition::Deny => {
                let prompt = format_bundle_feedback_for_provider(
                    &eval_result.failure_bundle,
                    "Session cannot end: Arc guard requirements unmet.",
                )?;
                CodexStopOutput::abort(prompt)
            }
            EffectiveDisposition::Ask => {
                let prompt = format_bundle_feedback_for_provider(
                    &eval_result.failure_bundle,
                    "Confirmation required before finishing.",
                )?;
                CodexStopOutput::continue_loop(prompt)
            }
            EffectiveDisposition::RuntimeFault => {
                let prompt = format_bundle_feedback_for_provider(
                    &eval_result.failure_bundle,
                    "[ARC PROBE ERROR] Guard evaluation failed; see local Arc diagnostics.",
                )?;
                CodexStopOutput::abort(prompt)
            }
        })
    }

    /// Translates a Codex SessionStart input payload into a normalized ArcEvent (trigger: start).
    pub fn session_start_to_event(input: &CodexSessionStartInput, sequence: u64) -> ArcEvent {
        let session_id = input
            .session_id
            .clone()
            .unwrap_or_else(|| "codex-session-default".to_string());
        let event_id = format!("ev-codex-start-{}", sequence);

        ArcEvent {
            provider: Some(ProviderTarget::Codex),
            session_id,
            event_id,
            event_type: ArcEventType::Start,
            sequence,
            correlation_id: None,
            transcript_path: provider_transcript_path(
                input.transcript_path.as_deref(),
                input.cwd.as_deref(),
            ),
            payload: ArcEventPayload::Empty,
        }
    }

    pub fn evaluation_result_to_session_start_output(
        eval_result: &ArcEvaluationResult,
    ) -> Result<CodexSessionStartOutput> {
        if matches!(
            eval_result.effective_disposition,
            EffectiveDisposition::Continue
        ) && eval_result.authorization_requirements.is_empty()
            && eval_result.failure_bundle.failed_guards.is_empty()
        {
            return Ok(CodexSessionStartOutput::allow());
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
            ProviderTarget::Codex,
            OsTarget::host().expect("Arc only runs on a supported host OS"),
            CapabilityEvent::Start,
            action,
            DecisionUiMode::Auto,
        ));
        Self::evaluation_result_to_session_start_output_with_resolution(eval_result, &resolution)
    }

    pub fn evaluation_result_to_session_start_output_with_resolution(
        eval_result: &ArcEvaluationResult,
        resolution: &CapabilityResolution,
    ) -> Result<CodexSessionStartOutput> {
        let action = match eval_result.effective_disposition {
            EffectiveDisposition::Continue => None,
            EffectiveDisposition::Message => Some(crate::manifest::schema::ActionType::Message),
            EffectiveDisposition::Deny | EffectiveDisposition::RuntimeFault => {
                Some(crate::manifest::schema::ActionType::Deny)
            }
            EffectiveDisposition::Ask => Some(crate::manifest::schema::ActionType::Ask),
        };
        validate_resolution_action(
            resolution,
            ProviderTarget::Codex,
            CapabilityEvent::Start,
            action,
        )?;
        Ok(match eval_result.effective_disposition {
            EffectiveDisposition::Continue => CodexSessionStartOutput::allow(),
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
                    CodexSessionStartOutput::allow_with_context(msg)
                } else {
                    CodexSessionStartOutput::allow()
                }
            }
            EffectiveDisposition::Deny => {
                let feedback = format_bundle_feedback_for_provider(
                    &eval_result.failure_bundle,
                    "Arc policy denied session start.",
                )?;
                CodexSessionStartOutput::abort(Some(feedback))
            }
            EffectiveDisposition::Ask => {
                let prompt = format_bundle_feedback_for_provider(
                    &eval_result.failure_bundle,
                    "Confirmation required before session start.",
                )?;
                CodexSessionStartOutput::abort(Some(prompt))
            }
            EffectiveDisposition::RuntimeFault => {
                let prompt = format_bundle_feedback_for_provider(
                    &eval_result.failure_bundle,
                    "[ARC RUNTIME ERROR] Guard evaluation failed; see local Arc diagnostics.",
                )?;
                CodexSessionStartOutput::abort(Some(prompt))
            }
        })
    }
}

fn validate_resolution_action(
    resolution: &CapabilityResolution,
    provider: ProviderTarget,
    event: CapabilityEvent,
    action: Option<crate::manifest::schema::ActionType>,
) -> Result<()> {
    if resolution.context.provider != provider || resolution.context.event != event {
        bail!(
            "capability resolution targets {}/{}, adapter requires {}/{}",
            resolution.context.provider,
            resolution.context.event,
            provider,
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
            != expected_ask_effective_action(provider, event, resolution.decision_transport)
    {
        bail!(
            "ask resolution action '{}' contradicts provider/event transport contract",
            resolution.effective_action
        );
    }
    Ok(())
}

fn validate_native_resolution(
    resolution: &CapabilityResolution,
    event: CapabilityEvent,
) -> Result<()> {
    if resolution.context.provider != ProviderTarget::Codex
        || resolution.context.event != event
        || resolution.context.requested_action != crate::manifest::schema::ActionType::Ask
        || resolution.decision_transport != Some(DecisionTransport::ArcEmbeddedUi)
        || resolution.capability != crate::target::CapabilityLevel::Emulated
        || resolution.effective_action
            != expected_ask_effective_action(
                ProviderTarget::Codex,
                event,
                resolution.decision_transport,
            )
    {
        bail!("Codex lifecycle embedded UI output contradicts the supplied capability resolution");
    }
    Ok(())
}

fn provider_transcript_path(path: Option<&str>, cwd: Option<&str>) -> Option<PathBuf> {
    let path = Path::new(path?.trim());
    if path.is_absolute() {
        return Some(path.to_path_buf());
    }
    let absolute_cwd = cwd
        .map(str::trim)
        .map(Path::new)
        .filter(|candidate| candidate.is_absolute());
    Some(
        absolute_cwd
            .map(|base| base.join(path))
            .unwrap_or_else(|| path.to_path_buf()),
    )
}

#[cfg(test)]
mod tests {
    use super::super::test_support::evaluate_result;
    use super::*;

    #[test]
    fn test_codex_pre_tool_use_translation() {
        let raw_json = r#"{
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {
                "command": "git push --force origin dev"
            },
            "session_id": "01a0205a-a192-7012-a9dc-ac713b22f85a",
            "turn_id": "01a0205a-a1ed-7732-b995-d4f118379a8b",
            "tool_use_id": "exec-f4666136-3554-4269-aa42-59742780ebf4",
            "cwd": "C:/project"
            ,"transcriptPath": "C:/project/.codex/sessions/rollout.jsonl"
        }"#;

        let input: CodexPreToolUseInput = serde_json::from_str(raw_json).unwrap();
        let event = CodexAdapter::pre_tool_use_to_event(&input, 1);

        assert_eq!(event.session_id, "01a0205a-a192-7012-a9dc-ac713b22f85a");
        assert_eq!(event.event_type, ArcEventType::ToolCall);
        assert_eq!(
            event.transcript_path.as_deref(),
            Some(Path::new("C:/project/.codex/sessions/rollout.jsonl"))
        );
        match event.payload {
            ArcEventPayload::ToolCall {
                tool, command_text, ..
            } => {
                assert_eq!(tool, "Bash");
                assert_eq!(command_text, Some("git push --force origin dev".into()));
            }
            _ => panic!("Expected ToolCall payload"),
        }

        // Test output deny conversion
        let deny_result = evaluate_result(
            EffectiveDisposition::Deny,
            ArcEventType::ToolCall,
            "Force push denied on protected branch 'dev'",
        );
        let output = CodexAdapter::evaluation_result_to_pre_tool_use_output(&deny_result).unwrap();
        assert_eq!(
            output
                .hook_specific_output
                .as_ref()
                .unwrap()
                .permission_decision,
            "deny"
        );
        assert!(
            output
                .hook_specific_output
                .unwrap()
                .permission_decision_reason
                .unwrap()
                .contains("Force push denied on protected branch 'dev'")
        );
    }

    #[test]
    fn codex_transcript_and_rollout_path_aliases_are_preserved() {
        let root = std::env::temp_dir().join(format!(
            "arc_codex_path_aliases_{}_{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        let sessions = root.join("sessions");
        std::fs::create_dir_all(&sessions).unwrap();
        let transcript = sessions.join("rollout-alias.jsonl");
        std::fs::write(
            &transcript,
            "{\"type\":\"session_meta\",\"payload\":{\"id\":\"path-alias-session\"}}\n\
             {\"type\":\"USER_INPUT\",\"content\":\"valid alias transcript\"}\n",
        )
        .unwrap();
        let transcript_value = transcript.to_string_lossy().into_owned();

        for field in ["transcript_path", "rollout_path", "rolloutPath"] {
            let mut raw = serde_json::json!({
                "hook_event_name": "PreToolUse",
                "tool_name": "Bash",
                "tool_input": {"command": "cargo test"},
                "session_id": "path-alias-session",
                "cwd": "C:/workspace"
            });
            raw.as_object_mut()
                .expect("test payload is an object")
                .insert(field.to_string(), serde_json::json!(transcript_value));
            let input: CodexPreToolUseInput = serde_json::from_value(raw)
                .unwrap_or_else(|error| panic!("{field} must deserialize: {error}"));
            let event = CodexAdapter::pre_tool_use_to_event(&input, 1);
            assert_eq!(event.transcript_path, Some(transcript.clone()));
            let opened = crate::runtime::context::OpenedTranscript::open_with_allowed_roots(
                event.transcript_path.as_deref().unwrap(),
                "path-alias-session",
                std::slice::from_ref(&sessions),
            )
            .unwrap_or_else(|error| panic!("{field} must resolve: {error}"));
            assert_eq!(opened.into_context().user_intent, "valid alias transcript");
        }

        let stop: CodexStopInput = serde_json::from_value(serde_json::json!({
            "session_id": "stop-path-session",
            "rolloutPath": "C:/allowed/stop-rollout.jsonl"
        }))
        .unwrap();
        assert_eq!(
            CodexAdapter::stop_to_event(&stop, 1).transcript_path,
            Some(PathBuf::from("C:/allowed/stop-rollout.jsonl"))
        );

        let start: CodexSessionStartInput = serde_json::from_value(serde_json::json!({
            "session_id": "start-path-session",
            "rolloutPath": "C:/allowed/start-rollout.jsonl"
        }))
        .unwrap();
        assert_eq!(
            CodexAdapter::session_start_to_event(&start, 1).transcript_path,
            Some(PathBuf::from("C:/allowed/start-rollout.jsonl"))
        );

        let invalid_but_present = CodexPreToolUseInput {
            hook_event_name: Some("PreToolUse".into()),
            tool_name: "Bash".into(),
            tool_input: serde_json::json!({"command": "cargo test"}),
            session_id: Some("invalid-path-session".into()),
            turn_id: None,
            tool_use_id: None,
            cwd: None,
            model: None,
            transcript_path: Some("../outside-rollout.jsonl".into()),
        };
        assert_eq!(
            CodexAdapter::pre_tool_use_to_event(&invalid_but_present, 1).transcript_path,
            Some(PathBuf::from("../outside-rollout.jsonl")),
            "an invalid supplied path must remain present so runtime rejects it without fallback"
        );
        let _ = std::fs::remove_dir_all(root);
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
    fn test_codex_stop_translation() {
        let raw_json = r#"{
            "hook_event_name": "Stop",
            "session_id": "session-123"
        }"#;

        let input: CodexStopInput = serde_json::from_str(raw_json).unwrap();
        assert!(!input.stop_hook_active);
        let event = CodexAdapter::stop_to_event(&input, 1);
        assert_eq!(event.session_id, "session-123");
        assert_eq!(event.event_type, ArcEventType::End);

        let deny_result = evaluate_result(
            EffectiveDisposition::Deny,
            ArcEventType::End,
            "Run unit tests before finishing",
        );
        let output = CodexAdapter::evaluation_result_to_stop_output(&deny_result).unwrap();
        assert_eq!(output.r#continue, Some(false));
        assert!(
            output
                .stop_reason
                .unwrap()
                .contains("Run unit tests before finishing")
        );
    }

    #[test]
    fn codex_alternative_ask_transports_fail_closed_for_tool_and_stop() {
        let ask_result = evaluate_result(
            EffectiveDisposition::Ask,
            ArcEventType::ToolCall,
            "Confirm the protected operation",
        );
        let ask_result_end = evaluate_result(
            EffectiveDisposition::Ask,
            ArcEventType::End,
            "Confirm the protected operation",
        );

        for transport in [
            DecisionTransport::CodexAppServer,
            DecisionTransport::DirectMcp,
        ] {
            let mut tool_context = CapabilityContext::cli(
                ProviderTarget::Codex,
                OsTarget::host().expect("supported host"),
                CapabilityEvent::ToolCall,
                crate::manifest::schema::ActionType::Ask,
                DecisionUiMode::Auto,
            );
            tool_context.decision_environment = crate::target::DecisionEnvironment {
                provider_native: false,
                arc_embedded_ui: false,
                arc_owns_app_server_session: transport == DecisionTransport::CodexAppServer,
                direct_mcp_channel: transport == DecisionTransport::DirectMcp,
            };
            let tool_resolution = resolve_capability(tool_context);
            assert_eq!(tool_resolution.decision_transport, Some(transport));
            let tool_output =
                CodexAdapter::evaluation_result_to_pre_tool_use_output_with_resolution(
                    &ask_result,
                    &tool_resolution,
                )
                .expect("alternative ask transport must degrade to a provider denial");
            assert_eq!(
                tool_output
                    .hook_specific_output
                    .expect("fail-closed ToolCall output")
                    .permission_decision,
                "deny"
            );

            let mut stop_context = CapabilityContext::cli(
                ProviderTarget::Codex,
                OsTarget::host().expect("supported host"),
                CapabilityEvent::End,
                crate::manifest::schema::ActionType::Ask,
                DecisionUiMode::Auto,
            );
            stop_context.decision_environment = crate::target::DecisionEnvironment {
                provider_native: false,
                arc_embedded_ui: false,
                arc_owns_app_server_session: transport == DecisionTransport::CodexAppServer,
                direct_mcp_channel: transport == DecisionTransport::DirectMcp,
            };
            let stop_resolution = resolve_capability(stop_context);
            assert_eq!(stop_resolution.decision_transport, Some(transport));
            let stop_output = CodexAdapter::evaluation_result_to_stop_output_with_resolution(
                &ask_result_end,
                &stop_resolution,
            )
            .expect("alternative ask transport must keep Stop blocked");
            assert_eq!(stop_output.decision.as_deref(), Some("block"));
        }
    }

    #[test]
    fn stop_timeout_keeps_session_active() {
        let resolution = resolve_capability(CapabilityContext::cli(
            ProviderTarget::Codex,
            OsTarget::host().unwrap(),
            CapabilityEvent::End,
            crate::manifest::schema::ActionType::Ask,
            DecisionUiMode::Native,
        ));
        let output = CodexAdapter::embedded_decision_to_stop_output(
            &resolution,
            crate::decision_ui::PortableDecision::Unresolved(
                crate::decision_ui::UnresolvedReason::TimedOut,
            ),
            "ensure_clean_completion",
            "invocation-1",
            None,
            None,
        )
        .unwrap();
        assert_eq!(output.decision.as_deref(), Some("block"));
        assert!(output.reason.unwrap().contains("ask the user again"));
    }

    #[test]
    fn test_codex_stop_active_flag_accepts_snake_and_camel_case() {
        for raw_json in [
            r#"{"hook_event_name":"Stop","stop_hook_active":true}"#,
            r#"{"hookEventName":"Stop","stopHookActive":true}"#,
        ] {
            let input: CodexStopInput = serde_json::from_str(raw_json).unwrap();
            assert!(input.stop_hook_active);
        }
    }

    #[test]
    fn test_codex_runtime_error_translation() {
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

        let pre_tool =
            CodexAdapter::evaluation_result_to_pre_tool_use_output(&fault_result).unwrap();
        assert_eq!(
            pre_tool
                .hook_specific_output
                .as_ref()
                .unwrap()
                .permission_decision,
            "deny"
        );
        assert!(
            pre_tool
                .hook_specific_output
                .unwrap()
                .permission_decision_reason
                .unwrap()
                .contains("[ARC PROBE ERROR]")
        );

        let stop = CodexAdapter::evaluation_result_to_stop_output(&fault_result_end).unwrap();
        assert_eq!(stop.r#continue, Some(false));
        assert!(stop.stop_reason.unwrap().contains("[ARC PROBE ERROR]"));
    }

    #[test]
    fn test_codex_ask_translation() {
        let ask_result = evaluate_result(
            EffectiveDisposition::Ask,
            ArcEventType::ToolCall,
            "Confirm deleting prueba.txt?",
        );

        let pre_tool = CodexAdapter::evaluation_result_to_pre_tool_use_output(&ask_result).unwrap();
        let payload = serde_json::to_value(pre_tool).unwrap();
        assert_eq!(payload["hookSpecificOutput"]["permissionDecision"], "deny");
        assert!(
            payload["hookSpecificOutput"]["permissionDecisionReason"]
                .as_str()
                .unwrap()
                .contains("Confirm deleting prueba.txt?")
        );
    }

    #[test]
    fn message_is_advisory_on_tool_and_end_hooks() {
        let tool_result = evaluate_result(
            EffectiveDisposition::Message,
            ArcEventType::ToolCall,
            "Review completed",
        );
        let pre_tool =
            CodexAdapter::evaluation_result_to_pre_tool_use_output(&tool_result).unwrap();
        let output = pre_tool.hook_specific_output.expect("advisory context");
        assert_eq!(output.permission_decision, "allow");
        assert!(
            output
                .additional_context
                .unwrap()
                .contains("Review completed")
        );

        let end_result = evaluate_result(
            EffectiveDisposition::Message,
            ArcEventType::End,
            "Review completed",
        );
        let stop = CodexAdapter::evaluation_result_to_stop_output(&end_result).unwrap();
        assert_eq!(stop.r#continue, None);
        assert_eq!(stop.decision, None);
        assert!(stop.system_message.unwrap().contains("Review completed"));
    }

    #[test]
    fn test_codex_outputs_match_wire_contract() {
        assert_eq!(
            serde_json::to_value(CodexStopOutput::allow()).unwrap(),
            serde_json::json!({})
        );
        assert_eq!(
            serde_json::to_value(CodexStopOutput::continue_loop("keep going".into())).unwrap(),
            serde_json::json!({"decision": "block", "reason": "keep going"})
        );
        assert_eq!(
            serde_json::to_value(CodexStopOutput::abort("decision required".into())).unwrap(),
            serde_json::json!({"continue": false, "stopReason": "decision required"})
        );
        assert_eq!(
            serde_json::to_value(CodexSessionStartOutput::abort(Some("blocked".into()))).unwrap(),
            serde_json::json!({
                "continue": false,
                "stopReason": "blocked",
                "hookSpecificOutput": {
                    "hookEventName": "SessionStart",
                    "additionalContext": "blocked"
                }
            })
        );
    }
}
