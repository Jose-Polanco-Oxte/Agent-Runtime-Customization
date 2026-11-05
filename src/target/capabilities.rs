use serde::{Deserialize, Serialize};

use crate::manifest::loader::LoadedArcProject;
use crate::manifest::schema::{ActionType, LifecycleTrigger};
use crate::target::decision_strategy::{
    CapabilityEvent, DecisionEnvironment, DecisionTransport, DecisionUiMode, ProviderEnvironment,
    resolve_decision_transport_for,
};
use crate::target::os::OsTarget;
use crate::target::provider::ProviderTarget;

/// Level of support for a given capability in an agent provider (H9).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityLevel {
    /// Fully supported natively by the provider's official mechanisms with deterministic semantics.
    Supported,
    /// Emulated via ARC dispatcher / UI / runtime glue; useful adaptation without 100% native determinism.
    Emulated,
    /// Partial support or limited coverage surface (e.g. only CLI local tools, desktop unverified).
    Partial,
    /// Not supported by the provider's runtime contract.
    Unsupported,
}

impl std::fmt::Display for CapabilityLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Supported => write!(f, "SUPPORTED"),
            Self::Emulated => write!(f, "EMULATED"),
            Self::Partial => write!(f, "PARTIAL"),
            Self::Unsupported => write!(f, "UNSUPPORTED"),
        }
    }
}

/// Matrix of specific capabilities supported by a provider.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderCapabilities {
    pub provider: ProviderTarget,
    pub persistent_instructions: CapabilityLevel,
    pub hierarchical_instructions: CapabilityLevel,
    pub skills: CapabilityLevel,
    pub custom_agent_roles: CapabilityLevel,
    pub tool_guards_pre_execution: CapabilityLevel,
    pub tool_arg_rewrite: CapabilityLevel,
    pub user_approval: CapabilityLevel,
    pub lifecycle_start: CapabilityLevel,
    pub lifecycle_end: CapabilityLevel,
    pub lifecycle_remediation_continuation: CapabilityLevel,
    pub lifecycle_structured_decision: CapabilityLevel,
    pub lifecycle_suspend: CapabilityLevel,
    pub lifecycle_reentry_identity: CapabilityLevel,
    pub deterministic_probes: CapabilityLevel,
    pub notes: &'static str,
}

impl ProviderCapabilities {
    pub fn for_provider(provider: ProviderTarget) -> Self {
        match provider {
            ProviderTarget::Gemini => Self {
                provider: ProviderTarget::Gemini,
                persistent_instructions: CapabilityLevel::Supported,
                hierarchical_instructions: CapabilityLevel::Supported,
                skills: CapabilityLevel::Supported,
                custom_agent_roles: CapabilityLevel::Supported,
                tool_guards_pre_execution: CapabilityLevel::Supported,
                tool_arg_rewrite: CapabilityLevel::Supported,
                user_approval: CapabilityLevel::Supported,
                lifecycle_start: CapabilityLevel::Supported,
                lifecycle_end: CapabilityLevel::Supported,
                lifecycle_remediation_continuation: CapabilityLevel::Supported,
                lifecycle_structured_decision: CapabilityLevel::Partial,
                lifecycle_suspend: CapabilityLevel::Partial,
                lifecycle_reentry_identity: CapabilityLevel::Unsupported,
                deterministic_probes: CapabilityLevel::Supported,
                notes: "AGY runtime supports native PreToolUse deny/force_ask and terminal Stop.",
            },
            ProviderTarget::Codex => Self {
                provider: ProviderTarget::Codex,
                persistent_instructions: CapabilityLevel::Supported,
                hierarchical_instructions: CapabilityLevel::Supported,
                skills: CapabilityLevel::Supported,
                custom_agent_roles: CapabilityLevel::Supported,
                tool_guards_pre_execution: CapabilityLevel::Partial,
                tool_arg_rewrite: CapabilityLevel::Partial,
                user_approval: CapabilityLevel::Emulated,
                lifecycle_start: CapabilityLevel::Partial,
                lifecycle_end: CapabilityLevel::Partial,
                lifecycle_remediation_continuation: CapabilityLevel::Supported,
                lifecycle_structured_decision: CapabilityLevel::Partial,
                lifecycle_suspend: CapabilityLevel::Partial,
                lifecycle_reentry_identity: CapabilityLevel::Partial,
                deterministic_probes: CapabilityLevel::Partial,
                notes: "OpenAI Codex CLI hooks cover most local tools, but hosted/specialized paths may opt out. Codex Desktop enforcement is unverified.",
            },
            ProviderTarget::Claude => Self {
                provider: ProviderTarget::Claude,
                persistent_instructions: CapabilityLevel::Supported,
                hierarchical_instructions: CapabilityLevel::Partial,
                skills: CapabilityLevel::Unsupported,
                custom_agent_roles: CapabilityLevel::Partial,
                tool_guards_pre_execution: CapabilityLevel::Unsupported,
                tool_arg_rewrite: CapabilityLevel::Unsupported,
                user_approval: CapabilityLevel::Unsupported,
                lifecycle_start: CapabilityLevel::Unsupported,
                lifecycle_end: CapabilityLevel::Unsupported,
                lifecycle_remediation_continuation: CapabilityLevel::Unsupported,
                lifecycle_structured_decision: CapabilityLevel::Unsupported,
                lifecycle_suspend: CapabilityLevel::Unsupported,
                lifecycle_reentry_identity: CapabilityLevel::Unsupported,
                deterministic_probes: CapabilityLevel::Unsupported,
                notes: "Claude CLI / Desktop integration target (in development).",
            },
            ProviderTarget::OpenCode => Self {
                provider: ProviderTarget::OpenCode,
                persistent_instructions: CapabilityLevel::Supported,
                hierarchical_instructions: CapabilityLevel::Supported,
                skills: CapabilityLevel::Partial,
                custom_agent_roles: CapabilityLevel::Partial,
                tool_guards_pre_execution: CapabilityLevel::Partial,
                tool_arg_rewrite: CapabilityLevel::Partial,
                user_approval: CapabilityLevel::Partial,
                lifecycle_start: CapabilityLevel::Partial,
                lifecycle_end: CapabilityLevel::Partial,
                lifecycle_remediation_continuation: CapabilityLevel::Partial,
                lifecycle_structured_decision: CapabilityLevel::Unsupported,
                lifecycle_suspend: CapabilityLevel::Unsupported,
                lifecycle_reentry_identity: CapabilityLevel::Unsupported,
                deterministic_probes: CapabilityLevel::Partial,
                notes: "OpenCode target (in development).",
            },
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CoverageSurface {
    GeminiPreToolUse,
    GeminiPreToolUseWithArcEmbeddedUi,
    GeminiPreInvocation,
    GeminiStop,
    GeminiStopWithArcEmbeddedUi,
    CodexCliPreToolUse,
    CodexCliPreToolUseWithArcEmbeddedUi,
    CodexCliPreToolUseWithCodexAppServer,
    CodexCliPreToolUseWithDirectMcp,
    CodexCliSessionStart,
    CodexCliSessionStartWithArcEmbeddedUi,
    CodexCliStop,
    CodexCliStopWithArcEmbeddedUi,
    CodexCliStopWithCodexAppServer,
    CodexCliStopWithDirectMcp,
    NoVerifiedSurface,
}

impl std::fmt::Display for CoverageSurface {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let value = match self {
            Self::GeminiPreToolUse => "Gemini PreToolUse",
            Self::GeminiPreToolUseWithArcEmbeddedUi => "Gemini PreToolUse + Arc embedded UI",
            Self::GeminiPreInvocation => "Gemini PreInvocation",
            Self::GeminiStop => "Gemini Stop",
            Self::GeminiStopWithArcEmbeddedUi => "Gemini Stop + Arc embedded UI",
            Self::CodexCliPreToolUse => "Codex CLI PreToolUse",
            Self::CodexCliPreToolUseWithArcEmbeddedUi => "Codex CLI PreToolUse + Arc embedded UI",
            Self::CodexCliPreToolUseWithCodexAppServer => "Codex CLI PreToolUse + Codex App Server",
            Self::CodexCliPreToolUseWithDirectMcp => "Codex CLI PreToolUse + Direct MCP",
            Self::CodexCliSessionStart => "Codex CLI SessionStart",
            Self::CodexCliSessionStartWithArcEmbeddedUi => {
                "Codex CLI SessionStart + Arc embedded UI"
            }
            Self::CodexCliStop => "Codex CLI Stop",
            Self::CodexCliStopWithArcEmbeddedUi => "Codex CLI Stop + Arc embedded UI",
            Self::CodexCliStopWithCodexAppServer => "Codex CLI Stop + Codex App Server",
            Self::CodexCliStopWithDirectMcp => "Codex CLI Stop + Direct MCP",
            Self::NoVerifiedSurface => "No verified surface",
        };
        write!(f, "{value}")
    }
}

/// Returns the exact action contract for an ask transport on a concrete event.
/// Keeping this mapping next to capability resolution prevents the orchestrator
/// and generated capability reports from assigning a embedded UI action to another
/// transport by accident.
pub(crate) fn expected_ask_effective_action(
    provider: ProviderTarget,
    event: CapabilityEvent,
    transport: Option<DecisionTransport>,
) -> &'static str {
    match (provider, event, transport) {
        (
            ProviderTarget::Gemini,
            CapabilityEvent::ToolCall,
            Some(DecisionTransport::ProviderNative),
        ) => "decision_force_ask",
        (
            ProviderTarget::Gemini,
            CapabilityEvent::ToolCall,
            Some(DecisionTransport::ArcEmbeddedUi),
        )
        | (
            ProviderTarget::Codex,
            CapabilityEvent::ToolCall,
            Some(DecisionTransport::ArcEmbeddedUi),
        ) => "arc_embedded_ui_ask",
        (ProviderTarget::Gemini, CapabilityEvent::End, Some(DecisionTransport::ArcEmbeddedUi)) => {
            "continue_loop_with_arc_embedded_ui"
        }
        (ProviderTarget::Codex, CapabilityEvent::End, Some(DecisionTransport::ArcEmbeddedUi)) => {
            "decision_block_with_embedded_ui"
        }
        (
            ProviderTarget::Codex,
            CapabilityEvent::ToolCall,
            Some(DecisionTransport::CodexAppServer),
        ) => "codex_app_server_ask",
        (ProviderTarget::Codex, CapabilityEvent::End, Some(DecisionTransport::CodexAppServer)) => {
            "decision_block_with_codex_app_server"
        }
        (ProviderTarget::Codex, CapabilityEvent::ToolCall, Some(DecisionTransport::DirectMcp)) => {
            "direct_mcp_ask"
        }
        (ProviderTarget::Codex, CapabilityEvent::End, Some(DecisionTransport::DirectMcp)) => {
            "decision_block_with_direct_mcp"
        }
        (_, CapabilityEvent::Start, Some(_)) => "unsupported_ask",
        (_, CapabilityEvent::Start, None) => "unsupported_ask",
        (_, _, None) => "fail_closed_deny",
        (_, _, Some(DecisionTransport::ProviderNative)) => "unsupported_ask",
        (_, _, Some(DecisionTransport::ArcEmbeddedUi)) => "unsupported_ask",
        (_, _, Some(DecisionTransport::CodexAppServer | DecisionTransport::DirectMcp)) => {
            "unsupported_ask"
        }
    }
}

/// Every dimension that can change the real provider contract. Callers must
/// construct this context before reporting, emitting, or adapting a guard.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityContext {
    pub provider: ProviderTarget,
    pub environment: ProviderEnvironment,
    pub target_os: OsTarget,
    pub event: CapabilityEvent,
    pub requested_action: ActionType,
    pub decision_ui: DecisionUiMode,
    pub decision_environment: DecisionEnvironment,
}

impl CapabilityContext {
    pub fn cli(
        provider: ProviderTarget,
        target_os: OsTarget,
        event: CapabilityEvent,
        requested_action: ActionType,
        decision_ui: DecisionUiMode,
    ) -> Self {
        let decision_environment = match provider {
            ProviderTarget::Gemini => DecisionEnvironment {
                provider_native: true,
                arc_embedded_ui: true,
                arc_owns_app_server_session: false,
                direct_mcp_channel: false,
            },
            ProviderTarget::Codex => DecisionEnvironment::codex_hook_with_embedded_ui(),
            ProviderTarget::Claude | ProviderTarget::OpenCode => DecisionEnvironment {
                provider_native: false,
                arc_embedded_ui: false,
                arc_owns_app_server_session: false,
                direct_mcp_channel: false,
            },
        };
        Self {
            provider,
            environment: ProviderEnvironment::Cli,
            target_os,
            event,
            requested_action,
            decision_ui,
            decision_environment,
        }
    }

    pub fn desktop(
        provider: ProviderTarget,
        target_os: OsTarget,
        event: CapabilityEvent,
        requested_action: ActionType,
        decision_ui: DecisionUiMode,
    ) -> Self {
        Self {
            provider,
            environment: ProviderEnvironment::Desktop,
            target_os,
            event,
            requested_action,
            decision_ui,
            decision_environment: DecisionEnvironment {
                provider_native: false,
                arc_embedded_ui: false,
                arc_owns_app_server_session: false,
                direct_mcp_channel: false,
            },
        }
    }
}

/// Complete provider contract consumed unchanged by reports, emitters and
/// adapters. `decision_transport` is populated only for an enforceable ask.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityResolution {
    pub context: CapabilityContext,
    pub capability: CapabilityLevel,
    pub effective_action: String,
    pub guarantee: String,
    pub mechanism: String,
    pub decision_transport: Option<DecisionTransport>,
    pub coverage_surface: CoverageSurface,
}

pub fn resolve_capability(context: CapabilityContext) -> CapabilityResolution {
    if context.environment == ProviderEnvironment::Desktop {
        return resolution(
            context,
            CapabilityLevel::Unsupported,
            "unsupported",
            "None",
            "Provider desktop environment exposes no verified Arc hook surface",
            None,
            CoverageSurface::NoVerifiedSurface,
        );
    }

    let ask_transport = (context.requested_action == ActionType::Ask).then(|| {
        resolve_decision_transport_for(
            context.provider,
            context.event,
            context.decision_ui,
            &context.decision_environment,
        )
        .selected
    });
    let selected = ask_transport.flatten();

    match (context.provider, context.event, context.requested_action) {
        (ProviderTarget::Gemini, CapabilityEvent::ToolCall, ActionType::Deny) => resolution(
            context,
            CapabilityLevel::Supported,
            "decision_deny",
            "Preventive",
            "Native PreToolUse deny",
            None,
            CoverageSurface::GeminiPreToolUse,
        ),
        (ProviderTarget::Gemini, CapabilityEvent::ToolCall, ActionType::Message) => resolution(
            context,
            CapabilityLevel::Supported,
            "ephemeral_message",
            "Advisory",
            "PreToolUse reason/context",
            None,
            CoverageSurface::GeminiPreToolUse,
        ),
        (ProviderTarget::Gemini, CapabilityEvent::ToolCall, ActionType::Ask) => match selected {
            Some(DecisionTransport::ProviderNative) => resolution(
                context,
                CapabilityLevel::Supported,
                "decision_force_ask",
                "Interactive",
                "Native PreToolUse force_ask",
                selected,
                CoverageSurface::GeminiPreToolUse,
            ),
            Some(DecisionTransport::ArcEmbeddedUi) => resolution(
                context,
                CapabilityLevel::Emulated,
                "arc_embedded_ui_ask",
                "Interactive",
                "PreToolUse suspended by Arc embedded UI",
                selected,
                CoverageSurface::GeminiPreToolUseWithArcEmbeddedUi,
            ),
            _ => fail_closed_ask(context, selected, CoverageSurface::GeminiPreToolUse),
        },
        (ProviderTarget::Gemini, CapabilityEvent::Start, ActionType::Message) => resolution(
            context,
            CapabilityLevel::Supported,
            "ephemeral_message",
            "Advisory",
            "PreInvocation first-turn context injection",
            None,
            CoverageSurface::GeminiPreInvocation,
        ),
        (ProviderTarget::Gemini, CapabilityEvent::Start, ActionType::Deny) => resolution(
            context,
            CapabilityLevel::Unsupported,
            "unsupported_deny",
            "None",
            "PreInvocation does not support blocking",
            None,
            CoverageSurface::GeminiPreInvocation,
        ),
        (ProviderTarget::Gemini, CapabilityEvent::Start, ActionType::Ask) => resolution(
            context,
            CapabilityLevel::Unsupported,
            "unsupported_ask",
            "None",
            "PreInvocation cannot suspend for a structured decision",
            None,
            CoverageSurface::GeminiPreInvocation,
        ),
        (ProviderTarget::Gemini, CapabilityEvent::End, ActionType::Deny) => resolution(
            context,
            CapabilityLevel::Supported,
            "stop",
            "Preventive",
            "Native Stop terminal",
            None,
            CoverageSurface::GeminiStop,
        ),
        (ProviderTarget::Gemini, CapabilityEvent::End, ActionType::Message) => resolution(
            context,
            CapabilityLevel::Supported,
            "stop_with_feedback",
            "Advisory",
            "Stop reason",
            None,
            CoverageSurface::GeminiStop,
        ),
        (ProviderTarget::Gemini, CapabilityEvent::End, ActionType::Ask) => match selected {
            Some(DecisionTransport::ArcEmbeddedUi) => resolution(
                context,
                CapabilityLevel::Emulated,
                "continue_loop_with_arc_embedded_ui",
                "Interactive",
                "Stop hook coordinated with Arc embedded UI",
                selected,
                CoverageSurface::GeminiStopWithArcEmbeddedUi,
            ),
            _ => fail_closed_ask(context, selected, CoverageSurface::GeminiStop),
        },
        (ProviderTarget::Codex, CapabilityEvent::ToolCall, ActionType::Deny) => resolution(
            context,
            CapabilityLevel::Partial,
            "permission_decision_deny",
            "Preventive",
            "PreToolUse on covered Codex CLI tools",
            None,
            CoverageSurface::CodexCliPreToolUse,
        ),
        (ProviderTarget::Codex, CapabilityEvent::ToolCall, ActionType::Message) => resolution(
            context,
            CapabilityLevel::Partial,
            "additional_context",
            "Advisory",
            "PreToolUse additionalContext on covered Codex CLI tools",
            None,
            CoverageSurface::CodexCliPreToolUse,
        ),
        (ProviderTarget::Codex, CapabilityEvent::ToolCall, ActionType::Ask) => match selected {
            Some(DecisionTransport::ArcEmbeddedUi) => resolution(
                context,
                CapabilityLevel::Emulated,
                "arc_embedded_ui_ask",
                "Interactive",
                "Codex CLI PreToolUse suspended by Arc embedded UI",
                selected,
                CoverageSurface::CodexCliPreToolUseWithArcEmbeddedUi,
            ),
            Some(DecisionTransport::CodexAppServer) => resolution(
                context,
                CapabilityLevel::Emulated,
                "codex_app_server_ask",
                "Interactive",
                "Codex CLI PreToolUse suspended through an Arc-owned Codex App Server session",
                selected,
                CoverageSurface::CodexCliPreToolUseWithCodexAppServer,
            ),
            Some(DecisionTransport::DirectMcp) => resolution(
                context,
                CapabilityLevel::Emulated,
                "direct_mcp_ask",
                "Interactive",
                "Codex CLI PreToolUse suspended through an Arc-owned Direct MCP channel",
                selected,
                CoverageSurface::CodexCliPreToolUseWithDirectMcp,
            ),
            _ => fail_closed_ask(context, selected, CoverageSurface::CodexCliPreToolUse),
        },
        (ProviderTarget::Codex, CapabilityEvent::Start, ActionType::Deny) => resolution(
            context,
            CapabilityLevel::Partial,
            "continue_false",
            "Preventive",
            "SessionStart continue=false on Codex CLI",
            None,
            CoverageSurface::CodexCliSessionStart,
        ),
        (ProviderTarget::Codex, CapabilityEvent::Start, ActionType::Message) => resolution(
            context,
            CapabilityLevel::Partial,
            "additional_context",
            "Advisory",
            "SessionStart additionalContext on Codex CLI",
            None,
            CoverageSurface::CodexCliSessionStart,
        ),
        (ProviderTarget::Codex, CapabilityEvent::Start, ActionType::Ask) => resolution(
            context,
            CapabilityLevel::Unsupported,
            "unsupported_ask",
            "None",
            "Arc lifecycle start guards cannot use action ask",
            None,
            CoverageSurface::CodexCliSessionStart,
        ),
        (ProviderTarget::Codex, CapabilityEvent::End, ActionType::Deny) => resolution(
            context,
            CapabilityLevel::Partial,
            "decision_block",
            "Preventive",
            "Stop decision=block on Codex CLI",
            None,
            CoverageSurface::CodexCliStop,
        ),
        (ProviderTarget::Codex, CapabilityEvent::End, ActionType::Message) => resolution(
            context,
            CapabilityLevel::Partial,
            "system_message",
            "Advisory",
            "Stop systemMessage on Codex CLI",
            None,
            CoverageSurface::CodexCliStop,
        ),
        (ProviderTarget::Codex, CapabilityEvent::End, ActionType::Ask) => match selected {
            Some(DecisionTransport::ArcEmbeddedUi) => resolution(
                context,
                CapabilityLevel::Emulated,
                "decision_block_with_embedded_ui",
                "Interactive",
                "Stop coordinated with Arc embedded UI",
                selected,
                CoverageSurface::CodexCliStopWithArcEmbeddedUi,
            ),
            Some(DecisionTransport::CodexAppServer) => resolution(
                context,
                CapabilityLevel::Emulated,
                "decision_block_with_codex_app_server",
                "Interactive",
                "Stop coordinated through an Arc-owned Codex App Server session",
                selected,
                CoverageSurface::CodexCliStopWithCodexAppServer,
            ),
            Some(DecisionTransport::DirectMcp) => resolution(
                context,
                CapabilityLevel::Emulated,
                "decision_block_with_direct_mcp",
                "Interactive",
                "Stop coordinated through an Arc-owned Direct MCP channel",
                selected,
                CoverageSurface::CodexCliStopWithDirectMcp,
            ),
            _ => fail_closed_ask(context, selected, CoverageSurface::CodexCliStop),
        },
        _ => resolution(
            context,
            CapabilityLevel::Unsupported,
            "unsupported",
            "None",
            "No verified provider surface",
            None,
            CoverageSurface::NoVerifiedSurface,
        ),
    }
}

fn resolution(
    context: CapabilityContext,
    capability: CapabilityLevel,
    effective_action: &str,
    guarantee: &str,
    mechanism: &str,
    decision_transport: Option<DecisionTransport>,
    coverage_surface: CoverageSurface,
) -> CapabilityResolution {
    CapabilityResolution {
        context,
        capability,
        effective_action: effective_action.to_string(),
        guarantee: guarantee.to_string(),
        mechanism: mechanism.to_string(),
        decision_transport,
        coverage_surface,
    }
}

fn fail_closed_ask(
    context: CapabilityContext,
    selected: Option<DecisionTransport>,
    surface: CoverageSurface,
) -> CapabilityResolution {
    resolution(
        context,
        CapabilityLevel::Unsupported,
        "fail_closed_deny",
        "Preventive fallback",
        "No ask transport; protected operation is denied",
        selected,
        surface,
    )
}

/// A specific capability diagnostic issue encountered when evaluating a project against a provider.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityDiagnostic {
    pub guard_id: String,
    pub feature: String,
    pub reason: String,
    pub provider: ProviderTarget,
}

impl std::fmt::Display for CapabilityDiagnostic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "[{}] Guard '{}' requires '{}', which is unsupported by target '{}': {}",
            self.provider, self.guard_id, self.feature, self.provider, self.reason
        )
    }
}

/// Report entry describing effective capability, guarantee, and coverage per guard.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuardDegradationReport {
    pub provider: ProviderTarget,
    pub environment: ProviderEnvironment,
    pub target_os: OsTarget,
    pub guard_id: String,
    pub event: CapabilityEvent,
    pub requested_action: ActionType,
    pub decision_ui: DecisionUiMode,
    pub decision_transport: Option<DecisionTransport>,
    pub effective_action: String,
    pub capability: CapabilityLevel,
    pub guarantee: String,
    pub mechanism: String,
    pub coverage_surface: CoverageSurface,
}

/// Generates a detailed degradation report for all guards against a provider (H9).
pub fn generate_degradation_report(
    project: &LoadedArcProject,
    provider: ProviderTarget,
) -> Vec<GuardDegradationReport> {
    generate_degradation_report_for_target(
        project,
        provider,
        ProviderEnvironment::Cli,
        OsTarget::host().expect("Arc only runs on a supported host OS"),
        DecisionUiMode::Auto,
        default_decision_environment(provider),
    )
}

/// Generates a report for the concrete environment selected by a build,
/// which may be a host OS or an explicit multi-OS target list (H9).
pub fn generate_degradation_report_for_environment(
    project: &LoadedArcProject,
    provider: ProviderTarget,
    environment: &str,
) -> Vec<GuardDegradationReport> {
    let provider_environment = if environment.trim().eq_ignore_ascii_case("desktop") {
        ProviderEnvironment::Desktop
    } else {
        ProviderEnvironment::Cli
    };
    let target_os = [OsTarget::WINDOWS, OsTarget::LINUX, OsTarget::MACOS]
        .into_iter()
        .find(|candidate| environment.to_ascii_lowercase().contains(candidate))
        .and_then(|candidate| OsTarget::new(candidate).ok())
        .unwrap_or_else(|| OsTarget::host().expect("Arc only runs on a supported host OS"));
    let decision_environment = if provider_environment == ProviderEnvironment::Desktop {
        DecisionEnvironment {
            provider_native: false,
            arc_embedded_ui: false,
            arc_owns_app_server_session: false,
            direct_mcp_channel: false,
        }
    } else {
        default_decision_environment(provider)
    };
    generate_degradation_report_for_target(
        project,
        provider,
        provider_environment,
        target_os,
        DecisionUiMode::Auto,
        decision_environment,
    )
}

pub fn generate_degradation_report_for_target(
    project: &LoadedArcProject,
    provider: ProviderTarget,
    environment: ProviderEnvironment,
    target_os: OsTarget,
    decision_ui: DecisionUiMode,
    decision_environment: DecisionEnvironment,
) -> Vec<GuardDegradationReport> {
    let mut reports = Vec::new();

    // 1. Lifecycle guards
    for (guard_id, guard) in &project.guards.lifecycle {
        for trigger in guard.trigger.to_vec() {
            let event = match trigger {
                LifecycleTrigger::Start => CapabilityEvent::Start,
                LifecycleTrigger::End => CapabilityEvent::End,
            };

            let resolution = resolve_capability(CapabilityContext {
                provider,
                environment,
                target_os: target_os.clone(),
                event,
                requested_action: guard.on_failure.action,
                decision_ui,
                decision_environment: decision_environment.clone(),
            });

            reports.push(GuardDegradationReport {
                provider,
                environment,
                target_os: target_os.clone(),
                guard_id: guard_id.clone(),
                event,
                requested_action: guard.on_failure.action,
                decision_ui,
                decision_transport: resolution.decision_transport,
                effective_action: resolution.effective_action,
                capability: resolution.capability,
                guarantee: resolution.guarantee,
                mechanism: resolution.mechanism,
                coverage_surface: resolution.coverage_surface,
            });
        }
    }

    // 2. Tool guards
    for (guard_id, guard) in &project.guards.tools {
        let resolution = resolve_capability(CapabilityContext {
            provider,
            environment,
            target_os: target_os.clone(),
            event: CapabilityEvent::ToolCall,
            requested_action: guard.on_failure.action,
            decision_ui,
            decision_environment: decision_environment.clone(),
        });

        reports.push(GuardDegradationReport {
            provider,
            environment,
            target_os: target_os.clone(),
            guard_id: guard_id.clone(),
            event: CapabilityEvent::ToolCall,
            requested_action: guard.on_failure.action,
            decision_ui,
            decision_transport: resolution.decision_transport,
            effective_action: resolution.effective_action,
            capability: resolution.capability,
            guarantee: resolution.guarantee,
            mechanism: resolution.mechanism,
            coverage_surface: resolution.coverage_surface,
        });
    }

    reports
}

/// Generates one ordered degradation-report segment for each requested OS.
///
/// The result preserves the caller's OS order and includes one row per
/// `(Guard event, target OS)` pair. An empty OS slice produces an empty report.
pub fn generate_degradation_report_for_targets(
    project: &LoadedArcProject,
    provider: ProviderTarget,
    environment: ProviderEnvironment,
    target_oses: &[OsTarget],
    decision_ui: DecisionUiMode,
    decision_environment: DecisionEnvironment,
) -> Vec<GuardDegradationReport> {
    let mut reports = Vec::new();
    for target_os in target_oses {
        reports.extend(generate_degradation_report_for_target(
            project,
            provider,
            environment,
            target_os.clone(),
            decision_ui,
            decision_environment.clone(),
        ));
    }
    reports
}

fn default_decision_environment(provider: ProviderTarget) -> DecisionEnvironment {
    match provider {
        ProviderTarget::Gemini => DecisionEnvironment {
            provider_native: true,
            arc_embedded_ui: true,
            arc_owns_app_server_session: false,
            direct_mcp_channel: false,
        },
        ProviderTarget::Codex => DecisionEnvironment::codex_hook_with_embedded_ui(),
        ProviderTarget::Claude | ProviderTarget::OpenCode => DecisionEnvironment {
            provider_native: false,
            arc_embedded_ui: false,
            arc_owns_app_server_session: false,
            direct_mcp_channel: false,
        },
    }
}

/// Validates whether a loaded project is compatible with the given target provider.
pub fn check_project_compatibility(
    project: &LoadedArcProject,
    provider: ProviderTarget,
) -> Vec<CapabilityDiagnostic> {
    generate_degradation_report(project, provider)
        .into_iter()
        .filter(|row| row.capability == CapabilityLevel::Unsupported)
        .map(|row| CapabilityDiagnostic {
            guard_id: row.guard_id,
            feature: format!(
                "event: {} with action: {} in {}",
                row.event, row.requested_action, row.environment
            ),
            reason: row.mechanism,
            provider,
        })
        .collect()
}

/// Generates a formatted ASCII capability matrix for the selected providers.
pub fn generate_capabilities_table(providers: &[ProviderTarget]) -> String {
    type CapabilityGetter = fn(&ProviderCapabilities) -> CapabilityLevel;

    const ROWS: &[(&str, CapabilityGetter)] = &[
        ("Persistent Instructions", |caps| {
            caps.persistent_instructions
        }),
        ("Hierarchical Instructions", |caps| {
            caps.hierarchical_instructions
        }),
        ("Modular Skills", |caps| caps.skills),
        ("Custom Agent Roles", |caps| caps.custom_agent_roles),
        ("PreToolUse (Tool Guards)", |caps| {
            caps.tool_guards_pre_execution
        }),
        ("Tool Argument Rewrite", |caps| caps.tool_arg_rewrite),
        ("User Approval Dialog", |caps| caps.user_approval),
        ("Lifecycle: Start", |caps| caps.lifecycle_start),
        ("Lifecycle: End", |caps| caps.lifecycle_end),
        ("Lifecycle: Remediation", |caps| {
            caps.lifecycle_remediation_continuation
        }),
        ("Lifecycle: Decision Receipt", |caps| {
            caps.lifecycle_structured_decision
        }),
        ("Lifecycle: Suspend", |caps| caps.lifecycle_suspend),
        ("Lifecycle: Re-entry ID", |caps| {
            caps.lifecycle_reentry_identity
        }),
        ("Deterministic Probes", |caps| caps.deterministic_probes),
    ];

    let capabilities: Vec<_> = providers
        .iter()
        .copied()
        .map(ProviderCapabilities::for_provider)
        .collect();
    let table_width = 28 + (15 * capabilities.len());
    let mut out = String::new();
    out.push_str("ARC Provider Capability Matrix:\n");
    out.push_str(&format!("{}\n", "=".repeat(table_width)));
    out.push_str(&format!("{:<28}", "Capability"));
    for capability in &capabilities {
        let label = match capability.provider {
            ProviderTarget::Gemini => "Gemini (AGY)".to_string(),
            ProviderTarget::Codex => "Codex".to_string(),
            ProviderTarget::Claude => "Claude".to_string(),
            ProviderTarget::OpenCode => "OpenCode".to_string(),
        };
        out.push_str(&format!(" | {label:<12}"));
    }
    out.push('\n');
    out.push_str(&format!("{}\n", "-".repeat(table_width)));

    for (label, get_capability) in ROWS {
        out.push_str(&format!("{label:<28}"));
        for capability in &capabilities {
            out.push_str(&format!(" | {:<12}", get_capability(capability)));
        }
        out.push('\n');
    }
    out
}

/// Formats a degradation report as a clean table string (H9).
pub fn format_degradation_table(
    reports: &[GuardDegradationReport],
    provider: ProviderTarget,
) -> String {
    if reports.is_empty() {
        return format!("No guards configured for provider '{}'.\n", provider);
    }
    let mut out = String::new();
    out.push_str(&format!(
        "\nGuard Degradation & Capability Report for '{}':\n",
        provider
    ));
    out.push_str("----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------\n");
    out.push_str(&format!(
        "{:<20} | {:<8} | {:<8} | {:<10} | {:<10} | {:<9} | {:<18} | {:<20} | {:<12} | {:<18} | {:<25} | {:<30}\n",
        "Guard ID",
        "Environment",
        "Target OS",
        "Event",
        "Action",
        "UI",
        "Transport",
        "Effective",
        "Capability",
        "Guarantee",
        "Mechanism",
        "Coverage Surface"
    ));
    out.push_str("----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------\n");
    for r in reports {
        let transport = r
            .decision_transport
            .map(|value| format!("{value:?}"))
            .unwrap_or_else(|| "none".to_string());
        out.push_str(&format!(
            "{:<20} | {:<8} | {:<8} | {:<10} | {:<10} | {:<9} | {:<18} | {:<20} | {:<12} | {:<18} | {:<25} | {:<30}\n",
            r.guard_id,
            r.environment,
            r.target_os,
            r.event,
            r.requested_action,
            r.decision_ui,
            transport,
            r.effective_action,
            format!("{}", r.capability),
            r.guarantee,
            r.mechanism,
            r.coverage_surface
        ));
    }
    out.push_str("----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::schema::*;
    use std::collections::BTreeMap;

    #[test]
    fn codex_lifecycle_is_partial_because_desktop_is_not_a_verified_hook_surface() {
        let capabilities = ProviderCapabilities::for_provider(ProviderTarget::Codex);

        assert_eq!(capabilities.lifecycle_start, CapabilityLevel::Partial);
        assert_eq!(capabilities.lifecycle_end, CapabilityLevel::Partial);
        assert_eq!(
            capabilities.lifecycle_structured_decision,
            CapabilityLevel::Partial
        );
        assert_eq!(
            capabilities.lifecycle_reentry_identity,
            CapabilityLevel::Partial
        );
        assert!(capabilities.notes.contains("Codex Desktop"));
    }

    #[test]
    fn test_gemini_start_deny_rejection() {
        let mut lifecycle = BTreeMap::new();
        lifecycle.insert(
            "check_start".to_string(),
            LifecycleGuardConfig {
                trigger: TriggerSelector::Single(LifecycleTrigger::Start),
                require: RuleExpression::Decide {
                    decide: DecideConfig {
                        prompt: "ok?".into(),
                    },
                },
                on_failure: OnFailureConfig {
                    action: ActionType::Deny,
                    feedback: None,
                },
                order: None,
                declaration_order: 0,
            },
        );

        let project = LoadedArcProject {
            manifest_path: std::path::PathBuf::from("arc.yaml"),
            manifest: ArcManifest {
                schema: "1.0".into(),
                root: RootConfig {
                    workdir: std::path::PathBuf::from("."),
                    instructions: None,
                },
                runtime: Default::default(),
                modules: None,
                skills: None,
                roles: None,
                guards: None,
            },
            workdir: std::path::PathBuf::from("."),
            instructions_path: None,
            instructions_content: None,
            skills: BTreeMap::new(),
            roles: BTreeMap::new(),
            role_sources: BTreeMap::new(),
            guards: GuardsConfig {
                lifecycle,
                tools: BTreeMap::new(),
            },
            rules: None,
            aliases: None,
        };

        let gemini_diagnostics = check_project_compatibility(&project, ProviderTarget::Gemini);
        assert_eq!(gemini_diagnostics.len(), 1);
        assert!(
            gemini_diagnostics[0]
                .reason
                .contains("does not support blocking")
        );

        let degradation = generate_degradation_report(&project, ProviderTarget::Gemini);
        assert_eq!(degradation.len(), 1);
        assert_eq!(degradation[0].capability, CapabilityLevel::Unsupported);
        assert_eq!(degradation[0].provider, ProviderTarget::Gemini);
        assert_eq!(degradation[0].environment, ProviderEnvironment::Cli);
        assert_eq!(degradation[0].target_os, OsTarget::host().unwrap());
        let targeted = generate_degradation_report_for_environment(
            &project,
            ProviderTarget::Gemini,
            "windows,linux",
        );
        assert_eq!(targeted[0].environment, ProviderEnvironment::Cli);
        assert_eq!(targeted[0].target_os.as_str(), "windows");

        let matrix = generate_degradation_report_for_targets(
            &project,
            ProviderTarget::Gemini,
            ProviderEnvironment::Cli,
            &[
                OsTarget::new(OsTarget::WINDOWS).unwrap(),
                OsTarget::new(OsTarget::LINUX).unwrap(),
                OsTarget::new(OsTarget::MACOS).unwrap(),
            ],
            DecisionUiMode::Auto,
            default_decision_environment(ProviderTarget::Gemini),
        );
        assert_eq!(
            matrix
                .iter()
                .map(|report| report.target_os.as_str())
                .collect::<Vec<_>>(),
            ["windows", "linux", "macos"]
        );
    }

    #[test]
    fn capability_context_resolves_required_provider_event_transport_cases() {
        let windows = OsTarget::new("windows").unwrap();
        let gemini_ask = resolve_capability(CapabilityContext::cli(
            ProviderTarget::Gemini,
            windows.clone(),
            CapabilityEvent::ToolCall,
            ActionType::Ask,
            DecisionUiMode::Auto,
        ));
        assert_eq!(gemini_ask.capability, CapabilityLevel::Emulated);
        assert_eq!(
            gemini_ask.decision_transport,
            Some(DecisionTransport::ArcEmbeddedUi)
        );
        assert_eq!(gemini_ask.effective_action, "arc_embedded_ui_ask");

        let gemini_end_deny = resolve_capability(CapabilityContext::cli(
            ProviderTarget::Gemini,
            windows.clone(),
            CapabilityEvent::End,
            ActionType::Deny,
            DecisionUiMode::Auto,
        ));
        assert_eq!(gemini_end_deny.capability, CapabilityLevel::Supported);
        assert_eq!(gemini_end_deny.effective_action, "stop");
        assert_eq!(gemini_end_deny.decision_transport, None);

        let gemini_start_deny = resolve_capability(CapabilityContext::cli(
            ProviderTarget::Gemini,
            windows.clone(),
            CapabilityEvent::Start,
            ActionType::Deny,
            DecisionUiMode::Auto,
        ));
        assert_eq!(gemini_start_deny.capability, CapabilityLevel::Unsupported);

        for provider in [ProviderTarget::Gemini, ProviderTarget::Codex] {
            let start_ask = resolve_capability(CapabilityContext::cli(
                provider,
                windows.clone(),
                CapabilityEvent::Start,
                ActionType::Ask,
                DecisionUiMode::Auto,
            ));
            assert_eq!(start_ask.capability, CapabilityLevel::Unsupported);
            assert_eq!(start_ask.decision_transport, None);
        }

        let codex_native = resolve_capability(CapabilityContext::cli(
            ProviderTarget::Codex,
            windows.clone(),
            CapabilityEvent::ToolCall,
            ActionType::Ask,
            DecisionUiMode::Native,
        ));
        assert_eq!(codex_native.capability, CapabilityLevel::Emulated);
        assert_eq!(
            codex_native.decision_transport,
            Some(DecisionTransport::ArcEmbeddedUi)
        );

        let mut codex_without_transport_context = CapabilityContext::cli(
            ProviderTarget::Codex,
            windows.clone(),
            CapabilityEvent::ToolCall,
            ActionType::Ask,
            DecisionUiMode::Auto,
        );
        codex_without_transport_context.decision_environment = DecisionEnvironment {
            provider_native: false,
            arc_embedded_ui: false,
            arc_owns_app_server_session: false,
            direct_mcp_channel: false,
        };
        let codex_without_transport = resolve_capability(codex_without_transport_context);
        assert_eq!(
            codex_without_transport.capability,
            CapabilityLevel::Unsupported
        );
        assert_eq!(codex_without_transport.effective_action, "fail_closed_deny");

        let codex_deny = resolve_capability(CapabilityContext::cli(
            ProviderTarget::Codex,
            windows.clone(),
            CapabilityEvent::ToolCall,
            ActionType::Deny,
            DecisionUiMode::Auto,
        ));
        assert_eq!(codex_deny.capability, CapabilityLevel::Partial);

        let codex_desktop = resolve_capability(CapabilityContext::desktop(
            ProviderTarget::Codex,
            windows,
            CapabilityEvent::ToolCall,
            ActionType::Deny,
            DecisionUiMode::Auto,
        ));
        assert_eq!(codex_desktop.capability, CapabilityLevel::Unsupported);
    }

    #[test]
    fn complete_resolution_keeps_capability_and_surface_together() {
        let cases = [
            (
                ProviderTarget::Gemini,
                CapabilityEvent::Start,
                ActionType::Message,
            ),
            (
                ProviderTarget::Gemini,
                CapabilityEvent::Start,
                ActionType::Deny,
            ),
            (
                ProviderTarget::Gemini,
                CapabilityEvent::End,
                ActionType::Ask,
            ),
            (
                ProviderTarget::Gemini,
                CapabilityEvent::ToolCall,
                ActionType::Ask,
            ),
            (
                ProviderTarget::Codex,
                CapabilityEvent::Start,
                ActionType::Ask,
            ),
            (
                ProviderTarget::Codex,
                CapabilityEvent::End,
                ActionType::Deny,
            ),
            (
                ProviderTarget::Codex,
                CapabilityEvent::ToolCall,
                ActionType::Message,
            ),
        ];

        for (provider, event, action) in cases {
            let resolution = resolve_capability(CapabilityContext::cli(
                provider,
                OsTarget::new("linux").unwrap(),
                event,
                action,
                DecisionUiMode::Auto,
            ));
            assert_eq!(resolution.context.provider, provider);
            assert_eq!(resolution.context.event, event);
            assert_eq!(resolution.context.requested_action, action);
            assert!(!resolution.effective_action.is_empty());
            assert!(!resolution.mechanism.is_empty());
            assert_ne!(resolution.coverage_surface.to_string(), "");
        }
    }

    #[test]
    fn codex_alternative_ask_transports_keep_distinct_actions_and_surfaces() {
        let cases = [
            (
                CapabilityEvent::ToolCall,
                true,
                false,
                DecisionTransport::CodexAppServer,
                "codex_app_server_ask",
                CoverageSurface::CodexCliPreToolUseWithCodexAppServer,
                "App Server",
            ),
            (
                CapabilityEvent::End,
                true,
                false,
                DecisionTransport::CodexAppServer,
                "decision_block_with_codex_app_server",
                CoverageSurface::CodexCliStopWithCodexAppServer,
                "App Server",
            ),
            (
                CapabilityEvent::ToolCall,
                false,
                true,
                DecisionTransport::DirectMcp,
                "direct_mcp_ask",
                CoverageSurface::CodexCliPreToolUseWithDirectMcp,
                "Direct MCP",
            ),
            (
                CapabilityEvent::End,
                false,
                true,
                DecisionTransport::DirectMcp,
                "decision_block_with_direct_mcp",
                CoverageSurface::CodexCliStopWithDirectMcp,
                "Direct MCP",
            ),
        ];

        for (event, app_server, direct_mcp, transport, action, surface, mechanism) in cases {
            let mut context = CapabilityContext::cli(
                ProviderTarget::Codex,
                OsTarget::new("windows").expect("supported target"),
                event,
                ActionType::Ask,
                DecisionUiMode::Auto,
            );
            context.decision_environment = DecisionEnvironment {
                provider_native: false,
                arc_embedded_ui: false,
                arc_owns_app_server_session: app_server,
                direct_mcp_channel: direct_mcp,
            };
            let resolution = resolve_capability(context);
            assert_eq!(resolution.decision_transport, Some(transport));
            assert_eq!(resolution.effective_action, action);
            assert_eq!(resolution.coverage_surface, surface);
            assert!(resolution.mechanism.contains(mechanism));
        }
    }
}
