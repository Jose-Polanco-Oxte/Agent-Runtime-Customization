use super::ProviderTarget;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderEnvironment {
    Cli,
    Desktop,
}

impl std::fmt::Display for ProviderEnvironment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Cli => write!(f, "cli"),
            Self::Desktop => write!(f, "desktop"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityEvent {
    Start,
    End,
    ToolCall,
}

impl std::fmt::Display for CapabilityEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Start => write!(f, "start"),
            Self::End => write!(f, "end"),
            Self::ToolCall => write!(f, "tool_call"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DecisionUiMode {
    Auto,
    Native,
    Provider,
}

impl std::fmt::Display for DecisionUiMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Auto => write!(f, "auto"),
            Self::Native => write!(f, "native"),
            Self::Provider => write!(f, "provider"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DecisionTransport {
    ProviderNative,
    #[serde(rename = "arc_embedded_ui")]
    ArcEmbeddedUi,
    CodexAppServer,
    DirectMcp,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecisionEnvironment {
    pub provider_native: bool,
    #[serde(rename = "arc_embedded_ui")]
    pub arc_embedded_ui: bool,
    pub arc_owns_app_server_session: bool,
    pub direct_mcp_channel: bool,
}

impl DecisionEnvironment {
    pub fn hook_with_embedded_ui() -> Self {
        Self {
            provider_native: false,
            arc_embedded_ui: true,
            arc_owns_app_server_session: false,
            direct_mcp_channel: false,
        }
    }

    pub fn codex_hook_with_embedded_ui() -> Self {
        Self::hook_with_embedded_ui()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransportResolution {
    pub selected: Option<DecisionTransport>,
    pub considered: Vec<DecisionTransport>,
    pub compatibility_message: Option<String>,
}

/// Resolves only transports that can suspend and resume the current operation.
/// Presentation failures after selection are terminal: they must not cascade to
/// a second prompt, because a user selection may already have occurred.
pub fn resolve_decision_transport(
    provider: ProviderTarget,
    environment: &DecisionEnvironment,
) -> TransportResolution {
    resolve_decision_transport_for(
        provider,
        CapabilityEvent::ToolCall,
        DecisionUiMode::Auto,
        environment,
    )
}

/// Resolves the transport for one concrete provider event and UI preference.
/// Provider-native ask is deliberately event-specific: AGY exposes it only on
/// PreToolUse, while Codex hooks cannot open a native decision dialog.
pub fn resolve_decision_transport_for(
    provider: ProviderTarget,
    event: CapabilityEvent,
    mode: DecisionUiMode,
    environment: &DecisionEnvironment,
) -> TransportResolution {
    let automatic_candidates = match provider {
        ProviderTarget::Gemini => vec![
            DecisionTransport::ArcEmbeddedUi,
            DecisionTransport::ProviderNative,
        ],
        ProviderTarget::Codex => vec![
            DecisionTransport::ProviderNative,
            DecisionTransport::ArcEmbeddedUi,
            DecisionTransport::CodexAppServer,
            DecisionTransport::DirectMcp,
        ],
        _ => vec![DecisionTransport::ProviderNative],
    };

    let candidates = match mode {
        DecisionUiMode::Auto => automatic_candidates,
        DecisionUiMode::Native => vec![DecisionTransport::ArcEmbeddedUi],
        DecisionUiMode::Provider => vec![DecisionTransport::ProviderNative],
    };

    let selected = candidates
        .iter()
        .copied()
        .find(|candidate| match candidate {
            DecisionTransport::ProviderNative => {
                environment.provider_native
                    && provider == ProviderTarget::Gemini
                    && event == CapabilityEvent::ToolCall
            }
            DecisionTransport::ArcEmbeddedUi => environment.arc_embedded_ui,
            DecisionTransport::CodexAppServer => environment.arc_owns_app_server_session,
            DecisionTransport::DirectMcp => environment.direct_mcp_channel,
        });

    TransportResolution {
        selected,
        considered: candidates,
        compatibility_message: selected.is_none().then(|| {
            format!(
                "No deterministic ask transport is available for provider '{}'; the protected operation was denied.",
                provider
            )
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn antigravity_can_use_native_but_never_codex_specific_fallbacks() {
        let resolution = resolve_decision_transport(
            ProviderTarget::Gemini,
            &DecisionEnvironment {
                provider_native: false,
                arc_embedded_ui: true,
                arc_owns_app_server_session: true,
                direct_mcp_channel: true,
            },
        );
        assert_eq!(resolution.selected, Some(DecisionTransport::ArcEmbeddedUi));
        assert_eq!(
            resolution.considered,
            vec![
                DecisionTransport::ArcEmbeddedUi,
                DecisionTransport::ProviderNative,
            ]
        );
    }

    #[test]
    fn codex_hook_uses_deterministic_native_emulation() {
        let resolution = resolve_decision_transport(
            ProviderTarget::Codex,
            &DecisionEnvironment::hook_with_embedded_ui(),
        );
        assert_eq!(resolution.selected, Some(DecisionTransport::ArcEmbeddedUi));
    }

    #[test]
    fn app_server_requires_session_ownership() {
        let mut environment = DecisionEnvironment::codex_hook_with_embedded_ui();
        environment.arc_embedded_ui = false;
        assert_eq!(
            resolve_decision_transport(ProviderTarget::Codex, &environment).selected,
            None
        );
        environment.arc_owns_app_server_session = true;
        assert_eq!(
            resolve_decision_transport(ProviderTarget::Codex, &environment).selected,
            Some(DecisionTransport::CodexAppServer)
        );
    }

    #[test]
    fn embedded_ui_symbols_emit_neutral_wire_contract_and_reject_legacy_values() {
        assert_eq!(
            serde_json::to_value(DecisionTransport::ArcEmbeddedUi)
                .expect("transport should serialize"),
            serde_json::json!("arc_embedded_ui")
        );
        assert_eq!(
            serde_json::to_value(DecisionEnvironment::hook_with_embedded_ui())
                .expect("environment should serialize"),
            serde_json::json!({
                "provider_native": false,
                "arc_embedded_ui": true,
                "arc_owns_app_server_session": false,
                "direct_mcp_channel": false
            })
        );
        assert!(
            serde_json::from_value::<DecisionTransport>(serde_json::json!(
                ["arc", "native", "egui"].join("_")
            ))
            .is_err()
        );
        assert!(
            serde_json::from_value::<DecisionEnvironment>(serde_json::json!({
                "provider_native": false,
                ["arc", "native", "egui"].join("_"): true,
                "arc_owns_app_server_session": false,
                "direct_mcp_channel": false
            }))
            .is_err()
        );
    }
}
