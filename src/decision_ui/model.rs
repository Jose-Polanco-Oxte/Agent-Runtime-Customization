use serde::{Deserialize, Serialize};

/// Stable, renderer-neutral wire token for Arc's owned decision UI transport.
///
/// This is the only accepted label.
pub const ARC_EMBEDDED_UI_TRANSPORT_LABEL: &str = "arc_embedded_ui";
pub const MAX_DECISION_HOST_INPUT_BYTES: usize = 64 * 1024;
pub const MAX_DECISION_HOST_OUTPUT_BYTES: usize = 64 * 1024;
pub const MAX_DIALOG_USER_MESSAGE_CHARS: usize = 4_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnresolvedReason {
    Closed,
    TimedOut,
    TransportFailed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", content = "reason", rename_all = "snake_case")]
pub enum PortableDecision {
    Allow,
    Deny,
    Unresolved(UnresolvedReason),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UiTheme {
    Light,
    Dark,
}

impl UiTheme {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Light => "light",
            Self::Dark => "dark",
        }
    }
}

impl std::fmt::Display for UiTheme {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decision_wire_format_distinguishes_allow_deny_and_unresolved() {
        assert_eq!(
            serde_json::to_value(PortableDecision::Allow).expect("allow serializes"),
            serde_json::json!({"status": "allow"})
        );
        assert_eq!(
            serde_json::to_value(PortableDecision::Deny).expect("deny serializes"),
            serde_json::json!({"status": "deny"})
        );
        assert_eq!(
            serde_json::to_value(PortableDecision::Unresolved(UnresolvedReason::TimedOut))
                .expect("unresolved serializes"),
            serde_json::json!({"status": "unresolved", "reason": "timed_out"})
        );
    }

    #[test]
    fn theme_has_only_typed_system_values() {
        assert_eq!(UiTheme::Light.as_str(), "light");
        assert_eq!(UiTheme::Dark.to_string(), "dark");
        assert_eq!(ARC_EMBEDDED_UI_TRANSPORT_LABEL, "arc_embedded_ui");
    }
}
