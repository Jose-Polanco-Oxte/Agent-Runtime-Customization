use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GuardActivation {
    SessionStart,
    ToolCall,
    SessionStop,
    SubagentStop,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct GuardExecutionKey {
    pub workspace_id: String,
    pub session_id: String,
    pub turn_id: Option<String>,
    pub guard_id: String,
    pub activation: GuardActivation,
    pub subject_id: Option<String>,
}

impl GuardExecutionKey {
    pub fn storage_key(&self) -> String {
        // JSON is canonical for this struct because field order is fixed and it
        // contains no maps. Keeping the full key also makes collisions impossible.
        serde_json::to_string(self).expect("GuardExecutionKey must be serializable")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReentryKind {
    FirstInvocation,
    ContinuedByHook,
    RetriedByProvider,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderSignals {
    pub reentry: ReentryKind,
    pub native_invocation_id: Option<String>,
    pub native_interaction_id: Option<String>,
}

impl Default for ProviderSignals {
    fn default() -> Self {
        Self {
            reentry: ReentryKind::Unknown,
            native_invocation_id: None,
            native_interaction_id: None,
        }
    }
}
