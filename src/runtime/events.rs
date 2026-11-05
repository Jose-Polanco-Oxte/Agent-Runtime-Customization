use serde::{Deserialize, Serialize};
use std::fmt;
use std::path::PathBuf;

use crate::manifest::schema::LifecycleTrigger;
use crate::target::ProviderTarget;

/// Normalized runtime event types in Arc Runtime Architecture v2.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArcEventType {
    Start,
    End,
    ToolCall,
}

impl ArcEventType {
    /// Attempts to convert an ArcEventType to a LifecycleTrigger.
    pub fn to_lifecycle_trigger(&self) -> Option<LifecycleTrigger> {
        match self {
            Self::Start => Some(LifecycleTrigger::Start),
            Self::End => Some(LifecycleTrigger::End),
            Self::ToolCall => None,
        }
    }
}

impl fmt::Display for ArcEventType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Start => write!(f, "start"),
            Self::End => write!(f, "end"),
            Self::ToolCall => write!(f, "tool_call"),
        }
    }
}

/// Result of normalizing tool arguments across provider models and tool types (H1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum ToolArgumentExtraction {
    /// Command execution tool with an unambiguously extracted command string.
    Command { command: String },
    /// Non-command tool without command execution semantics (e.g. read_file, file_search).
    NonCommand,
    /// Command tool (or command inspection requested) where arguments are malformed, ambiguous, or unrecognized.
    MalformedOrUnrecognized {
        raw: serde_json::Value,
        reason: String,
    },
}

impl Default for ToolArgumentExtraction {
    fn default() -> Self {
        Self::NonCommand
    }
}

/// Normalized payload of an Arc event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ArcEventPayload {
    Empty,
    ToolCall {
        tool: String,
        input: serde_json::Value,
        command_text: Option<String>,
        #[serde(default)]
        argument_extraction: ToolArgumentExtraction,
    },
}

impl Default for ArcEventPayload {
    fn default() -> Self {
        Self::Empty
    }
}

/// Normalized logical event envelope received by Arc Runtime from a provider adapter.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArcEvent {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<ProviderTarget>,
    pub session_id: String,
    pub event_id: String,
    #[serde(rename = "type")]
    pub event_type: ArcEventType,
    pub sequence: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub correlation_id: Option<String>,
    /// Optional transcript path delivered by the provider. When present, the
    /// runtime validates this exact file before falling back to local discovery.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transcript_path: Option<PathBuf>,
    #[serde(default)]
    pub payload: ArcEventPayload,
}

impl ArcEvent {
    pub fn new(
        session_id: impl Into<String>,
        event_id: impl Into<String>,
        event_type: ArcEventType,
        sequence: u64,
        payload: ArcEventPayload,
    ) -> Self {
        Self {
            provider: None,
            session_id: session_id.into(),
            event_id: event_id.into(),
            event_type,
            sequence,
            correlation_id: None,
            transcript_path: None,
            payload,
        }
    }

    pub fn tool_call(
        session_id: impl Into<String>,
        event_id: impl Into<String>,
        sequence: u64,
        tool: impl Into<String>,
        command_text: impl Into<String>,
    ) -> Self {
        let cmd = command_text.into();
        Self {
            provider: None,
            session_id: session_id.into(),
            event_id: event_id.into(),
            event_type: ArcEventType::ToolCall,
            sequence,
            correlation_id: None,
            transcript_path: None,
            payload: ArcEventPayload::ToolCall {
                tool: tool.into(),
                input: serde_json::json!({ "command": &cmd }),
                command_text: Some(cmd.clone()),
                argument_extraction: ToolArgumentExtraction::Command { command: cmd },
            },
        }
    }

    pub fn non_command_tool_call(
        session_id: impl Into<String>,
        event_id: impl Into<String>,
        sequence: u64,
        tool: impl Into<String>,
        input: serde_json::Value,
    ) -> Self {
        Self {
            provider: None,
            session_id: session_id.into(),
            event_id: event_id.into(),
            event_type: ArcEventType::ToolCall,
            sequence,
            correlation_id: None,
            transcript_path: None,
            payload: ArcEventPayload::ToolCall {
                tool: tool.into(),
                input,
                command_text: None,
                argument_extraction: ToolArgumentExtraction::NonCommand,
            },
        }
    }

    pub fn malformed_tool_call(
        session_id: impl Into<String>,
        event_id: impl Into<String>,
        sequence: u64,
        tool: impl Into<String>,
        input: serde_json::Value,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            provider: None,
            session_id: session_id.into(),
            event_id: event_id.into(),
            event_type: ArcEventType::ToolCall,
            sequence,
            correlation_id: None,
            transcript_path: None,
            payload: ArcEventPayload::ToolCall {
                tool: tool.into(),
                input: input.clone(),
                command_text: None,
                argument_extraction: ToolArgumentExtraction::MalformedOrUnrecognized {
                    raw: input,
                    reason: reason.into(),
                },
            },
        }
    }

    pub fn lifecycle(
        session_id: impl Into<String>,
        event_id: impl Into<String>,
        event_type: ArcEventType,
        sequence: u64,
    ) -> Self {
        Self {
            provider: None,
            session_id: session_id.into(),
            event_id: event_id.into(),
            event_type,
            sequence,
            correlation_id: None,
            transcript_path: None,
            payload: ArcEventPayload::Empty,
        }
    }
}

/// Kind of activation that triggered a Guard evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActivationKind {
    Lifecycle(LifecycleTrigger),
    Tool { matched_pattern: Option<String> },
}

/// State of a Guard evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvaluationState {
    Pending,
    Satisfied,
    Failed,
    Errored { error: String },
}

/// One concrete evaluation of one Guard caused by one current runtime activation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuardEvaluation {
    pub evaluation_id: String,
    pub session_id: String,
    pub guard_id: String,
    pub originating_event_id: String,
    pub activation_kind: ActivationKind,
    pub state: EvaluationState,
}
