use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

use crate::manifest::schema::{LifecycleTrigger, OnFailureConfig};

/// Compiled Lifecycle Guard representation in BehaviorIR.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BoundLifecycleGuard {
    pub id: String,
    pub triggers: Vec<LifecycleTrigger>,
    pub require: BoundRuleExpression,
    pub on_failure: OnFailureConfig,
    pub order: u32,
    #[serde(default)]
    pub declaration_order: usize,
}

/// Compiled Tool Guard representation in BehaviorIR.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BoundToolGuard {
    pub id: String,
    pub matcher: BoundMatcher,
    pub require: BoundRuleExpression,
    pub on_failure: OnFailureConfig,
    pub order: u32,
    #[serde(default)]
    pub declaration_order: usize,
}

/// Resolved matcher patterns for a specific OS target or unified cross-platform matchers.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct BoundMatcher {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exact_patterns: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub regex_patterns: Vec<String>,
}

/// Errors raised while validating or resolving a compiled probe command.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ProbeCommandError {
    #[error("unsupported operating system '{os}'; expected windows, linux, or macos")]
    UnsupportedOs { os: String },
    #[error("probe command map cannot be empty")]
    EmptyMap,
    #[error("probe command cannot be empty or whitespace")]
    EmptyCommand,
    #[error("probe command for operating system '{os}' cannot be empty or whitespace")]
    EmptyCommandForOs { os: String },
    #[error("duplicate operating system key '{os}'")]
    DuplicateOs { os: String },
    #[error("no probe command is defined for operating system '{os}'")]
    MissingForOs { os: String },
}

fn canonical_os_key(raw: &str) -> Result<String, ProbeCommandError> {
    let normalized = raw.trim().to_ascii_lowercase();
    match normalized.as_str() {
        "windows" | "linux" | "macos" => Ok(normalized),
        _ => Err(ProbeCommandError::UnsupportedOs {
            os: raw.to_string(),
        }),
    }
}

fn reject_empty_command(command: &str, os: Option<&str>) -> Result<(), ProbeCommandError> {
    if command.trim().is_empty() {
        return Err(match os {
            Some(os) => ProbeCommandError::EmptyCommandForOs { os: os.to_string() },
            None => ProbeCommandError::EmptyCommand,
        });
    }
    Ok(())
}

/// Probe command representation in BehaviorIR, supporting single command or multi-OS mapping (H5/L4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BoundProbeCommand {
    Single(String),
    MultiOs(BTreeMap<String, String>),
}

impl Serialize for BoundProbeCommand {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            Self::Single(s) => serializer.serialize_str(s),
            Self::MultiOs(map) => map.serialize(serializer),
        }
    }
}

impl<'de> Deserialize<'de> for BoundProbeCommand {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error;
        let val = serde_json::Value::deserialize(deserializer)?;
        match val {
            serde_json::Value::String(s) => {
                let command = BoundProbeCommand::Single(s);
                command.validate().map_err(D::Error::custom)?;
                Ok(command)
            }
            serde_json::Value::Object(map) => {
                if map.is_empty() {
                    return Err(D::Error::custom(ProbeCommandError::EmptyMap));
                }
                let mut btree = BTreeMap::new();
                for (raw_key, v) in map {
                    let key = canonical_os_key(&raw_key).map_err(D::Error::custom)?;
                    if let serde_json::Value::String(str_val) = v {
                        if btree.insert(key.clone(), str_val).is_some() {
                            return Err(D::Error::custom(ProbeCommandError::DuplicateOs {
                                os: key,
                            }));
                        }
                    } else {
                        return Err(D::Error::custom(
                            "MultiOs probe commands must map OS names to string commands",
                        ));
                    }
                }
                let command = BoundProbeCommand::MultiOs(btree);
                command.validate().map_err(D::Error::custom)?;
                Ok(command)
            }
            _ => Err(D::Error::custom(
                "Expected a command string or OS-to-command map for probe command",
            )),
        }
    }
}

impl BoundProbeCommand {
    /// Validates an IR command independently of the compiler.
    pub fn validate(&self) -> Result<(), ProbeCommandError> {
        match self {
            Self::Single(command) => reject_empty_command(command, None),
            Self::MultiOs(map) => {
                if map.is_empty() {
                    return Err(ProbeCommandError::EmptyMap);
                }
                for (os, command) in map {
                    let canonical = canonical_os_key(os)?;
                    if canonical != *os {
                        return Err(ProbeCommandError::UnsupportedOs { os: os.clone() });
                    }
                    reject_empty_command(command, Some(os))?;
                }
                Ok(())
            }
        }
    }

    pub fn resolve_for_os<'a>(&'a self, os: &str) -> Result<&'a str, ProbeCommandError> {
        self.validate()?;
        let os = canonical_os_key(os)?;
        match self {
            Self::Single(command) => Ok(command.as_str()),
            Self::MultiOs(map) => map
                .get(&os)
                .map(String::as_str)
                .ok_or(ProbeCommandError::MissingForOs { os }),
        }
    }

    pub fn resolve_for_host<'a>(&'a self) -> Result<&'a str, ProbeCommandError> {
        let current_os = match std::env::consts::OS {
            "windows" => "windows",
            "linux" => "linux",
            "macos" => "macos",
            other => {
                return Err(ProbeCommandError::UnsupportedOs {
                    os: other.to_string(),
                });
            }
        };
        self.resolve_for_os(current_os)
    }
}

#[cfg(test)]
mod tests {
    use super::{BoundProbeCommand, ProbeCommandError};
    use std::collections::BTreeMap;

    #[test]
    fn multi_os_requires_exact_host_match() {
        let command = BoundProbeCommand::MultiOs(BTreeMap::from([(
            "linux".to_string(),
            "check-linux".to_string(),
        )]));

        assert_eq!(command.resolve_for_os("linux"), Ok("check-linux"));
        assert_eq!(
            command.resolve_for_os("windows"),
            Err(ProbeCommandError::MissingForOs {
                os: "windows".to_string()
            })
        );
    }

    #[test]
    fn single_command_is_universal() {
        let command = BoundProbeCommand::Single("check".to_string());
        assert_eq!(command.resolve_for_os("linux"), Ok("check"));
        assert_eq!(command.resolve_for_os("windows"), Ok("check"));
    }

    #[test]
    fn rejects_invalid_multi_os_commands_at_deserialization_boundary() {
        for raw in [
            r#"{"freebsd":"check"}"#,
            r#"{"default":"check"}"#,
            r#"{"windows":""}"#,
            r#"{"linux":"   "}"#,
        ] {
            assert!(
                serde_json::from_str::<BoundProbeCommand>(raw).is_err(),
                "invalid probe command must be rejected: {raw}"
            );
        }
    }

    #[test]
    fn rejects_programmatically_constructed_invalid_commands() {
        let invalid = BoundProbeCommand::MultiOs(BTreeMap::from([(
            "default".to_string(),
            "check".to_string(),
        )]));
        assert!(matches!(
            invalid.validate(),
            Err(ProbeCommandError::UnsupportedOs { .. })
        ));

        let empty = BoundProbeCommand::Single("  ".to_string());
        assert!(matches!(
            empty.resolve_for_host(),
            Err(ProbeCommandError::EmptyCommand)
        ));
    }
}

impl From<&str> for BoundProbeCommand {
    fn from(s: &str) -> Self {
        Self::Single(s.to_string())
    }
}

impl From<String> for BoundProbeCommand {
    fn from(s: String) -> Self {
        Self::Single(s)
    }
}

/// Compiled Rule expression representation in BehaviorIR with all aliases resolved.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BoundRuleExpression {
    RuleRef {
        name: String,
    },
    Probe {
        command: BoundProbeCommand,
        expected_in: Vec<String>,
    },
    Decide {
        prompt: String,
    },
    All(Vec<BoundRuleExpression>),
    Any(Vec<BoundRuleExpression>),
    Not(Box<BoundRuleExpression>),
}
