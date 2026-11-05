use anyhow::bail;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

/// Canonical identifiers known to Arc.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderTarget {
    Claude,
    Gemini,
    Codex,
    OpenCode,
}

impl ProviderTarget {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Claude => "claude",
            Self::Gemini => "gemini",
            Self::Codex => "codex",
            Self::OpenCode => "opencode",
        }
    }
}

impl fmt::Display for ProviderTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl FromStr for ProviderTarget {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_lowercase().as_str() {
            "gemini" => Ok(Self::Gemini),
            "codex" => Ok(Self::Codex),
            unknown => bail!(
                "Unknown or unimplemented provider '{}'. Available providers: gemini, codex",
                unknown
            ),
        }
    }
}
