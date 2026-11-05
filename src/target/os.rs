use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

/// Recognized platform/OS identifiers for Schema `1.0`: windows, linux, macos.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct OsTarget(String);

impl<'de> Deserialize<'de> for OsTarget {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error;
        let s = String::deserialize(deserializer)?;
        let clean = s.trim().to_lowercase();
        match clean.as_str() {
            "windows" | "linux" | "macos" => Ok(Self(clean)),
            "host" => Self::host().map_err(D::Error::custom),
            other => Err(D::Error::custom(format!(
                "Invalid OS '{}'. Schema 1.0 recognizes only 'windows', 'linux', 'macos'",
                other
            ))),
        }
    }
}

impl OsTarget {
    pub const WINDOWS: &'static str = "windows";
    pub const LINUX: &'static str = "linux";
    pub const MACOS: &'static str = "macos";
    pub fn new(os: impl Into<String>) -> Result<Self> {
        let clean = os.into().trim().to_lowercase();
        match clean.as_str() {
            "windows" | "linux" | "macos" => Ok(Self(clean)),
            "host" => Self::host(),
            other => bail!(
                "Invalid OS '{}'. Schema 1.0 recognizes only 'windows', 'linux', 'macos'",
                other
            ),
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn is_valid(&self) -> bool {
        matches!(self.0.as_str(), "windows" | "linux" | "macos")
    }

    /// Gets standard schema 1.0 all OS list
    pub fn all_os() -> Vec<Self> {
        vec![
            Self("windows".to_string()),
            Self("linux".to_string()),
            Self("macos".to_string()),
        ]
    }

    /// Obtains the host operating system.
    pub fn host() -> Result<Self> {
        match std::env::consts::OS {
            "windows" => Ok(Self("windows".to_string())),
            "linux" => Ok(Self("linux".to_string())),
            "macos" => Ok(Self("macos".to_string())),
            other => bail!("Unsupported host operating system '{}'", other),
        }
    }
}

impl fmt::Display for OsTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl FromStr for OsTarget {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let clean = s.trim().to_lowercase();
        match clean.as_str() {
            "windows" | "linux" | "macos" => Ok(Self(clean)),
            "host" => Self::host(),
            other => bail!(
                "Invalid OS '{}'. Schema 1.0 recognizes only 'windows', 'linux', 'macos'",
                other
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::OsTarget;
    use std::str::FromStr;

    #[test]
    fn rejects_invalid_constructor_values() {
        assert!(OsTarget::new("").is_err());
        assert!(OsTarget::new("all").is_err());
        assert!(OsTarget::new("freebsd").is_err());
    }

    #[test]
    fn all_os_contains_only_supported_targets() {
        let names: Vec<_> = OsTarget::all_os()
            .into_iter()
            .map(|target| target.as_str().to_string())
            .collect();
        assert_eq!(names, vec!["windows", "linux", "macos"]);
        assert!(names.iter().all(|name| !name.is_empty()));
    }

    #[test]
    fn host_and_parser_preserve_closed_set() {
        let parsed = OsTarget::from_str(" HOST ").expect("host resolves");
        assert!(parsed.is_valid());
        assert_eq!(parsed, OsTarget::host().expect("host resolves"));
    }
}
