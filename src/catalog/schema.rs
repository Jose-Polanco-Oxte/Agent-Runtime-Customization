use crate::manifest::schema::{
    AliasVariant, AliasesManifest, InlineMatcher, MatcherAliasEntry, OperationAliasEntry,
};
use anyhow::{Result, bail};

/// Resolves an alias entry for a specific target OS according to the Arc Schema 1.0 rules:
/// 1. Exact OS variant (windows, linux, macos)
/// 2. If absent, fallback to default (either concrete definition or `set: <os>`)
/// 3. If neither exists, returns error.
pub trait AliasResolver<T> {
    fn resolve(&self, target_os: &str) -> Result<T>;
}

impl AliasResolver<InlineMatcher> for MatcherAliasEntry {
    fn resolve(&self, target_os: &str) -> Result<InlineMatcher> {
        // 1. Exact OS match
        let exact = match target_os {
            "windows" => self.windows.as_ref(),
            "linux" => self.linux.as_ref(),
            "macos" => self.macos.as_ref(),
            other => bail!(
                "Invalid target OS '{}'. Recognized OSes: windows, linux, macos",
                other
            ),
        };

        if let Some(matcher) = exact {
            return Ok(matcher.clone());
        }

        // 2. Fallback to default
        if let Some(ref default_val) = self.default {
            match default_val {
                AliasVariant::Concrete(matcher) => Ok(matcher.clone()),
                AliasVariant::Set { set } => {
                    let target = match set.as_str() {
                        "windows" => self.windows.as_ref(),
                        "linux" => self.linux.as_ref(),
                        "macos" => self.macos.as_ref(),
                        other => bail!(
                            "Invalid 'default.set' target '{}'. Must be one of: windows, linux, macos",
                            other
                        ),
                    };

                    target.cloned().ok_or_else(|| {
                        anyhow::anyhow!(
                            "Alias 'default.set' targets '{}' which is not defined in this alias",
                            set
                        )
                    })
                }
            }
        } else {
            bail!(
                "No definition found for OS '{}' and no 'default' fallback defined",
                target_os
            )
        }
    }
}

impl AliasResolver<String> for OperationAliasEntry {
    fn resolve(&self, target_os: &str) -> Result<String> {
        // 1. Exact OS match
        let exact = match target_os {
            "windows" => self.windows.as_ref(),
            "linux" => self.linux.as_ref(),
            "macos" => self.macos.as_ref(),
            other => bail!(
                "Invalid target OS '{}'. Recognized OSes: windows, linux, macos",
                other
            ),
        };

        if let Some(cmd) = exact {
            return Ok(cmd.clone());
        }

        // 2. Fallback to default
        if let Some(ref default_val) = self.default {
            match default_val {
                AliasVariant::Concrete(cmd) => Ok(cmd.clone()),
                AliasVariant::Set { set } => {
                    let target = match set.as_str() {
                        "windows" => self.windows.as_ref(),
                        "linux" => self.linux.as_ref(),
                        "macos" => self.macos.as_ref(),
                        other => bail!(
                            "Invalid 'default.set' target '{}'. Must be one of: windows, linux, macos",
                            other
                        ),
                    };

                    target.cloned().ok_or_else(|| {
                        anyhow::anyhow!(
                            "Alias 'default.set' targets '{}' which is not defined in this alias",
                            set
                        )
                    })
                }
            }
        } else {
            bail!(
                "No definition found for OS '{}' and no 'default' fallback defined",
                target_os
            )
        }
    }
}

impl AliasesManifest {
    /// Resolves a matcher alias for a specific OS.
    pub fn resolve_matcher(&self, alias: &str, target_os: &str) -> Result<InlineMatcher> {
        let matchers = self.matchers.as_ref().ok_or_else(|| {
            anyhow::anyhow!(
                "No 'matchers' section found in aliases.yaml when resolving alias '{}'",
                alias
            )
        })?;

        let entry = matchers.get(alias).ok_or_else(|| {
            anyhow::anyhow!("Matcher alias '{}' not found in aliases.yaml", alias)
        })?;

        entry.resolve(target_os)
    }

    /// Resolves an operation alias for a specific OS.
    pub fn resolve_operation(&self, alias: &str, target_os: &str) -> Result<String> {
        let operations = self.operations.as_ref().ok_or_else(|| {
            anyhow::anyhow!(
                "No 'operations' section found in aliases.yaml when resolving alias '{}'",
                alias
            )
        })?;

        let entry = operations.get(alias).ok_or_else(|| {
            anyhow::anyhow!("Operation alias '{}' not found in aliases.yaml", alias)
        })?;

        entry.resolve(target_os)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::schema::StringList;

    #[test]
    fn test_resolve_exact_os_matcher() {
        let entry = MatcherAliasEntry {
            default: Some(AliasVariant::Set {
                set: "linux".into(),
            }),
            windows: Some(InlineMatcher {
                exact: Some(StringList::Single("del file.txt".into())),
                regex: None,
            }),
            linux: Some(InlineMatcher {
                exact: Some(StringList::Single("rm file.txt".into())),
                regex: None,
            }),
            macos: None,
        };

        let win = entry.resolve("windows").unwrap();
        assert_eq!(win.exact.unwrap().to_vec(), vec!["del file.txt"]);

        let lin = entry.resolve("linux").unwrap();
        assert_eq!(lin.exact.unwrap().to_vec(), vec!["rm file.txt"]);

        // macos falls back to default -> set: linux -> linux
        let mac = entry.resolve("macos").unwrap();
        assert_eq!(mac.exact.unwrap().to_vec(), vec!["rm file.txt"]);
    }

    #[test]
    fn test_resolve_exact_os_operation() {
        let entry = OperationAliasEntry {
            default: Some(AliasVariant::Concrete("git rev-parse HEAD".into())),
            windows: Some("echo %USERNAME%".into()),
            linux: Some("whoami".into()),
            macos: None,
        };

        assert_eq!(entry.resolve("windows").unwrap(), "echo %USERNAME%");
        assert_eq!(entry.resolve("linux").unwrap(), "whoami");
        assert_eq!(entry.resolve("macos").unwrap(), "git rev-parse HEAD");
    }
}
