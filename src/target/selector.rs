use super::os::OsTarget;
use super::provider::ProviderTarget;
use anyhow::{Result, bail};
use std::collections::BTreeSet;
use std::fmt::Debug;
use std::str::FromStr;

/// Selector representing the intent to compile for All or a Specific subset.
#[derive(Debug, Clone, PartialEq, Eq)]

pub enum TargetSelector<T: Ord> {
    All,
    Specific(BTreeSet<T>),
}

impl TargetSelector<ProviderTarget> {
    pub fn resolve(&self, available_providers: &[ProviderTarget]) -> Vec<ProviderTarget> {
        match self {
            Self::All => available_providers.to_vec(),
            Self::Specific(set) => set.iter().copied().collect(),
        }
    }
}

impl TargetSelector<OsTarget> {
    pub fn resolve(&self, _catalog_platforms: &[String]) -> Vec<OsTarget> {
        match self {
            Self::All => OsTarget::all_os(),
            Self::Specific(set) => set.iter().cloned().collect(),
        }
    }
}

impl FromStr for TargetSelector<ProviderTarget> {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let clean = s.trim().to_lowercase();
        if clean == "all" || clean == "*" {
            return Ok(Self::All);
        }

        let mut set = BTreeSet::new();
        for token in clean.split(',') {
            let token = token.trim();
            if !token.is_empty() {
                set.insert(ProviderTarget::from_str(token)?);
            }
        }

        if set.is_empty() {
            bail!("Provider selection cannot be empty");
        }

        Ok(Self::Specific(set))
    }
}

impl FromStr for TargetSelector<OsTarget> {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let clean = s.trim().to_lowercase();
        if clean == "all" || clean == "*" {
            return Ok(Self::All);
        }

        let mut set = BTreeSet::new();
        for token in clean.split(',') {
            let token = token.trim();
            if !token.is_empty() {
                set.insert(OsTarget::from_str(token)?);
            }
        }

        if set.is_empty() {
            bail!("OS selection cannot be empty");
        }

        Ok(Self::Specific(set))
    }
}
