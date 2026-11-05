pub mod context;
pub mod policy;
pub mod skill;

pub use context::{BoundRole, WorkspaceContext};
pub use policy::{
    BoundLifecycleGuard, BoundMatcher, BoundProbeCommand, BoundRuleExpression, BoundToolGuard,
    ProbeCommandError,
};
pub use skill::NormalizedSkill;

use crate::manifest::schema::RuntimeConfig;
use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

fn default_schema() -> String {
    "1.0".to_string()
}

fn default_compiler_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BehaviorIR {
    #[serde(default = "default_schema")]
    pub schema: String,
    #[serde(default = "default_compiler_version")]
    pub compiler_version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub build_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_hash: Option<String>,
    #[serde(default)]
    pub runtime: RuntimeConfig,
    pub context: WorkspaceContext,
    pub skills: Vec<NormalizedSkill>,
    pub lifecycle_guards: Vec<BoundLifecycleGuard>,
    pub tool_guards: Vec<BoundToolGuard>,
    pub rules: BTreeMap<String, BoundRuleExpression>,
}

impl BehaviorIR {
    pub fn compute_content_hash(&self) -> String {
        #[derive(Serialize)]
        struct HashablePayload<'a> {
            runtime: &'a RuntimeConfig,
            context: &'a WorkspaceContext,
            skills: &'a Vec<NormalizedSkill>,
            lifecycle_guards: &'a Vec<BoundLifecycleGuard>,
            tool_guards: &'a Vec<BoundToolGuard>,
            rules: &'a BTreeMap<String, BoundRuleExpression>,
        }

        let payload = HashablePayload {
            runtime: &self.runtime,
            context: &self.context,
            skills: &self.skills,
            lifecycle_guards: &self.lifecycle_guards,
            tool_guards: &self.tool_guards,
            rules: &self.rules,
        };

        let json = serde_json::to_vec(&payload).unwrap_or_default();
        let mut hasher = Sha256::new();
        hasher.update(&json);
        hex::encode(hasher.finalize())
    }

    /// Computes the SHA-256 digest of this BehaviorIR when formatted as canonical pretty JSON,
    /// matching the byte domain registered in SQLite `trusted_irs` during `arc build`.
    pub fn compute_raw_bytes_digest(&self) -> String {
        let json = serde_json::to_string_pretty(self).unwrap_or_default();
        let mut hasher = Sha256::new();
        hasher.update(json.as_bytes());
        hex::encode(hasher.finalize())
    }

    pub fn validate_integrity(&self) -> Result<()> {
        if self.schema != "1.0" {
            bail!(
                "Unsupported IR schema version '{}'. Expected '1.0'",
                self.schema
            );
        }

        if let Some(ref expected_hash) = self.content_hash {
            let actual_hash = self.compute_content_hash();
            if expected_hash != &actual_hash {
                bail!(
                    "IR integrity verification failed: content hash mismatch (expected {}, got {})",
                    expected_hash,
                    actual_hash
                );
            }
        }

        self.validate_runtime_invariants()?;

        Ok(())
    }

    /// Returns true if `digest` matches the external raw bytes digest (SQLite / canonical JSON domain).
    /// Does NOT accept semantic `content_hash`, which is caller-controllable and not an external trust anchor.
    pub fn matches_digest(&self, digest: &str) -> bool {
        self.compute_raw_bytes_digest().eq_ignore_ascii_case(digest)
    }

    /// Returns the canonical external bytes digest for this BehaviorIR.
    pub fn digest(&self) -> String {
        self.compute_raw_bytes_digest()
    }

    /// Validates invariants required by the runtime even when the IR was
    /// deserialized directly instead of produced by the compiler.
    fn validate_runtime_invariants(&self) -> Result<()> {
        self.runtime.validate()?;
        for guard in &self.lifecycle_guards {
            Self::validate_expression_commands(&guard.require)?;
        }
        for guard in &self.tool_guards {
            Self::validate_expression_commands(&guard.require)?;
        }
        for expression in self.rules.values() {
            Self::validate_expression_commands(expression)?;
        }
        Ok(())
    }

    fn validate_expression_commands(root: &BoundRuleExpression) -> Result<()> {
        let mut stack = vec![root];
        while let Some(expression) = stack.pop() {
            match expression {
                BoundRuleExpression::Probe { command, .. } => {
                    command
                        .validate()
                        .map_err(|error| anyhow::anyhow!("invalid probe command in IR: {error}"))?;
                }
                BoundRuleExpression::All(children) | BoundRuleExpression::Any(children) => {
                    stack.extend(children.iter());
                }
                BoundRuleExpression::Not(child) => stack.push(child),
                BoundRuleExpression::RuleRef { .. } | BoundRuleExpression::Decide { .. } => {}
            }
        }
        Ok(())
    }
}
