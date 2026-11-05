use crate::ir::BehaviorIR;
use crate::target::{
    DecisionEnvironment, DecisionUiMode, OsTarget, ProviderEnvironment, ProviderTarget,
};
use anyhow::Result;
use std::path::PathBuf;

/// Contextual information provided to the emitter during artifact generation.
#[derive(Debug, Clone)]
pub struct EmissionContext {
    /// Implemented provider for which artifacts are being emitted (Gemini or Codex).
    pub provider: ProviderTarget,
    /// Target operating system / platform.
    pub target_os: OsTarget,
    /// Concrete provider surface being generated. Current hook emitters target CLI.
    pub environment: ProviderEnvironment,
    /// Decision UI requested by the generated hook command.
    pub decision_ui: DecisionUiMode,
    /// Decision transports actually available to the generated runtime.
    pub decision_environment: DecisionEnvironment,
    /// Physical base directory assigned to this compilation cell (e.g. ".generated/codex/linux/").
    pub base_output_path: PathBuf,
    /// Indicates whether the compilation involves multiple targets (to isolate subdirectories).
    pub is_multi_target: bool,
    /// Optional path or command to invoke the Arc binary in generated hooks.
    pub arc_bin: Option<String>,
}

/// Represents a generated in-memory artifact ready to be validated and written to disk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeneratedArtifact {
    /// Provider that originated the artifact.
    pub provider: ProviderTarget,
    /// Platform for which the artifact was generated.
    pub target_os: OsTarget,
    /// Relative path with respect to `base_output_path` (e.g. ".codex/config.toml", "AGENTS.md").
    pub relative_path: PathBuf,
    /// Serialized content of the file (JSON, Markdown, Shell script, etc.).
    pub content: String,
    /// Flags whether the file requires executable permissions (+x on POSIX systems).
    pub is_executable: bool,
}

/// Universal contract that every target provider emitter must implement.
pub trait TargetEmitter: Send + Sync {
    /// Canonical provider identifier associated with this emitter.
    fn provider(&self) -> ProviderTarget;

    /// Transforms the normalized BehaviorIR into a collection of concrete artifacts.
    fn emit(&self, ir: &BehaviorIR, ctx: &EmissionContext) -> Result<Vec<GeneratedArtifact>>;
}
