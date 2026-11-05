pub mod collision;
mod skill_document;
pub mod targets;
pub mod traits;
pub mod writer;

use anyhow::{Result, anyhow};
use std::collections::BTreeMap;

use crate::target::ProviderTarget;
pub use collision::CollisionDetector;
pub use targets::codex::CodexEmitter;
pub use targets::gemini::GeminiEmitter;
pub use traits::{EmissionContext, GeneratedArtifact, TargetEmitter};
pub use writer::{
    BuildArtifactRecord, BuildManifest, recover_pending_build, write_artifacts,
    write_artifacts_with_trust,
};

/// Central registry of supported target emitters.
pub struct EmitterRegistry {
    emitters: BTreeMap<ProviderTarget, Box<dyn TargetEmitter>>,
}

impl EmitterRegistry {
    pub fn new() -> Self {
        let mut registry = Self {
            emitters: BTreeMap::new(),
        };
        // Register default provider emitters
        registry.register(Box::new(GeminiEmitter));
        registry.register(Box::new(CodexEmitter));
        registry
    }

    /// Registers a provider adapter.
    pub fn register(&mut self, emitter: Box<dyn TargetEmitter>) {
        self.emitters.insert(emitter.provider(), emitter);
    }

    /// Returns every provider with an emitter registered in this Arc build.
    pub fn providers(&self) -> Vec<ProviderTarget> {
        self.emitters.keys().copied().collect()
    }

    /// Obtains an emitter reference for a requested provider target.
    pub fn get(&self, provider: ProviderTarget) -> Result<&dyn TargetEmitter> {
        self.emitters
            .get(&provider)
            .map(|b| b.as_ref())
            .ok_or_else(|| anyhow!("No emitter registered for provider '{}'", provider))
    }
}

impl Default for EmitterRegistry {
    fn default() -> Self {
        Self::new()
    }
}
