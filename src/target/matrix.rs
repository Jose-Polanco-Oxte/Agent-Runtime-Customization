use super::os::OsTarget;
use super::provider::ProviderTarget;
use super::selector::TargetSelector;

/// Represents the Cartesian compilation matrix: (Providers × Operating Systems).
#[derive(Debug, Clone)]
pub struct CompilationMatrix {
    pub providers: TargetSelector<ProviderTarget>,
    pub platforms: TargetSelector<OsTarget>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct MatrixCell {
    pub provider: ProviderTarget,
    pub os: OsTarget,
}

impl CompilationMatrix {
    pub fn new(
        providers: TargetSelector<ProviderTarget>,
        platforms: TargetSelector<OsTarget>,
    ) -> Self {
        Self {
            providers,
            platforms,
        }
    }

    /// Expands the matrix into all individual execution combinations.
    pub fn expand(
        &self,
        known_catalog_platforms: &[String],
        available_providers: &[ProviderTarget],
    ) -> Vec<MatrixCell> {
        let resolved_providers = self.providers.resolve(available_providers);
        let resolved_platforms = self.platforms.resolve(known_catalog_platforms);

        let mut cells = Vec::new();
        for os in resolved_platforms {
            for provider in &resolved_providers {
                cells.push(MatrixCell {
                    provider: *provider,
                    os: os.clone(),
                });
            }
        }
        cells
    }
}
