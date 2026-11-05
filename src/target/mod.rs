pub mod capabilities;
pub mod decision_strategy;
pub mod matrix;
pub mod os;
pub mod provider;
pub mod selector;

pub use capabilities::{
    CapabilityContext, CapabilityDiagnostic, CapabilityLevel, CapabilityResolution,
    CoverageSurface, ProviderCapabilities, check_project_compatibility,
    generate_capabilities_table, resolve_capability,
};
pub use decision_strategy::{
    CapabilityEvent, DecisionEnvironment, DecisionTransport, DecisionUiMode, ProviderEnvironment,
    TransportResolution, resolve_decision_transport, resolve_decision_transport_for,
};
pub use matrix::{CompilationMatrix, MatrixCell};
pub use os::OsTarget;
pub use provider::ProviderTarget;
pub use selector::TargetSelector;
