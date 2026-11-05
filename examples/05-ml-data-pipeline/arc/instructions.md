# ML Data Pipeline Rules

- Source datasets are immutable; derive new versioned datasets instead.
- Training and release require lineage metadata.
- Upload only a reviewed synthetic model artifact with explicit authorization.
- Dependency changes must update the environment lock as one reviewed change.
