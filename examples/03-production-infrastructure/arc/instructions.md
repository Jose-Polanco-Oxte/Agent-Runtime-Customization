# Production Infrastructure Rules

- Start with read-only context and plan inspection.
- Never run production destroy or namespace deletion operations.
- Apply only a reviewed plan during an open change window.
- Approval is scoped to the exact pending command and never carries forward.
- Preserve plan evidence before completion.
