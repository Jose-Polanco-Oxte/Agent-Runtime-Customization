# Clinical API Safety Rules

- Patient-derived data must remain inside the synthetic sandbox boundary.
- Never delete or truncate audit evidence.
- Production-schema changes require a reviewed migration record, an explicit
  request for the exact migration, and a rollback statement.
- Log identifiers and counts only; do not reproduce clinical record contents.
