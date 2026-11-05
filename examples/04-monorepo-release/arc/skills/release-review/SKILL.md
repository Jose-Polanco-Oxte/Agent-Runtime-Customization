---
name: monorepo-release-review
description: Review a monorepo release before any irreversible publication.
---

# Monorepo Release Review

1. Identify the exact package, version, commit, and registry.
2. Verify tests and provenance evidence without publishing.
3. Check that the branch and sandbox worktree markers are safe.
4. Request authorization for the exact publish command only.
5. Record the resulting digest without modifying or deleting release tags.
