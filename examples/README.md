# Arc Provider Sandboxes

This directory is a manual acceptance suite for Arc. Each sandbox represents a
configured project, not a schema snippet. Every sandbox contains an Arc
workspace, realistic non-sensitive fixtures, provider-neutral operating
instructions, one or more roles or skills, and a `CASES.md` execution ledger.

## Sandboxes

| Sandbox | Primary controls | Arc features exercised |
| --- | --- | --- |
| `01-fintech-payments` | Payment secrets, production mutations, release evidence | Inline catalogs, grouped skills, reusable rules, `deny`, `ask`, `message` |
| `02-healthcare-api` | PHI export, audit-log deletion, clinical migrations | Section modules, roles, deterministic probes, decision continuation |
| `03-production-infrastructure` | Terraform destroy, namespace deletion, production apply | OS aliases, change-window state, start/end lifecycle controls |
| `04-monorepo-release` | Force push, tag deletion, package publishing | Protected-branch probes, release approval, clean-completion gate |
| `05-ml-data-pipeline` | Dataset deletion, model upload, dependency mutation | Skill groups, data-lineage evidence, current-call matcher boundaries |
| `06-incident-response` | Evidence destruction, containment, credential rotation | Fully inline rules/matchers, multi-trigger lifecycle guard, minimal workspace |

## Test invariant

A successful `arc build` proves only that the selected configuration can be
compiled. It does not prove that a provider installed the artifacts, emitted
the expected event, exposed the complete tool command, waited for Arc, or
enforced the returned verdict. Record each layer independently in `CASES.md`.

The current executable registers only `gemini` and `codex`. Codex CLI hook
coverage is reported as partial for several controls; record that degradation
instead of treating it as native full-surface enforcement.

## Repeatable workflow

Run commands from the repository root. Replace `<sandbox>` and `<output>` with
concrete paths; keep generated artifacts outside `examples/` so the case-study
sources remain unchanged.

```powershell
.\target\debug\arc.exe capabilities --path examples\<sandbox>\arc.yaml
.\target\debug\arc.exe build --path examples\<sandbox>\arc.yaml --target all --os host --output-dir <output>
.\target\debug\arc.exe monitor --workspace examples\<sandbox> --latest --format json
```

For a full portability check, replace `--os host` with `--os all`. A matrix
build is atomic at the result level: any failed provider/OS combination makes
the command fail.

## Result vocabulary

Use exactly one result in each provider checkbox note:

- `PASS`: observed behavior and evidence match the expected result.
- `FAIL`: the operation proceeded or the verdict/feedback was incorrect.
- `BLOCKED`: the environment could not exercise the case.
- `ANOMALY`: behavior was inconsistent, incomplete, duplicated, or ambiguous.
- `N/A`: the case is intentionally outside that provider surface.

Never execute a destructive case against real credentials, remotes, clusters,
registries, databases, or patient data. The included targets are synthetic;
provider command attempts should still be intercepted before execution.
