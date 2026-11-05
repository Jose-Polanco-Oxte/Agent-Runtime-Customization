# Provider E2E and cross-platform contract harness

This harness automates the provider-facing decision contract without using
WebDriver. It intentionally separates three claims:

| Layer | What runs | Permitted result |
|---|---|---|
| Contract | Direct `arc hook run` calls with a scripted sidecar | `CONTRACT_STATUS=PASS`; provider E2E remains `NOT-RUN` |
| Authenticated provider | Real Codex or AGY CLI session, generated hooks, scripted sidecar, provider continuation | `PROVIDER_E2E_STATUS=PASS` when the complete event/re-entry contract passes |
| Live UI | Tauri/WebView user interaction | Always `NOT-RUN` in this harness |

The scripted sidecar is the Cargo example
`provider_decision_host`. It reads the production `DialogRequest`, returns one
bounded `DialogResponse`, and is selected only through the existing
`ARC_DECISION_UI_HOST` override. It is not shipped in the product and cannot be
mistaken for live Tauri/WebView evidence.

## Deterministic contract suite

```powershell
cargo build --bin arc --example provider_decision_host
python -m unittest discover -s tests/provider_e2e -p "test_*.py" -v
python tests/provider_e2e/provider_runner.py --mode contract --provider codex --decision allow
python tests/provider_e2e/provider_runner.py --mode contract --provider codex --decision deny
python tests/provider_e2e/provider_runner.py --mode contract --provider gemini --decision allow
python tests/provider_e2e/provider_runner.py --mode contract --provider gemini --decision deny
```

The GitHub Actions workflow
`.github/workflows/provider-e2e-cross-platform.yml` executes this matrix on
Windows, Linux, and macOS. A configured workflow is not evidence of those
platforms passing; only completed run artifacts may change their status from
`NOT-RUN`.

## Authenticated provider suite

The provider CLI must already be installed and authenticated. The runner uses
an isolated temporary workspace and stores only hashes/byte counts for provider
stdout and stderr.

```powershell
python tests/provider_e2e/provider_runner.py --mode authenticated --provider codex --decision allow --allow-external-provider
python tests/provider_e2e/provider_runner.py --mode authenticated --provider codex --decision deny --allow-external-provider
python tests/provider_e2e/provider_runner.py --mode authenticated --provider gemini --decision allow --allow-external-provider
python tests/provider_e2e/provider_runner.py --mode authenticated --provider gemini --decision deny --allow-external-provider
```

Codex runs with `--enable hooks` and `--approve-for-me` (which selects its
`workspace-write` approval mode), an ephemeral session, and the explicit
hook-trust bypass required for the generated isolated fixture. It does not bypass
the filesystem sandbox. AGY runs with permission
prompts disabled inside the same isolated workspace. Authenticated mode contacts
the external provider using local credentials and therefore refuses to start
unless `--allow-external-provider` is present. For Codex, the runner creates an
ephemeral `CODEX_HOME` containing only an opaque copy of local `auth.json` and
the generated hook file; it does not load the user's global config or hooks. The
only submitted prompt is the fixed fixture instruction returned by
`_provider_prompt`; repository content is not copied into the temporary workspace.

## Acceptance rules

Every accepted case requires ordered, correlated evidence for:

```text
DecisionTransportResolved -> DecisionReceived -> ProviderOutput
```

Allow additionally requires a later provider hook and output after the
remediation marker is created. Codex also requires
`StateTransition(GuardSatisfied)`. Deny requires successful provider completion
without the marker. An unresolved decision is rejected if a waiver transition
appears.

Evidence is written under
`docs/internal/evidence/decision-ui/provider-e2e-runs/` by default. Raw provider
output, prompts, workspace paths, and session IDs are not persisted; streams
are represented by SHA-256 and byte count, and session IDs by SHA-256.

## Explicitly excluded

- DPI/monitor/theme/keyboard/focus/timeout/frontend-failure/UDF-writeability,
  successive x10, and cleanup timing live matrix.
- WebDriver readiness/ACL and unauthorized-window tests.
- Protected installation, absent WebView2 runtime, upgrade/rollback, and
  distribution.
- DUI-012 administrative reconciliation, links, hashes, and claims.
