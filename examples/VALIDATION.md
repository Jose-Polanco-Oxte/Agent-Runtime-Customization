# Sandbox Validation Status

Last preflight: 2026-08-24 on Windows.

## Repository-level checklist

- [x] Previous `examples/manual-testing` content removed.
- [x] Six independent `arc.yaml` roots discovered successfully.
- [x] Every sandbox includes a `CASES.md` provider ledger.
- [x] Every declared module, role source, skill source, Rule, and alias resolves.
- [x] Full atomic matrix compiled: `gemini × codex × windows/linux/macos`.
- [x] Generated artifacts were emitted outside `examples/`.
- [ ] Gemini live hook cases executed and recorded.
- [ ] Codex CLI live hook cases executed and recorded.
- [ ] Cross-provider anomalies triaged and reproduced.

## Per-sandbox preflight

| Sandbox | Load/schema | Gemini matrix build | Codex matrix build | Live cases |
| --- | --- | --- | --- | --- |
| `01-fintech-payments` | PASS | PASS | PASS | PENDING |
| `02-healthcare-api` | PASS | PASS | PASS | PENDING |
| `03-production-infrastructure` | PASS | PASS | PASS | PENDING |
| `04-monorepo-release` | PASS | PASS | PASS | PENDING |
| `05-ml-data-pipeline` | PASS | PASS | PASS | PENDING |
| `06-incident-response` | PASS | PASS | PASS | PENDING |

## Capability observations from preflight

- Gemini Tool Guard `deny` controls compiled as native `PreToolUse` preventive
  controls; Gemini Tool Guard `ask` used native `force_ask` in this CLI build.
- Gemini start `message` compiled as advisory first-turn context injection; it
  is not a blocking control.
- Codex CLI Tool Guard `deny`, lifecycle start, and lifecycle end compiled with
  `Partial` coverage and must be tested only on the declared covered CLI hook
  surface.
- Codex Tool Guard `ask` compiled as `Emulated` through Arc WebView. Codex
  Desktop without a verified project-hook trust flow is not covered by this
  classification.

## Validation command

In a restricted environment, place Arc's trust database in a writable state
directory. Use a fresh output directory per sandbox.

```powershell
$env:ARC_STATE_DIR = (New-Item -ItemType Directory -Force target\example-validation\state).FullName
.\target\debug\arc.exe build `
  --path examples\01-fintech-payments `
  --target all `
  --os all `
  --output-dir target\example-validation\01-fintech-payments
```

The live provider checklists intentionally remain pending. A successful build
cannot prove artifact activation, event delivery, command-evidence coverage,
provider waiting behavior, decision receipt, or actual prevention.
