# Tauri WebDriver integration

This suite exercises the release Tauri application through the native
WebView2 WebDriver stack. It is intentionally separate from component tests,
the sidecar process matrix, and provider E2E.

## Accredited behavior

- The `decision` WebView reaches an observable `data-arc-readiness="ready"`
  state after Svelte has settled the DOM and Rust accepts `frontend_ready`.
- The authorized window can invoke a canonical command after readiness.
- A second Tauri WebView labeled `unauthorized` loads the same application but
  receives typed ACL rejection for all five custom commands.
- Rejected calls do not attempt a terminal response. The fixture records every
  terminal write attempt before delegating to the production response sink.
- JSON and JUnit evidence include platform/toolchain data, exit codes, events,
  and the SHA-256 of the exact release fixture.

The suite does not instantiate a provider event store, receipt writer, or
waiver consumer. Those provider-layer assertions are therefore recorded as
`NOT-APPLICABLE`, not as a provider E2E pass.

## Isolation and production boundary

`arc-decision-ui-webdriver-fixture` is gated by the non-default
`webdriver-fixture` Cargo feature. Production `arc-decision-ui-host` does not
create the unauthorized window or the test evidence sink.

EdgeDriver appends WebView2 switches to the application command line. The
fixture consequently receives its absolute evidence path through
`ARC_WEBDRIVER_TERMINAL_EVIDENCE`; it does not interpret driver arguments as
application configuration. Its request ID and display text are fixed,
synthetic, and safe to persist.

The current external-driver harness accredits Windows only. It requires an
installed WebView2 runtime and `tauri-driver` 2.0.6. A declared CI job or a
successful provider run on another operating system is not a cross-platform
WebDriver pass.

## Local execution

From the repository root:

```powershell
Set-Location ui/decision
npm ci --ignore-scripts
npm run test:webdriver:types
npm test -- --run
Set-Location ../..
cargo install tauri-driver --version 2.0.6 --locked
cargo test --locked --manifest-path ui/decision/src-tauri/Cargo.toml --features webdriver-fixture
./tests/decision_ui_webdriver_harness.ps1
```

The harness builds the frontend and the release fixture unless `-SkipBuild` is
passed. It then launches WebdriverIO, `tauri-driver`, the matching EdgeDriver,
and the real Tauri binary. Readiness uses bounded polling of application state;
there is no fixed sleep as the synchronization oracle.

Before launching WebdriverIO, the PowerShell harness snapshots existing
`tauri-driver` and `msedgedriver` PIDs. Its `finally` cleanup terminates only
new PIDs from that run and records stopped/remaining IDs as a separate command
in `run.json`. A remaining driver makes the complete run fail.

The dependency set has been exercised successfully without package lifecycle
scripts, which is the mode used by CI. npm currently reports 16 transitive
advisories for the complete frontend development tree (1 moderate, 15 high).
Their applicability and upgrade path require a separate dependency-security
review; this suite does not suppress or auto-fix them.

Each run is written under
`docs/internal/evidence/decision-ui/webdriver-runs/<run-id>/` with:

- `run.json`, validated by `run.schema.json`;
- `webdriver.json`, containing readiness, ACL, terminal, and event assertions;
- `junit/webdriver-readiness-acl.xml`;
- separate WebdriverIO stdout/stderr logs;
- `wdio-exit.json` and `terminal-attempts.log`;
- a per-run WebView2 user-data directory.

The Windows CI entry point is
`.github/workflows/decision-ui-webdriver-windows.yml`, and it uploads the run
directory even when an assertion fails.
