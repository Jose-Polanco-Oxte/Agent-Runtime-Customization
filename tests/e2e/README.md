# Arc Agent E2E Evaluation Suite

This directory contains the automated End-to-End (E2E) testing framework designed to evaluate and verify that compiled Arc agent configurations (`.agents/`) control real agent behavior as expected when running with **Google Antigravity (AGY)** and the **Gemini** provider.

The decision-UI provider chain has a separate, stricter harness in
[`tests/provider_e2e`](../provider_e2e/README.md). It validates ordered Arc
observability events, Allow/Deny continuation, sanitized evidence, Codex and
Gemini adapters, and cross-platform execution without treating a scripted
sidecar as live UI acceptance.

---

## Architecture

The harness decouples test orchestration from the core compiler:

```
tests/e2e/
├── harness.py          # ArcE2EHarness: Sandbox creation, compilation, AGY driver, transcript parser
├── test_scenarios.py   # Concrete test cases (Negative Gates, Progressive Skills, Stop Guard, etc.)
├── runner.py           # CLI test runner
└── README.md           # Documentation
```

---

## Running the E2E Suite

### 1. Deterministic Mode (Fast / CI-Ready)
Tests full workspace creation, `arc build`, artifact integrity, and simulates AGY hook interception via `arc hook run`:

```bash
python tests/e2e/runner.py
```

### 2. Live Agent Mode
Spawns actual headless AGY sessions (`agy --print "<prompt>"`) against the compiled workspace and validates agent transcripts:

```bash
python tests/e2e/runner.py --live
```

### 3. Run a Specific Scenario
```bash
python tests/e2e/runner.py -s tool_guard_force_push
```

---

## Adding New Scenarios

To add a new scenario:
1. Define a function `scenario_<name>(live_agent: bool) -> Tuple[bool, str]` in `test_scenarios.py`.
2. Register it in `ALL_SCENARIOS`.
