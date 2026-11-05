#!/usr/bin/env python3
"""
CLI Test Runner for Arc E2E Evaluation Suite.

Usage:
  python tests/e2e/runner.py                # Run all scenarios in deterministic mode
  python tests/e2e/runner.py --live         # Run all scenarios with live AGY agent CLI calls
  python tests/e2e/runner.py -s tool_guard_force_push
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

# Add repo root and tests/e2e directory to sys.path
_E2E_DIR = Path(__file__).resolve().parent
_REPO_ROOT = _E2E_DIR.parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))
if str(_E2E_DIR) not in sys.path:
    sys.path.insert(0, str(_E2E_DIR))

from test_scenarios import ALL_SCENARIOS



def main() -> int:
    parser = argparse.ArgumentParser(description="Arc E2E Test Suite Runner for AGY / Gemini Agent")
    parser.add_argument("-s", "--scenario", type=str, help="Specific scenario name to run")
    parser.add_argument("--live", action="store_true", help="Execute live AGY CLI agent invocations")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")

    args = parser.parse_args()

    scenarios_to_run = {}
    if args.scenario:
        if args.scenario not in ALL_SCENARIOS:
            print(f"Error: Unknown scenario '{args.scenario}'. Available: {list(ALL_SCENARIOS.keys())}")
            return 1
        scenarios_to_run[args.scenario] = ALL_SCENARIOS[args.scenario]
    else:
        scenarios_to_run = ALL_SCENARIOS

    print("=" * 70)
    print("ARC AGENT RUNTIME E2E EVALUATION SUITE")
    print(f"Mode: {'LIVE AGENT INVOCATION' if args.live else 'DETERMINISTIC COMPILATION & HOOK ENGINE'}")
    print(f"Scenarios: {len(scenarios_to_run)}")
    print("=" * 70)

    passed = 0
    failed = 0

    for name, func in scenarios_to_run.items():
        print(f"\n[RUNNING] Scenario: {name} ...", end=" ", flush=True)
        start = time.time()
        try:
            success, msg = func(live_agent=args.live)
            elapsed = time.time() - start
            if success:
                print(f"PASS ({elapsed:.2f}s)")
                print(f"  -> {msg}")
                passed += 1
            else:
                print(f"FAIL ({elapsed:.2f}s)")
                print(f"  -> Reason: {msg}")
                failed += 1
        except Exception as e:
            elapsed = time.time() - start
            print(f"ERROR ({elapsed:.2f}s)")
            print(f"  -> Exception: {e}")
            if args.verbose:
                import traceback
                traceback.print_exc()
            failed += 1

    print("\n" + "=" * 70)
    print(f"SUMMARY: {passed} passed, {failed} failed (Total: {len(scenarios_to_run)})")
    repo_root = Path(__file__).resolve().parent.parent.parent
    logs_dir = repo_root / "tests" / "e2e" / "logs"
    print(f"Audit Logs & Transcripts Directory: {logs_dir}")
    print("=" * 70)

    return 0 if failed == 0 else 1



if __name__ == "__main__":
    sys.exit(main())
