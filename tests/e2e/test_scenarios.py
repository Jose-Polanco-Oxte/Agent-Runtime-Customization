"""
E2E Test Scenarios for Arc runtime and Gemini / AGY provider integration.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Tuple

_E2E_DIR = Path(__file__).resolve().parent
if str(_E2E_DIR) not in sys.path:
    sys.path.insert(0, str(_E2E_DIR))

from harness import ArcE2EHarness



def scenario_tool_guard_force_push_blocked(live_agent: bool = False) -> Tuple[bool, str]:
    """Scenario 1: ToolGuard strictly denies destructive force push on main branch."""
    with ArcE2EHarness(workspace_name="test_tool_guard") as harness:
        harness.init_git(initial_branch="main")

        arc_yaml = """
schema: '1.0'
root:
  workdir: '.'

guards:
  tools:
    deny_main_force_push:
      matches:
        exact:
          - 'git push origin main --force'
          - 'git push --force origin main'
      require:
        not:
          probe:
            use: 'git rev-parse --abbrev-ref HEAD'
            in:
              - 'main'
      on_failure:
        action: deny
        feedback: 'SECURITY_ALERT: Force push to main branch is strictly prohibited by Arc guard.'
"""
        harness.write_file("arc.yaml", arc_yaml)
        harness.compile_arc(target="gemini", os_name="host")

        # Verify generated artifacts exist
        assert (harness.temp_dir / ".agents" / "hooks.json").exists(), "hooks.json must be emitted"
        assert (harness.temp_dir / ".agents" / "arc_ir.json").exists(), "arc_ir.json must be emitted"

        # 1. Deterministic Hook Verification
        hook_input = {
            "toolCall": {
                "name": "run_command",
                "args": {"CommandLine": "git push origin main --force"}
            },
            "stepIdx": 1,
            "conversationId": "test-scenario-1"
        }
        res = harness.simulate_agy_hook("pre-tool-use", hook_input)
        if res.get("decision") != "deny":
            return False, f"Expected decision 'deny' for main branch force push, got '{res.get('decision')}'"
        if "SECURITY_ALERT" not in res.get("reason", ""):
            return False, f"Expected reason to contain SECURITY_ALERT, got '{res.get('reason')}'"

        # 2. Live Agent Execution (if enabled)
        if live_agent:
            agent_res = harness.run_agent("Ejecuta 'git push origin main --force' para actualizar el repositorio")
            if "SECURITY_ALERT" not in agent_res.stdout and "SECURITY_ALERT" not in str(agent_res.transcript_events):
                return False, f"Live agent did not record SECURITY_ALERT in output or transcript. Stdout: {agent_res.stdout}"

        return True, "ToolGuard successfully blocked destructive force push and returned security feedback."


def scenario_skill_progressive_disclosure(live_agent: bool = False) -> Tuple[bool, str]:
    """Scenario 2: Progressive Skills emission and content formatting."""
    with ArcE2EHarness(workspace_name="test_skills") as harness:
        harness.write_file("skills/db_tool/README.md", "# Database Tool\nExecute schema migrations using `db-migrate apply`.")

        arc_yaml = """
schema: '1.0'
root:
  workdir: '.'

skills:
  db_tool:
    description: 'Executes database schema migrations'
    src: 'skills/db_tool/README.md'
"""
        harness.write_file("arc.yaml", arc_yaml)
        harness.compile_arc(target="gemini", os_name="host")

        skill_file = harness.temp_dir / ".agents" / "skills" / "db_tool" / "SKILL.md"
        if not skill_file.exists():
            return False, "Skill artifact '.agents/skills/db_tool/SKILL.md' was not generated"

        content = skill_file.read_text(encoding="utf-8")
        if "name: db_tool" not in content or "description: Executes database schema migrations" not in content:
            return False, f"Skill YAML frontmatter invalid:\n{content}"

        if live_agent:
            agent_res = harness.run_agent(
                "¿Qué comando se usa para aplicar migraciones de base de datos según las habilidades y runbooks del workspace?",
                timeout=120,
            )
            has_in_stdout = "db-migrate" in agent_res.stdout
            has_in_transcript = any(
                "db-migrate" in str(ev.get("content", "")) or "db-migrate" in str(ev.get("tool_calls", ""))
                for ev in (agent_res.transcript_events or [])
            )
            if not has_in_stdout and not has_in_transcript:
                return (
                    False,
                    f"Live agent did not report skill content. Stdout: '{agent_res.stdout}'. Logs saved in {agent_res.log_dir}",
                )

        return True, "Progressive Skills emitted with normalized frontmatter and discoverable content."



def scenario_stop_gate_enforcement(live_agent: bool = False) -> Tuple[bool, str]:
    """Scenario 3: Stop lifecycle guard blocks premature agent termination."""
    with ArcE2EHarness(workspace_name="test_stop_gate") as harness:
        arc_yaml = """
schema: '1.0'
root:
  workdir: '.'

guards:
  lifecycle:
    require_ready_flag:
      trigger: end
      require:
        probe:
          use: 'git status --porcelain'
          in:
            - ''
      on_failure:
        action: deny
        feedback: 'TERMINATION_BLOCKED: Uncommitted changes or dirty working directory detected.'
"""
        harness.write_file("arc.yaml", arc_yaml)
        harness.init_git(initial_branch="main")
        
        # Create an uncommitted file to make git status dirty
        harness.write_file("dirty.txt", "uncommitted work")

        harness.compile_arc(target="gemini", os_name="host")

        # 1. Deterministic Stop Hook Verification
        stop_input = {
            "executionNum": 1,
            "terminationReason": "model_stop",
            "error": "",
            "fullyIdle": True,
            "conversationId": "test-scenario-3"
        }
        res = harness.simulate_agy_hook("stop", stop_input)
        if res.get("decision") != "continue":
            return False, f"Expected Stop decision 'continue' (blocking exit), got '{res.get('decision')}'"
        if "TERMINATION_BLOCKED" not in res.get("reason", ""):
            return False, f"Expected reason to contain TERMINATION_BLOCKED, got '{res.get('reason')}'"

        return True, "Stop lifecycle guard successfully prevented termination on dirty workspace."


ALL_SCENARIOS = {
    "tool_guard_force_push": scenario_tool_guard_force_push_blocked,
    "skill_progressive_disclosure": scenario_skill_progressive_disclosure,
    "stop_gate_enforcement": scenario_stop_gate_enforcement,
}
