"""
Arc E2E Test Harness for Antigravity (AGY) / Gemini Agent Validation.

Provides isolated workspace setup, Arc compilation, headless AGY agent execution,
transcript inspection, and multi-layer assertion utilities.
"""

from __future__ import annotations

import datetime
import json
import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass
class AgentExecutionResult:
    returncode: int
    stdout: str
    stderr: str
    command_executed: List[str]
    transcript_path: Optional[Path] = None
    transcript_events: Optional[List[Dict[str, Any]]] = None
    log_dir: Optional[Path] = None


class ArcE2EHarness:
    """Manages an isolated test workspace and structured logs for live agent evaluation."""

    def __init__(self, workspace_name: str = "arc_e2e_sandbox", arc_bin: Optional[str] = None):
        self.workspace_name = workspace_name
        self.temp_dir = Path(tempfile.mkdtemp(prefix=f"{workspace_name}_"))
        self.arc_bin = arc_bin or self._find_arc_binary()

        # Create persistent logs directory inside tests/e2e/logs/<timestamp>_<name>
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        repo_root = Path(__file__).resolve().parent.parent.parent
        self.log_dir = repo_root / "tests" / "e2e" / "logs" / f"{timestamp}_{workspace_name}"
        self.log_dir.mkdir(parents=True, exist_ok=True)

    def _find_arc_binary(self) -> str:
        # 1. Check environment variable first
        if os.environ.get("ARC_BIN"):
            return os.environ["ARC_BIN"]

        # 2. Check installed binary via PATH (e.g. ~/.cargo/bin/arc.exe)
        which_arc = shutil.which("arc")
        if which_arc:
            return which_arc

        # 3. Check release then debug target candidates
        repo_root = Path(__file__).resolve().parent.parent.parent
        candidates = [
            repo_root / "target" / "release" / "arc.exe",
            repo_root / "target" / "release" / "arc",
            repo_root / "target" / "debug" / "arc.exe",
            repo_root / "target" / "debug" / "arc",
        ]
        for c in candidates:
            if c.exists():
                return str(c)

        return "arc"


    def write_file(self, relative_path: str | Path, content: str) -> Path:
        target = self.temp_dir / relative_path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
        return target

    def init_git(self, initial_branch: str = "main") -> None:
        subprocess.run(["git", "init", "-b", initial_branch], cwd=self.temp_dir, check=True, capture_output=True)
        subprocess.run(["git", "config", "user.name", "ArcTestBot"], cwd=self.temp_dir, check=True, capture_output=True)
        subprocess.run(["git", "config", "user.email", "arc-bot@example.com"], cwd=self.temp_dir, check=True, capture_output=True)
        subprocess.run(["git", "commit", "--allow-empty", "-m", "Initial commit"], cwd=self.temp_dir, check=True, capture_output=True)

    def _run_arc_cmd(self, args: List[str], input_text: Optional[str] = None) -> subprocess.CompletedProcess[str]:
        env = os.environ.copy()
        env["ARC_BIN"] = self.arc_bin

        # Attempt 1: direct binary execution
        cmd = [self.arc_bin] + args
        try:
            return subprocess.run(cmd, cwd=self.temp_dir, input=input_text, capture_output=True, text=True, env=env)
        except OSError as e:
            # Fallback if Windows Application Control blocks unsigned binary invocation
            repo_root = Path(__file__).resolve().parent.parent.parent
            cargo_cmd = ["cargo", "run", "--quiet", "--bin", "arc", "--manifest-path", str(repo_root / "Cargo.toml"), "--"] + args
            return subprocess.run(cargo_cmd, cwd=self.temp_dir, input=input_text, capture_output=True, text=True, env=env)

    def compile_arc(self, target: str = "gemini", os_name: str = "host") -> subprocess.CompletedProcess[str]:
        args = ["build", "--target", target, "--os", os_name]
        res = self._run_arc_cmd(args)

        # Log build output
        (self.log_dir / "arc_build_stdout.log").write_text(res.stdout, encoding="utf-8")
        (self.log_dir / "arc_build_stderr.log").write_text(res.stderr, encoding="utf-8")

        if res.returncode != 0:
            raise RuntimeError(f"Arc compilation failed with code {res.returncode}:\nStdout: {res.stdout}\nStderr: {res.stderr}")
        return res

    def run_agent(self, prompt: str, timeout: int = 60, output_format: str = "text") -> AgentExecutionResult:
        """Executes AGY CLI headlessly in this workspace with the given prompt and archives logs."""
        cli_log_path = self.log_dir / "agy_cli.log"
        cmd = [
            "agy",
            "--print",
            prompt,
            "--output-format",
            output_format,
            "--print-timeout",
            f"{timeout}s",
            "--log-file",
            str(cli_log_path),
            "--dangerously-skip-permissions",
        ]

        env = os.environ.copy()
        env["ARC_BIN"] = self.arc_bin

        res = subprocess.run(cmd, cwd=self.temp_dir, capture_output=True, text=True, env=env)

        # Save stdout and stderr
        (self.log_dir / "agent_stdout.log").write_text(res.stdout, encoding="utf-8")
        (self.log_dir / "agent_stderr.log").write_text(res.stderr, encoding="utf-8")

        transcript_path = self._discover_latest_transcript()
        transcript_events = []
        if transcript_path and transcript_path.exists():
            # Copy transcript into our test log directory for audit
            shutil.copy2(transcript_path, self.log_dir / "transcript.jsonl")
            transcript_events = self._parse_transcript(transcript_path)

        metadata = {
            "workspace_name": self.workspace_name,
            "prompt": prompt,
            "returncode": res.returncode,
            "cmd": cmd,
            "transcript_found": transcript_path is not None,
            "transcript_path": str(transcript_path) if transcript_path else None,
            "events_count": len(transcript_events),
        }
        (self.log_dir / "execution_metadata.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")

        return AgentExecutionResult(
            returncode=res.returncode,
            stdout=res.stdout,
            stderr=res.stderr,
            command_executed=cmd,
            transcript_path=transcript_path,
            transcript_events=transcript_events,
            log_dir=self.log_dir,
        )

    def simulate_agy_hook(self, event_type: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Simulates AGY invoking `arc hook run` directly through stdin/stdout and logs the exchange."""
        input_json = json.dumps(payload)

        # Log simulated input
        (self.log_dir / f"hook_{event_type}_input.json").write_text(input_json, encoding="utf-8")

        args = ["hook", "run", "--event-type", event_type, "--ir-path", str(self.temp_dir / ".agents" / "arc_ir.json")]
        res = self._run_arc_cmd(args, input_text=input_json)

        (self.log_dir / f"hook_{event_type}_stdout.log").write_text(res.stdout, encoding="utf-8")
        (self.log_dir / f"hook_{event_type}_stderr.log").write_text(res.stderr, encoding="utf-8")

        if res.returncode != 0:
            raise RuntimeError(f"arc hook run failed with code {res.returncode}:\nStdout: {res.stdout}\nStderr: {res.stderr}")

        output_data = json.loads(res.stdout.strip())
        (self.log_dir / f"hook_{event_type}_output.json").write_text(json.dumps(output_data, indent=2), encoding="utf-8")
        return output_data


    def _discover_latest_transcript(self) -> Optional[Path]:
        # Search ~/.gemini/antigravity/brain/*/transcript.jsonl
        app_data = Path(os.environ.get("USERPROFILE", os.environ.get("HOME", ""))) / ".gemini" / "antigravity" / "brain"
        if not app_data.exists():
            return None

        transcripts = list(app_data.glob("*/.system_generated/logs/transcript.jsonl"))
        if not transcripts:
            return None
        # Return most recently modified transcript
        transcripts.sort(key=lambda p: p.stat().st_mtime, reverse=True)
        return transcripts[0]

    def _parse_transcript(self, transcript_path: Path) -> List[Dict[str, Any]]:
        events = []
        if not transcript_path.exists():
            return events
        with open(transcript_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        events.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass
        return events

    def cleanup(self) -> None:
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def __enter__(self) -> ArcE2EHarness:
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.cleanup()

