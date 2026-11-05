from __future__ import annotations

import argparse
import datetime as dt
import enum
import hashlib
import json
import os
import platform
import shutil
import sqlite3
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path, PureWindowsPath
from typing import Mapping, Sequence

from provider_contract import (
    DecisionCase,
    EvidenceContractError,
    ExecutionMode,
    PresentationMode,
    ProviderE2EResult,
    validate_provider_e2e,
)


class HarnessConfigurationError(ValueError):
    """Raised when a runner input or captured session is ambiguous."""


class HarnessExecutionError(RuntimeError):
    """Raised when a subprocess or persisted evidence violates the harness contract."""


class HostFamily(enum.Enum):
    WINDOWS = "windows"
    POSIX = "posix"


class Provider(enum.Enum):
    CODEX = "codex"
    GEMINI = "gemini"


class HarnessMode(enum.Enum):
    CONTRACT = "contract"
    AUTHENTICATED = "authenticated"


def require_external_provider_consent(
    *, mode: HarnessMode, allow_external_provider: bool
) -> None:
    if mode is HarnessMode.AUTHENTICATED and not allow_external_provider:
        raise HarnessConfigurationError(
            "authenticated mode requires explicit external-provider consent via "
            "--allow-external-provider"
        )


def prepare_provider_environment(
    provider: Provider, environment: Mapping[str, str]
) -> dict[str, str]:
    prepared = dict(environment)
    if provider is not Provider.CODEX or prepared.get("CODEX_HOME", "").strip():
        return prepared

    profile_root = prepared.get("USERPROFILE") or prepared.get("HOME")
    if profile_root:
        if "\\" in profile_root or (len(profile_root) >= 2 and profile_root[1] == ":"):
            prepared["CODEX_HOME"] = str(PureWindowsPath(profile_root) / ".codex")
        else:
            prepared["CODEX_HOME"] = str(Path(profile_root) / ".codex")
    return prepared


def prepare_codex_provider_home(
    *, workspace: Path, source_home: Path, hook_source: Path
) -> Path:
    auth_source = source_home / "auth.json"
    if not auth_source.is_file():
        raise HarnessConfigurationError(
            "Codex local authentication file was not found in the configured provider home"
        )
    if not hook_source.is_file():
        raise HarnessExecutionError("generated Codex hook file was not created")

    provider_home = workspace / ".codex-provider-home"
    provider_home.mkdir()
    shutil.copyfile(auth_source, provider_home / "auth.json")
    shutil.copyfile(hook_source, provider_home / "hooks.json")
    return provider_home


@dataclass(frozen=True)
class CommandSpec:
    argv: tuple[str, ...]
    safe_display: str


@dataclass(frozen=True)
class CommandCapture:
    spec: CommandSpec
    exit_code: int
    stdout: str
    stderr: str
    timed_out: bool


@dataclass(frozen=True)
class HarnessOutcome:
    run_directory: Path
    result: ProviderE2EResult


def build_arc_manifest(host_family: HostFamily) -> str:
    if host_family is HostFamily.WINDOWS:
        probe = (
            "powershell -NoProfile -Command \"if (Test-Path -LiteralPath "
            "'provider-e2e-ready.txt') { 'ready' } else { 'missing' }\""
        )
        remediation = (
            "powershell -NoProfile -Command \"[System.IO.File]::WriteAllText("
            "'provider-e2e-ready.txt','ready')\""
        )
    else:
        probe = (
            "sh -c 'if [ -f provider-e2e-ready.txt ]; then printf ready; "
            "else printf missing; fi'"
        )
        remediation = "printf ready > provider-e2e-ready.txt"

    probe_yaml = json.dumps(probe, ensure_ascii=True)
    feedback_yaml = json.dumps(
        f"Run exactly this remediation command, then finish: {remediation}",
        ensure_ascii=True,
    )
    return (
        'schema: "1.0"\n'
        "root:\n"
        '  workdir: "."\n'
        "runtime:\n"
        "  decision_timeout_seconds: 20\n"
        "guards:\n"
        "  lifecycle:\n"
        "    provider_e2e_completion:\n"
        "      trigger: end\n"
        "      require:\n"
        "        probe:\n"
        f"          use: {probe_yaml}\n"
        "          in:\n"
        '            - "ready"\n'
        "      on_failure:\n"
        "        action: ask\n"
        f"        feedback: {feedback_yaml}\n"
    )


def build_provider_command(
    provider: Provider,
    *,
    executable: str,
    workspace: Path,
    prompt: str,
    timeout_seconds: int,
) -> CommandSpec:
    if not executable.strip():
        raise HarnessConfigurationError("provider executable must not be empty")
    if not prompt.strip():
        raise HarnessConfigurationError("provider prompt must not be empty")
    if timeout_seconds < 1:
        raise HarnessConfigurationError("provider timeout must be positive")

    if provider is Provider.CODEX:
        argv = (
            executable,
            "exec",
            "--json",
            "--color",
            "never",
            "--approve-for-me",
            "--enable",
            "hooks",
            "--dangerously-bypass-hook-trust",
            "--ephemeral",
            "-C",
            str(workspace),
            prompt,
        )
        safe_display = (
            f"{executable} exec --json --color never --approve-for-me "
            "--enable hooks (workspace-write) --dangerously-bypass-hook-trust "
            "--ephemeral "
            "-C <workspace> <prompt>"
        )
    else:
        argv = (
            executable,
            "--print",
            prompt,
            "--output-format",
            "json",
            "--print-timeout",
            f"{timeout_seconds}s",
            "--dangerously-skip-permissions",
            "--disable-slash-commands",
        )
        safe_display = (
            f"{executable} --print <prompt> --output-format json "
            f"--print-timeout {timeout_seconds}s --dangerously-skip-permissions "
            "--disable-slash-commands"
        )
    return CommandSpec(argv=argv, safe_display=safe_display)


def select_matching_session(
    events: Sequence[Mapping[str, object]],
    *,
    provider: Provider,
    decision: DecisionCase,
) -> tuple[str, list[Mapping[str, object]]]:
    grouped: dict[str, list[Mapping[str, object]]] = {}
    for event in events:
        if event.get("provider") != provider.value:
            continue
        session_id = event.get("session_id")
        if not isinstance(session_id, str) or not session_id:
            continue
        grouped.setdefault(session_id, []).append(event)

    candidates: list[tuple[str, list[Mapping[str, object]]]] = []
    for session_id, captured in grouped.items():
        captured.sort(key=_event_sort_key)
        if any(_event_has_decision(event, decision) for event in captured):
            candidates.append((session_id, captured))

    if not candidates:
        raise HarnessConfigurationError(
            f"no {provider.value} session contains decision {decision.value}"
        )
    if len(candidates) != 1:
        raise HarnessConfigurationError(
            f"ambiguous provider evidence: {len(candidates)} sessions contain decision {decision.value}"
        )
    return candidates[0]


def sanitize_event_evidence(
    events: Sequence[Mapping[str, object]], *, session_id: str
) -> dict[str, object]:
    if not session_id:
        raise HarnessConfigurationError("session id must not be empty")
    sanitized_events: list[dict[str, object]] = []
    for event in events:
        event_type = event.get("event_type")
        if not isinstance(event_type, str):
            raise HarnessConfigurationError("captured event type must be a string")
        sanitized_events.append(
            {
                "id": _event_sort_key(event),
                "event_type": event_type,
                "provider": event.get("provider"),
                "reason_code": event.get("reason_code"),
                "details": _sanitize_details(event_type, event.get("details")),
            }
        )
    return {
        "session_sha256": hashlib.sha256(session_id.encode("utf-8")).hexdigest(),
        "events": sanitized_events,
    }


def _event_sort_key(event: Mapping[str, object]) -> int:
    event_id = event.get("id")
    if not isinstance(event_id, int) or isinstance(event_id, bool) or event_id < 0:
        raise HarnessConfigurationError("captured event id must be a non-negative integer")
    return event_id


def _event_has_decision(event: Mapping[str, object], decision: DecisionCase) -> bool:
    if event.get("event_type") != "DecisionReceived":
        return False
    details = event.get("details")
    if not isinstance(details, Mapping):
        return False
    metadata = details.get("metadata")
    if not isinstance(metadata, Mapping):
        return False
    outcome = metadata.get("outcome")
    return isinstance(outcome, Mapping) and outcome.get("outcome") == decision.value


def _sanitize_details(event_type: str, value: object) -> dict[str, object]:
    if not isinstance(value, Mapping):
        return {}
    allowlist: dict[str, tuple[str, ...]] = {
        "DecisionTransportResolved": ("transport", "effective_action"),
        "ProviderOutput": (
            "capture",
            "output_bytes",
            "output_sha256",
            "output_kind",
        ),
        "HookReceived": ("event", "payload_bytes", "capture"),
        "StateTransition": ("disposition",),
    }
    if event_type == "DecisionReceived":
        metadata = value.get("metadata")
        if not isinstance(metadata, Mapping):
            return {}
        outcome = metadata.get("outcome")
        safe_outcome = (
            {"outcome": outcome.get("outcome")}
            if isinstance(outcome, Mapping) and isinstance(outcome.get("outcome"), str)
            else {}
        )
        return {
            "metadata": {
                "outcome": safe_outcome,
                "transport": metadata.get("transport"),
            }
        }
    keys = allowlist.get(event_type, ())
    return {key: value[key] for key in keys if key in value}


def run_provider_harness(
    *,
    repo_root: Path,
    mode: HarnessMode,
    provider: Provider,
    decision: DecisionCase,
    arc_binary: Path,
    fixture_binary: Path,
    provider_executable: str,
    allow_external_provider: bool,
    timeout_seconds: int,
    output_root: Path,
) -> HarnessOutcome:
    require_external_provider_consent(
        mode=mode,
        allow_external_provider=allow_external_provider,
    )
    if decision not in (DecisionCase.ALLOW, DecisionCase.DENY):
        raise HarnessConfigurationError("runner supports only mandatory allow and deny cases")
    if timeout_seconds < 10:
        raise HarnessConfigurationError("runner timeout must be at least 10 seconds")
    arc_binary = arc_binary.resolve()
    fixture_binary = fixture_binary.resolve()
    if not arc_binary.is_file():
        raise HarnessConfigurationError(f"Arc binary was not found: {arc_binary}")
    if not fixture_binary.is_file():
        raise HarnessConfigurationError(
            f"provider decision fixture was not found: {fixture_binary}"
        )

    revision = _git_revision(repo_root)
    run_id = (
        f"provider-{mode.value}-{provider.value}-{decision.value}-"
        f"{dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')}"
    )
    run_directory = output_root.resolve() / run_id
    run_directory.mkdir(parents=True, exist_ok=False)
    captures: list[CommandCapture] = []
    result: ProviderE2EResult | None = None
    sanitized_events: dict[str, object] = {"events": []}
    marker_present = False

    try:
        with tempfile.TemporaryDirectory(prefix="arc-provider-e2e-") as temporary:
            workspace = Path(temporary).resolve()
            state_directory = workspace / ".arc-provider-e2e-state"
            marker = workspace / "provider-e2e-ready.txt"
            manifest_path = workspace / "arc.yaml"
            manifest_path.write_text(
                build_arc_manifest(
                    HostFamily.WINDOWS if os.name == "nt" else HostFamily.POSIX
                ),
                encoding="utf-8",
            )
            environment = prepare_provider_environment(provider, os.environ)
            environment["ARC_BIN"] = str(arc_binary)
            environment["ARC_STATE_DIR"] = str(state_directory)
            environment["ARC_DECISION_UI_HOST"] = str(fixture_binary)
            environment["ARC_PROVIDER_E2E_DECISION"] = decision.value

            git_spec = CommandSpec(
                argv=("git", "init", "--quiet"),
                safe_display="git init --quiet <isolated-workspace>",
            )
            git_capture = _run_command(
                git_spec,
                cwd=workspace,
                environment=environment,
                timeout_seconds=timeout_seconds,
            )
            captures.append(git_capture)
            _require_success(git_capture, "isolated provider workspace initialization")

            build_spec = CommandSpec(
                argv=(
                    str(arc_binary),
                    "build",
                    "--target",
                    provider.value,
                    "--os",
                    "host",
                    "--path",
                    str(manifest_path),
                ),
                safe_display=(
                    f"<arc> build --target {provider.value} --os host --path <workspace>"
                ),
            )
            build_capture = _run_command(
                build_spec,
                cwd=workspace,
                environment=environment,
                timeout_seconds=timeout_seconds,
            )
            captures.append(build_capture)
            _require_success(build_capture, "Arc fixture workspace build")

            ir_path = workspace / (
                ".codex/arc_ir.json"
                if provider is Provider.CODEX
                else ".agents/arc_ir.json"
            )
            if not ir_path.is_file():
                raise HarnessExecutionError("Arc build did not emit the provider IR")

            if mode is HarnessMode.CONTRACT:
                session_id = f"arc-provider-contract-{provider.value}-{decision.value}"
                first_capture = _run_hook(
                    arc_binary=arc_binary,
                    ir_path=ir_path,
                    workspace=workspace,
                    environment=environment,
                    provider=provider,
                    session_id=session_id,
                    reentry=False,
                    timeout_seconds=timeout_seconds,
                )
                captures.append(first_capture)
                _require_success(first_capture, "first simulated provider hook")
                _assert_hook_output(first_capture.stdout, provider, decision, reentry=False)
                if decision is DecisionCase.ALLOW:
                    marker.write_text("ready", encoding="utf-8")
                    reentry_capture = _run_hook(
                        arc_binary=arc_binary,
                        ir_path=ir_path,
                        workspace=workspace,
                        environment=environment,
                        provider=provider,
                        session_id=session_id,
                        reentry=True,
                        timeout_seconds=timeout_seconds,
                    )
                    captures.append(reentry_capture)
                    _require_success(reentry_capture, "simulated provider re-entry hook")
                    _assert_hook_output(
                        reentry_capture.stdout,
                        provider,
                        decision,
                        reentry=True,
                    )
                provider_exit_code = 0
                execution_mode = ExecutionMode.SIMULATED_HOOK
            else:
                if provider is Provider.CODEX:
                    source_home = Path(environment["CODEX_HOME"])
                    provider_home = prepare_codex_provider_home(
                        workspace=workspace,
                        source_home=source_home,
                        hook_source=workspace / ".codex/hooks.json",
                    )
                    environment["CODEX_HOME"] = str(provider_home)
                prompt = _provider_prompt()
                provider_spec = build_provider_command(
                    provider,
                    executable=provider_executable,
                    workspace=workspace,
                    prompt=prompt,
                    timeout_seconds=timeout_seconds,
                )
                provider_capture = _run_command(
                    provider_spec,
                    cwd=workspace,
                    environment=environment,
                    timeout_seconds=timeout_seconds,
                )
                captures.append(provider_capture)
                _require_success(provider_capture, "authenticated provider session")
                provider_exit_code = provider_capture.exit_code
                execution_mode = ExecutionMode.AUTHENTICATED_PROVIDER
                session_id = ""

            marker_present = marker.is_file()
            captured_events = _read_events(state_directory / "runtime-state.sqlite3")
            if mode is HarnessMode.AUTHENTICATED:
                session_id, selected_events = select_matching_session(
                    captured_events,
                    provider=provider,
                    decision=decision,
                )
            else:
                selected_events = [
                    event
                    for event in captured_events
                    if event.get("provider") == provider.value
                    and event.get("session_id") == session_id
                ]
            selected_events.sort(key=_event_sort_key)
            sanitized_events = sanitize_event_evidence(
                selected_events,
                session_id=session_id,
            )
            result = validate_provider_e2e(
                selected_events,
                expected_provider=provider.value,
                expected_session_id=session_id,
                decision=decision,
                execution_mode=execution_mode,
                presentation=PresentationMode.SCRIPTED_SIDECAR,
                provider_exit_code=provider_exit_code,
                remediation_marker_present=marker_present,
            )
    except (
        EvidenceContractError,
        HarnessConfigurationError,
        HarnessExecutionError,
        OSError,
        sqlite3.Error,
        json.JSONDecodeError,
    ) as error:
        _write_evidence(
            run_directory=run_directory,
            repo_root=repo_root,
            revision=revision,
            mode=mode,
            provider=provider,
            decision=decision,
            arc_binary=arc_binary,
            fixture_binary=fixture_binary,
            provider_executable=provider_executable,
            captures=captures,
            result=result,
            sanitized_events=sanitized_events,
            marker_present=marker_present,
            failure=_sanitize_failure(str(error), (arc_binary, fixture_binary)),
        )
        raise HarnessExecutionError(
            f"provider harness failed; sanitized evidence: {run_directory}"
        ) from error

    if result is None:
        raise HarnessExecutionError("provider harness completed without a result")
    _write_evidence(
        run_directory=run_directory,
        repo_root=repo_root,
        revision=revision,
        mode=mode,
        provider=provider,
        decision=decision,
        arc_binary=arc_binary,
        fixture_binary=fixture_binary,
        provider_executable=provider_executable,
        captures=captures,
        result=result,
        sanitized_events=sanitized_events,
        marker_present=marker_present,
        failure=None,
    )
    return HarnessOutcome(run_directory=run_directory, result=result)


def _run_hook(
    *,
    arc_binary: Path,
    ir_path: Path,
    workspace: Path,
    environment: Mapping[str, str],
    provider: Provider,
    session_id: str,
    reentry: bool,
    timeout_seconds: int,
) -> CommandCapture:
    payload = _hook_payload(provider, session_id, workspace, reentry)
    spec = CommandSpec(
        argv=(
            str(arc_binary),
            "hook",
            "run",
            "--event-type",
            "stop",
            "--provider",
            provider.value,
            "--decision-ui",
            "native",
            "--ir-path",
            str(ir_path),
        ),
        safe_display=(
            f"<arc> hook run --event-type stop --provider {provider.value} "
            "--decision-ui native --ir-path <provider-ir>"
        ),
    )
    return _run_command(
        spec,
        cwd=workspace,
        environment=environment,
        timeout_seconds=timeout_seconds,
        stdin_text=json.dumps(payload, separators=(",", ":")),
    )


def _hook_payload(
    provider: Provider, session_id: str, workspace: Path, reentry: bool
) -> dict[str, object]:
    if provider is Provider.CODEX:
        return {
            "hook_event_name": "Stop",
            "session_id": session_id,
            "turn_id": "provider-e2e-turn",
            "cwd": str(workspace),
            "stop_hook_active": reentry,
        }
    return {
        "executionNum": 2 if reentry else 1,
        "terminationReason": "model_stop",
        "error": "",
        "fullyIdle": True,
        "conversationId": session_id,
    }


def _run_command(
    spec: CommandSpec,
    *,
    cwd: Path,
    environment: Mapping[str, str],
    timeout_seconds: int,
    stdin_text: str | None = None,
) -> CommandCapture:
    try:
        completed = subprocess.run(
            spec.argv,
            cwd=cwd,
            env=dict(environment),
            input=stdin_text,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout_seconds,
            check=False,
            shell=False,
        )
        return CommandCapture(
            spec=spec,
            exit_code=completed.returncode,
            stdout=completed.stdout,
            stderr=completed.stderr,
            timed_out=False,
        )
    except subprocess.TimeoutExpired as error:
        return CommandCapture(
            spec=spec,
            exit_code=-1,
            stdout=_timeout_text(error.stdout),
            stderr=_timeout_text(error.stderr),
            timed_out=True,
        )


def _timeout_text(value: str | bytes | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value


def _require_success(capture: CommandCapture, phase: str) -> None:
    if capture.timed_out:
        raise HarnessExecutionError(f"{phase} exceeded its supervisor timeout")
    if capture.exit_code != 0:
        raise HarnessExecutionError(f"{phase} exited with code {capture.exit_code}")


def _assert_hook_output(
    stdout: str, provider: Provider, decision: DecisionCase, *, reentry: bool
) -> None:
    output = json.loads(stdout.strip())
    if not isinstance(output, dict):
        raise HarnessExecutionError("provider hook output is not a JSON object")
    if reentry:
        if provider is Provider.CODEX and output != {}:
            raise HarnessExecutionError("Codex re-entry did not release the satisfied guard")
        if provider is Provider.GEMINI and output.get("decision") != "stop":
            raise HarnessExecutionError("Gemini re-entry did not stop after remediation")
        return
    if provider is Provider.CODEX:
        if decision is DecisionCase.ALLOW and output.get("decision") != "block":
            raise HarnessExecutionError("Codex Allow did not request remediation re-entry")
        if decision is DecisionCase.DENY and output.get("decision") is not None:
            raise HarnessExecutionError("Codex Deny did not release session completion")
    else:
        expected = "continue" if decision is DecisionCase.ALLOW else "stop"
        if output.get("decision") != expected:
            raise HarnessExecutionError(
                f"Gemini {decision.value} emitted an unexpected stop decision"
            )


def _read_events(database: Path) -> list[dict[str, object]]:
    if not database.is_file():
        raise HarnessExecutionError("Arc observability database was not created")
    connection = sqlite3.connect(database)
    try:
        rows = connection.execute(
            "SELECT id, event_type, provider, session_id, reason_code, details_json "
            "FROM observability_events "
            "WHERE event_type IN ("
            "'DecisionTransportResolved','DecisionReceived','ProviderOutput',"
            "'HookReceived','StateTransition') ORDER BY id ASC"
        ).fetchall()
    finally:
        connection.close()
    events: list[dict[str, object]] = []
    for event_id, event_type, provider, session_id, reason_code, details_json in rows:
        events.append(
            {
                "id": event_id,
                "event_type": event_type,
                "provider": provider,
                "session_id": session_id,
                "reason_code": reason_code,
                "details": json.loads(details_json),
            }
        )
    return events


def _provider_prompt() -> str:
    return (
        "This is an isolated Arc provider E2E fixture. Do not create "
        "provider-e2e-ready.txt before your first attempt to finish. Reply briefly and finish. "
        "If Arc blocks stopping and supplies one exact remediation command, execute that exact "
        "command once and then finish. Do not modify any other file."
    )


def _write_evidence(
    *,
    run_directory: Path,
    repo_root: Path,
    revision: str,
    mode: HarnessMode,
    provider: Provider,
    decision: DecisionCase,
    arc_binary: Path,
    fixture_binary: Path,
    provider_executable: str,
    captures: Sequence[CommandCapture],
    result: ProviderE2EResult | None,
    sanitized_events: Mapping[str, object],
    marker_present: bool,
    failure: str | None,
) -> None:
    command_records: list[dict[str, object]] = []
    for index, capture in enumerate(captures, start=1):
        stdout_name = f"command-{index:02d}.stdout.log"
        stderr_name = f"command-{index:02d}.stderr.log"
        _write_redacted_stream(run_directory / stdout_name, capture.stdout)
        _write_redacted_stream(run_directory / stderr_name, capture.stderr)
        command_records.append(
            {
                "command": capture.spec.safe_display,
                "working_directory": "<isolated-workspace>",
                "exit_code": capture.exit_code,
                "result": "PASS" if capture.exit_code == 0 else "FAIL",
                "stdout_log": stdout_name,
                "stderr_log": stderr_name,
                "notes": f"timed_out={str(capture.timed_out).lower()}",
            }
        )

    overall = "PASS" if result is not None and failure is None else "FAIL"
    provider_status = result.provider_e2e_status if result is not None else "NOT-RUN"
    live_status = result.live_ui_status if result is not None else "NOT-RUN"
    evidence = {
        "schema_version": "1.0",
        "mode": mode.value,
        "provider": provider.value,
        "decision": decision.value,
        "presentation": PresentationMode.SCRIPTED_SIDECAR.value,
        "result": overall,
        "provider_e2e_status": provider_status,
        "live_ui_status": live_status,
        "remediation_marker_present": marker_present,
        "binary_hashes": {
            "arc_sha256": _sha256_file(arc_binary),
            "fixture_sha256": _sha256_file(fixture_binary),
        },
        "chain_event_ids": list(result.chain_event_ids) if result is not None else [],
        "limitations": list(result.limitations) if result is not None else [],
        "failure": failure,
        "captured": sanitized_events,
    }
    (run_directory / "evidence.json").write_text(
        json.dumps(evidence, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    platform_name = platform.system() or os.name
    cases = [
        {
            "case_id": f"DUI008-provider-contract-{provider.value}-{decision.value}",
            "finding_ids": ["DUI-008"],
            "layer": "provider contract fixture",
            "platform": platform_name,
            "result": overall,
            "artifact": "evidence.json",
        },
        {
            "case_id": f"DUI011-provider-chain-reentry-{provider.value}-{decision.value}",
            "finding_ids": ["DUI-011"],
            "layer": "provider E2E with scripted sidecar",
            "platform": provider.value,
            "result": provider_status,
            "artifact": "evidence.json",
        },
        {
            "case_id": "DUI011-live-ui-excluded",
            "finding_ids": ["DUI-011"],
            "layer": "live desktop UI",
            "platform": platform_name,
            "result": live_status,
            "artifact": "evidence.json",
        },
        {
            "case_id": f"DUI008-cross-platform-contract-{platform_name.lower()}",
            "finding_ids": ["DUI-008"],
            "layer": "cross-platform provider contract",
            "platform": platform_name,
            "result": overall,
            "artifact": "evidence.json",
        },
    ]
    run_record = {
        "run_id": run_directory.name,
        "plan": "PLAN-20260829-DECISION-UI-TAURI-SVELTE-REMEDIATION.md",
        "revision": revision,
        "platform": {
            "os": platform_name,
            "shell": "Python subprocess argv",
            "interactive_desktop": False,
        },
        "toolchains": {
            "python": f"{platform.python_implementation()} {platform.python_version()}",
            "rustc": _version(("rustc", "--version")),
            "provider": _version((provider_executable, "--version")),
        },
        "commands": command_records,
        "cases": cases,
    }
    (run_directory / "run.json").write_text(
        json.dumps(run_record, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _write_redacted_stream(path: Path, content: str) -> None:
    digest = hashlib.sha256(content.encode("utf-8")).hexdigest()
    path.write_text(
        f"redacted=true\nbytes={len(content.encode('utf-8'))}\nsha256={digest}\n",
        encoding="utf-8",
    )


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _git_revision(repo_root: Path) -> str:
    completed = subprocess.run(
        ("git", "rev-parse", "HEAD"),
        cwd=repo_root,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=10,
        check=False,
        shell=False,
    )
    revision = completed.stdout.strip()
    if completed.returncode != 0 or len(revision) != 40:
        raise HarnessConfigurationError("repository revision could not be resolved")
    return revision


def _version(argv: tuple[str, ...]) -> str:
    try:
        completed = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=10,
            check=False,
            shell=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return "unavailable"
    output = (completed.stdout or completed.stderr).strip().splitlines()
    return output[0][:256] if completed.returncode == 0 and output else "unavailable"


def _provider_version_binary(provider: Provider) -> str:
    return "codex" if provider is Provider.CODEX else "agy"


def _sanitize_failure(message: str, paths: Sequence[Path]) -> str:
    sanitized = message
    for path in paths:
        sanitized = sanitized.replace(str(path), "<binary>")
    return sanitized[:512]


def _default_binary(repo_root: Path, relative: str) -> Path:
    suffix = ".exe" if os.name == "nt" else ""
    return repo_root / f"{relative}{suffix}"


def _parse_arguments(argv: Sequence[str]) -> argparse.Namespace:
    repo_root = Path(__file__).resolve().parents[2]
    parser = argparse.ArgumentParser(
        description="Arc provider E2E and cross-platform contract harness"
    )
    parser.add_argument("--mode", choices=[mode.value for mode in HarnessMode], required=True)
    parser.add_argument("--provider", choices=[item.value for item in Provider], required=True)
    parser.add_argument(
        "--decision",
        choices=[DecisionCase.ALLOW.value, DecisionCase.DENY.value],
        required=True,
    )
    parser.add_argument(
        "--arc-bin",
        type=Path,
        default=_default_binary(repo_root, "target/debug/arc"),
    )
    parser.add_argument(
        "--fixture-bin",
        type=Path,
        default=_default_binary(
            repo_root, "target/debug/examples/provider_decision_host"
        ),
    )
    parser.add_argument("--provider-bin", type=str)
    parser.add_argument(
        "--allow-external-provider",
        action="store_true",
        help=(
            "acknowledge that authenticated mode uses local provider credentials "
            "and contacts the external provider with the fixed isolated fixture prompt"
        ),
    )
    parser.add_argument("--timeout-seconds", type=int, default=240)
    parser.add_argument(
        "--output-root",
        type=Path,
        default=repo_root / "docs/internal/evidence/decision-ui/provider-e2e-runs",
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = _parse_arguments(sys.argv[1:] if argv is None else argv)
    repo_root = Path(__file__).resolve().parents[2]
    provider = Provider(args.provider)
    provider_binary = args.provider_bin or _provider_version_binary(provider)
    try:
        outcome = run_provider_harness(
            repo_root=repo_root,
            mode=HarnessMode(args.mode),
            provider=provider,
            decision=DecisionCase(args.decision),
            arc_binary=args.arc_bin,
            fixture_binary=args.fixture_bin,
            provider_executable=provider_binary,
            allow_external_provider=args.allow_external_provider,
            timeout_seconds=args.timeout_seconds,
            output_root=args.output_root,
        )
    except (HarnessConfigurationError, HarnessExecutionError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1
    print(f"RUN_DIRECTORY={outcome.run_directory}")
    print(f"CONTRACT_STATUS={outcome.result.contract_status}")
    print(f"PROVIDER_E2E_STATUS={outcome.result.provider_e2e_status}")
    print(f"LIVE_UI_STATUS={outcome.result.live_ui_status}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
