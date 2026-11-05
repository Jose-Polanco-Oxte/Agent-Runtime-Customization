from __future__ import annotations

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from provider_contract import DecisionCase
from provider_runner import (
    HarnessConfigurationError,
    HarnessMode,
    HostFamily,
    Provider,
    build_arc_manifest,
    build_provider_command,
    prepare_codex_provider_home,
    prepare_provider_environment,
    require_external_provider_consent,
    sanitize_event_evidence,
    select_matching_session,
)


def captured(
    event_id: int,
    event_type: str,
    *,
    provider: str = "codex",
    session_id: str = "session-a",
    details: dict[str, object] | None = None,
) -> dict[str, object]:
    return {
        "id": event_id,
        "event_type": event_type,
        "provider": provider,
        "session_id": session_id,
        "reason_code": None,
        "details": details or {},
    }


def chain(session_id: str, decision: DecisionCase, start: int) -> list[dict[str, object]]:
    return [
        captured(
            start,
            "DecisionTransportResolved",
            session_id=session_id,
            details={"transport": "arc_embedded_ui"},
        ),
        captured(
            start + 1,
            "DecisionReceived",
            session_id=session_id,
            details={"metadata": {"outcome": {"outcome": decision.value}}},
        ),
        captured(
            start + 2,
            "ProviderOutput",
            session_id=session_id,
            details={
                "capture": "metadata",
                "output_bytes": 12,
                "output_sha256": "c" * 64,
            },
        ),
    ]


class ProviderRunnerTests(unittest.TestCase):
    def test_provider_environment_derives_codex_home_without_overwriting_it(self) -> None:
        prepared = prepare_provider_environment(
            Provider.CODEX,
            {"USERPROFILE": r"C:\Users\fixture"},
        )
        self.assertEqual(prepared["CODEX_HOME"], r"C:\Users\fixture\.codex")

        explicit = prepare_provider_environment(
            Provider.CODEX,
            {
                "USERPROFILE": r"C:\Users\fixture",
                "CODEX_HOME": r"C:\custom\codex",
            },
        )
        self.assertEqual(explicit["CODEX_HOME"], r"C:\custom\codex")

        gemini = prepare_provider_environment(
            Provider.GEMINI,
            {"USERPROFILE": r"C:\Users\fixture"},
        )
        self.assertNotIn("CODEX_HOME", gemini)

    def test_codex_provider_home_copies_only_auth_and_generated_hooks(self) -> None:
        with TemporaryDirectory() as source_name, TemporaryDirectory() as workspace_name:
            source = Path(source_name)
            workspace = Path(workspace_name)
            hook_source = workspace / ".codex" / "hooks.json"
            hook_source.parent.mkdir()
            (source / "auth.json").write_text("opaque-auth-fixture", encoding="utf-8")
            hook_source.write_text('{"hooks": {}}', encoding="utf-8")

            provider_home = prepare_codex_provider_home(
                workspace=workspace,
                source_home=source,
                hook_source=hook_source,
            )

            self.assertEqual(
                (provider_home / "auth.json").read_text(encoding="utf-8"),
                "opaque-auth-fixture",
            )
            self.assertEqual(
                (provider_home / "hooks.json").read_text(encoding="utf-8"),
                '{"hooks": {}}',
            )
            self.assertFalse((provider_home / "config.toml").exists())

    def test_authenticated_mode_requires_explicit_external_provider_consent(self) -> None:
        with self.assertRaisesRegex(
            HarnessConfigurationError,
            "explicit external-provider consent",
        ):
            require_external_provider_consent(
                mode=HarnessMode.AUTHENTICATED,
                allow_external_provider=False,
            )

        require_external_provider_consent(
            mode=HarnessMode.AUTHENTICATED,
            allow_external_provider=True,
        )
        require_external_provider_consent(
            mode=HarnessMode.CONTRACT,
            allow_external_provider=False,
        )

    def test_manifest_uses_host_specific_probe_without_user_paths(self) -> None:
        windows = build_arc_manifest(HostFamily.WINDOWS)
        posix = build_arc_manifest(HostFamily.POSIX)

        self.assertIn("action: ask", windows)
        self.assertIn("powershell -NoProfile", windows)
        self.assertNotIn("sh -c", windows)
        self.assertIn("action: ask", posix)
        self.assertIn("sh -c", posix)
        self.assertNotIn("powershell -NoProfile", posix)
        self.assertNotIn(str(Path.home()), windows)
        self.assertNotIn(str(Path.home()), posix)

    def test_codex_command_is_argv_based_and_keeps_workspace_sandbox(self) -> None:
        spec = build_provider_command(
            Provider.CODEX,
            executable="codex",
            workspace=Path("provider-workspace"),
            prompt="sensitive prompt",
            timeout_seconds=120,
        )

        self.assertEqual(spec.argv[0:2], ("codex", "exec"))
        self.assertIn("--json", spec.argv)
        self.assertIn("--approve-for-me", spec.argv)
        self.assertIn("--enable", spec.argv)
        self.assertIn("hooks", spec.argv)
        self.assertNotIn("--sandbox", spec.argv)
        self.assertNotIn("workspace-write", spec.argv)
        self.assertNotIn("--ask-for-approval", spec.argv)
        self.assertNotIn("--skip-git-repo-check", spec.argv)
        self.assertNotIn("--ignore-user-config", spec.argv)
        self.assertIn("--dangerously-bypass-hook-trust", spec.argv)
        self.assertNotIn("--dangerously-bypass-approvals-and-sandbox", spec.argv)
        self.assertNotIn("sensitive prompt", spec.safe_display)
        self.assertIn("<prompt>", spec.safe_display)
        self.assertNotIn("--ignore-user-config", spec.safe_display)

    def test_gemini_command_is_argv_based_and_bounded(self) -> None:
        spec = build_provider_command(
            Provider.GEMINI,
            executable="agy",
            workspace=Path("provider-workspace"),
            prompt="sensitive prompt",
            timeout_seconds=75,
        )

        self.assertEqual(spec.argv[0], "agy")
        self.assertIn("--print", spec.argv)
        self.assertIn("--output-format", spec.argv)
        self.assertIn("75s", spec.argv)
        self.assertNotIn("sensitive prompt", spec.safe_display)

    def test_selects_one_correlated_provider_session(self) -> None:
        events = chain("unrelated", DecisionCase.ALLOW, 1)
        events.extend(chain("wanted", DecisionCase.DENY, 10))

        session_id, selected = select_matching_session(
            events,
            provider=Provider.CODEX,
            decision=DecisionCase.DENY,
        )

        self.assertEqual(session_id, "wanted")
        self.assertTrue(all(event["session_id"] == "wanted" for event in selected))

    def test_rejects_ambiguous_provider_sessions(self) -> None:
        events = chain("first", DecisionCase.DENY, 1)
        events.extend(chain("second", DecisionCase.DENY, 10))

        with self.assertRaisesRegex(HarnessConfigurationError, "ambiguous"):
            select_matching_session(
                events,
                provider=Provider.CODEX,
                decision=DecisionCase.DENY,
            )

    def test_sanitized_evidence_uses_session_hash_and_allowlisted_details(self) -> None:
        events = chain("sensitive-session", DecisionCase.DENY, 7)
        events[0]["details"] = {
            "transport": "arc_embedded_ui",
            "source": "C:/Users/person/private/arc_ir.json",
        }

        sanitized = sanitize_event_evidence(events, session_id="sensitive-session")

        self.assertRegex(sanitized["session_sha256"], r"^[0-9a-f]{64}$")
        self.assertNotIn("sensitive-session", str(sanitized))
        self.assertNotIn("C:/Users/person", str(sanitized))
        self.assertEqual(
            sanitized["events"][0]["details"],
            {"transport": "arc_embedded_ui"},
        )


if __name__ == "__main__":
    unittest.main()
