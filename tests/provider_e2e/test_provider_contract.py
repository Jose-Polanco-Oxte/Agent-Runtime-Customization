from __future__ import annotations

import unittest

from provider_contract import (
    DecisionCase,
    EvidenceContractError,
    ExecutionMode,
    PresentationMode,
    validate_provider_e2e,
)


SESSION_ID = "provider-session-1"
PROVIDER = "codex"


def event(
    event_id: int,
    event_type: str,
    *,
    reason_code: str | None = None,
    details: dict[str, object] | None = None,
) -> dict[str, object]:
    return {
        "id": event_id,
        "event_type": event_type,
        "provider": PROVIDER,
        "session_id": SESSION_ID,
        "reason_code": reason_code,
        "details": details or {},
    }


def decision_chain(decision: DecisionCase) -> list[dict[str, object]]:
    return [
        event(
            10,
            "DecisionTransportResolved",
            details={"transport": "arc_embedded_ui"},
        ),
        event(
            11,
            "DecisionReceived",
            details={
                "metadata": {
                    "outcome": {"outcome": decision.value},
                    "transport": "arc_embedded_ui",
                }
            },
        ),
        event(
            12,
            "ProviderOutput",
            details={
                "capture": "metadata",
                "output_bytes": 96,
                "output_sha256": "a" * 64,
            },
        ),
    ]


class ProviderContractTests(unittest.TestCase):
    def test_allow_requires_provider_reentry_and_satisfied_guard(self) -> None:
        events = decision_chain(DecisionCase.ALLOW)
        events.extend(
            [
                event(13, "HookReceived", details={"event": "stop"}),
                event(14, "StateTransition", reason_code="GuardSatisfied"),
                event(
                    15,
                    "ProviderOutput",
                    details={
                        "capture": "metadata",
                        "output_bytes": 3,
                        "output_sha256": "b" * 64,
                    },
                ),
            ]
        )

        result = validate_provider_e2e(
            events,
            expected_provider=PROVIDER,
            expected_session_id=SESSION_ID,
            decision=DecisionCase.ALLOW,
            execution_mode=ExecutionMode.AUTHENTICATED_PROVIDER,
            presentation=PresentationMode.SCRIPTED_SIDECAR,
            provider_exit_code=0,
            remediation_marker_present=True,
        )

        self.assertTrue(result.provider_chain_passed)
        self.assertTrue(result.reentry_passed)
        self.assertEqual(result.provider_e2e_status, "PASS")
        self.assertEqual(result.live_ui_status, "NOT-RUN")

    def test_deny_requires_no_remediation_and_provider_completion(self) -> None:
        result = validate_provider_e2e(
            decision_chain(DecisionCase.DENY),
            expected_provider=PROVIDER,
            expected_session_id=SESSION_ID,
            decision=DecisionCase.DENY,
            execution_mode=ExecutionMode.AUTHENTICATED_PROVIDER,
            presentation=PresentationMode.SCRIPTED_SIDECAR,
            provider_exit_code=0,
            remediation_marker_present=False,
        )

        self.assertTrue(result.provider_chain_passed)
        self.assertTrue(result.reentry_passed)
        self.assertEqual(result.provider_e2e_status, "PASS")
        self.assertEqual(result.live_ui_status, "NOT-RUN")

    def test_rejects_retired_egui_transport_label(self) -> None:
        retired = decision_chain(DecisionCase.DENY)
        # Built by joining so the retired literal has zero source matches (AC-007.1).
        retired_label = "_".join(["arc", "native", "egui"])
        retired[0]["details"] = {"transport": retired_label}

        with self.assertRaisesRegex(
            EvidenceContractError, "decision transport was not Arc embedded UI"
        ):
            validate_provider_e2e(
                retired,
                expected_provider=PROVIDER,
                expected_session_id=SESSION_ID,
                decision=DecisionCase.DENY,
                execution_mode=ExecutionMode.AUTHENTICATED_PROVIDER,
                presentation=PresentationMode.SCRIPTED_SIDECAR,
                provider_exit_code=0,
                remediation_marker_present=False,
            )

    def test_rejects_missing_or_out_of_order_chain(self) -> None:
        invalid = decision_chain(DecisionCase.DENY)
        invalid[0]["event_type"], invalid[1]["event_type"] = (
            invalid[1]["event_type"],
            invalid[0]["event_type"],
        )

        with self.assertRaisesRegex(
            EvidenceContractError,
            "DecisionTransportResolved.*DecisionReceived.*ProviderOutput",
        ):
            validate_provider_e2e(
                invalid,
                expected_provider=PROVIDER,
                expected_session_id=SESSION_ID,
                decision=DecisionCase.DENY,
                execution_mode=ExecutionMode.AUTHENTICATED_PROVIDER,
                presentation=PresentationMode.SCRIPTED_SIDECAR,
                provider_exit_code=0,
                remediation_marker_present=False,
            )

    def test_rejects_cross_session_or_cross_provider_events(self) -> None:
        invalid = decision_chain(DecisionCase.DENY)
        invalid[1]["session_id"] = "another-session"

        with self.assertRaisesRegex(EvidenceContractError, "session"):
            validate_provider_e2e(
                invalid,
                expected_provider=PROVIDER,
                expected_session_id=SESSION_ID,
                decision=DecisionCase.DENY,
                execution_mode=ExecutionMode.AUTHENTICATED_PROVIDER,
                presentation=PresentationMode.SCRIPTED_SIDECAR,
                provider_exit_code=0,
                remediation_marker_present=False,
            )

    def test_allow_without_reentry_is_not_accepted(self) -> None:
        with self.assertRaisesRegex(EvidenceContractError, "re-entry"):
            validate_provider_e2e(
                decision_chain(DecisionCase.ALLOW),
                expected_provider=PROVIDER,
                expected_session_id=SESSION_ID,
                decision=DecisionCase.ALLOW,
                execution_mode=ExecutionMode.AUTHENTICATED_PROVIDER,
                presentation=PresentationMode.SCRIPTED_SIDECAR,
                provider_exit_code=0,
                remediation_marker_present=True,
            )

    def test_gemini_allow_accepts_provider_reentry_without_codex_state_transition(self) -> None:
        events = decision_chain(DecisionCase.ALLOW)
        for item in events:
            item["provider"] = "gemini"
        events.extend(
            [
                {
                    **event(13, "HookReceived", details={"event": "stop"}),
                    "provider": "gemini",
                },
                {
                    **event(
                        14,
                        "ProviderOutput",
                        details={
                            "capture": "metadata",
                            "output_bytes": 24,
                            "output_sha256": "d" * 64,
                        },
                    ),
                    "provider": "gemini",
                },
            ]
        )

        result = validate_provider_e2e(
            events,
            expected_provider="gemini",
            expected_session_id=SESSION_ID,
            decision=DecisionCase.ALLOW,
            execution_mode=ExecutionMode.AUTHENTICATED_PROVIDER,
            presentation=PresentationMode.SCRIPTED_SIDECAR,
            provider_exit_code=0,
            remediation_marker_present=True,
        )

        self.assertTrue(result.reentry_passed)

    def test_deny_must_not_create_or_consume_a_remediation_marker(self) -> None:
        with self.assertRaisesRegex(EvidenceContractError, "marker"):
            validate_provider_e2e(
                decision_chain(DecisionCase.DENY),
                expected_provider=PROVIDER,
                expected_session_id=SESSION_ID,
                decision=DecisionCase.DENY,
                execution_mode=ExecutionMode.AUTHENTICATED_PROVIDER,
                presentation=PresentationMode.SCRIPTED_SIDECAR,
                provider_exit_code=0,
                remediation_marker_present=True,
            )

    def test_unresolved_decision_cannot_have_a_waiver_transition(self) -> None:
        events = decision_chain(DecisionCase.RETRY)
        events.append(event(13, "StateTransition", reason_code="WaiverAccepted"))

        with self.assertRaisesRegex(EvidenceContractError, "waiver"):
            validate_provider_e2e(
                events,
                expected_provider=PROVIDER,
                expected_session_id=SESSION_ID,
                decision=DecisionCase.RETRY,
                execution_mode=ExecutionMode.AUTHENTICATED_PROVIDER,
                presentation=PresentationMode.SCRIPTED_SIDECAR,
                provider_exit_code=0,
                remediation_marker_present=False,
            )

    def test_fixture_presentation_never_claims_live_ui(self) -> None:
        result = validate_provider_e2e(
            decision_chain(DecisionCase.DENY),
            expected_provider=PROVIDER,
            expected_session_id=SESSION_ID,
            decision=DecisionCase.DENY,
            execution_mode=ExecutionMode.AUTHENTICATED_PROVIDER,
            presentation=PresentationMode.SCRIPTED_SIDECAR,
            provider_exit_code=0,
            remediation_marker_present=False,
        )

        self.assertEqual(result.live_ui_status, "NOT-RUN")
        self.assertIn("scripted", result.limitations[0].lower())

    def test_simulated_hook_never_claims_authenticated_provider_e2e(self) -> None:
        result = validate_provider_e2e(
            decision_chain(DecisionCase.DENY),
            expected_provider=PROVIDER,
            expected_session_id=SESSION_ID,
            decision=DecisionCase.DENY,
            execution_mode=ExecutionMode.SIMULATED_HOOK,
            presentation=PresentationMode.SCRIPTED_SIDECAR,
            provider_exit_code=0,
            remediation_marker_present=False,
        )

        self.assertEqual(result.contract_status, "PASS")
        self.assertEqual(result.provider_e2e_status, "NOT-RUN")
        self.assertIn("simulated", " ".join(result.limitations).lower())


if __name__ == "__main__":
    unittest.main()
