from __future__ import annotations

import enum
import re
from dataclasses import dataclass
from typing import Mapping, Sequence


class EvidenceContractError(ValueError):
    """Raised when captured events cannot support the requested acceptance claim."""


class DecisionCase(enum.Enum):
    ALLOW = "allow"
    DENY = "deny"
    RETRY = "retry"


class ExecutionMode(enum.Enum):
    SIMULATED_HOOK = "simulated_hook"
    AUTHENTICATED_PROVIDER = "authenticated_provider"


class PresentationMode(enum.Enum):
    SCRIPTED_SIDECAR = "scripted_sidecar"
    LIVE_UI = "live_ui"


@dataclass(frozen=True)
class ProviderE2EResult:
    contract_status: str
    provider_e2e_status: str
    live_ui_status: str
    provider_chain_passed: bool
    reentry_passed: bool
    chain_event_ids: tuple[int, int, int]
    limitations: tuple[str, ...]


_CHAIN = (
    "DecisionTransportResolved",
    "DecisionReceived",
    "ProviderOutput",
)
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


def validate_provider_e2e(
    events: Sequence[Mapping[str, object]],
    *,
    expected_provider: str,
    expected_session_id: str,
    decision: DecisionCase,
    execution_mode: ExecutionMode,
    presentation: PresentationMode,
    provider_exit_code: int,
    remediation_marker_present: bool,
) -> ProviderE2EResult:
    if not expected_provider.strip():
        raise EvidenceContractError("expected provider must not be empty")
    if not expected_session_id.strip():
        raise EvidenceContractError("expected session must not be empty")
    if provider_exit_code != 0:
        raise EvidenceContractError(
            f"provider process did not complete successfully: exit {provider_exit_code}"
        )
    if not events:
        raise EvidenceContractError("provider evidence contains no events")

    ordered_events = _validate_event_envelope(
        events,
        expected_provider=expected_provider,
        expected_session_id=expected_session_id,
    )
    chain_indexes = _find_strict_chain(ordered_events)
    transport_event = ordered_events[chain_indexes[0]]
    decision_event = ordered_events[chain_indexes[1]]
    output_event = ordered_events[chain_indexes[2]]

    _validate_transport(transport_event)
    _validate_decision(decision_event, decision)
    _validate_provider_output(output_event)
    _reject_unauthorized_waiver(ordered_events, decision)

    reentry_passed = _validate_continuation(
        ordered_events,
        expected_provider=expected_provider,
        decision=decision,
        first_provider_output_index=chain_indexes[2],
        remediation_marker_present=remediation_marker_present,
    )

    limitations: list[str] = []
    if execution_mode is ExecutionMode.SIMULATED_HOOK:
        limitations.append(
            "Simulated hook execution validates the provider contract but is not an authenticated provider session."
        )
    if presentation is PresentationMode.SCRIPTED_SIDECAR:
        limitations.append(
            "Scripted sidecar presentation does not validate the live Tauri/WebView user interface."
        )

    provider_e2e_status = (
        "PASS"
        if execution_mode is ExecutionMode.AUTHENTICATED_PROVIDER
        else "NOT-RUN"
    )
    live_ui_status = "PASS" if presentation is PresentationMode.LIVE_UI else "NOT-RUN"

    return ProviderE2EResult(
        contract_status="PASS",
        provider_e2e_status=provider_e2e_status,
        live_ui_status=live_ui_status,
        provider_chain_passed=True,
        reentry_passed=reentry_passed,
        chain_event_ids=tuple(
            _event_id(ordered_events[index]) for index in chain_indexes
        ),
        limitations=tuple(limitations),
    )


def _validate_event_envelope(
    events: Sequence[Mapping[str, object]],
    *,
    expected_provider: str,
    expected_session_id: str,
) -> list[Mapping[str, object]]:
    ordered = list(events)
    previous_id = -1
    for captured in ordered:
        event_id = _event_id(captured)
        if event_id <= previous_id:
            raise EvidenceContractError("event ids must be strictly increasing")
        previous_id = event_id
        if captured.get("provider") != expected_provider:
            raise EvidenceContractError("provider event does not match the expected provider")
        if captured.get("session_id") != expected_session_id:
            raise EvidenceContractError("provider event belongs to another session")
        if not isinstance(captured.get("event_type"), str):
            raise EvidenceContractError("event_type must be a string")
        details = captured.get("details")
        if not isinstance(details, Mapping):
            raise EvidenceContractError("event details must be an object")
    return ordered


def _find_strict_chain(events: Sequence[Mapping[str, object]]) -> tuple[int, int, int]:
    indexes: list[int] = []
    cursor = 0
    for expected in _CHAIN:
        while cursor < len(events) and events[cursor].get("event_type") != expected:
            cursor += 1
        if cursor == len(events):
            chain = " -> ".join(_CHAIN)
            raise EvidenceContractError(f"required event chain was not observed: {chain}")
        indexes.append(cursor)
        cursor += 1
    return indexes[0], indexes[1], indexes[2]


def _validate_transport(event: Mapping[str, object]) -> None:
    details = _details(event)
    if details.get("transport") != "arc_embedded_ui":
        raise EvidenceContractError("decision transport was not Arc embedded UI")


def _validate_decision(event: Mapping[str, object], expected: DecisionCase) -> None:
    details = _details(event)
    metadata = details.get("metadata")
    if not isinstance(metadata, Mapping):
        raise EvidenceContractError("DecisionReceived metadata is missing")
    outcome = metadata.get("outcome")
    if not isinstance(outcome, Mapping):
        raise EvidenceContractError("DecisionReceived outcome is missing")
    if outcome.get("outcome") != expected.value:
        raise EvidenceContractError(
            f"DecisionReceived outcome does not match {expected.value}"
        )


def _validate_provider_output(event: Mapping[str, object]) -> None:
    details = _details(event)
    if details.get("capture") != "metadata":
        raise EvidenceContractError("ProviderOutput must retain metadata only")
    output_bytes = details.get("output_bytes")
    if not isinstance(output_bytes, int) or isinstance(output_bytes, bool) or output_bytes <= 0:
        raise EvidenceContractError("ProviderOutput byte count is invalid")
    output_sha256 = details.get("output_sha256")
    if not isinstance(output_sha256, str) or _SHA256.fullmatch(output_sha256) is None:
        raise EvidenceContractError("ProviderOutput SHA-256 is invalid")


def _reject_unauthorized_waiver(
    events: Sequence[Mapping[str, object]], decision: DecisionCase
) -> None:
    if decision is not DecisionCase.RETRY:
        return
    if any(event.get("reason_code") == "WaiverAccepted" for event in events):
        raise EvidenceContractError("unresolved decision created or consumed a waiver")


def _validate_continuation(
    events: Sequence[Mapping[str, object]],
    *,
    expected_provider: str,
    decision: DecisionCase,
    first_provider_output_index: int,
    remediation_marker_present: bool,
) -> bool:
    if decision is DecisionCase.DENY:
        if remediation_marker_present:
            raise EvidenceContractError("deny case unexpectedly created the remediation marker")
        return True

    if decision is DecisionCase.RETRY:
        if remediation_marker_present:
            raise EvidenceContractError("retry case unexpectedly created the remediation marker")
        return True

    if not remediation_marker_present:
        raise EvidenceContractError("allow case did not create the remediation marker")

    expected_after_output = (
        ("HookReceived", "StateTransition", "ProviderOutput")
        if expected_provider == "codex"
        else ("HookReceived", "ProviderOutput")
    )
    cursor = first_provider_output_index + 1
    matched: list[Mapping[str, object]] = []
    for expected in expected_after_output:
        while cursor < len(events) and events[cursor].get("event_type") != expected:
            cursor += 1
        if cursor == len(events):
            raise EvidenceContractError(
                "allow case did not prove provider re-entry after ProviderOutput"
            )
        matched.append(events[cursor])
        cursor += 1
    if expected_provider == "codex":
        if matched[1].get("reason_code") != "GuardSatisfied":
            raise EvidenceContractError("provider re-entry did not satisfy the original guard")
        _validate_provider_output(matched[2])
    else:
        _validate_provider_output(matched[1])
    return True


def _event_id(event: Mapping[str, object]) -> int:
    value = event.get("id")
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise EvidenceContractError("event id must be a non-negative integer")
    return value


def _details(event: Mapping[str, object]) -> Mapping[str, object]:
    details = event.get("details")
    if not isinstance(details, Mapping):
        raise EvidenceContractError("event details must be an object")
    return details
