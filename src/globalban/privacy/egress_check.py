"""Validate outbound payloads against the privacy allowlist."""

from collections.abc import Mapping

ALLOWED_AI_FIELDS = frozenset(
    {"source_network", "failed_attempts", "window_seconds", "event_type"}
)
ALLOWED_WINDOWS_FIELDS = frozenset(
    {"event_id", "event_type", "priority", "provider", "fields"}
)
ALLOWED_RISK_FIELDS = frozenset(
    {"event_type", "risk_score", "event_ids", "reasons", "source_network"}
)


def validate_ai_payload(payload: Mapping[str, object]) -> None:
    unexpected = set(payload) - ALLOWED_AI_FIELDS
    if unexpected:
        raise ValueError(f"Outbound AI payload contains disallowed fields: {sorted(unexpected)}")
    required = ALLOWED_AI_FIELDS
    missing = required - set(payload)
    if missing:
        raise ValueError(f"Outbound AI payload is missing required fields: {sorted(missing)}")
    if not isinstance(payload["source_network"], str) or "/" not in payload["source_network"]:
        raise ValueError("source_network must be a masked CIDR network")
    for field in ("failed_attempts", "window_seconds"):
        value = payload[field]
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ValueError(f"{field} must be a non-negative integer")
    if payload["event_type"] != "ssh_authentication_failures":
        raise ValueError("Unsupported outbound event_type")


def validate_windows_payload(payload: Mapping[str, object]) -> None:
    unexpected = set(payload) - ALLOWED_WINDOWS_FIELDS
    if unexpected or set(payload) != ALLOWED_WINDOWS_FIELDS:
        raise ValueError("Windows payload contains disallowed or missing fields")
    event_id = payload["event_id"]
    if isinstance(event_id, bool) or not isinstance(event_id, int) or event_id < 1:
        raise ValueError("event_id must be a positive integer")
    if payload["priority"] not in {"P0", "P1", "P2"}:
        raise ValueError("Unsupported event priority")
    if not isinstance(payload["event_type"], str) or not payload["event_type"].startswith(
        "windows_event_"
    ):
        raise ValueError("Unsupported Windows event type")
    if not isinstance(payload["provider"], str) or not payload["provider"]:
        raise ValueError("provider must be a non-empty string")
    fields = payload["fields"]
    if not isinstance(fields, Mapping) or not all(
        isinstance(name, str) and isinstance(value, str) for name, value in fields.items()
    ):
        raise ValueError("Windows fields must be text metadata")


def validate_risk_payload(payload: Mapping[str, object]) -> None:
    if set(payload) != ALLOWED_RISK_FIELDS:
        raise ValueError("Risk payload contains disallowed or missing fields")
    score = payload["risk_score"]
    if isinstance(score, bool) or not isinstance(score, int) or not 0 <= score <= 100:
        raise ValueError("risk_score must be an integer from 0 to 100")
    event_ids = payload["event_ids"]
    if not isinstance(event_ids, list) or not all(isinstance(item, int) for item in event_ids):
        raise ValueError("event_ids must be a list of integers")
    reasons = payload["reasons"]
    if not isinstance(reasons, list) or not all(isinstance(item, str) for item in reasons):
        raise ValueError("reasons must be a list of strings")
    source_network = payload["source_network"]
    if source_network is not None and (
        not isinstance(source_network, str) or "/" not in source_network
    ):
        raise ValueError("source_network must be a masked CIDR network or null")
