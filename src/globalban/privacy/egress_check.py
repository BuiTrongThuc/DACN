"""Validate outbound payloads against the privacy allowlist."""

from collections.abc import Mapping

ALLOWED_AI_FIELDS = frozenset(
    {"source_network", "failed_attempts", "window_seconds", "event_type"}
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
