"""Construct the minimal metadata payload permitted for optional AI requests."""

from globalban.models.decisions import BanCandidate
from globalban.models.events import WindowsEvent
from globalban.detection.sequence import RiskCandidate
from globalban.privacy.masking import mask_ip


def build_ai_payload(candidate: BanCandidate) -> dict[str, object]:
    return {
        "source_network": mask_ip(candidate.source_ip),
        "failed_attempts": candidate.failed_attempts,
        "window_seconds": max(
            0,
            int((candidate.window_ended_at - candidate.window_started_at).total_seconds()),
        ),
        "event_type": "ssh_authentication_failures",
    }


def build_windows_event_payload(event: WindowsEvent) -> dict[str, object]:
    safe_fields = {
        name: value
        for name, value in event.fields.items()
        if name in {"TargetUserName", "SubjectUserName", "ServiceName", "TaskName"}
    }
    return {
        "event_id": event.event_id,
        "event_type": event.event_type,
        "priority": event.priority,
        "provider": event.provider,
        "fields": safe_fields,
    }


def build_risk_payload(candidate: RiskCandidate) -> dict[str, object]:
    return {
        "event_type": "windows_behavior_risk",
        "risk_score": candidate.score,
        "event_ids": list(candidate.event_ids),
        "reasons": list(candidate.reasons),
        "source_network": (
            mask_ip(candidate.source_ip) if candidate.source_ip is not None else None
        ),
    }
