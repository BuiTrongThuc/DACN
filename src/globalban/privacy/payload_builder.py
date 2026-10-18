"""Construct the minimal metadata payload permitted for optional AI requests."""

from globalban.models.decisions import BanCandidate
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
