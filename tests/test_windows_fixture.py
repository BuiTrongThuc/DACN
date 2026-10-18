from datetime import datetime, timezone
from pathlib import Path

from globalban.detection.sequence import SequenceCorrelator
from globalban.ingestion.parser import parse_windows_security_event


def test_windows_fixture_detects_suspicious_sequence_without_executing_actions():
    fixture = Path(__file__).parents[1] / "datasets" / "windows_events.xmll"
    detector = SequenceCorrelator(window_seconds=300)
    candidates = []

    for line in fixture.read_text(encoding="utf-8").splitlines():
        event = parse_windows_security_event(
            line, now=datetime(2025, 1, 1, tzinfo=timezone.utc)
        )
        assert event is not None
        candidate = detector.add(event)
        if candidate is not None:
            candidates.append(candidate)

    assert len(candidates) == 1
    assert candidates[0].username == "alice"
    assert candidates[0].event_ids == (4624, 4688, 4698)
    assert candidates[0].score == 100