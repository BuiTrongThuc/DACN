from datetime import datetime, timedelta, timezone

from globalban.detection.sequence import SequenceCorrelator
from globalban.models.events import WindowsEvent


def make_event(event_id: int, at: datetime, **fields: str) -> WindowsEvent:
    return WindowsEvent(
        timestamp=at,
        event_id=event_id,
        provider="Security",
        fields=fields,
        host="WS-01",
    )


def test_sequence_correlator_links_login_process_and_persistence():
    start = datetime(2025, 1, 1, tzinfo=timezone.utc)
    detector = SequenceCorrelator(window_seconds=300)

    assert detector.add(make_event(4624, start, TargetUserName="alice")) is None
    assert detector.add(
        make_event(4688, start + timedelta(seconds=5), TargetUserName="alice", ProcessId="10")
    ) is None
    candidate = detector.add(
        make_event(4698, start + timedelta(seconds=10), TargetUserName="alice")
    )

    assert candidate is not None
    assert candidate.score == 100
    assert candidate.event_ids == (4624, 4688, 4698)
    assert "persistence" in " ".join(candidate.reasons)


def test_duplicate_event_is_ignored():
    start = datetime(2025, 1, 1, tzinfo=timezone.utc)
    detector = SequenceCorrelator(window_seconds=300)
    event = make_event(1102, start, SubjectUserName="admin")

    first = detector.add(event)
    second = detector.add(event)

    assert first is not None
    assert second is None


def test_behavior_signals_can_raise_risk_without_special_event_id():
    event = make_event(
        9999,
        datetime(2025, 1, 1, tzinfo=timezone.utc),
        SubjectUserName="alice",
        NewProcessName="C:\\Users\\Public\\stage.exe",
        CommandLine="powershell.exe -EncodedCommand abc",
    )

    candidate = SequenceCorrelator(window_seconds=300).add(event)

    assert candidate is not None
    assert "encoded or obfuscated execution behavior" in candidate.reasons