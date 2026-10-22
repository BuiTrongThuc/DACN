from datetime import datetime, timedelta, timezone

from globalban.detection.behavior import WindowsBehaviorDetector
from globalban.models.events import WindowsEvent


def test_detects_fast_bruteforce(tmp_path):
    detector = WindowsBehaviorDetector(state_path=tmp_path / "state.json")
    start = datetime(2025, 1, 1, tzinfo=timezone.utc)
    candidate = None
    for index in range(5):
        candidate = detector.add(WindowsEvent(
            start + timedelta(seconds=index * 5),
            4625,
            "Security",
            {"IpAddress": "203.0.113.7", "TargetUserName": "admin"},
        ))
    assert candidate is not None
    assert candidate.score >= 60
    assert "brute-force" in " ".join(candidate.reasons)


def test_detects_success_after_failures(tmp_path):
    detector = WindowsBehaviorDetector(state_path=tmp_path / "state.json")
    start = datetime(2025, 1, 1, tzinfo=timezone.utc)
    for index in range(3):
        detector.add(WindowsEvent(
            start + timedelta(seconds=index),
            4625,
            "Security",
            {"IpAddress": "203.0.113.8", "TargetUserName": "deploy"},
        ))
    candidate = detector.add(WindowsEvent(
        start + timedelta(seconds=10),
        4624,
        "Security",
        {"IpAddress": "203.0.113.8", "TargetUserName": "deploy"},
    ))
    assert candidate is not None
    assert "successful login" in " ".join(candidate.reasons)
