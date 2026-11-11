from datetime import datetime, timezone

from globalban.detection.baseline import BehaviorBaseline
from globalban.models.events import WindowsEvent


def make_event(*, host: str, user: str, hour: int, executable: str) -> WindowsEvent:
    return WindowsEvent(
        timestamp=datetime(2025, 1, 1, hour, tzinfo=timezone.utc),
        event_id=4688,
        provider="Microsoft-Windows-Sysmon",
        fields={"SubjectUserName": user, "Image": executable},
        host=host,
    )


def test_baseline_profiles_user_and_host_together(tmp_path):
    baseline = BehaviorBaseline(path=str(tmp_path / "baseline.json"), warmup_events=2)

    assert baseline.observe(
        make_event(host="WIN-01", user="alice", hour=9, executable="explorer.exe")
    ) == (0, None)
    assert baseline.observe(
        make_event(host="WIN-01", user="alice", hour=9, executable="explorer.exe")
    ) == (0, None)

    score, reason = baseline.observe(
        make_event(host="WIN-02", user="alice", hour=2, executable="powershell.exe")
    )

    assert score == 45
    assert reason is not None
    assert "user on this host" in reason
    assert "first-seen executable" in reason


def test_baseline_persists_profile_signals(tmp_path):
    path = tmp_path / "baseline.json"
    event = make_event(host="WIN-01", user="alice", hour=9, executable="explorer.exe")
    BehaviorBaseline(path=str(path), warmup_events=1).observe(event)

    restored = BehaviorBaseline(path=str(path), warmup_events=1)
    assert restored.observe(event) == (0, None)