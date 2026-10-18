from datetime import datetime, timedelta, timezone
from ipaddress import ip_address

from globalban.detection.aggregator import FailedAttemptAggregator
from globalban.models.events import AuthEvent


def make_event(at: datetime, event_type: str = "failed") -> AuthEvent:
    return AuthEvent(ip_address("8.8.8.8"), at, "root", event_type)


def test_candidate_emitted_once_when_threshold_is_reached():
    aggregator = FailedAttemptAggregator(window_seconds=60, threshold=3)
    start = datetime(2025, 1, 1, tzinfo=timezone.utc)

    assert aggregator.add(make_event(start)) is None
    assert aggregator.add(make_event(start + timedelta(seconds=1))) is None
    candidate = aggregator.add(make_event(start + timedelta(seconds=2)))

    assert candidate is not None
    assert candidate.failed_attempts == 3
    assert candidate.source_ip == ip_address("8.8.8.8")
    assert aggregator.add(make_event(start + timedelta(seconds=3))) is None


def test_success_does_not_increase_failed_attempt_count():
    aggregator = FailedAttemptAggregator(window_seconds=60, threshold=2)
    start = datetime(2025, 1, 1, tzinfo=timezone.utc)

    assert aggregator.add(make_event(start, "success")) is None
    assert aggregator.add(make_event(start + timedelta(seconds=1))) is None
    assert aggregator.add(make_event(start + timedelta(seconds=2))) is not None


def test_attempts_outside_window_are_discarded():
    aggregator = FailedAttemptAggregator(window_seconds=10, threshold=2)
    start = datetime(2025, 1, 1, tzinfo=timezone.utc)

    assert aggregator.add(make_event(start)) is None
    assert aggregator.add(make_event(start + timedelta(seconds=11))) is None
