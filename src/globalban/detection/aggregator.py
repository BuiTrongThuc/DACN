"""Time-window aggregation of failed SSH authentication attempts."""

from collections import defaultdict, deque
from datetime import datetime, timedelta
from ipaddress import IPv4Address, IPv6Address

from globalban.models.decisions import BanCandidate
from globalban.models.events import AuthEvent


class FailedAttemptAggregator:
    def __init__(self, *, window_seconds: int, threshold: int) -> None:
        if window_seconds <= 0:
            raise ValueError("window_seconds must be greater than zero")
        if threshold <= 0:
            raise ValueError("threshold must be greater than zero")
        self._window = timedelta(seconds=window_seconds)
        self._threshold = threshold
        self._attempts: dict[IPv4Address | IPv6Address, deque[datetime]] = defaultdict(deque)
        self._reported: set[IPv4Address | IPv6Address] = set()

    def add(self, event: AuthEvent) -> BanCandidate | None:
        """Add an event and return a candidate only on the threshold crossing."""
        if not event.failed:
            return None

        attempts = self._attempts[event.source_ip]
        cutoff = event.timestamp - self._window
        while attempts and attempts[0] < cutoff:
            attempts.popleft()
        if not attempts and event.source_ip in self._reported:
            self._reported.remove(event.source_ip)

        attempts.append(event.timestamp)
        if len(attempts) < self._threshold or event.source_ip in self._reported:
            return None

        self._reported.add(event.source_ip)
        return BanCandidate(
            source_ip=event.source_ip,
            failed_attempts=len(attempts),
            window_started_at=attempts[0],
            window_ended_at=attempts[-1],
        )
