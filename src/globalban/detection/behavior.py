"""Stateful Windows authentication behavior detection.

The detector is deliberately conservative: it produces explainable risk
candidates, while policy and the action adapter remain responsible for
allowlisting, dry-run, and firewall execution.
"""

from __future__ import annotations

import json
import ipaddress
import statistics
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path

from globalban.detection.sequence import RiskCandidate
from globalban.models.events import WindowsEvent


@dataclass
class _AuthRecord:
    timestamp: datetime
    source_ip: str
    username: str
    failed: bool
    substatus: str


class WindowsBehaviorDetector:
    def __init__(
        self,
        *,
        state_path: str | Path | None = "globalban-behavior-state.json",
        retention_hours: int = 24,
        fast_window_seconds: int = 60,
        fast_threshold: int = 5,
        slow_tiers: tuple[tuple[int, int], ...] = ((3600, 5), (21600, 8), (86400, 12)),
        spray_users: int = 5,
        spray_window_seconds: int = 21600,
        distributed_ips: int = 5,
        distributed_window_seconds: int = 3600,
    ) -> None:
        if retention_hours <= 0 or fast_window_seconds <= 0:
            raise ValueError("behavior detector windows must be positive")
        self._path = Path(state_path) if state_path else None
        self._retention = timedelta(hours=retention_hours)
        self._fast_window = timedelta(seconds=fast_window_seconds)
        self._fast_threshold = fast_threshold
        self._slow_tiers = slow_tiers
        self._spray_users = spray_users
        self._spray_window = timedelta(seconds=spray_window_seconds)
        self._distributed_ips = distributed_ips
        self._distributed_window = timedelta(seconds=distributed_window_seconds)
        self._records: list[_AuthRecord] = []
        self._reported: dict[str, datetime] = {}
        self._load()

    def add(self, event: WindowsEvent) -> RiskCandidate | None:
        if event.event_id not in {4624, 4625} or event.source_ip is None:
            return None
        timestamp = event.timestamp
        record = _AuthRecord(
            timestamp=timestamp,
            source_ip=str(event.source_ip),
            username=event.username[:64],
            failed=event.event_id == 4625,
            substatus=(event.fields.get("SubStatus") or "").lower(),
        )
        self._records.append(record)
        self._prune(timestamp)
        if not record.failed:
            self._save()
            return self._success_after_failures(record)
        candidate = self._analyze(record)
        self._save()
        return candidate

    def _analyze(self, record: _AuthRecord) -> RiskCandidate | None:
        now = record.timestamp
        failures = [
            item for item in self._records
            if item.failed and item.source_ip == record.source_ip
        ]
        recent_failures = [
            item for item in failures if now - item.timestamp <= self._fast_window
        ]
        open_failures = [
            item for item in failures
            if item.username and not self._has_later_success(item)
        ]
        score = 0
        reasons: list[str] = []
        if len(recent_failures) >= self._fast_threshold:
            score += 60
            reasons.append(
                f"fast brute-force: {len(recent_failures)} failures in "
                f"{int(self._fast_window.total_seconds())} seconds"
            )
        if not recent_failures:
            for seconds, threshold in self._slow_tiers:
                count = sum(1 for item in open_failures if now - item.timestamp <= timedelta(seconds=seconds))
                if count >= threshold:
                    score += 45
                    reasons.append(f"slow-and-low: {count} failures in {seconds // 3600}h")
                    break
        intervals = [
            (b.timestamp - a.timestamp).total_seconds()
            for a, b in zip(open_failures[-12:], open_failures[-11:])
        ]
        if len(intervals) >= 5 and statistics.mean(intervals) >= 5:
            mean = statistics.mean(intervals)
            if statistics.pstdev(intervals) / mean < 0.30:
                score += 15
                reasons.append("periodic automated login pattern")

        spray_users = {
            item.username.lower() for item in open_failures
            if now - item.timestamp <= self._spray_window and item.username
        }
        if len(spray_users) >= self._spray_users:
            score += 40
            reasons.append(f"password spraying: {len(spray_users)} distinct usernames")
        enum_count = sum(
            1 for item in open_failures
            if item.substatus in {"0xc0000064", "c0000064"}
            and now - item.timestamp <= self._spray_window
        )
        if enum_count >= 3:
            score += 20
            reasons.append(f"user enumeration: {enum_count} nonexistent-user failures")

        distinct_ips = {
            item.source_ip for item in self._records
            if item.failed and item.username.lower() == record.username.lower()
            and now - item.timestamp <= self._distributed_window
        }
        if len(distinct_ips) >= self._distributed_ips:
            score += 60
            reasons.append(f"distributed attack: {len(distinct_ips)} source IPs targeted one user")
        return self._candidate(record, score, reasons, (4625,))

    def _success_after_failures(self, success: _AuthRecord) -> RiskCandidate | None:
        failures = [
            item for item in self._records
            if item.failed and item.username.lower() == success.username.lower()
            and item.source_ip == success.source_ip and item.timestamp < success.timestamp
        ]
        recent = [item for item in failures if success.timestamp - item.timestamp <= timedelta(hours=1)]
        if len(recent) < 3:
            return None
        score = 100 if len(recent) >= 5 else 20
        reason = f"successful login after {len(recent)} failures for the same user"
        return self._candidate(success, score, [reason], (4624, 4625))

    def _candidate(
        self,
        record: _AuthRecord,
        score: int,
        reasons: list[str],
        event_ids: tuple[int, ...],
    ) -> RiskCandidate | None:
        if not reasons:
            return None
        key = f"{record.source_ip}:{'|'.join(reasons)}"
        previous = self._reported.get(key)
        if previous and record.timestamp - previous < timedelta(minutes=10):
            return None
        self._reported[key] = record.timestamp
        severity = "critical" if score >= 100 else "high" if score >= 60 else "medium"
        return RiskCandidate(
            timestamp=record.timestamp,
            host="Windows authentication",
            username=record.username,
            source_ip=ipaddress.ip_address(record.source_ip),
            score=min(score, 100),
            reasons=(f"{severity} authentication behavior", *reasons),
            event_ids=event_ids,
        )

    def _has_later_success(self, failure: _AuthRecord) -> bool:
        return any(
            not item.failed
            and item.source_ip == failure.source_ip
            and item.username.lower() == failure.username.lower()
            and item.timestamp > failure.timestamp
            for item in self._records
        )

    def _prune(self, now: datetime) -> None:
        cutoff = now - self._retention
        self._records = [item for item in self._records if item.timestamp >= cutoff]
        self._reported = {
            key: value for key, value in self._reported.items() if value >= cutoff
        }

    def _load(self) -> None:
        if not self._path or not self._path.exists():
            return
        try:
            data = json.loads(self._path.read_text(encoding="utf-8"))
            self._records = [_AuthRecord(
                datetime.fromisoformat(item["timestamp"]),
                item["source_ip"], item["username"], item["failed"], item["substatus"],
            ) for item in data.get("records", [])]
            self._reported = {
                key: datetime.fromisoformat(value)
                for key, value in data.get("reported", {}).items()
            }
        except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError):
            self._records = []
            self._reported = {}

    def _save(self) -> None:
        if not self._path:
            return
        self._path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "records": [
                {
                    "timestamp": item.timestamp.isoformat(),
                    "source_ip": item.source_ip,
                    "username": item.username,
                    "failed": item.failed,
                    "substatus": item.substatus,
                }
                for item in self._records
            ],
            "reported": {key: value.isoformat() for key, value in self._reported.items()},
        }
        self._path.write_text(json.dumps(payload), encoding="utf-8")
