"""Explainable correlation of Windows events into behavior candidates."""

from collections import deque
from dataclasses import dataclass
from datetime import datetime, timedelta
from ipaddress import IPv4Address, IPv6Address

from globalban.detection.baseline import BehaviorBaseline
from globalban.models.events import WindowsEvent

IPAddress = IPv4Address | IPv6Address


@dataclass(frozen=True, slots=True)
class RiskCandidate:
    timestamp: datetime
    host: str
    username: str
    source_ip: IPAddress | None
    score: int
    reasons: tuple[str, ...]
    event_ids: tuple[int, ...]


class SequenceCorrelator:
    def __init__(
        self,
        *,
        window_seconds: int,
        baseline: BehaviorBaseline | None = None,
    ) -> None:
        if window_seconds <= 0:
            raise ValueError("window_seconds must be greater than zero")
        self._window = timedelta(seconds=window_seconds)
        self._baseline = baseline
        self._events: dict[tuple[str, str], deque[WindowsEvent]] = {}
        self._fingerprints: set[tuple[str, int, str, datetime]] = set()

    def add(self, event: WindowsEvent) -> RiskCandidate | None:
        fingerprint = (event.provider, event.event_id, event.process_id or "", event.timestamp)
        if fingerprint in self._fingerprints:
            return None
        self._fingerprints.add(fingerprint)
        key = (event.host or "<unknown-host>", event.username or "<unknown>")
        events = self._events.setdefault(key, deque())
        cutoff = event.timestamp - self._window
        while events and events[0].timestamp < cutoff:
            events.popleft()
        events.append(event)

        score, reasons = self._score(events, event)
        if self._baseline:
            baseline_score, baseline_reason = self._baseline.observe(event)
            score += baseline_score
            if baseline_reason:
                reasons.append(baseline_reason)
        if score < 60:
            return None
        return RiskCandidate(
            timestamp=event.timestamp,
            host=event.host or event.provider,
            username=event.username,
            source_ip=event.source_ip,
            score=min(score, 100),
            reasons=tuple(dict.fromkeys(reasons)),
            event_ids=tuple(sorted({item.event_id for item in events})),
        )

    @staticmethod
    def _score(events: deque[WindowsEvent], current: WindowsEvent) -> tuple[int, list[str]]:
        event_ids = {event.event_id for event in events}
        score = 0
        reasons: list[str] = []
        behavior_text = " ".join(
            value
            for value in (
                current.command_line,
                current.executable,
                current.fields.get("TaskName"),
                current.fields.get("ServiceName"),
                current.fields.get("TargetFilename"),
            )
            if value
        ).lower()
        if current.event_id in {1102, 4719}:
            score += 80
            reasons.append(f"high-impact audit event {current.event_id}")
        if current.event_id in {1116, 1117, 7045, 4698, 4702}:
            score += 65
            reasons.append(f"persistence or malware event {current.event_id}")
        if {4624, 4688}.issubset(event_ids):
            score += 35
            reasons.append("login followed by process creation")
        if {4688, 4698}.issubset(event_ids) or {4688, 7045}.issubset(event_ids):
            score += 35
            reasons.append("process creation followed by persistence change")
        if {4672, 4688}.issubset(event_ids):
            score += 25
            reasons.append("special privilege followed by process creation")
        if current.event_id in {4104, 1} and current.command_line:
            suspicious_tokens = {
                "-enc", "encodedcommand", "downloadstring", "invoke-expression",
                "rundll32", "regsvr32", "mshta", "certutil", "bitsadmin",
            }
            if any(token in current.command_line.lower() for token in suspicious_tokens):
                score += 50
                reasons.append("suspicious script or process command indicator")
        if any(token in behavior_text for token in ("-enc", "encodedcommand", "invoke-expression")):
            score += 50
            reasons.append("encoded or obfuscated execution behavior")
        if any(token in behavior_text for token in ("downloadstring", "invoke-webrequest", "curl", "bitsadmin")):
            score += 35
            reasons.append("download behavior in command or executable metadata")
        if any(token in behavior_text for token in ("\\temp\\", "\\appdata\\", "\\public\\", "\\downloads\\")):
            score += 25
            reasons.append("execution from a user-writable or staging path")
        if any(token in behavior_text for token in ("schtasks", "scheduled task", "service")):
            score += 60
            reasons.append("persistence behavior in event metadata")
        if any(token in behavior_text for token in ("lsass", "sam", "ntds.dit", "credential", "password")):
            score += 60
            reasons.append("credential-access behavior in event metadata")
        if any(token in behavior_text for token in ("wevtutil", "clear-eventlog", "auditpol")):
            score += 80
            reasons.append("audit or log manipulation behavior")
        return score, reasons