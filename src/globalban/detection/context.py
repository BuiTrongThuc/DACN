"""Time-window behavioral context builder."""

from collections import deque
from dataclasses import dataclass
from datetime import datetime, timedelta

from globalban.detection.process_monitor import ProcessObservation
from globalban.models.events import WindowsEvent


@dataclass(frozen=True, slots=True)
class BehaviorContext:
    host: str
    username: str
    source_ip: str | None
    events: tuple[WindowsEvent, ...]
    processes: tuple[ProcessObservation, ...]


class ContextBuilder:
    def __init__(self, *, window_seconds: int) -> None:
        if window_seconds <= 0:
            raise ValueError("window_seconds must be greater than zero")
        self._window = timedelta(seconds=window_seconds)
        self._events: deque[WindowsEvent] = deque()
        self._processes: deque[ProcessObservation] = deque()

    def add(
        self,
        event: WindowsEvent,
        process: ProcessObservation | None = None,
    ) -> BehaviorContext:
        self._events.append(event)
        if process is not None:
            self._processes.append(process)
        cutoff = event.timestamp - self._window
        while self._events and self._events[0].timestamp < cutoff:
            self._events.popleft()
        while self._processes and self._processes[0].timestamp < cutoff:
            self._processes.popleft()
        related_events = tuple(
            item
            for item in self._events
            if item.host == event.host
            and (not event.username or item.username == event.username)
        )
        related_processes = tuple(
            item
            for item in self._processes
            if item.host == event.host
            and (not event.username or item.username == event.username)
        )
        source_ip = str(event.source_ip) if event.source_ip is not None else None
        return BehaviorContext(
            host=event.host,
            username=event.username,
            source_ip=source_ip,
            events=related_events,
            processes=related_processes,
        )