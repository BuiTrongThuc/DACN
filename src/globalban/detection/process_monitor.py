"""Process observations and parent-child context from Windows events."""

from dataclasses import dataclass
from datetime import datetime

from globalban.models.events import WindowsEvent


@dataclass(frozen=True, slots=True)
class ProcessObservation:
    timestamp: datetime
    host: str
    username: str
    process_id: str
    parent_process_id: str | None
    executable: str | None
    command_line: str | None
    source_event_id: int


def observe_process(event: WindowsEvent) -> ProcessObservation | None:
    """Normalize Sysmon 1 or Security 4688 into a process observation."""
    if event.event_id not in {1, 4688} or not event.process_id:
        return None
    return ProcessObservation(
        timestamp=event.timestamp,
        host=event.host,
        username=event.username,
        process_id=event.process_id,
        parent_process_id=event.parent_process_id,
        executable=event.executable,
        command_line=event.command_line,
        source_event_id=event.event_id,
    )


class ProcessTree:
    def __init__(self) -> None:
        self._processes: dict[tuple[str, str], ProcessObservation] = {}

    def add(self, observation: ProcessObservation) -> None:
        self._processes[(observation.host, observation.process_id)] = observation

    def ancestry(self, observation: ProcessObservation) -> tuple[ProcessObservation, ...]:
        chain: list[ProcessObservation] = []
        parent_id = observation.parent_process_id
        seen: set[str] = {observation.process_id}
        while parent_id and parent_id not in seen:
            parent = self._processes.get((observation.host, parent_id))
            if parent is None:
                break
            chain.append(parent)
            seen.add(parent_id)
            parent_id = parent.parent_process_id
        return tuple(chain)