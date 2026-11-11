"""Small explainable baseline for Windows user and host behavior."""

import json
from collections import Counter
from pathlib import Path
from typing import Any

from globalban.models.events import WindowsEvent


class BehaviorBaseline:
    def __init__(self, *, path: str | None = None, warmup_events: int = 20) -> None:
        if warmup_events < 1:
            raise ValueError("warmup_events must be greater than zero")
        self._path = Path(path) if path else None
        self._warmup_events = warmup_events
        self._total = 0
        self._counts: Counter[str] = Counter()
        self._hours: Counter[str] = Counter()
        self._executables: Counter[str] = Counter()
        self._commands: Counter[str] = Counter()
        if self._path and self._path.exists():
            try:
                data = json.loads(self._path.read_text(encoding="utf-8"))
                if not isinstance(data, dict):
                    raise ValueError("baseline must be a JSON object")
                self._total = int(data.get("total", 0))
                counts = data.get("counts", {})
                if not isinstance(counts, dict):
                    raise ValueError("baseline counts must be a JSON object")
                self._counts.update(counts)
                hours = data.get("hours", {})
                if isinstance(hours, dict):
                    self._hours.update(hours)
                executables = data.get("executables", {})
                if isinstance(executables, dict):
                    self._executables.update(executables)
                commands = data.get("commands", {})
                if isinstance(commands, dict):
                    self._commands.update(commands)
            except (OSError, ValueError, TypeError, json.JSONDecodeError):
                self._total = 0
                self._counts.clear()
                self._hours.clear()
                self._executables.clear()
                self._commands.clear()

    def observe(self, event: WindowsEvent) -> tuple[int, str | None]:
        key = self._key(event)
        previous = self._counts[key]
        profile = self._profile_key(event)
        hour_key = f"{profile}|hour={event.timestamp.hour}"
        executable = event.executable
        executable_key = f"{profile}|executable={executable.lower()}" if executable else None
        command = event.command_line
        command_key = f"{profile}|command={command.lower()}" if command else None
        new_signals: list[str] = []
        self._counts[key] += 1
        self._hours[hour_key] += 1
        if executable_key:
            self._executables[executable_key] += 1
        if command_key:
            self._commands[command_key] += 1
        self._total += 1
        self._save()
        if self._total < self._warmup_events:
            return 0, None
        if not previous:
            new_signals.append("first-seen event type for this user on this host")
        if self._hours[hour_key] == 1:
            new_signals.append("first-seen activity hour for this user on this host")
        if executable_key and self._executables[executable_key] == 1:
            new_signals.append("first-seen executable for this user on this host")
        if command_key and self._commands[command_key] == 1:
            new_signals.append("first-seen command line for this user on this host")
        if not new_signals:
            return 0, None
        return min(15 * len(new_signals), 45), "; ".join(new_signals)

    @staticmethod
    def _key(event: WindowsEvent) -> str:
        return "|".join((BehaviorBaseline._profile_key(event), event.provider, str(event.event_id)))

    @staticmethod
    def _profile_key(event: WindowsEvent) -> str:
        return "|".join((event.host or "<unknown-host>", event.username or "<unknown-user>"))

    def _save(self) -> None:
        if not self._path:
            return
        self._path.parent.mkdir(parents=True, exist_ok=True)
        data: dict[str, Any] = {
            "total": self._total,
            "counts": self._counts,
            "hours": self._hours,
            "executables": self._executables,
            "commands": self._commands,
        }
        self._path.write_text(json.dumps(data, sort_keys=True), encoding="utf-8")