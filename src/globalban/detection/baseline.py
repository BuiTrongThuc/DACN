"""Small explainable baseline for Windows event frequency."""

import json
from collections import Counter
from pathlib import Path

from globalban.models.events import WindowsEvent


class BehaviorBaseline:
    def __init__(self, *, path: str | None = None, warmup_events: int = 20) -> None:
        if warmup_events < 1:
            raise ValueError("warmup_events must be greater than zero")
        self._path = Path(path) if path else None
        self._warmup_events = warmup_events
        self._total = 0
        self._counts: Counter[str] = Counter()
        if self._path and self._path.exists():
            data = json.loads(self._path.read_text(encoding="utf-8"))
            self._total = int(data.get("total", 0))
            self._counts.update(data.get("counts", {}))

    def observe(self, event: WindowsEvent) -> tuple[int, str | None]:
        key = self._key(event)
        previous = self._counts[key]
        self._counts[key] += 1
        self._total += 1
        self._save()
        if self._total < self._warmup_events or previous:
            return 0, None
        return 15, "first-seen event for this host/user/event type"

    @staticmethod
    def _key(event: WindowsEvent) -> str:
        return "|".join((event.provider, str(event.event_id), event.username or "<unknown>"))

    def _save(self) -> None:
        if not self._path:
            return
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._path.write_text(
            json.dumps({"total": self._total, "counts": self._counts}, sort_keys=True),
            encoding="utf-8",
        )