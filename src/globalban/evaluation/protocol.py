"""Reproducible evaluation protocol for labeled Windows event cases."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable

from globalban.detection.sequence import SequenceCorrelator
from globalban.evaluation.metrics import DetectionMetrics, evaluate_binary
from globalban.models.events import WindowsEvent


@dataclass(frozen=True, slots=True)
class LabeledCase:
    case_id: str
    expected_detected: bool
    events: tuple[WindowsEvent, ...]


@dataclass(frozen=True, slots=True)
class CasePrediction:
    case_id: str
    expected_detected: bool
    predicted_detected: bool
    max_score: int


@dataclass(frozen=True, slots=True)
class EvaluationReport:
    cases: int
    metrics: DetectionMetrics
    predictions: tuple[CasePrediction, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "cases": self.cases,
            "metrics": asdict(self.metrics),
            "predictions": [asdict(item) for item in self.predictions],
        }


def load_labeled_cases(path: Path) -> tuple[LabeledCase, ...]:
    cases: list[LabeledCase] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            try:
                payload = json.loads(line)
                events = tuple(_event_from_dict(item) for item in payload["events"])
                cases.append(
                    LabeledCase(
                        case_id=str(payload["case_id"]),
                        expected_detected=bool(payload["expected_detected"]),
                        events=events,
                    )
                )
            except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
                raise ValueError(f"invalid labeled case at line {line_number}") from exc
    return tuple(cases)


def evaluate_cases(
    cases: Iterable[LabeledCase],
    *,
    window_seconds: int = 300,
) -> EvaluationReport:
    predictions: list[CasePrediction] = []
    for case in cases:
        correlator = SequenceCorrelator(window_seconds=window_seconds)
        scores: list[int] = []
        for event in sorted(case.events, key=lambda item: item.timestamp):
            candidate = correlator.add(event)
            if candidate is not None:
                scores.append(candidate.score)
        max_score = max(scores, default=0)
        predictions.append(
            CasePrediction(
                case.case_id,
                case.expected_detected,
                bool(scores),
                max_score,
            )
        )
    metrics = evaluate_binary(
        [item.expected_detected for item in predictions],
        [item.predicted_detected for item in predictions],
    )
    return EvaluationReport(len(predictions), metrics, tuple(predictions))


def _event_from_dict(payload: Any) -> WindowsEvent:
    if not isinstance(payload, dict):
        raise TypeError("event must be an object")
    timestamp = datetime.fromisoformat(str(payload["timestamp"]))
    fields = payload.get("fields", {})
    if not isinstance(fields, dict):
        raise TypeError("event fields must be an object")
    return WindowsEvent(
        timestamp=timestamp,
        event_id=int(payload["event_id"]),
        provider=str(payload.get("provider", "fixture")),
        fields={str(key): str(value) for key, value in fields.items()},
        host=str(payload.get("host", "fixture-host")),
    )
