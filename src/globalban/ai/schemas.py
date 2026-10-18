"""Validation for the compact explanation returned by the AI service."""

from dataclasses import dataclass
import json
from typing import Any


@dataclass(frozen=True, slots=True)
class AIExplanation:
    severity: str
    summary: str


def parse_explanation(content: str) -> AIExplanation:
    try:
        data: Any = json.loads(content)
    except json.JSONDecodeError as exc:
        raise ValueError("AI response is not valid JSON") from exc
    if not isinstance(data, dict):
        raise ValueError("AI response must be a JSON object")
    severity = data.get("severity")
    summary = data.get("summary")
    if severity not in {"low", "medium", "high"}:
        raise ValueError("AI response severity must be low, medium, or high")
    if not isinstance(summary, str) or not summary.strip() or len(summary) > 500:
        raise ValueError("AI response summary must contain 1 to 500 characters")
    return AIExplanation(severity=severity, summary=summary.strip())
