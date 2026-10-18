"""Validation for the compact explanation returned by the AI service."""

from dataclasses import dataclass
import json
from typing import Any


@dataclass(frozen=True, slots=True)
class AIExplanation:
    severity: str
    summary: str
    confidence: float = 0.0
    evidence: tuple[str, ...] = ()
    hypotheses: tuple[str, ...] = ()
    mitre_attack: tuple[str, ...] = ()
    missing_data: tuple[str, ...] = ()
    recommended_actions: tuple[str, ...] = ()


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
    confidence = data.get("confidence", 0.0)
    if (
        isinstance(confidence, bool)
        or not isinstance(confidence, (int, float))
        or not 0 <= confidence <= 1
    ):
        raise ValueError("AI response confidence must be between 0 and 1")

    def string_tuple(name: str) -> tuple[str, ...]:
        value = data.get(name, [])
        if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
            raise ValueError(f"AI response {name} must be a list of strings")
        return tuple(item.strip() for item in value if item.strip())

    return AIExplanation(
        severity=severity,
        summary=summary.strip(),
        confidence=float(confidence),
        evidence=string_tuple("evidence"),
        hypotheses=string_tuple("hypotheses"),
        mitre_attack=string_tuple("mitre_attack"),
        missing_data=string_tuple("missing_data"),
        recommended_actions=string_tuple("recommended_actions"),
    )
