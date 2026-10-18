import json

import pytest

from globalban.ai.schemas import parse_explanation


def test_parse_structured_ai_explanation():
    explanation = parse_explanation(
        json.dumps(
            {
                "severity": "high",
                "summary": "A persistence sequence followed a process launch.",
                "confidence": 0.8,
                "evidence": ["4688", "4698"],
                "hypotheses": ["scheduled task persistence"],
                "mitre_attack": ["T1053.005"],
                "missing_data": ["task author"],
                "recommended_actions": ["review the task before containment"],
            }
        )
    )

    assert explanation.severity == "high"
    assert explanation.confidence == 0.8
    assert explanation.mitre_attack == ("T1053.005",)


def test_parse_rejects_invalid_confidence():
    with pytest.raises(ValueError, match="confidence"):
        parse_explanation('{"severity":"low","summary":"ok","confidence":2}')