"""Replay synthetic scenarios through GlobalBan detectors and score the result."""

import argparse
import json
from dataclasses import dataclass, asdict
from datetime import datetime, timezone

from globalban.detection.behavior import WindowsBehaviorDetector
from globalban.detection.sequence import SequenceCorrelator
from globalban.ingestion.parser import parse_windows_security_event
from globalban.redteam.scenarios import SCENARIOS, Scenario


@dataclass(slots=True)
class ScenarioResult:
    name: str
    technique: str
    expected: bool
    detected: bool
    events: int
    first_alert_at_event: int | None
    max_score: int
    reasons: list[str]

    @property
    def verdict(self) -> str:
        if self.expected and self.detected:
            return "TRUE_POSITIVE"
        if self.expected and not self.detected:
            return "MISSED"
        if not self.expected and self.detected:
            return "FALSE_POSITIVE"
        return "TRUE_NEGATIVE"


def run_scenario(scenario: Scenario) -> ScenarioResult:
    sequence = SequenceCorrelator(window_seconds=300)
    behavior = WindowsBehaviorDetector(state_path=None)
    lines = scenario.build()
    first: int | None = None
    max_score = 0
    reasons: list[str] = []
    for index, line in enumerate(lines, start=1):
        event = parse_windows_security_event(
            line, now=datetime(2025, 1, 1, tzinfo=timezone.utc)
        )
        if event is None:
            continue
        for detector in (sequence, behavior):
            candidate = detector.add(event)
            if candidate is None:
                continue
            first = first or index
            max_score = max(max_score, candidate.score)
            for reason in candidate.reasons:
                if reason not in reasons:
                    reasons.append(reason)
    return ScenarioResult(
        name=scenario.name,
        technique=scenario.technique,
        expected=scenario.expect_detect,
        detected=first is not None,
        events=len(lines),
        first_alert_at_event=first,
        max_score=max_score,
        reasons=reasons,
    )


def run_all() -> list[ScenarioResult]:
    return [run_scenario(s) for s in SCENARIOS]


def summarize(results: list[ScenarioResult]) -> dict[str, float]:
    tp = sum(r.verdict == "TRUE_POSITIVE" for r in results)
    fn = sum(r.verdict == "MISSED" for r in results)
    fp = sum(r.verdict == "FALSE_POSITIVE" for r in results)
    tn = sum(r.verdict == "TRUE_NEGATIVE" for r in results)
    recall = tp / (tp + fn) if tp + fn else 0.0
    precision = tp / (tp + fp) if tp + fp else 0.0
    return {"tp": tp, "fn": fn, "fp": fp, "tn": tn,
            "recall": round(recall, 3), "precision": round(precision, 3)}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Replay synthetic attack scenarios against GlobalBan (no real attack)."
    )
    parser.add_argument("--json", action="store_true", help="print JSON instead of a table")
    args = parser.parse_args(argv)

    results = run_all()
    summary = summarize(results)
    if args.json:
        print(json.dumps({"results": [asdict(r) | {"verdict": r.verdict} for r in results],
                          "summary": summary}, indent=2))
    else:
        print(f"{'SCENARIO':32} {'VERDICT':15} {'SCORE':>5} {'ALERT@':>6}  TECHNIQUE")
        for r in results:
            print(f"{r.name:32} {r.verdict:15} {r.max_score:>5} "
                  f"{str(r.first_alert_at_event or '-'):>6}  {r.technique}")
            for reason in r.reasons[1:]:
                print(f"{'':34}- {reason}")
        print(f"\nSummary: {summary}")
    return 0 if summary["fn"] == 0 and summary["fp"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
