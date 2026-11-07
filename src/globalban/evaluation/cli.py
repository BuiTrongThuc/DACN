"""Command-line entry point for labeled evaluation."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from globalban.evaluation.protocol import evaluate_cases, load_labeled_cases


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate labeled Windows events.")
    parser.add_argument("--labels", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--window-seconds", type=int, default=300)
    args = parser.parse_args()
    report = evaluate_cases(
        load_labeled_cases(args.labels),
        window_seconds=args.window_seconds,
    )
    args.output.write_text(
        json.dumps(report.to_dict(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(report.to_dict(), indent=2, sort_keys=True))
