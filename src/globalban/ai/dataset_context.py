"""Local, bounded dataset context for defensive AI explanations.

The two source datasets are intentionally indexed separately. Their labels are
never merged into one truth value; the combined result only supplies references
for an analyst-reviewed explanation.
"""

from __future__ import annotations

import csv
import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable


@dataclass(frozen=True, slots=True)
class DatasetReference:
    source: str
    summary: str
    technique: str = ""
    label: str = ""


def _tokens(value: str) -> set[str]:
    return {
        token
        for token in re.findall(r"[a-z0-9_./:-]{3,}", value.lower())
        if token not in {"the", "and", "event", "process"}
    }


def _payload_text(payload: dict[str, object]) -> str:
    return json.dumps(payload, ensure_ascii=True, sort_keys=True)


class ADGenPreprocessor:
    """Indexes a bounded sample of AD-GEN narrative records."""

    source = "AD-GEN"

    def __init__(self, root: Path, *, max_records: int = 5000) -> None:
        self._records: list[tuple[set[str], DatasetReference]] = []
        for path in (root / "LAB", root / "REAL"):
            for record in _jsonl_records(path, max_records=max_records):
                narrative = str(record.get("narrative") or "")
                label = record.get("label") if isinstance(record.get("label"), dict) else {}
                techniques = label.get("mitre_techniques", []) if isinstance(label, dict) else []
                technique = ", ".join(str(item) for item in techniques[:3])
                summary = str(label.get("summary") or narrative).strip()
                if summary:
                    reference = DatasetReference(self.source, summary[:500], technique, str(label.get("verdict") or ""))
                    self._records.append((_tokens(narrative + " " + summary), reference))

    def search(self, text: str, *, limit: int = 3) -> tuple[DatasetReference, ...]:
        return _rank(self._records, text, limit=limit)


class WinLolbinPreprocessor:
    """Indexes a bounded sample of processed WinLOLBIN-GT CSV rows."""

    source = "WinLOLBIN-GT"

    def __init__(self, root: Path, *, max_records: int = 5000) -> None:
        self._records: list[tuple[set[str], DatasetReference]] = []
        candidates = sorted(root.rglob("*processed*.csv"))
        for path in candidates:
            with path.open("r", encoding="utf-8-sig", newline="") as file:
                for row in _limited_rows(csv.DictReader(file), max_records):
                    text = " ".join(
                        str(row.get(key) or "")
                        for key in ("process_name", "parent_process", "command_line", "model_text", "mitre_technique")
                    )
                    if text.strip():
                        reference = DatasetReference(
                            self.source,
                            str(row.get("model_text") or text)[:500],
                            str(row.get("mitre_technique") or ""),
                            "malicious" if str(row.get("label") or "0") == "1" else "benign",
                        )
                        self._records.append((_tokens(text), reference))

    def search(self, text: str, *, limit: int = 3) -> tuple[DatasetReference, ...]:
        return _rank(self._records, text, limit=limit)


class CombinedDatasetKnowledge:
    """Search AD-GEN and WinLOLBIN-GT independently for prompt references."""

    def __init__(self, adgen: ADGenPreprocessor, lolbin: WinLolbinPreprocessor) -> None:
        self._adgen = adgen
        self._lolbin = lolbin

    @classmethod
    def from_environment(cls) -> CombinedDatasetKnowledge:
        cwd = Path.cwd()
        adgen_root = Path(os.getenv("GLOBALBAN_ADGEN_PATH", str(cwd / "AD-GEN")))
        lolbin_root = Path(
            os.getenv("GLOBALBAN_LOLBIN_DATASET_PATH", str(cwd / "datasets" / "WinLOLBIN-GT-dataset"))
        )
        return cls(ADGenPreprocessor(adgen_root), WinLolbinPreprocessor(lolbin_root))

    def context_for(self, payload: dict[str, object], *, limit_per_source: int = 2) -> str:
        text = _payload_text(payload)
        sections: list[str] = []
        for source, references in (
            (ADGenPreprocessor.source, self._adgen.search(text, limit=limit_per_source)),
            (WinLolbinPreprocessor.source, self._lolbin.search(text, limit=limit_per_source)),
        ):
            if not references:
                continue
            lines = [f"[{source}]"]
            lines.extend(
                f"- label={reference.label or 'unknown'} technique={reference.technique or 'unknown'}: {reference.summary}"
                for reference in references
            )
            sections.append("\n".join(lines))
        return "\n".join(sections)


def _jsonl_records(root: Path, *, max_records: int) -> Iterable[dict[str, Any]]:
    if not root.exists():
        return ()
    paths = sorted(root.glob("*.jsonl"))
    records: list[dict[str, Any]] = []
    for path in paths:
        with path.open("r", encoding="utf-8") as file:
            for line in file:
                if len(records) >= max_records:
                    return records
                try:
                    value = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(value, dict):
                    records.append(value)
    return records


def _limited_rows(rows: Iterable[dict[str, str]], max_records: int) -> Iterable[dict[str, str]]:
    for index, row in enumerate(rows):
        if index >= max_records:
            break
        yield row


def _rank(
    records: Iterable[tuple[set[str], DatasetReference]],
    text: str,
    *,
    limit: int,
) -> tuple[DatasetReference, ...]:
    query = _tokens(text)
    ranked = sorted(
        ((len(query.intersection(tokens)), reference) for tokens, reference in records),
        key=lambda item: item[0],
        reverse=True,
    )
    return tuple(reference for score, reference in ranked[:limit] if score > 0)
