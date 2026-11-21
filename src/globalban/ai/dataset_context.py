"""Local, bounded dataset context for defensive AI explanations.

The source datasets (AD-GEN, WinLOLBIN-GT, MITRE ATT&CK) are indexed separately.
Their labels are never merged into one truth value; the combined result supplies
contextual references for analyst-reviewed AI explanations.
"""

from __future__ import annotations

import csv
import json
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

# Tăng giới hạn kích thước field CSV để đọc được các file dữ liệu lớn (AD-GEN narratives)
try:
    csv.field_size_limit(min(sys.maxsize, 10_000_000))
except OverflowError:
    csv.field_size_limit(10_000_000)


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
    """Indexes balanced AD-GEN narrative records."""

    source = "AD-GEN"

    def __init__(self, root: Path, *, max_records: int = 20000) -> None:
        self._records: list[tuple[set[str], DatasetReference]] = []

        # 1. Ưu tiên đọc từ file adgen_sample.csv đã chuẩn bị và cân bằng rủi ro
        csv_candidates = [
            root / "adgen_sample.csv",
            root.parent / "datasets" / "adgen_sample.csv",
            Path("datasets") / "adgen_sample.csv",
        ]
        loaded_from_csv = False
        for csv_path in csv_candidates:
            if csv_path.is_file():
                with csv_path.open("r", encoding="utf-8-sig", newline="") as file:
                    reader = csv.DictReader(file)
                    for row in _limited_rows(reader, max_records):
                        narrative = str(row.get("narrative") or "")
                        summary = str(row.get("summary") or narrative).strip()
                        technique = str(row.get("mitre_techniques") or row.get("mitre_tactics") or "")
                        verdict = str(row.get("verdict") or row.get("risk_level") or "")
                        rationale = str(row.get("analyst_rationale") or "")
                        combined_text = f"{narrative} {summary} {technique} {rationale}"
                        if summary:
                            reference = DatasetReference(
                                self.source,
                                summary[:500],
                                technique,
                                verdict,
                            )
                            self._records.append((_tokens(combined_text), reference))
                loaded_from_csv = True
                break

        # 2. Đồng thời hoặc fallback đọc từ JSONL trong LAB và REAL
        if not loaded_from_csv or len(self._records) < max_records:
            remaining = max_records - len(self._records)
            per_path = max(1000, remaining // 2)
            for path in (root / "LAB", root / "REAL"):
                for record in _jsonl_records(path, max_records=per_path):
                    narrative = str(record.get("narrative") or "")
                    label = record.get("label") if isinstance(record.get("label"), dict) else {}
                    techniques = label.get("mitre_techniques", []) if isinstance(label, dict) else []
                    technique = ", ".join(str(item) for item in techniques[:3])
                    summary = str(label.get("summary") or narrative).strip()
                    if summary:
                        reference = DatasetReference(
                            self.source,
                            summary[:500],
                            technique,
                            str(label.get("verdict") or ""),
                        )
                        self._records.append((_tokens(narrative + " " + summary + " " + technique), reference))

    def search(self, text: str, *, limit: int = 3) -> tuple[DatasetReference, ...]:
        return _rank(self._records, text, limit=limit)


class WinLolbinPreprocessor:
    """Indexes processed WinLOLBIN-GT CSV rows."""

    source = "WinLOLBIN-GT"

    def __init__(self, root: Path, *, max_records: int = 20000) -> None:
        self._records: list[tuple[set[str], DatasetReference]] = []

        # Ưu tiên các file sample processed CSV (tránh đọc file 10 triệu dòng > 50MB)
        candidates: list[Path] = []
        if root.is_dir():
            for p in sorted(root.glob("*.csv")):
                try:
                    if p.is_file() and p.stat().st_size < 50 * 1024 * 1024:
                        candidates.append(p)
                except OSError:
                    continue

        if not candidates:
            sample_names = [
                "winlolbin_gt_sample_processed_features_benign_500_lines.csv",
                "winlolbin_gt_sample_processed_features_malicious_500_lines.csv",
            ]
            candidates = [root / name for name in sample_names if (root / name).is_file()]

        for path in candidates:
            with path.open("r", encoding="utf-8-sig", newline="") as file:
                reader = csv.DictReader(file)
                for row in _limited_rows(reader, max_records):
                    text = " ".join(
                        str(row.get(key) or "")
                        for key in (
                            "process_name",
                            "parent_process",
                            "command_line",
                            "model_text",
                            "mitre_technique",
                        )
                    )
                    if not text.strip():
                        continue

                    reference = DatasetReference(
                        self.source,
                        str(row.get("model_text") or text)[:500],
                        str(row.get("mitre_technique") or ""),
                        "malicious"
                        if str(row.get("label") or "0") == "1"
                        else "benign",
                    )
                    self._records.append((_tokens(text), reference))

    def search(self, text: str, *, limit: int = 3) -> tuple[DatasetReference, ...]:
        return _rank(self._records, text, limit=limit)


class MitreAttackPreprocessor:
    """Indexes MITRE ATT&CK Windows techniques for grounding."""

    source = "MITRE ATT&CK"

    def __init__(self, root: Path, *, max_records: int = 1000) -> None:
        self._records: list[tuple[set[str], DatasetReference]] = []
        candidates = [
            root / "attack_techniques.csv",
            root / "datasets" / "attack_techniques.csv",
            Path("datasets") / "attack_techniques.csv",
        ]
        target_path: Path | None = None
        for p in candidates:
            if p.is_file():
                target_path = p
                break

        if target_path is None and root.is_dir():
            found = list(root.glob("*attack*technique*.csv"))
            if found:
                target_path = found[0]

        if target_path and target_path.is_file():
            with target_path.open("r", encoding="utf-8-sig", newline="") as file:
                reader = csv.DictReader(file)
                for row in _limited_rows(reader, max_records):
                    tid = str(row.get("technique_id") or "").strip()
                    name = str(row.get("name") or "").strip()
                    tactics = str(row.get("tactics") or "").strip()
                    desc = str(row.get("description") or "").strip()
                    summary = f"[{tid}] {name} ({tactics}): {desc}"
                    tokens = _tokens(f"{tid} {name} {tactics} {desc}")
                    reference = DatasetReference(
                        self.source,
                        summary[:500],
                        tid,
                        tactics,
                    )
                    self._records.append((tokens, reference))

    def search(self, text: str, *, limit: int = 2) -> tuple[DatasetReference, ...]:
        return _rank(self._records, text, limit=limit)


class CombinedDatasetKnowledge:
    """Search AD-GEN, WinLOLBIN-GT, and MITRE ATT&CK independently for prompt references."""

    def __init__(
        self,
        adgen: ADGenPreprocessor,
        lolbin: WinLolbinPreprocessor,
        mitre: MitreAttackPreprocessor | None = None,
    ) -> None:
        self._adgen = adgen
        self._lolbin = lolbin
        self._mitre = mitre

    @classmethod
    def from_environment(cls) -> CombinedDatasetKnowledge:
        cwd = Path.cwd()
        adgen_root = Path(os.getenv("GLOBALBAN_ADGEN_PATH", str(cwd / "AD-GEN")))
        lolbin_root = Path(
            os.getenv("GLOBALBAN_LOLBIN_DATASET_PATH", str(cwd / "datasets" / "WinLOLBIN-GT-dataset"))
        )
        mitre_root = Path(os.getenv("GLOBALBAN_MITRE_PATH", str(cwd / "datasets")))
        return cls(
            ADGenPreprocessor(adgen_root),
            WinLolbinPreprocessor(lolbin_root),
            MitreAttackPreprocessor(mitre_root),
        )

    def context_for(self, payload: dict[str, object], *, limit_per_source: int = 2) -> str:
        text = _payload_text(payload)
        sections: list[str] = []
        sources = [
            (ADGenPreprocessor.source, self._adgen.search(text, limit=limit_per_source)),
            (WinLolbinPreprocessor.source, self._lolbin.search(text, limit=limit_per_source)),
        ]
        if self._mitre is not None:
            sources.append(
                (MitreAttackPreprocessor.source, self._mitre.search(text, limit=limit_per_source))
            )

        for source, references in sources:
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
