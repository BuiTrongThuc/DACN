"""
attack_simulator.generator.exporter
===================================
Xuất dataset giả lập ra định dạng .jsonl (kèm Ground Truth) và .xml (Windows Event Viewer XML).
"""

from __future__ import annotations

import json
from pathlib import Path

from attack_simulator.core.models import SimulatedRecord

def export_dataset_files(
    records: list[SimulatedRecord],
    jsonl_path: str | Path,
    xml_path: str | Path | None = None,
) -> tuple[Path, Path | None]:
    j_path = Path(jsonl_path)
    j_path.parent.mkdir(parents=True, exist_ok=True)
    with j_path.open("w", encoding="utf-8", newline="\n") as f:
        for rec in records:
            f.write(json.dumps(rec.to_jsonl_dict(), ensure_ascii=False) + "\n")

    x_path: Path | None = None
    if xml_path is not None:
        x_path = Path(xml_path)
        x_path.parent.mkdir(parents=True, exist_ok=True)
        with x_path.open("w", encoding="utf-8", newline="\n") as f:
            f.write('<?xml version="1.0" encoding="utf-8"?>\n<Events>\n')
            for rec in records:
                f.write(f"  {rec.xml}\n")
            f.write("</Events>\n")

    return j_path, x_path
