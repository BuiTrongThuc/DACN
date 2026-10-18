"""Load Atomic-EVTX attack metadata for evaluation, not runtime blocking."""

import csv
from collections import Counter
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True, slots=True)
class AtomicTechnique:
    category: str
    technique_id: str
    description: str


def load_atomic_catalog(path: str | Path) -> tuple[AtomicTechnique, ...]:
    """Load the repository's full_list_of_attacks_simulated.csv locally."""
    techniques: list[AtomicTechnique] = []
    with Path(path).open("r", encoding="utf-8-sig", newline="") as file:
        for row in csv.DictReader(file):
            category = (row.get("Category") or "").strip()
            technique_id = (row.get("TTP ID") or "").strip()
            description = " ".join((row.get("Description") or "").split())
            if category and technique_id and description:
                techniques.append(AtomicTechnique(category, technique_id, description))
    return tuple(techniques)


def summarize_atomic_catalog(
    techniques: tuple[AtomicTechnique, ...],
) -> dict[str, int]:
    return dict(Counter(technique.category for technique in techniques))