"""
attack_simulator.generator
==========================
Điều phối sinh dữ liệu tấn công, nhiễu sạch, dữ liệu UEBA 7 ngày và xuất file.
"""

from __future__ import annotations

import random
from datetime import datetime, timedelta, timezone

from attack_simulator.core.models import SCENARIO_CATALOG, SimulatedRecord
from attack_simulator.generator.attack_campaigns import (
    generate_brute_force_campaign,
    generate_c2_beaconing_campaign,
    generate_defense_evasion_campaign,
    generate_obfuscation_campaign,
    generate_persistence_campaign,
    generate_privilege_escalation_campaign,
)
from attack_simulator.generator.benign_noise import (
    generate_ambiguous_admin_noise,
    generate_benign_events,
)
from attack_simulator.generator.exporter import export_dataset_files
from attack_simulator.generator.ueba_dataset import generate_ueba_baseline_and_test_datasets


class WindowsAttackLogGenerator:
    """Generate synthetic Windows Event XML logs for attacks, benign activity, and admin noise."""

    def __init__(self, seed: int = 42) -> None:
        self.rng = random.Random(seed)
        self._ip_counter = 1

    def _next_attacker_ip(self) -> str:
        idx = self._ip_counter
        self._ip_counter += 1
        b2 = (idx // 65025) % 200 + 50
        b3 = (idx // 255) % 250 + 1
        b4 = (idx % 254) + 1
        return f"91.{b2}.{b3}.{b4}"

    def generate_dataset(
        self,
        *,
        selected_scenarios: list[str] | tuple[str, ...] | None = None,
        campaigns_per_scenario: int = 25,
        benign_count: int = 600,
        fp_noise_count: int = 30,
        unfiltered_fp: bool = False,
        start_time: datetime | None = None,
    ) -> list[SimulatedRecord]:
        if selected_scenarios is None:
            selected_scenarios = [s.key for s in SCENARIO_CATALOG]
        base = start_time or datetime(2026, 1, 15, 8, 0, 0, tzinfo=timezone.utc)

        all_records: list[SimulatedRecord] = []
        cursor = base

        for c_idx in range(campaigns_per_scenario):
            for key in selected_scenarios:
                if key == "brute_force":
                    all_records.extend(
                        generate_brute_force_campaign(self.rng, self._next_attacker_ip(), c_idx, cursor)
                    )
                    cursor += timedelta(seconds=25)
                elif key == "obfuscation":
                    all_records.extend(generate_obfuscation_campaign(c_idx, cursor))
                    cursor += timedelta(seconds=10)
                elif key == "persistence":
                    all_records.extend(generate_persistence_campaign(c_idx, cursor))
                    cursor += timedelta(seconds=15)
                elif key == "privilege_escalation":
                    all_records.extend(generate_privilege_escalation_campaign(c_idx, cursor))
                    cursor += timedelta(seconds=15)
                elif key == "defense_evasion":
                    all_records.extend(generate_defense_evasion_campaign(c_idx, cursor))
                    cursor += timedelta(seconds=12)
                elif key == "c2_beaconing":
                    all_records.extend(generate_c2_beaconing_campaign(c_idx, cursor))
                    cursor += timedelta(seconds=130)

        total_span = max(300, int((cursor - base).total_seconds()))
        if benign_count > 0:
            all_records.extend(generate_benign_events(benign_count, base, total_span))
        if fp_noise_count > 0:
            all_records.extend(
                generate_ambiguous_admin_noise(
                    fp_noise_count, base, total_span, unfiltered_fp=unfiltered_fp
                )
            )

        all_records.sort(key=lambda r: r.timestamp)
        for idx, rec in enumerate(all_records, start=1):
            rec.event_id = f"win-sim-{idx:05d}"

        return all_records


__all__ = [
    "WindowsAttackLogGenerator",
    "export_dataset_files",
    "generate_ueba_baseline_and_test_datasets",
]
