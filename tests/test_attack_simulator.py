"""
tests.test_attack_simulator
===========================
Unit tests for the modular GlobalBan Red-Team simulation & evaluation suite.
Tests full pipeline across all scenarios, admin noise FPR filtering, UEBA 7-day profiling,
and WinLOLBIN-GT living-off-the-land benchmark with zero external dependencies.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from attack_simulator.engine import BuiltinGlobalBanEngine, BuiltinUEBAEngine
from attack_simulator.evaluator import (
    DEFAULT_GLOBALBAN_ROOT,
    push_xml_to_globalban_cli,
    run_globalban_evaluation,
    run_lolbin_evaluation,
    run_ueba_evaluation,
    run_unified_evaluation,
)
from attack_simulator.generator import (
    WindowsAttackLogGenerator,
    export_dataset_files,
    generate_ueba_baseline_and_test_datasets,
)
from attack_simulator.models import SCENARIO_CATALOG


class AttackSimulatorTests(unittest.TestCase):
    def test_all_six_scenarios_and_benign_reach_perfect_metrics(self) -> None:
        gen = WindowsAttackLogGenerator(seed=123)
        records = gen.generate_dataset(
            selected_scenarios=[s.key for s in SCENARIO_CATALOG],
            campaigns_per_scenario=10,
            benign_count=300,
            fp_noise_count=0,
        )
        self.assertGreater(len(records), 450)

        with tempfile.TemporaryDirectory() as tmp:
            jsonl_path = Path(tmp) / "eval.jsonl"
            xml_path = Path(tmp) / "events.xml"
            export_dataset_files(records, jsonl_path, xml_path)

            report = run_globalban_evaluation(
                jsonl_path, xml_path, globalban_root=DEFAULT_GLOBALBAN_ROOT
            )
            self.assertEqual(report.precision, 1.0)
            self.assertEqual(report.recall, 1.0)
            self.assertEqual(report.f1, 1.0)
            self.assertEqual(report.false_positive_rate, 0.0)
            self.assertEqual(report.rule_match_accuracy, 1.0)
            self.assertGreater(report.auth_burst_level1_count, 0)
            self.assertGreater(report.auth_burst_level2_count, 0)
            self.assertGreater(report.persistence_correlator_count, 0)

            for expected_rule in (
                "AUTH-FAILURE-BURST",
                "OBFUSCATED-COMMAND-LINE",
                "WINDOWS-4624-4688-4698",
                "PRIVILEGE-CHANGE",
                "WINDOWS-4720-4732-4704",
                "WINDOWS-7045-1102",
                "C2-BEACONING",
            ):
                self.assertIn(expected_rule, report.triggered_rule_counts)

            cli_alerts = push_xml_to_globalban_cli(
                xml_path, globalban_root=DEFAULT_GLOBALBAN_ROOT
            )
            self.assertEqual(
                len(cli_alerts), sum(report.triggered_rule_counts.values())
            )

    def test_admin_noise_filtered_without_false_positives_by_default(self) -> None:
        gen = WindowsAttackLogGenerator(seed=99)
        records = gen.generate_dataset(
            selected_scenarios=["c2_beaconing"],
            campaigns_per_scenario=5,
            benign_count=100,
            fp_noise_count=20,
        )
        with tempfile.TemporaryDirectory() as tmp:
            jsonl_path = Path(tmp) / "eval_admin_noise.jsonl"
            export_dataset_files(records, jsonl_path)
            report = run_globalban_evaluation(
                jsonl_path, globalban_root=DEFAULT_GLOBALBAN_ROOT
            )
            self.assertEqual(report.false_positive, 0)
            self.assertEqual(report.false_positive_rate, 0.0)
            self.assertEqual(report.precision, 1.0)
            self.assertEqual(report.recall, 1.0)
            self.assertEqual(report.f1, 1.0)
            self.assertEqual(report.rule_match_accuracy, 1.0)

    def test_unfiltered_false_positive_noise_increases_fpr_and_lowers_precision(self) -> None:
        gen = WindowsAttackLogGenerator(seed=99)
        records = gen.generate_dataset(
            selected_scenarios=["obfuscation"],
            campaigns_per_scenario=10,
            benign_count=100,
            fp_noise_count=10,
            unfiltered_fp=True,
        )
        with tempfile.TemporaryDirectory() as tmp:
            jsonl_path = Path(tmp) / "eval_fp.jsonl"
            export_dataset_files(records, jsonl_path)
            report = run_globalban_evaluation(
                jsonl_path, globalban_root=DEFAULT_GLOBALBAN_ROOT
            )
            self.assertEqual(report.false_positive, 10)
            self.assertGreater(report.false_positive_rate, 0.0)
            self.assertLess(report.precision, 1.0)
            self.assertEqual(report.recall, 1.0)

    def test_ueba_7day_baseline_atomic_redteam_and_lolbin_evaluation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ueba_res = run_ueba_evaluation(tmp, globalban_root=DEFAULT_GLOBALBAN_ROOT)
            self.assertEqual(ueba_res["learned_user_count"], 3)
            self.assertEqual(ueba_res["learned_machine_count"], 3)
            self.assertEqual(ueba_res["confusion_matrix"]["TP"], 8)
            self.assertEqual(ueba_res["confusion_matrix"]["FP"], 0)
            self.assertEqual(ueba_res["confusion_matrix"]["FN"], 0)
            self.assertEqual(ueba_res["confusion_matrix"]["TN"], 10)
            self.assertEqual(ueba_res["metrics"]["precision"], 1.0)
            self.assertEqual(ueba_res["metrics"]["recall"], 1.0)
            self.assertEqual(ueba_res["metrics"]["f1_score"], 1.0)
            self.assertEqual(ueba_res["metrics"]["false_positive_rate"], 0.0)
            self.assertEqual(ueba_res["metrics"]["deviation_tag_match_rate"], 1.0)
            self.assertTrue(Path(ueba_res["profile_json_path"]).is_file())

            cli_ueba_alerts = push_xml_to_globalban_cli(
                ueba_res["test_xml_path"],
                globalban_root=DEFAULT_GLOBALBAN_ROOT,
                learn_baseline_xml=ueba_res["baseline_xml_path"],
                profile_path=ueba_res["profile_json_path"],
            )
            ueba_rules = [a.get("rule_id") for a in cli_ueba_alerts]
            self.assertEqual(ueba_rules.count("UEBA-BEHAVIOR-DEVIATION"), 8)

            lolbin_res = run_lolbin_evaluation(globalban_root=DEFAULT_GLOBALBAN_ROOT)
            self.assertIsNotNone(lolbin_res)
            assert lolbin_res is not None
            self.assertEqual(lolbin_res["metrics"]["precision"], 1.0)
            self.assertEqual(lolbin_res["metrics"]["recall"], 1.0)
            self.assertEqual(lolbin_res["metrics"]["f1_score"], 1.0)
            self.assertEqual(lolbin_res["metrics"]["false_positive_rate"], 0.0)


if __name__ == "__main__":
    unittest.main()
