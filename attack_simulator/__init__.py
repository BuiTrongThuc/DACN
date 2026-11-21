"""
attack_simulator
================
GlobalBan Red-Team Adversary Emulation, Benchmark Generator & SOC Evaluation Suite (Modular).
"""

from __future__ import annotations

from attack_simulator.core.engine import BuiltinGlobalBanEngine, BuiltinUEBAEngine
from attack_simulator.core.evaluator import (
    DEFAULT_GLOBALBAN_ROOT,
    DetailedEvaluationReport,
    format_report_text,
    push_xml_to_globalban_cli,
    resolve_default_globalban_root,
    run_builtin_lolbin_benchmark,
    run_globalban_evaluation,
    run_lolbin_evaluation,
    run_ueba_evaluation,
    run_unified_evaluation,
)
from attack_simulator.core.models import (
    MITRE_METADATA,
    PUBLIC_C2_IPS,
    SCENARIO_BY_CODE,
    SCENARIO_BY_KEY,
    SCENARIO_CATALOG,
    ScenarioSpec,
    SimulatedRecord,
)
from attack_simulator.core.xml_utils import (
    ParsedWinEvent,
    build_windows_event_xml,
    parse_xml_event_element,
    parse_xml_event_string,
    parse_xml_events_file,
)
from attack_simulator.generator import (
    WindowsAttackLogGenerator,
    export_dataset_files,
    generate_ueba_baseline_and_test_datasets,
)
from attack_simulator.ui import ModernRedTeamStudioApp, launch_gui

__all__ = [
    "ScenarioSpec",
    "SCENARIO_CATALOG",
    "SCENARIO_BY_KEY",
    "SCENARIO_BY_CODE",
    "MITRE_METADATA",
    "PUBLIC_C2_IPS",
    "SimulatedRecord",
    "build_windows_event_xml",
    "ParsedWinEvent",
    "parse_xml_event_element",
    "parse_xml_event_string",
    "parse_xml_events_file",
    "WindowsAttackLogGenerator",
    "export_dataset_files",
    "generate_ueba_baseline_and_test_datasets",
    "BuiltinGlobalBanEngine",
    "BuiltinUEBAEngine",
    "resolve_default_globalban_root",
    "DEFAULT_GLOBALBAN_ROOT",
    "DetailedEvaluationReport",
    "run_builtin_lolbin_benchmark",
    "run_unified_evaluation",
    "format_report_text",
    "push_xml_to_globalban_cli",
    "run_globalban_evaluation",
    "run_ueba_evaluation",
    "run_lolbin_evaluation",
    "ModernRedTeamStudioApp",
    "launch_gui",
]
