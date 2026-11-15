"""
attack_simulator
================
GlobalBan Red-Team Adversary Emulation, Benchmark Generator & SOC Evaluation Suite.

Modules:
  - models: ScenarioSpec, SCENARIO_CATALOG, MITRE metadata, SimulatedRecord
  - xml_utils: Windows Event XML builder, ParsedWinEvent, XML parsers
  - generator: Attack campaign log generators, benign events, 7-day UEBA baseline
  - engine: BuiltinGlobalBanEngine & BuiltinUEBAEngine (faithful standalone detection)
  - evaluator: Unified dual-mode evaluation pipeline & WinLOLBIN-GT benchmark
  - gui: Modern Dark Cybersecurity SOC & Red-Team GUI
"""

from __future__ import annotations

from attack_simulator.engine import BuiltinGlobalBanEngine, BuiltinUEBAEngine
from attack_simulator.evaluator import (
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
from attack_simulator.generator import (
    WindowsAttackLogGenerator,
    export_dataset_files,
    generate_ueba_baseline_and_test_datasets,
)
from attack_simulator.gui import ModernRedTeamStudioApp, launch_gui
from attack_simulator.models import (
    MITRE_METADATA,
    PUBLIC_C2_IPS,
    SCENARIO_BY_CODE,
    SCENARIO_BY_KEY,
    SCENARIO_CATALOG,
    ScenarioSpec,
    SimulatedRecord,
)
from attack_simulator.xml_utils import (
    ParsedWinEvent,
    build_windows_event_xml,
    parse_xml_event_element,
    parse_xml_event_string,
    parse_xml_events_file,
)

__all__ = [
    # Models & metadata
    "ScenarioSpec",
    "SCENARIO_CATALOG",
    "SCENARIO_BY_KEY",
    "SCENARIO_BY_CODE",
    "MITRE_METADATA",
    "PUBLIC_C2_IPS",
    "SimulatedRecord",
    # XML utilities
    "build_windows_event_xml",
    "ParsedWinEvent",
    "parse_xml_event_element",
    "parse_xml_event_string",
    "parse_xml_events_file",
    # Generator
    "WindowsAttackLogGenerator",
    "export_dataset_files",
    "generate_ueba_baseline_and_test_datasets",
    # Built-in Engine
    "BuiltinGlobalBanEngine",
    "BuiltinUEBAEngine",
    # Evaluator & Benchmarks
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
    # GUI
    "ModernRedTeamStudioApp",
    "launch_gui",
]
