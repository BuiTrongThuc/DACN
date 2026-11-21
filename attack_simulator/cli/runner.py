"""
attack_simulator.cli.runner
===========================
Xử lý lựa chọn kịch bản CLI, menu tương tác terminal và luồng thực thi tự động.
"""

from __future__ import annotations

import json
from pathlib import Path

from attack_simulator.core.evaluator import format_report_text, run_unified_evaluation
from attack_simulator.core.models import SCENARIO_BY_CODE, SCENARIO_BY_KEY, SCENARIO_CATALOG
from attack_simulator.generator import WindowsAttackLogGenerator, export_dataset_files
from config import (
    DEFAULT_BENIGN_COUNT,
    DEFAULT_CAMPAIGNS_PER_SCENARIO,
    DEFAULT_FP_NOISE_COUNT,
    DEFAULT_SEED,
)


def parse_scenario_selection(raw_values: list[str] | None) -> list[str]:
    if not raw_values:
        return [s.key for s in SCENARIO_CATALOG]
    tokens: list[str] = []
    for item in raw_values:
        for part in item.split(","):
            cleaned = part.strip().lower()
            if cleaned:
                tokens.append(cleaned)
    if not tokens or "all" in tokens or "0" in tokens:
        return [s.key for s in SCENARIO_CATALOG]

    selected: list[str] = []
    for tok in tokens:
        if tok.isdecimal() and int(tok) in SCENARIO_BY_CODE:
            key = SCENARIO_BY_CODE[int(tok)].key
        elif tok in SCENARIO_BY_KEY:
            key = tok
        else:
            valid = ", ".join(f"{s.code}:{s.key}" for s in SCENARIO_CATALOG)
            raise ValueError(f"Kịch bản không hợp lệ '{tok}'. Hỗ trợ: all hoặc {valid}")
        if key not in selected:
            selected.append(key)
    return selected


def run_interactive_cli(globalban_root: Path | None, output_dir: Path) -> int:
    print("=" * 78)
    print("   CÔNG CỤ GIẢ LẬP TẤN CÔNG WINDOWS XML & CHẤM ĐIỂM GLOBALBAN (INTERACTIVE)")
    print("=" * 78)
    for spec in SCENARIO_CATALOG:
        print(f"  [{spec.code}] {spec.title} -> {spec.expected_rules_desc}")
    print("  [0 / all] Chạy toàn bộ 6 kịch bản tấn công")
    print("-" * 78)

    raw_scen = input("Chọn kịch bản (VD: all hoặc 1,2,3,4,5,6) [mặc định: all]: ").strip()
    selected = parse_scenario_selection([raw_scen] if raw_scen else None)

    raw_camp = input(f"Số chiến dịch cho mỗi kịch bản [mặc định: {DEFAULT_CAMPAIGNS_PER_SCENARIO}]: ").strip()
    campaigns = int(raw_camp) if raw_camp.isdecimal() else DEFAULT_CAMPAIGNS_PER_SCENARIO

    raw_benign = input(f"Số lượng log bình thường (Benign) trộn lẫn [mặc định: {DEFAULT_BENIGN_COUNT}]: ").strip()
    benign = int(raw_benign) if raw_benign.isdecimal() else DEFAULT_BENIGN_COUNT

    raw_noise = input(f"Số lượng log nhiễu Admin (test False Positive) [mặc định: {DEFAULT_FP_NOISE_COUNT}]: ").strip()
    fp_noise = int(raw_noise) if raw_noise.isdecimal() else DEFAULT_FP_NOISE_COUNT

    return execute_cli_pipeline(
        selected_scenarios=selected,
        campaigns_per_scenario=campaigns,
        benign_count=benign,
        fp_noise_count=fp_noise,
        seed=DEFAULT_SEED,
        output_dir=output_dir,
        globalban_root=globalban_root,
    )


def execute_cli_pipeline(
    *,
    selected_scenarios: list[str],
    campaigns_per_scenario: int,
    benign_count: int,
    fp_noise_count: int,
    seed: int,
    output_dir: Path,
    globalban_root: Path | None,
) -> int:
    gen = WindowsAttackLogGenerator(seed=seed)
    records = gen.generate_dataset(
        selected_scenarios=selected_scenarios,
        campaigns_per_scenario=campaigns_per_scenario,
        benign_count=benign_count,
        fp_noise_count=fp_noise_count,
    )

    jsonl_path = output_dir / "simulated_windows_eval.jsonl"
    xml_path = output_dir / "simulated_windows_events.xml"
    report_json_path = output_dir / "evaluation_report.json"

    export_dataset_files(records, jsonl_path=jsonl_path, xml_path=xml_path)
    report = run_unified_evaluation(
        jsonl_path=jsonl_path,
        xml_path=xml_path,
        globalban_root=globalban_root,
        evaluate_ueba=True,
        evaluate_lolbin=True,
        output_dir=output_dir,
    )
    print(format_report_text(report))
    report_json_path.write_text(
        json.dumps(report.to_dict(), indent=2, ensure_ascii=False), encoding="utf-8"
    )
    print(f"[+] Đã xuất trọn bộ 7 file dữ liệu & báo cáo tại: {output_dir.resolve()}")
    return 0
