#!/usr/bin/env python3
"""
GlobalBan Red-Team Adversary Emulation, Benchmark Generator & SOC Evaluation Suite
All-in-One Standalone Application (Modern Dark UI + Full CLI + Built-in Detection & UEBA Engine)

Features:
  1. Generates all 6 multi-step Windows Event XML attack campaigns + Benign + Admin FP Noise.
  2. Generates 7-Day UEBA Baseline (1,078 events) + Atomic Red Team test set (18 events) + Ground Truth.
  3. Evaluates against external GlobalBan project (if found/selected) OR built-in faithful GlobalBan
     Detection & UEBA Engine (100% self-contained, zero external dependencies, never crashes on missing path).
  4. Evaluates WinLOLBIN-GT dataset (external CSV or built-in 1,000-sample benchmark).
  5. Modern Dark Cybersecurity GUI with KPI cards, Confusion Matrix heatmap, MITRE ATT&CK Canvas chart,
     Live Alert Table, XML Event Inspector, UEBA Profile Explorer, and VMware EVTX Toolkit helper.

Usage:
  python attack_globalban_studio.py          # GUI (default)
  python attack_globalban_studio.py --cli    # CLI batch mode
  python attack_globalban_studio.py -i       # Interactive terminal
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

# Import everything from the modular package
from attack_simulator.models import SCENARIO_BY_CODE, SCENARIO_BY_KEY, SCENARIO_CATALOG
from attack_simulator.generator import WindowsAttackLogGenerator, export_dataset_files
from attack_simulator.evaluator import (
    resolve_default_globalban_root,
    run_unified_evaluation,
    format_report_text,
)

import json


# ==============================================================================
# CLI & INTERACTIVE ENTRYPOINT
# ==============================================================================

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

    raw_camp = input("Số chiến dịch cho mỗi kịch bản [mặc định: 25]: ").strip()
    campaigns = int(raw_camp) if raw_camp.isdecimal() else 25

    raw_benign = input("Số lượng log bình thường (Benign) trộn lẫn [mặc định: 600]: ").strip()
    benign = int(raw_benign) if raw_benign.isdecimal() else 600

    raw_noise = input("Số lượng log nhiễu Admin (test False Positive) [mặc định: 30]: ").strip()
    fp_noise = int(raw_noise) if raw_noise.isdecimal() else 30

    return execute_cli_pipeline(
        selected_scenarios=selected,
        campaigns_per_scenario=campaigns,
        benign_count=benign,
        fp_noise_count=fp_noise,
        seed=42,
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


def launch_gui(output_dir: Path | None = None, globalban_root: Path | None = None) -> None:
    from attack_simulator.gui import ModernRedTeamStudioApp
    import tkinter as tk

    root = tk.Tk()
    ModernRedTeamStudioApp(root, output_dir=output_dir, globalban_root=globalban_root)
    root.mainloop()


def main(argv: list[str] | None = None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")

    parser = argparse.ArgumentParser(
        description="GlobalBan Red-Team Adversary Studio & Benchmark Suite (All-in-One)"
    )
    parser.add_argument("--gui", action="store_true", help="Mở giao diện đồ họa hiện đại (mặc định nếu không truyền tham số)")
    parser.add_argument("--cli", action="store_true", help="Chạy chế độ dòng lệnh tự động (CLI Batch Mode)")
    parser.add_argument("-i", "--interactive", action="store_true", help="Chạy menu tương tác trên terminal")
    parser.add_argument("-s", "--scenarios", nargs="*", default=None, help="Chọn kịch bản: all hoặc 1,2,3,4,5,6")
    parser.add_argument("-c", "--campaigns", type=int, default=25, help="Số chiến dịch mỗi kịch bản (mặc định: 25)")
    parser.add_argument("-b", "--benign", type=int, default=600, help="Số log bình thường (mặc định: 600)")
    parser.add_argument("--fp-noise", type=int, default=30, help="Số log nhiễu Admin test FPR (mặc định: 30)")
    parser.add_argument("--seed", type=int, default=42, help="Random seed (mặc định: 42)")
    parser.add_argument("-o", "--output-dir", type=Path, default=Path(__file__).resolve().parent / "output", help="Thư mục xuất file")
    parser.add_argument("--globalban-root", type=Path, default=resolve_default_globalban_root(), help="Đường dẫn thư mục GlobalBan")
    parser.add_argument("--list-scenarios", action="store_true", help="Liệt kê các kịch bản và thoát")

    raw_args = sys.argv[1:] if argv is None else argv
    args = parser.parse_args(raw_args)

    if args.list_scenarios:
        for spec in SCENARIO_CATALOG:
            print(f"{spec.code}. {spec.title} ({spec.key})")
            print(f"   Chuỗi Event ID : {spec.event_chain_desc}")
            print(f"   Rule kỳ vọng   : {spec.expected_rules_desc}\n")
        return 0

    if args.interactive:
        return run_interactive_cli(globalban_root=args.globalban_root, output_dir=args.output_dir)

    if args.cli or args.scenarios is not None:
        selected = parse_scenario_selection(args.scenarios)
        return execute_cli_pipeline(
            selected_scenarios=selected,
            campaigns_per_scenario=args.campaigns,
            benign_count=args.benign,
            fp_noise_count=args.fp_noise,
            seed=args.seed,
            output_dir=args.output_dir,
            globalban_root=args.globalban_root,
        )

    # Default: launch Modern GUI directly when double-clicked or run without CLI flags
    launch_gui(output_dir=args.output_dir, globalban_root=args.globalban_root)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
