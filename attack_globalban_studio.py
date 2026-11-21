#!/usr/bin/env python3
"""
attack_globalban_studio.py
==========================
Entrypoint chính điều phối 3 chế độ:
  1. GUI (Mặc định)
  2. CLI Batch Mode (--cli)
  3. Interactive Terminal (-i)
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from attack_simulator.cli.runner import (
    execute_cli_pipeline,
    parse_scenario_selection,
    run_interactive_cli,
)
from attack_simulator.core.evaluator import resolve_default_globalban_root
from attack_simulator.core.models import SCENARIO_CATALOG
from attack_simulator.ui import launch_gui
from config import (
    DEFAULT_BENIGN_COUNT,
    DEFAULT_CAMPAIGNS_PER_SCENARIO,
    DEFAULT_FP_NOISE_COUNT,
    DEFAULT_OUTPUT_DIR,
    DEFAULT_SEED,
)


def main(argv: list[str] | None = None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")

    parser = argparse.ArgumentParser(
        description="GlobalBan Red-Team Adversary Studio & Benchmark Suite (Modular)"
    )
    parser.add_argument("--gui", action="store_true", help="Mở giao diện đồ họa hiện đại (mặc định)")
    parser.add_argument("--cli", action="store_true", help="Chạy chế độ dòng lệnh tự động (CLI Batch Mode)")
    parser.add_argument("-i", "--interactive", action="store_true", help="Chạy menu tương tác trên terminal")
    parser.add_argument("-s", "--scenarios", nargs="*", default=None, help="Chọn kịch bản: all hoặc 1,2,3,4,5,6")
    parser.add_argument("-c", "--campaigns", type=int, default=DEFAULT_CAMPAIGNS_PER_SCENARIO, help="Số chiến dịch mỗi kịch bản")
    parser.add_argument("-b", "--benign", type=int, default=DEFAULT_BENIGN_COUNT, help="Số log bình thường")
    parser.add_argument("--fp-noise", type=int, default=DEFAULT_FP_NOISE_COUNT, help="Số log nhiễu Admin test FPR")
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED, help="Random seed")
    parser.add_argument("-o", "--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR, help="Thư mục xuất file")
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

    launch_gui(output_dir=args.output_dir, globalban_root=args.globalban_root)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
