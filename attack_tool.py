from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from attack_simulator.evaluator import (
    DEFAULT_GLOBALBAN_ROOT,
    format_report_text,
    push_xml_to_globalban_cli,
    run_globalban_evaluation,
)
from attack_simulator.scenarios import (
    SCENARIO_BY_CODE,
    SCENARIO_BY_KEY,
    SCENARIO_CATALOG,
    WindowsAttackLogGenerator,
    export_dataset_files,
)


def parse_scenario_selection(raw_values: list[str] | None) -> list[str]:
    """Parse scenario numbers (1..6) or keys ('brute_force', ..., or 'all')."""
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


def run_interactive_cli(globalban_root: Path, output_dir: Path) -> int:
    print("=" * 78)
    print("   CÔNG CỤ GIẢ LẬP TẤN CÔNG WINDOWS XML & CHẤM ĐIỂM GLOBALBAN (INTERACTIVE)")
    print("=" * 78)
    print("Danh sách các kịch bản tấn công hỗ trợ:")
    for spec in SCENARIO_CATALOG:
        print(f"  [{spec.code}] {spec.title}")
        print(f"      - Chuỗi Event ID : {spec.event_chain_desc}")
        print(f"      - Rule kỳ vọng   : {spec.expected_rules_desc}")
    print("  [0 / all] Chạy toàn bộ 6 kịch bản tấn công")
    print("-" * 78)

    raw_scen = input("Chọn kịch bản (VD: all hoặc 1,2,3,4,5,6) [mặc định: all]: ").strip()
    selected = parse_scenario_selection([raw_scen] if raw_scen else None)

    raw_camp = input("Số chiến dịch cho mỗi kịch bản [mặc định: 25]: ").strip()
    campaigns = int(raw_camp) if raw_camp.isdecimal() else 25

    raw_benign = input("Số lượng log bình thường (Benign) trộn lẫn [mặc định: 600]: ").strip()
    benign = int(raw_benign) if raw_benign.isdecimal() else 600

    raw_noise = input("Số lượng log nhiễu Admin (test False Positive) [mặc định: 0]: ").strip()
    fp_noise = int(raw_noise) if raw_noise.isdecimal() else 0

    return execute_simulation_pipeline(
        selected_scenarios=selected,
        campaigns_per_scenario=campaigns,
        benign_count=benign,
        fp_noise_count=fp_noise,
        seed=42,
        output_dir=output_dir,
        globalban_root=globalban_root,
        push_cli=True,
    )


def execute_simulation_pipeline(
    *,
    selected_scenarios: list[str],
    campaigns_per_scenario: int,
    benign_count: int,
    fp_noise_count: int,
    seed: int,
    output_dir: Path,
    globalban_root: Path,
    push_cli: bool,
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
    report = run_globalban_evaluation(
        jsonl_path=jsonl_path,
        xml_path=xml_path,
        globalban_root=globalban_root,
        evaluate_ueba=True,
        evaluate_lolbin=True,
        output_dir=output_dir,
    )

    print(format_report_text(report))

    if push_cli:
        cli_alerts = push_xml_to_globalban_cli(
            xml_path,
            globalban_root=globalban_root,
            learn_baseline_xml=report.ueba_baseline_xml_path,
            profile_path=report.ueba_profile_json_path,
        )
        print(
            f"\n[+] Đã bắn trực tiếp file XML ({xml_path.name}) vào GlobalBan CLI "
            f"(--windows-xml --learn-baseline --profile-path): thu được {len(cli_alerts):,} cảnh báo/tín hiệu JSON."
        )
        if report.ueba_test_xml_path and report.ueba_test_xml_path.is_file():
            ueba_cli_alerts = push_xml_to_globalban_cli(
                report.ueba_test_xml_path,
                globalban_root=globalban_root,
                learn_baseline_xml=report.ueba_baseline_xml_path,
                profile_path=report.ueba_profile_json_path,
            )
            print(
                f"[+] Đã bắn tiếp bộ UEBA Atomic Red Team ({report.ueba_test_xml_path.name}) vào GlobalBan CLI: "
                f"thu được {len(ueba_cli_alerts):,} cảnh báo lệch chuẩn UEBA/Behavior JSON."
            )

    report_json_path.write_text(
        json.dumps(report.to_dict(), indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    print(f"[+] Đã lưu báo cáo JSON chi tiết tại: {report_json_path}")
    return 0


def main(argv: list[str] | None = None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    parser = argparse.ArgumentParser(
        description="Công cụ sinh log Windows XML (Attack + Benign) và chấm điểm GlobalBan tự động."
    )
    parser.add_argument(
        "--gui",
        action="store_true",
        help="Khởi chạy giao diện đồ họa (Tkinter GUI) để chọn kịch bản và chấm điểm",
    )
    parser.add_argument(
        "-i",
        "--interactive",
        action="store_true",
        help="Chạy menu tương tác trên dòng lệnh (Interactive CLI)",
    )
    parser.add_argument(
        "-s",
        "--scenarios",
        nargs="*",
        default=None,
        help="Chọn kịch bản: 'all' hoặc danh sách số 1..6 / tên kịch bản (VD: 1,2,3,4,5,6)",
    )
    parser.add_argument(
        "-c",
        "--campaigns",
        type=int,
        default=25,
        help="Số lượng chiến dịch sinh ra cho mỗi kịch bản tấn công (mặc định: 25)",
    )
    parser.add_argument(
        "-b",
        "--benign",
        type=int,
        default=600,
        help="Số lượng log bình thường (benign) trộn lẫn (mặc định: 600)",
    )
    parser.add_argument(
        "--fp-noise",
        type=int,
        default=0,
        help="Số lượng sự kiện nhiễu Admin hợp lệ để thử nghiệm False Positive Rate (mặc định: 0)",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=42,
        help="Random seed để tái lập bộ dữ liệu (mặc định: 42)",
    )
    parser.add_argument(
        "-o",
        "--output-dir",
        type=Path,
        default=Path(__file__).resolve().parent / "output",
        help="Thư mục xuất file .jsonl, .xml và báo cáo JSON",
    )
    parser.add_argument(
        "--globalban-root",
        type=Path,
        default=DEFAULT_GLOBALBAN_ROOT,
        help="Đường dẫn tới thư mục gốc của dự án GlobalBan",
    )
    parser.add_argument(
        "--push-cli",
        action="store_true",
        default=True,
        help="Đồng thời đẩy file XML vào GlobalBan CLI (--windows-xml)",
    )
    parser.add_argument(
        "--list-scenarios",
        action="store_true",
        help="Hiển thị bảng 6 kịch bản mô phỏng và thoát",
    )

    args = parser.parse_args(argv)

    if args.list_scenarios:
        for spec in SCENARIO_CATALOG:
            print(f"{spec.code}. {spec.title} ({spec.key})")
            print(f"   Chuỗi Event ID : {spec.event_chain_desc}")
            print(f"   Rule kỳ vọng   : {spec.expected_rules_desc}\n")
        return 0

    if args.gui:
        from attack_simulator.gui import launch_gui

        launch_gui(output_dir=args.output_dir, globalban_root=args.globalban_root)
        return 0

    if args.interactive:
        return run_interactive_cli(
            globalban_root=args.globalban_root, output_dir=args.output_dir
        )

    selected = parse_scenario_selection(args.scenarios)
    return execute_simulation_pipeline(
        selected_scenarios=selected,
        campaigns_per_scenario=args.campaigns,
        benign_count=args.benign,
        fp_noise_count=args.fp_noise,
        seed=args.seed,
        output_dir=args.output_dir,
        globalban_root=args.globalban_root,
        push_cli=args.push_cli,
    )


if __name__ == "__main__":
    raise SystemExit(main())

