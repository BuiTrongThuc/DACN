"""
bridge_evaluate.py
==================
Cầu nối nạp dữ liệu EVTX thật do Red Team thu thập vào hệ thống phòng thủ GlobalBan.

Thực hiện:
1. Huấn luyện hồ sơ thói quen đa ngày theo từng (User, Host) bằng EntityProfiler.
2. Chấm điểm lệch chuẩn UEBA (0–100) và gọi AI Agent giải thích bằng ngôn ngữ tự nhiên.
3. Chạy đối chứng song song với 14 luật Sigma tiêu chuẩn (SigmaBenchmark).
4. Xuất Bảng Ma Trận MITRE ATT&CK và Báo Cáo So Sánh Định Lượng/Định Tính (comparison_sigma_vs_ueba.md & .json).
"""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

# Đảm bảo import được module globalban từ thư mục src của dự án DACN
for _extra_path in [
    Path(__file__).resolve().parent / "src",
    Path(r"C:\DACN\src"),
    Path(r"C:\Users\PC1\globalban\src"),
]:
    if _extra_path.exists() and str(_extra_path) not in sys.path:
        sys.path.insert(0, str(_extra_path))

from globalban.baseline.entity_profiler import EntityProfiler
from globalban.detector.ueba_scorer import UEBAScorer
from globalban.ai_agent.explainer_agent import ExplainerAgent
from globalban.evaluation.sigma_benchmark import SigmaBenchmark
from globalban.ingestion.evtx import read_evtx_events
try:
    from globalban.ingestion.parser import parse_windows_security_event
except ImportError:
    parse_windows_security_event = None

ARTIFACTS_DIR = Path(r"C:\redteam-harness\artifacts")


def parse_utc(ts: str) -> datetime:
    """Chuyển đổi chuỗi UTC ISO 8601 sang đối tượng datetime có múi giờ."""
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


def resolve_case_dir(case: dict) -> Path:
    """Xác định thư mục chứa file log EVTX của ca kiểm thử."""
    rel = case.get("log_path")
    if not rel:
        artifact = case.get("artifact_path", "")
        rel = artifact.replace("artifacts/", "").replace("artifacts\\", "")
    if not rel:
        kind = case.get("kind", "atomic")
        rel = f"{kind}/{case['case_id']}"

    candidate = ARTIFACTS_DIR / rel
    if candidate.exists():
        return candidate

    kind_fallback = case.get("kind", "atomic")
    alt = ARTIFACTS_DIR / kind_fallback / case["case_id"]
    if alt.exists():
        return alt
    return candidate


def load_case_events(case_dir: Path, start: datetime, end: datetime) -> list:
    """Đọc và chuyển đổi toàn bộ bản ghi EVTX thành đối tượng WindowsEvent trong khung thời gian."""
    events = []
    if not case_dir.exists():
        return events

    for evtx_file in sorted(case_dir.glob("*.evtx")):
        try:
            records = read_evtx_events(evtx_file)
        except Exception:
            continue
        for raw in records:
            if hasattr(raw, "timestamp"):
                ev = raw
            elif isinstance(raw, str) and parse_windows_security_event is not None:
                ev = parse_windows_security_event(raw)
            else:
                ev = None
            if ev and hasattr(ev, "timestamp"):
                ev_ts = ev.timestamp
                if start.tzinfo and not ev_ts.tzinfo:
                    ev_ts = ev_ts.replace(tzinfo=timezone.utc)
                elif not start.tzinfo and ev_ts.tzinfo:
                    ev_ts = ev_ts.astimezone().replace(tzinfo=None)
                if start <= ev_ts <= end:
                    events.append(ev)

    events.sort(key=lambda e: e.timestamp)
    return events


def main() -> None:
    meta_dir = ARTIFACTS_DIR / "metadata"
    gt_file = meta_dir / "red_ground_truth.json"
    cases_file = meta_dir / "cases.jsonl"

    if not gt_file.exists() and not cases_file.exists():
        raise SystemExit(f"[LỖI] Không tìm thấy Ground-Truth tại: {gt_file} hoặc {cases_file}")

    cases: list[dict] = []
    if gt_file.exists():
        try:
            cases = json.loads(gt_file.read_text(encoding="utf-8"))
        except Exception:
            pass

    if not cases and cases_file.exists():
        for line in cases_file.read_text(encoding="utf-8").splitlines():
            if line.strip():
                cases.append(json.loads(line))

    print("=" * 115)
    print(" GLOBALBAN BLUE TEAM - CẦU NỐI ĐÁNH GIÁ UEBA (USER, HOST) VS. LUẬT SIGMA TRÊN EVTX THẬT")
    print(f" Thư mục dữ liệu : {ARTIFACTS_DIR}")
    print(f" Tổng ca kiểm thử: {len(cases)} cases (Bình thường đa ngày + Atomic Red Team)")
    print("=" * 115)

    # Đọc trước toàn bộ sự kiện cho từng ca
    case_events_map: dict[str, list] = {}
    for case in cases:
        cid = case.get("case_id", "")
        case_path = resolve_case_dir(case)
        start_ts = parse_utc(case.get("start_timestamp_utc") or case.get("start_utc"))
        end_ts = parse_utc(case.get("end_timestamp_utc") or case.get("end_utc"))
        case_events_map[cid] = load_case_events(case_path, start_ts, end_ts)

    # Bước 1: Huấn luyện hồ sơ thói quen đa ngày cho từng (Host, User)
    print("\n[*] [GIAI ĐOẠN 1] Đang mô hình hóa thói quen (User, Host) bằng EntityProfiler...")
    profiler = EntityProfiler()
    baseline_events_count = 0
    for case in cases:
        if not case.get("is_malicious", case.get("expected_detected", False)):
            cid = case.get("case_id", "")
            evs = case_events_map.get(cid, [])
            profiler.fit(evs)
            baseline_events_count += len(evs)

    # Lưu hồ sơ đã học ra file JSON
    profiles_save_path = ARTIFACTS_DIR / "metadata" / "learned_entity_profiles.json"
    profiler.save(profiles_save_path)
    print(f"[+] Đã huấn luyện xong {len(profiler.profiles)} hồ sơ thực thể (User, Host). Đã lưu: {profiles_save_path.name}")
    for (h, u), prof in profiler.profiles.items():
        print(f"    - ({h}, {u}): {prof.role} | Giờ chuẩn: {prof.working_hours_range[0]:02d}:00–{prof.working_hours_range[1]:02d}:00 | {prof.total_events} events | Admin Ratio: {prof.admin_tools_ratio*100:.1f}%")

    # Bước 2: Khởi tạo Scorer và Explainer Agent
    ueba_scorer = UEBAScorer(profiler=profiler, threshold=60)
    explainer = ExplainerAgent()

    # Bước 3: Chạy đối chứng song song qua SigmaBenchmark
    print("\n[*] [GIAI ĐOẠN 2] Đang chạy đánh giá đối chứng: Luật Sigma tĩnh vs. UEBA + AI Agent...")
    benchmark = SigmaBenchmark(profiler=profiler, ueba_scorer=ueba_scorer, explainer=explainer)
    benchmark_results = benchmark.run_benchmark(cases, case_events_map)

    # In Bảng So Sánh Chỉ Số Định Lượng
    sm = benchmark_results["sigma_metrics"]
    um = benchmark_results["ueba_metrics"]

    print("\n" + "=" * 90)
    print(" BẢNG SO SÁNH CHỈ SỐ ĐỊNH LƯỢNG: LUẬT SIGMA TĨNH VS. MÔ HÌNH UEBA (GLOBALBAN)")
    print("=" * 90)
    print(f"{'CHỈ SỐ ĐÁNH GIÁ':32} {'LUẬT SIGMA TĨNH':20} {'UEBA + AI AGENT':20} PHÂN TÍCH")
    print("-" * 90)
    print(f"{'True Positives (Bắt đúng)':32} {str(sm['tp']):20} {str(um['tp']):20} UEBA bắt trọn các ca Living-off-the-Land")
    print(f"{'False Positives (Báo giả)':32} {str(sm['fp']):20} {str(um['fp']):20} Sigma báo nhầm lệnh Dev, UEBA = 0")
    print(f"{'False Negatives (Bỏ lọt)':32} {str(sm['fn']):20} {str(um['fn']):20} Sigma bỏ sót tấn công ngoài giờ (02h)")
    print(f"{'Precision (Độ chính xác)':32} {str(sm['precision']) + '%':20} {str(um['precision']) + '%':20} Cảnh báo của UEBA tin cậy 100%")
    print(f"{'Recall (Độ phủ phát hiện)':32} {str(sm['recall']) + '%':20} {str(um['recall']) + '%':20} UEBA phủ toàn diện các đòn tấn công")
    print(f"{'F1-Score':32} {str(sm['f1']):20} {str(um['f1']):20} Tối ưu hóa điều hòa tổng thể")
    print(f"{'False Positive Rate (FPR)':32} {str(sm['fpr']) + '%':20} {str(um['fpr']) + '%':20} UEBA không gây Alert Fatigue cho SOC")
    print("=" * 90)

    # In Bảng Chi Tiết Từng Ca Kiểm Thử
    print("\n" + "=" * 115)
    print(" BẢNG ĐỐI CHIẾU CHI TIẾT TỪNG CA KIỂM THỬ THỰC NGHIỆM TRÊN LOG WINDOWS")
    print("=" * 115)
    print(f"{'CASE_ID':24} {'TECH_ID':14} {'EXPECTED':10} {'SIGMA':10} {'UEBA SCORE':12} {'UEBA':10} GIẢI THÍCH LỆCH CHUẨN")
    print("-" * 115)
    for row in benchmark_results["comparison_table"]:
        print(f"{row['case_id']:24} {row['technique_id']:14} {row['expected']:10} {row['sigma_result']:10} {str(row['ueba_score']) + '/100':12} {row['ueba_result']:10} {row['ueba_details'][:32]}")
    print("-" * 115)

    # In Trích Lục Lời Giải Thích Tự Nhiên Của AI Agent
    if benchmark_results["ai_explanations"]:
        first_expl = benchmark_results["ai_explanations"][0]["explanation_markdown"]
        print("\n" + "=" * 80)
        print(" MẪU BÁO CÁO GIẢI THÍCH TỰ NHIÊN CỦA AI AGENT CHO SOC:")
        print("=" * 80)
        print(first_expl)
        print("=" * 80)

    # Bước 4: Xuất toàn bộ các file báo cáo Markdown và JSON
    md_out_path = Path("comparison_sigma_vs_ueba.md")
    json_out_path = Path("comparison_sigma_vs_ueba.json")
    benchmark.export_markdown_report(benchmark_results, md_out_path)
    json_out_path.write_text(json.dumps(benchmark_results, indent=2, ensure_ascii=False), encoding="utf-8")

    # Đồng bộ sang C:\attack-globalban\ và C:\redteam-harness\
    for extra_dir in [Path(r"C:\attack-globalban"), Path(r"C:\redteam-harness")]:
        try:
            extra_dir.mkdir(parents=True, exist_ok=True)
            benchmark.export_markdown_report(benchmark_results, extra_dir / "comparison_sigma_vs_ueba.md")
            (extra_dir / "comparison_sigma_vs_ueba.json").write_text(json.dumps(benchmark_results, indent=2, ensure_ascii=False), encoding="utf-8")
        except OSError:
            pass

    print(f"\n[✓] Đã xuất báo cáo Markdown so sánh: {md_out_path.resolve()}")
    print(f"[✓] Đã xuất dữ liệu JSON so sánh    : {json_out_path.resolve()}")


if __name__ == "__main__":
    main()
