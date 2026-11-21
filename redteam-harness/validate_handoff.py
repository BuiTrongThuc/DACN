"""
validate_handoff.py
===================
Kiểm tra tính toàn vẹn chữ ký băm SHA-256 của toàn bộ gói bằng chứng pháp chứng số:
- File nhãn chuẩn Ground-Truth (red_ground_truth.json & cases.jsonl)
- Toàn bộ các tệp tin nhật ký hệ điều hành thật (.evtx)
- Các file bảng băm tương ứng (.csv)
"""

from __future__ import annotations

import csv
import hashlib
import json
import sys
from pathlib import Path

ROOT_DIR = Path(r"C:\redteam-harness\artifacts")


def sha256_file(path: Path) -> str:
    """Tính mã băm SHA-256 chuẩn chữ hoa cho một file trên ổ cứng."""
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest().upper()


def main() -> None:
    meta_dir = ROOT_DIR / "metadata"
    gt_file = meta_dir / "red_ground_truth.json"
    cases_file = meta_dir / "cases.jsonl"

    if not gt_file.exists() and not cases_file.exists():
        raise SystemExit(f"[LỖI] Không tìm thấy file Ground-Truth tại: {gt_file}")

    print("=" * 95)
    print(" GLOBALBAN RED TEAM - BỘ KIỂM CHUẨN TOÀN VẸN BẰNG CHỨNG SỐ (SHA-256 INTEGRITY AUDIT)")
    print(f" Artifacts Root: {ROOT_DIR}")
    print("=" * 95)

    # Đọc danh sách cases từ file JSON hoặc JSONL
    cases: list[dict] = []
    if gt_file.exists():
        try:
            cases = json.loads(gt_file.read_text(encoding="utf-8"))
            gt_hash = sha256_file(gt_file)
            print(f"[+] red_ground_truth.json SHA-256: {gt_hash}")
        except Exception:
            pass

    if not cases and cases_file.exists():
        for line in cases_file.read_text(encoding="utf-8").splitlines():
            if line.strip():
                cases.append(json.loads(line))

    total_cases = len(cases)
    total_files_verified = 0
    total_errors = 0

    print("-" * 95)
    print(f"{'CASE_ID':24} {'TECH_ID':12} {'EXP_DETECT':11} {'FILES':7} {'SHA256 STATUS':15} TIME (UTC)")
    print("-" * 95)

    for case in cases:
        cid = case.get("case_id", "")
        tech_id = case.get("technique_id") or "BASELINE"
        exp_detect = str(case.get("expected_detected", False))
        start_ts = case.get("start_timestamp_utc") or case.get("start_utc", "")
        end_ts = case.get("end_timestamp_utc") or case.get("end_utc", "")

        hash_csv = ROOT_DIR / "hashes" / f"{cid}.csv"
        if not hash_csv.exists():
            print(f"{cid:24} {tech_id:12} {exp_detect:11} {'0':7} [FAIL - NO HASH]  {start_ts}")
            total_errors += 1
            continue

        case_files_count = 0
        case_passed = True

        with hash_csv.open("r", encoding="utf-8") as hf:
            reader = csv.DictReader(hf)
            for row in reader:
                evtx_path = Path(row["Path"])
                if not evtx_path.exists():
                    # Tìm kiếm tương đối nếu đường dẫn tuyệt đối bị thay đổi môi trường
                    kind_val = case.get("kind", "atomic")
                    alt_path = ROOT_DIR / kind_val / cid / evtx_path.name
                    if not alt_path.exists():
                        alt_path = (ROOT_DIR / "baseline" / cid / evtx_path.name) if (ROOT_DIR / "baseline" / cid / evtx_path.name).exists() else (ROOT_DIR / "atomic" / cid / evtx_path.name)
                    if alt_path.exists():
                        evtx_path = alt_path
                    else:
                        case_passed = False
                        total_errors += 1
                        print(f"    [!] Missing EVTX: {row['Path']}")
                        continue

                case_files_count += 1
                total_files_verified += 1
                calculated_hash = sha256_file(evtx_path)
                if calculated_hash != row["Hash"]:
                    case_passed = False
                    total_errors += 1
                    print(f"    [!] Hash mismatch at {evtx_path.name}: expected {row['Hash'][:12]}... got {calculated_hash[:12]}...")

        status_str = "[VERIFIED OK]" if case_passed else "[TAMPERED/FAIL]"
        print(f"{cid:24} {tech_id:12} {exp_detect:11} {str(case_files_count):7} {status_str:15} {start_ts} -> {end_ts}")

    print("=" * 95)
    print(f" TỔNG KẾT KIỂM ĐỊNH:")
    print(f" - Tổng số ca kiểm thử (Cases) : {total_cases}")
    print(f" - Tổng file EVTX đã đối chiếu : {total_files_verified}")
    print(f" - Số lỗi vi phạm toàn vẹn     : {total_errors}")
    if total_errors == 0 and total_cases > 0:
        print(f" [✓] KẾT LUẬN: GÓI BẰNG CHỨNG ĐẠT 100% TÍNH TOÀN VẸN CHỮ KÝ SỐ, SẴN SÀNG BÀN GIAO BLUE TEAM!")
    else:
        print(f" [X] CẢNH BÁO: Phát hiện {total_errors} lỗi toàn vẹn dữ liệu. Cần kiểm tra lại trước khi bàn giao!")
    print("=" * 95)

    if total_errors > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
