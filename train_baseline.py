"""Huấn luyện hồ sơ hành vi người dùng & máy tính (Baseline) từ log bình thường.

Đọc toàn bộ file EVTX trong thư mục data/baseline, phân tích cú pháp sự kiện và
học các thuộc tính: tần suất loại sự kiện, khung giờ hoạt động, file thực thi, dòng lệnh.
Hồ sơ sau đó được lưu vào file globalban-baseline.json và đóng băng (freeze).
"""

from __future__ import annotations

import sys
from pathlib import Path
from collections import Counter

from globalban.detection.baseline import BehaviorBaseline
from globalban.ingestion.evtx import read_evtx_events
from globalban.ingestion.parser import parse_windows_security_event

# Thiết lập UTF-8 cho console Windows
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")


def main() -> None:
    baseline_dir = Path("data/baseline")
    output_path = Path("globalban-baseline.json")

    print(f"=== BẮT ĐẦU HUẤN LUYỆN BASELINE TỪ: {baseline_dir} ===")
    if not baseline_dir.exists():
        print(f"[LỖI] Không tìm thấy thư mục: {baseline_dir}")
        sys.exit(1)

    evtx_files = sorted(baseline_dir.glob("*.evtx"))
    if not evtx_files:
        print(f"[CẢNH BÁO] Không tìm thấy file .evtx nào trong {baseline_dir}")
        sys.exit(1)

    events = []
    hosts_seen = Counter()
    users_seen = Counter()

    for p in evtx_files:
        print(f"-> Đang đọc file EVTX: {p.name} ({p.stat().st_size / (1024 * 1024):.2f} MB)...")
        try:
            records = read_evtx_events(p, max_events=2000)  # Giới hạn tránh timeout file lớn
            print(f"   Trích xuất được {len(records)} bản ghi XML. Bắt đầu phân tích cú pháp...")
            parsed_count = 0
            for xml in records:
                ev = parse_windows_security_event(xml)
                if ev:
                    events.append(ev)
                    parsed_count += 1
                    if ev.host:
                        hosts_seen[ev.host] += 1
                    if ev.username:
                        users_seen[ev.username] += 1
            print(f"   Đã chuẩn hóa thành công: {parsed_count} sự kiện.")
        except Exception as exc:
            print(f"   [CẢNH BÁO] Không thể đọc {p.name}: {exc}")

    if not events:
        print("[LỖI] Không có sự kiện nào được chuẩn hóa để huấn luyện!")
        sys.exit(1)

    print(f"\nTổng số sự kiện thu thập được: {len(events)}")
    print(f"Danh sách máy tính ghi nhận (Hosts): {dict(hosts_seen)}")
    print(f"Danh sách tài khoản ghi nhận (Users): {dict(users_seen)}")

    baseline = BehaviorBaseline(path=str(output_path), warmup_events=20)
    print("\nĐang tiến hành fit() hồ sơ hành vi...")
    baseline.fit(events)
    baseline.freeze()

    print(f"\n[THÀNH CÔNG] Đã lưu và đóng băng Baseline tại: {output_path.resolve()}")
    print(f"- Tổng số mẫu sự kiện huấn luyện: {len(events)}")
    print(f"- Trạng thái Baseline: Đã đóng băng (Frozen = {baseline.frozen})")


if __name__ == "__main__":
    main()
