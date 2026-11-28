"""Giám sát Windows Event Log REALTIME — phát hiện Red Team tức thì.

Vòng lặp vô hạn: cứ mỗi POLL_INTERVAL giây lại đọc các kênh Event Log,
phân tích hành vi với UEBA baseline đã huấn luyện, in cảnh báo màu sắc
ra console VÀ ghi vào globalban-audit.jsonl để app.py đọc hiển thị.

Cách chạy:
    .venv\\Scripts\\python.exe live_monitor.py

Dừng bằng Ctrl+C.
"""

from __future__ import annotations

import json
import os
import sys
import signal
import time
from datetime import datetime, timezone
from pathlib import Path
from collections import Counter

# UTF-8 console
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")

from globalban.detection.baseline import BehaviorBaseline
from globalban.detection.sequence import SequenceCorrelator, RiskCandidate
from globalban.ingestion.windows_source import follow_windows_events
from globalban.ingestion.parser import parse_windows_security_event

# ── Cấu hình ──────────────────────────────────────────────────────────────
BASELINE_PATH   = Path("globalban-baseline.json")
AUDIT_PATH      = Path("globalban-live-alerts.jsonl")
POLL_INTERVAL   = 5          # giây giữa 2 lần poll
LOOKBACK_SEC    = 15         # Windows event lookback window
ALERT_THRESHOLD = 60         # Score >= này thì in cảnh báo
CRITICAL_SCORE  = 90         # Score >= này thì in cảnh báo đỏ nháy

# Kênh Windows Event Log cần giám sát
LOG_CHANNELS = [
    "Security",
    "Microsoft-Windows-PowerShell/Operational",
    "System",
    "Microsoft-Windows-Sysmon/Operational",
]

# ANSI màu cho console
class C:
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    RED     = "\033[91m"
    YELLOW  = "\033[93m"
    CYAN    = "\033[96m"
    GREEN   = "\033[92m"
    MAGENTA = "\033[95m"
    DIM     = "\033[2m"
    BLINK   = "\033[5m"


def _now() -> str:
    return datetime.now().strftime("%H:%M:%S")


def _banner() -> None:
    print(f"\n{C.CYAN}{C.BOLD}")
    print("╔══════════════════════════════════════════════════════════════╗")
    print("║          GLOBALBAN — REALTIME RED TEAM DETECTOR              ║")
    print("║   Giám sát hành vi Windows & Phát hiện tấn công tức thì     ║")
    print("╚══════════════════════════════════════════════════════════════╝")
    print(C.RESET)


def _print_alert(candidate: RiskCandidate) -> None:
    """In cảnh báo màu ra console."""
    is_critical = candidate.score >= CRITICAL_SCORE
    color = C.RED if is_critical else C.YELLOW
    label = f"{C.BLINK}🚨 CRITICAL" if is_critical else "⚠️  WARNING"

    print(f"\n{color}{C.BOLD}{'─'*66}{C.RESET}")
    print(f"{color}{C.BOLD} {label}  Score={candidate.score}/100{C.RESET}")
    print(f"{color}{'─'*66}{C.RESET}")
    print(f"  {C.BOLD}Host    :{C.RESET} {candidate.host or '—'}")
    print(f"  {C.BOLD}User    :{C.RESET} {candidate.username or '—'}")
    print(f"  {C.BOLD}Time    :{C.RESET} {_now()}")
    print(f"  {C.BOLD}Events  :{C.RESET} {candidate.event_ids}")
    for reason in candidate.reasons:
        print(f"  {C.BOLD}→{C.RESET} {reason}")
    print(f"{color}{'─'*66}{C.RESET}\n")


def _write_audit(candidate: RiskCandidate) -> None:
    """Ghi cảnh báo vào file JSONL để app.py đọc hiển thị."""
    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event": "LIVE_ALERT",
        "score": candidate.score,
        "host": candidate.host,
        "username": candidate.username,
        "event_ids": list(candidate.event_ids),
        "reasons": list(candidate.reasons),
        "severity": "CRITICAL" if candidate.score >= CRITICAL_SCORE else "HIGH",
    }
    with AUDIT_PATH.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")


def _write_audit_event(
    event_id: int,
    host: str,
    user: str,
    detail: str,
    *,
    event_record_id: str | None = None,
    event_time: str | None = None,
) -> None:
    """Ghi sự kiện thường vào audit kèm EventRecordID và thời gian."""
    record = {
        "timestamp": event_time or datetime.now(timezone.utc).isoformat(),
        "event": "WINDOWS_EVENT",
        "event_id": event_id,
        "event_record_id": event_record_id or "",
        "host": host,
        "username": user,
        "detail": detail[:1500],
    }
    with AUDIT_PATH.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")


def main() -> None:
    _banner()

    # 1. Nạp baseline
    if BASELINE_PATH.exists():
        print(f"[{C.GREEN}OK{C.RESET}] Nạp Baseline từ: {BASELINE_PATH}")
        baseline = BehaviorBaseline(path=str(BASELINE_PATH))
        print(f"      → {baseline._total} sự kiện đã học | Frozen={baseline.frozen}")
    else:
        print(f"[{C.YELLOW}WARN{C.RESET}] Chưa có baseline. Chạy train_baseline.py trước!")
        print("      → Khởi động với warmup baseline rỗng (sẽ cần 20 events warm-up)")
        baseline = BehaviorBaseline(warmup_events=20)

    correlator = SequenceCorrelator(window_seconds=300, baseline=baseline)

    # 2. Khởi tạo counter
    total_events = 0
    total_alerts = 0
    host_counter: Counter[str] = Counter()
    start_time = time.time()

    # 3. Thông báo kênh đang theo dõi
    available_channels = []
    for ch in LOG_CHANNELS:
        available_channels.append(ch)

    print(f"\n[{C.CYAN}INFO{C.RESET}] Đang theo dõi {len(available_channels)} kênh Event Log:")
    for ch in available_channels:
        print(f"      • {ch}")
    print(f"\n[{C.CYAN}INFO{C.RESET}] Poll interval: {POLL_INTERVAL}s | Alert threshold: score ≥ {ALERT_THRESHOLD}")
    print(f"[{C.CYAN}INFO{C.RESET}] Cảnh báo cũng ghi vào: {AUDIT_PATH.resolve()}")
    print(f"\n{C.DIM}Nhấn Ctrl+C để dừng...{C.RESET}\n")
    print(f"{'─'*66}")

    # Ghi nhật ký khởi động
    with AUDIT_PATH.open("a", encoding="utf-8") as f:
        f.write(json.dumps({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event": "MONITOR_STARTED",
            "baseline_total": baseline._total,
            "channels": available_channels,
            "poll_interval": POLL_INTERVAL,
            "alert_threshold": ALERT_THRESHOLD,
        }, ensure_ascii=False) + "\n")

    # 4. Vòng lặp chính — theo dõi realtime
    try:
        event_stream = follow_windows_events(
            available_channels,
            poll_interval_seconds=POLL_INTERVAL,
            lookback_seconds=LOOKBACK_SEC,
        )

        for xml_record in event_stream:
            ev = parse_windows_security_event(xml_record)
            if ev is None:
                continue

            total_events += 1
            if ev.host:
                host_counter[ev.host] += 1

            # In sự kiện quan trọng (4688 process create, 4104 PS scriptblock, 4624/4625 logon)
            interesting_ids = {4688, 4104, 4625, 4720, 4732, 4728, 7045, 1}
            if ev.event_id in interesting_ids:
                detail = ev.command_line or ev.executable or ""
                print(
                    f"{C.DIM}[{_now()}]{C.RESET} "
                    f"{C.CYAN}EID={ev.event_id:5d}{C.RESET} "
                    f"host={ev.host or '?':20s} "
                    f"user={ev.username or '?':12s} "
                    f"{C.DIM}{detail[:60]}{C.RESET}"
                )
                _write_audit_event(
                    ev.event_id,
                    ev.host or "",
                    ev.username or "",
                    detail,
                    event_record_id=ev.event_record_id,
                    event_time=ev.timestamp.isoformat(),
                )

            # Chấm điểm UEBA + Correlator
            candidate = correlator.add(ev)
            if candidate is not None and candidate.score >= ALERT_THRESHOLD:
                total_alerts += 1
                _print_alert(candidate)
                _write_audit(candidate)

            # In thống kê định kỳ mỗi 100 events
            if total_events % 100 == 0:
                elapsed = int(time.time() - start_time)
                print(
                    f"\n{C.DIM}[STATS] "
                    f"Events={total_events} | Alerts={total_alerts} | "
                    f"Hosts={dict(host_counter.most_common(3))} | "
                    f"Uptime={elapsed}s{C.RESET}\n"
                )

    except KeyboardInterrupt:
        elapsed = int(time.time() - start_time)
        print(f"\n\n{C.CYAN}[DỪNG] Đã nhận Ctrl+C.{C.RESET}")
        print(f"  Tổng sự kiện đã xử lý : {total_events}")
        print(f"  Tổng cảnh báo phát ra  : {total_alerts}")
        print(f"  Thời gian giám sát     : {elapsed}s")
        print(f"  File cảnh báo          : {AUDIT_PATH.resolve()}")
        with AUDIT_PATH.open("a", encoding="utf-8") as f:
            f.write(json.dumps({
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "event": "MONITOR_STOPPED",
                "total_events": total_events,
                "total_alerts": total_alerts,
                "uptime_seconds": elapsed,
            }, ensure_ascii=False) + "\n")


if __name__ == "__main__":
    # Bật ANSI trên Windows 10+
    if sys.platform == "win32":
        os.system("")
    main()
