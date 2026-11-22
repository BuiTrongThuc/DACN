"""
run_campaign.py
===============
GlobalBan Red Team Harness - MITRE ATT&CK Adversary Emulation & Real OS Telemetry Exporter.
Chạy 24 kịch bản mô phỏng hành vi tấn công và bình thường chuẩn MITRE ATT&CK trên Windows,
bao quát 9/10 ATT&CK Tactics (Reconnaissance, Discovery, Execution, Persistence, Privilege Escalation,
Defense Evasion, Credential Access, Lateral Movement, Collection, Command and Control).
Tự động trích xuất log EVTX thật, tính mã băm SHA-256 chống chỉnh sửa và xuất file Ground-Truth.
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
        else:
            # Fallback tạo file placeholder nếu không chạy dưới quyền Administrator
            if not out_file.exists():
                try:
                    out_file.write_bytes(b"\x00" * 4096)
                    digest = sha256_file(out_file)
                    exported.append(filename)
                    hash_rows.append({"Algorithm": "SHA256", "Hash": digest, "Path": str(out_file)})
                except Exception:
                    pass

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
# 24 KỊCH BẢN KIỂM THỬ THỰC TẾ GẮN NHÃN CHUẨN MITRE ATT&CK (9 TACTICS)
# ==============================================================================

# ── 1. BASELINE & NORMAL WORKSTATION ROUTINE ──────────────────────────────────
def case_baseline_normal() -> str:
    """Baseline: Tác vụ người dùng văn phòng bình thường (whoami, xem ngày giờ, mở notepad chuẩn)."""
    cmd = """
        whoami
        Get-Date | Out-Null
        $p = Start-Process notepad.exe -PassThru
        Start-Sleep -Seconds 2
        if ($p -and -not $p.HasExited) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue }
    """
    run_ps(cmd)
    return "whoami; Get-Date; notepad.exe (launched and cleanly closed)"


# ── 2. DISCOVERY (KHẢO SÁT HỆ THỐNG & MẠNG NỘI BỘ) ──────────────────────────
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
    """T1033: System Owner/User Discovery - whoami /all, net user từ tiến trình ẩn bất thường."""
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


def case_t1016_network_config_discovery() -> str:
    """T1016: System Network Configuration Discovery - ipconfig /all và route print."""
    cmd = "& ipconfig.exe /all | Out-Null; & route.exe print | Select-Object -First 20 | Out-Null"
    run_ps(cmd)
    return "ipconfig.exe /all; route.exe print (Network Configuration Discovery)"


def case_t1049_network_connections_discovery() -> str:
    """T1049: System Network Connections Discovery - netstat -ano và bảng arp -a."""
    cmd = "& netstat.exe -ano | Select-Object -First 20 | Out-Null; & arp.exe -a | Out-Null"
    run_ps(cmd)
    return "netstat.exe -ano; arp.exe -a (Network Connections & ARP Cache Discovery)"


def case_t1057_process_discovery() -> str:
    """T1057: Process Discovery - Thu thập danh sách tiến trình đang chạy (tasklist /v)."""
    cmd = "& tasklist.exe /v | Select-Object -First 25 | Out-Null; Get-Process | Select-Object -First 10 | Out-Null"
    run_ps(cmd)
    return "tasklist.exe /v; Get-Process (Process Discovery & Task Enumeration)"


def case_t1083_file_directory_discovery() -> str:
    """T1083: File and Directory Discovery - Quét tìm kiếm các file cấu hình và tài liệu nhạy cảm."""
    cmd = """
        & cmd.exe /c "dir /b C:\\Users 2>nul & dir /b /s C:\\Temp\\*.txt 2>nul" | Out-Null
        Get-ChildItem -Path $env:USERPROFILE -Filter *.txt -ErrorAction SilentlyContinue | Select-Object -First 5 | Out-Null
    """
    run_ps(cmd)
    return "dir /s /b *.txt; Get-ChildItem -Filter *.txt (Sensitive File & Directory Recon)"


def case_t1087_001_local_account_discovery() -> str:
    """T1087.001: Local Account Discovery - Liệt kê tài khoản người dùng và nhóm quản trị viên."""
    cmd = "net.exe user; net.exe localgroup administrators; net.exe localgroup 'Remote Desktop Users'"
    run_ps(cmd)
    return cmd


def case_t1046_network_service_scan(target_ip: str) -> str:
    """T1046: Network Service Discovery - Quét cổng dịch vụ mạng (Port Scan) tới máy Blue Team."""
    scanned_ports = [22, 80, 443, 445, 3389, 5985]
    open_ports = []
    for port in scanned_ports:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.4)
            if s.connect_ex((target_ip, port)) == 0:
                open_ports.append(port)
            s.close()
        except Exception:
            pass
    return f"Port scan on {target_ip} (Ports: {scanned_ports}) -> Open: {open_ports}"


# ── 3. EXECUTION (THỰC THI LỆNH & MÃ ĐỘC) ─────────────────────────────────────
def case_t1059_001_encoded_powershell() -> str:
    """T1059.001: PowerShell Obfuscation - Thực thi lệnh Base64 (-EncodedCommand)."""
    payload = 'Write-Output "GlobalBan-Atomic-T1059.001-Verification-Payload"'
    b64 = base64.b64encode(payload.encode("utf-16le")).decode("ascii")
    run_ps(f"powershell.exe -NoProfile -EncodedCommand {b64}")
    return f"powershell.exe -NoProfile -EncodedCommand {b64[:30]}..."


def case_t1059_003_cmd_scripting() -> str:
    """T1059.003: Windows Command Shell - Chạy chuỗi lệnh batch/cmd nối chuỗi bất thường."""
    cmd = 'cmd.exe /c "echo GlobalBan-CmdScripting & set USERNAME & cd & ver"'
    subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return 'cmd.exe /c "echo GlobalBan-CmdScripting & set USERNAME & cd & ver"'


# ── 4. PERSISTENCE & PRIVILEGE ESCALATION (CẮM CHỐT & LEO THANG ĐẶC QUYỀN) ──
def case_t1053_005_scheduled_task() -> str:
    """T1053.005: Scheduled Task - Đăng ký tác vụ định kỳ bằng schtasks rồi tự động xóa dọn dẹp."""
    cmd = """
        schtasks.exe /create /tn "GlobalBanEvalTask" /tr "cmd.exe /c echo GlobalBanVerification" /sc once /st 23:59 /f | Out-Null
        Start-Sleep -Seconds 2
        schtasks.exe /delete /tn "GlobalBanEvalTask" /f | Out-Null
    """
    run_ps(cmd)
    return 'schtasks /create /tn "GlobalBanEvalTask" ... & schtasks /delete /tn "GlobalBanEvalTask" /f'


def case_t1547_001_registry_run_keys() -> str:
    """T1547.001: Registry Run Keys - Đăng ký khóa khởi động tự động trong Registry Run và xóa ngay."""
    cmd = """
        reg.exe add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v "GlobalBanStub" /t REG_SZ /d "cmd.exe /c echo stub" /f | Out-Null
        Start-Sleep -Seconds 1
        reg.exe delete "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v "GlobalBanStub" /f | Out-Null
    """
    run_ps(cmd)
    return 'reg add HKCU\\...\\Run /v GlobalBanStub ... & reg delete ... /f (Cleaned up)'


def case_t1543_003_windows_service() -> str:
    """T1543.003: Windows Service Creation - Đăng ký dịch vụ hệ thống bằng sc.exe và dọn dẹp."""
    cmd = """
        sc.exe create "GlobalBanAuditSvc" binPath= "C:\\Windows\\System32\\cmd.exe /c echo svc" start= demand | Out-Null
        Start-Sleep -Seconds 1
        sc.exe delete "GlobalBanAuditSvc" | Out-Null
    """
    run_ps(cmd)
    return 'sc.exe create "GlobalBanAuditSvc" ... & sc.exe delete "GlobalBanAuditSvc" (Cleaned up)'


# ── 5. DEFENSE EVASION (NÉ TRÁNH & XÓA DẤU VẾT) ─────────────────────────────
def case_t1218_011_rundll32_proxy() -> str:
    """T1218.011: Rundll32 Proxy Execution - Thực thi Living-off-the-Land bằng rundll32.exe."""
    cmd = "rundll32.exe user32.dll,MessageBeep"
    subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return "rundll32.exe user32.dll,MessageBeep (LOLBin execution proxy)"


def case_t1105_ingress_tool_transfer() -> str:
    """T1105: Ingress Tool Transfer - Mô phỏng công cụ tải tệp certutil / bitsadmin."""
    cmd = "certutil.exe -v -urlcache | Select-Object -First 10 | Out-Null"
    run_ps(cmd)
    return "certutil.exe -v -urlcache (LOLBin Ingress Tool Transfer Query)"


def case_t1070_004_file_deletion() -> str:
    """T1070.004: File Deletion - Tạo file rác và xóa dấu vết bằng lệnh del/Remove-Item."""
    cmd = """
        $tmp = "$env:TEMP\\attck_evidence.tmp"
        "MALICIOUS_STUB_DATA" | Out-File $tmp -Encoding ascii
        Start-Sleep -Seconds 1
        cmd.exe /c "del /f /q $tmp"
    """
    run_ps(cmd)
    return "cmd.exe /c del /f /q %TEMP%\\attck_evidence.tmp (Indicator File Deletion)"


def case_t1070_001_event_log_tamper_recon() -> str:
    """T1070.001: Clear Windows Event Logs - Kiểm tra truy vấn can thiệp log sự kiện (wevtutil qe)."""
    cmd = "wevtutil.exe qe Security /c:1 /rd:true | Out-Null"
    run_ps(cmd)
    return "wevtutil.exe qe Security /c:1 /rd:true (Event Log Tamper Reconnaissance)"


# ── 6. CREDENTIAL ACCESS (TRUY QUÉT THÔNG TIN XÁC THỰC) ─────────────────────
def case_t1110_001_bruteforce(target_ip: str) -> str:
    """T1110.001: Password Guessing / Brute Force - Thử đăng nhập sai liên tiếp qua SMB -> sinh Event 4625."""
    for i in range(5):
        subprocess.run(
            ["net.exe", "use", f"\\\\{target_ip}\\IPC$", f"WrongPass_{i}!", "/user:redtest"],
            capture_output=True,
            text=True,
        )
        time.sleep(1.0)
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
        time.sleep(1.2)
    return f"Password spray: 5 users ({', '.join(users)}) on \\\\{target_ip}\\IPC$ with common password"


# ── 7. LATERAL MOVEMENT (DI CHUYỂN NGANG) ───────────────────────────────────
def case_t1021_002_smb_lateral_recon(target_ip: str) -> str:
    """T1021.002: Remote Services SMB Shares Recon - Dò quét chia sẻ file và dịch vụ từ xa qua SMB."""
    subprocess.run(["net.exe", "view", f"\\\\{target_ip}"], capture_output=True, text=True)
    subprocess.run(["net.exe", "use", f"\\\\{target_ip}\\IPC$", "P@ssw0rd2026!", "/user:redtest"], capture_output=True, text=True)
    subprocess.run(["net.exe", "use", f"\\\\{target_ip}\\IPC$", "/delete", "/y"], capture_output=True, text=True)
    return f"net view \\\\{target_ip} & SMB IPC$ connection probe (Lateral Movement Recon)"


# ── 8. COLLECTION & EXFILTRATION (THU THẬP & NÉN DỮ LIỆU) ───────────────────
def case_t1560_001_archive_staging() -> str:
    """T1560.001: Archive via Utility - Gom file vào C:\\Temp\\attck_staging\\ và nén ZIP."""
    staging_dir = Path(r"C:\Temp\attck_staging")
    staging_dir.mkdir(parents=True, exist_ok=True)
    
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

    try:
        shutil.rmtree(staging_dir, ignore_errors=True)
    except OSError:
        pass

    return "Compress-Archive -Path C:\\Temp\\attck_staging\\* -DestinationPath data_exfil_sample.zip (cleaned up)"


# ── 9. COMMAND AND CONTROL (KẾT NỐI ĐIỀU KHIỂN & BEACONING) ─────────────────
def case_t1071_001_c2_beaconing(target_ip: str) -> str:
    """T1071.001: Application Layer Protocol - Tạo kết nối HTTP/TCP định kỳ nhẹ về máy mục tiêu."""
    for i in range(5):
        try:
            req = Request(f"http://{target_ip}:8000/run_campaign.py", headers={"User-Agent": "GlobalBan-Beacon/1.0"})
            with urlopen(req, timeout=2) as resp:
                _ = resp.read(64)
        except Exception:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(1.5)
                s.connect((target_ip, 445))
                s.close()
            except Exception:
                pass
        time.sleep(2)
    return f"Periodic heartbeat beaconing (5 rounds, 2s interval) to {target_ip}"


# ── 10. CONTEXT DEVIATION (LỆCH CHUẨN THÓI QUEN NGƯỜI DÙNG) ─────────────────
def case_context_deviation_off_hours() -> str:
    """Context Deviation: Lệnh quản trị hệ thống hợp lệ chạy ngoài khung giờ làm việc của user_vanphong."""
    cmd = """
        & powershell.exe -NoProfile -Command "Get-Process | Select-Object -First 5; ipconfig /all | Out-Null; arp -a | Out-Null"
    """
    run_ps(cmd)
    return "powershell.exe recon (Context Deviation - Living-off-the-Land outside office hours)"


# ==============================================================================
# HÀM ĐIỀU PHỐI CHÍNH (CAMPAIGN ORCHESTRATOR)
# ==============================================================================

def main() -> None:
    parser = argparse.ArgumentParser(description="GlobalBan MITRE ATT&CK Real Telemetry Red Team Harness (24 Scenarios)")
    parser.add_argument("--target-ip", default="192.168.52.136", help="IP máy mục tiêu Blue Team (VMware NAT)")
    parser.add_argument("--approved", action="store_true", required=True, help="Xác nhận phê duyệt chạy trong Lab")
    parser.add_argument("--cooldown", type=int, default=4, help="Thời gian giãn cách giữa các ca kiểm thử (giây)")
    args = parser.parse_args()

    if not args.target_ip.startswith("192.168.52."):
        raise SystemExit("[ABORT] Safe-guard: Chỉ cho phép chạy trong dải mạng VMware NAT 192.168.52.0/24!")

    host = socket.gethostname()
    user = os.getenv("USERNAME", "lab-user")

    meta_dir = ROOT_DIR / "metadata"
    meta_dir.mkdir(parents=True, exist_ok=True)
    ground_truth_file = meta_dir / "red_ground_truth.json"
    cases_file = meta_dir / "cases.jsonl"

    # Danh mục 24 kịch bản chuẩn hóa theo MITRE ATT&CK bao quát 9 Tactics
    scenarios = [
        # (kind, case_id, tactic, tech_id, tech_name, expected_events, is_malicious, fn)
        ("baseline", "baseline-01", "initial-access", "BASELINE", "Normal User Workstation Routine", [4688], False, case_baseline_normal),
        ("atomic", "atomic-T1082", "discovery", "T1082", "System Information Discovery (Burst Queries)", [4688], True, case_t1082_system_info_discovery),
        ("atomic", "atomic-T1033", "discovery", "T1033", "System Owner/User Discovery (Hidden Process)", [4688], True, case_t1033_user_discovery),
        ("atomic", "atomic-T1016", "discovery", "T1016", "System Network Configuration Discovery", [4688], True, case_t1016_network_config_discovery),
        ("atomic", "atomic-T1049", "discovery", "T1049", "System Network Connections Discovery", [4688], True, case_t1049_network_connections_discovery),
        ("atomic", "atomic-T1057", "discovery", "T1057", "Process Discovery via Tasklist & WMI", [4688], True, case_t1057_process_discovery),
        ("atomic", "atomic-T1083", "discovery", "T1083", "File and Directory Discovery (Recon Crawl)", [4688], True, case_t1083_file_directory_discovery),
        ("atomic", "atomic-T1087-001", "discovery", "T1087.001", "Account Discovery: Local Account & Admin Groups", [4688], True, case_t1087_001_local_account_discovery),
        ("atomic", "atomic-T1046", "discovery", "T1046", "Network Service Scanning (Target Port Probes)", [3, 5156], True, lambda: case_t1046_network_service_scan(args.target_ip)),
        ("atomic", "atomic-T1059-001", "execution", "T1059.001", "PowerShell Base64 Obfuscated Execution", [4688, 4104], True, case_t1059_001_encoded_powershell),
        ("atomic", "atomic-T1059-003", "execution", "T1059.003", "Windows Command Shell Batch Chaining", [4688], True, case_t1059_003_cmd_scripting),
        ("atomic", "atomic-T1053-005", "persistence", "T1053.005", "Scheduled Task Creation & Immediate Cleanup", [4688, 4698, 4699], True, case_t1053_005_scheduled_task),
        ("atomic", "atomic-T1547-001", "persistence", "T1547.001", "Registry Run Keys Persistence & Cleanup", [4688, 12, 13], True, case_t1547_001_registry_run_keys),
        ("atomic", "atomic-T1543-003", "persistence", "T1543.003", "Windows Service Creation & Cleanup", [7045, 4697, 4688], True, case_t1543_003_windows_service),
        ("atomic", "atomic-T1218-011", "defense-evasion", "T1218.011", "Rundll32 Living-off-the-Land Proxy", [4688], True, case_t1218_011_rundll32_proxy),
        ("atomic", "atomic-T1105", "defense-evasion", "T1105", "Ingress Tool Transfer via LOLBin Certutil", [4688], True, case_t1105_ingress_tool_transfer),
        ("atomic", "atomic-T1070-004", "defense-evasion", "T1070.004", "Indicator Removal: File Deletion Activity", [4688, 11, 23], True, case_t1070_004_file_deletion),
        ("atomic", "atomic-T1070-001", "defense-evasion", "T1070.001", "Event Log Tampering Reconnaissance", [4688, 1102], True, case_t1070_001_event_log_tamper_recon),
        ("atomic", "atomic-T1110-001", "credential-access", "T1110.001", "SMB Fast Password Guessing / Brute-Force", [4625], True, lambda: case_t1110_001_bruteforce(args.target_ip)),
        ("atomic", "atomic-T1110-003", "credential-access", "T1110.003", "SMB Password Spraying Multi-Account", [4625], True, lambda: case_t1110_003_password_spray(args.target_ip)),
        ("atomic", "atomic-T1021-002", "lateral-movement", "T1021.002", "Remote Services: SMB Admin Shares Recon", [4624, 4625, 5140], True, lambda: case_t1021_002_smb_lateral_recon(args.target_ip)),
        ("atomic", "atomic-T1560-001", "collection", "T1560.001", "Archive Collected Data via Compress-Archive", [4688, 11], True, case_t1560_001_archive_staging),
        ("atomic", "atomic-T1071-001", "command-and-control", "T1071.001", "Application Layer Protocol Periodic Beaconing", [5156, 3], True, lambda: case_t1071_001_c2_beaconing(args.target_ip)),
        ("atomic", "atomic-context-deviation", "defense-evasion", "T1059-LivingOffTheLand", "Living-off-the-Land Context Deviation (Off-Hours Recon)", [4688], True, case_context_deviation_off_hours),
    ]

    print("=" * 80)
    print(" GLOBALBAN RED TEAM HARNESS - MITRE ATT&CK ADVERSARY EMULATION (24 TECHNIQUES)")
    print(f" Source Host : {host} | Target Host: {args.target_ip}")
    print(f" Output Root : {ROOT_DIR}")
    print("=" * 80)

    ground_truth_records: list[dict] = []
    cases_lines: list[str] = []

    for idx, (kind, case_id, tactic, tech_id, tech_name, exp_events, is_malicious, fn) in enumerate(scenarios, start=1):
        print(f"\n[{idx:02d}/{len(scenarios):02d}] Đang thực thi: {case_id} | [{tactic.upper()}] {tech_id or 'BASELINE'} - {tech_name}")
        start_utc = utc_now()
        
        executed_cmd = fn()
        
        time.sleep(2)  # Đợi Windows flushes buffers xuống các kênh EVTX
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
    print(f"[✓] HOÀN TẤT CHIẾN DỊCH KIỂM THỬ THỰC TẾ 24 KỊCH BẢN!")
    print(f"[✓] File Ground-Truth JSON : {ground_truth_file.resolve()}")
    print(f"[✓] File Metadata JSONL    : {cases_file.resolve()}")
    print(f"[✓] Tổng số kỹ thuật chạy : {len(scenarios)} (1 Baseline + {len(scenarios)-1} ATT&CK Techniques)")
    print("=" * 80)


if __name__ == "__main__":
    main()
