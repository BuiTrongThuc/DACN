"""
attack_simulator.generator.benign_noise
=======================================
Sinh log hoạt động sạch (Benign) và log nhiễu quản trị viên (Admin Noise) để kiểm định False Positive Rate (FPR).
"""

from __future__ import annotations

from datetime import datetime, timedelta

from attack_simulator.core.models import SimulatedRecord
from attack_simulator.core.xml_utils import build_windows_event_xml

def generate_benign_events(
    count: int, start_time: datetime, span_seconds: int
) -> list[SimulatedRecord]:
    records: list[SimulatedRecord] = []
    benign_users = ("bob", "charlie", "diana", "evan", "fiona", "george", "hannah", "ivan")
    benign_procs = (
        ("C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", "chrome.exe --type=renderer"),
        ("C:\\Windows\\System32\\notepad.exe", "notepad.exe C:\\Users\\bob\\notes.txt"),
        ("C:\\Windows\\explorer.exe", "explorer.exe shell:appsfolder"),
        ("C:\\Windows\\System32\\taskmgr.exe", "taskmgr.exe"),
        ("C:\\Windows\\System32\\calc.exe", "calc.exe"),
    )

    for i in range(count):
        offset = int((i / max(1, count)) * max(60, span_seconds))
        ts = start_time + timedelta(seconds=offset)
        kind = i % 5
        seq_idx = i // 5

        if kind == 0:
            host = f"WS-BENIGN-LOGON-{seq_idx % 40:02d}"
            user = benign_users[seq_idx % len(benign_users)]
            ip = f"10.55.{(seq_idx // 250) % 250}.{(seq_idx % 250) + 1}"
            xml = build_windows_event_xml(
                provider="Microsoft-Windows-Security-Auditing", computer=host, event_id=4624,
                timestamp=ts, data_fields={"TargetUserName": user, "IpAddress": ip},
            )
            scenario = "benign_workstation_logon"
        elif kind == 1:
            host = f"WS-BENIGN-NET-{seq_idx % 40:02d}"
            xml = build_windows_event_xml(
                provider="Microsoft-Windows-Security-Auditing", computer=host, event_id=5156,
                timestamp=ts, data_fields={
                    "Application": "C:\\Windows\\System32\\svchost.exe",
                    "Direction": "%%14592",
                    "DestAddress": f"10.88.{(seq_idx // 250) % 250}.{(seq_idx % 250) + 1}",
                    "DestPort": "443", "Protocol": "6",
                },
            )
            scenario = "benign_internal_private_network_connection"
        elif kind == 2:
            host = f"WS-BENIGN-AUTH-{seq_idx % 40:02d}"
            user = benign_users[seq_idx % len(benign_users)]
            b2 = (seq_idx // 65025) % 7
            b3 = (seq_idx // 255) % 250 + 1
            b4 = (seq_idx % 254) + 1
            typo_ip = f"172.{24 + b2}.{b3}.{b4}"
            xml = build_windows_event_xml(
                provider="Microsoft-Windows-Security-Auditing", computer=host, event_id=4625,
                timestamp=ts, data_fields={"TargetUserName": user, "IpAddress": typo_ip},
            )
            scenario = "benign_single_password_typo"
        elif kind == 3:
            host = f"WS-BENIGN-PROC-{seq_idx % 40:02d}"
            proc_name, cmd_line = benign_procs[seq_idx % len(benign_procs)]
            xml = build_windows_event_xml(
                provider="Microsoft-Windows-Security-Auditing", computer=host, event_id=4688,
                timestamp=ts, data_fields={
                    "NewProcessName": proc_name,
                    "CreatorProcessName": "C:\\Windows\\explorer.exe",
                    "CommandLine": cmd_line,
                },
            )
            scenario = "benign_standard_process_creation"
        else:
            host = f"SRV-BENIGN-WEB-{seq_idx % 20:02d}"
            xml = build_windows_event_xml(
                provider="Microsoft-Windows-Security-Auditing", computer=host, event_id=5156,
                timestamp=ts, data_fields={
                    "Application": "C:\\Windows\\System32\\inetsrv\\w3wp.exe",
                    "Direction": "%%14593",
                    "DestAddress": "45.33.32.156", "DestPort": "443", "Protocol": "6",
                },
            )
            scenario = "benign_inbound_web_connection"

        records.append(
            SimulatedRecord(
                timestamp=ts, xml=xml, dataset_source="otrf-security-datasets-sanitized",
                mitre_technique_id=None, mitre_technique_name=None, mitre_tactic=None,
                is_malicious=False, expected_signal=False, expected_rule_ids=[],
                scenario=scenario, scenario_key="benign",
            )
        )
    return records

def generate_ambiguous_admin_noise(
    count: int,
    start_time: datetime,
    span_seconds: int,
    *,
    unfiltered_fp: bool = False,
) -> list[SimulatedRecord]:
    records: list[SimulatedRecord] = []
    admin_cli_commands = (
        ("C:\\Windows\\System32\\whoami.exe", "whoami.exe /groups"),
        ("C:\\Windows\\System32\\ipconfig.exe", "ipconfig.exe /all"),
        ("C:\\Windows\\System32\\certutil.exe", "certutil.exe -store my"),
        ("C:\\Windows\\System32\\bitsadmin.exe", "bitsadmin.exe /list /allusers"),
        ("C:\\Windows\\System32\\wbem\\WMIC.exe", "wmic.exe logicaldisk get name,freespace,size"),
        ("C:\\Windows\\System32\\gpresult.exe", "gpresult.exe /scope computer /r"),
        ("C:\\Windows\\System32\\schtasks.exe", 'schtasks.exe /query /tn "microsoft\\windows\\defrag\\scheduleddefrag"'),
        ("C:\\Windows\\System32\\reg.exe", "reg.exe query hkcu\\software\\microsoft\\windows\\currentversion\\explorer"),
    )

    for i in range(count):
        offset = int((i / max(1, count)) * max(60, span_seconds))
        ts = start_time + timedelta(seconds=offset)
        host = f"SRV-ADMIN-NOISE-{i:04d}"

        if unfiltered_fp:
            # Force an alert on benign event to test False Positive Rate calculations
            xml = build_windows_event_xml(
                provider="Microsoft-Windows-Security-Auditing",
                computer=host,
                event_id=4688,
                timestamp=ts,
                data_fields={
                    "NewProcessName": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                    "CreatorProcessName": "C:\\Windows\\System32\\cmd.exe",
                    "CommandLine": "powershell.exe -EncodedCommand dGVzdA==",
                },
            )
            records.append(
                SimulatedRecord(
                    timestamp=ts, xml=xml, dataset_source="otrf-security-datasets-sanitized",
                    mitre_technique_id=None, mitre_technique_name=None, mitre_tactic=None,
                    is_malicious=False, expected_signal=False, expected_rule_ids=[],
                    scenario="unfiltered_fp_test_powershell_enc", scenario_key="benign_noise",
                )
            )
            continue

        noise_kind = i % 5
        seq_idx = i // 5

        if noise_kind == 0:
            proc_name, cmd_line = admin_cli_commands[seq_idx % len(admin_cli_commands)]
            xml = build_windows_event_xml(
                provider="Microsoft-Windows-Security-Auditing", computer=host, event_id=4688,
                timestamp=ts, data_fields={
                    "NewProcessName": proc_name,
                    "CreatorProcessName": "C:\\Windows\\System32\\cmd.exe",
                    "CommandLine": cmd_line,
                },
            )
            scenario = "benign_admin_diagnostic_cli_4688"
        elif noise_kind == 1:
            xml = build_windows_event_xml(
                provider="Microsoft-Windows-Security-Auditing", computer=host, event_id=4672,
                timestamp=ts, data_fields={"SubjectUserName": "sysadmin_oncall", "TargetUserName": "sysadmin_oncall"},
            )
            scenario = "benign_admin_special_logon_4672"
        elif noise_kind == 2:
            xml = build_windows_event_xml(
                provider="Microsoft-Windows-Security-Auditing", computer=host, event_id=4720,
                timestamp=ts, data_fields={"TargetUserName": f"new_hire_{seq_idx:04d}", "SubjectUserName": "hr_provisioning_svc"},
            )
            scenario = "benign_admin_standalone_user_creation_4720"
        elif noise_kind == 3:
            xml = build_windows_event_xml(
                provider="Microsoft-Windows-Security-Auditing", computer=host, event_id=5156,
                timestamp=ts, data_fields={
                    "Application": "C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe",
                    "Direction": "%%14592", "DestAddress": "13.107.42.14", "DestPort": "443", "Protocol": "6",
                },
            )
            scenario = "benign_admin_single_outbound_https_5156"
        else:
            b3 = (seq_idx // 254) % 255
            b4 = (seq_idx % 254) + 1
            admin_ip = f"10.250.{b3}.{b4}"
            xml = build_windows_event_xml(
                provider="Microsoft-Windows-Security-Auditing", computer=host, event_id=4771,
                timestamp=ts, data_fields={"TargetUserName": "sysadmin_oncall", "ClientAddress": admin_ip},
            )
            scenario = "benign_admin_isolated_kerberos_typo_4771"

        records.append(
            SimulatedRecord(
                timestamp=ts, xml=xml, dataset_source="otrf-security-datasets-sanitized",
                mitre_technique_id=None, mitre_technique_name=None, mitre_tactic=None,
                is_malicious=False, expected_signal=False, expected_rule_ids=[],
                scenario=scenario, scenario_key="benign_noise",
            )
        )
    return records
