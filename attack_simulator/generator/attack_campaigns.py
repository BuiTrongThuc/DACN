"""
attack_simulator.generator.attack_campaigns
===========================================
6 chiến dịch tấn công giả lập:
  1. Brute Force / Password Spraying (T1110.001 / T1110.003)
  2. PowerShell Obfuscation (T1059.001 / T1027.010)
  3. Task & Service Persistence (T1053.005 / T1543.003)
  4. Privilege Escalation (T1098 / T1134)
  5. Defense Evasion / Log Clearing (T1070.001 / T1562.002)
  6. C2 Periodic Beaconing (T1071.001)
"""

from __future__ import annotations

import random
from datetime import datetime, timedelta

from attack_simulator.core.models import MITRE_METADATA, PUBLIC_C2_IPS, SimulatedRecord
from attack_simulator.core.xml_utils import build_windows_event_xml

def generate_brute_force_campaign(
    rng: random.Random, attacker_ip: str, campaign_index: int, base_time: datetime
) -> list[SimulatedRecord]:
    records: list[SimulatedRecord] = []
    host = f"DC-AUTH-{campaign_index:04d}"
    event_id_choice = (4625, 4771, 4776)[campaign_index % 3]
    ip_field_name = "ClientAddress" if event_id_choice == 4771 else "IpAddress"

    is_spray = (campaign_index % 2 == 0)
    if is_spray:
        tech_id = "T1110.003"
        tech_name, tactic = MITRE_METADATA[tech_id]
        users = ["admin", "administrator", "svc_sql", "backup", "helpdesk", "svc_iis"]
        burst_len = rng.randint(5, 6)
        for i in range(burst_len):
            ts = base_time + timedelta(seconds=i * 3)
            user = users[i % len(users)]
            xml = build_windows_event_xml(
                provider="Microsoft-Windows-Security-Auditing",
                computer=host,
                event_id=event_id_choice,
                timestamp=ts,
                data_fields={"TargetUserName": user, ip_field_name: attacker_ip},
            )
            triggers = (i == 4)
            records.append(
                SimulatedRecord(
                    timestamp=ts,
                    xml=xml,
                    dataset_source="splunk-attack-data-sanitized",
                    mitre_technique_id=tech_id,
                    mitre_technique_name=tech_name,
                    mitre_tactic=tactic,
                    is_malicious=True,
                    expected_signal=triggers,
                    expected_rule_ids=["AUTH-FAILURE-BURST"] if triggers else [],
                    scenario=(
                        f"windows_password_spray_{event_id_choice}_step_{i + 1}_triggers_level2"
                        if triggers
                        else f"windows_password_spray_{event_id_choice}_step_{i + 1}"
                    ),
                    scenario_key="brute_force",
                )
            )
    else:
        tech_id = "T1110.001"
        tech_name, tactic = MITRE_METADATA[tech_id]
        for i in range(6):
            ts = base_time + timedelta(seconds=i * 2)
            user = "administrator" if i < 5 else "svc_domain_admin"
            xml = build_windows_event_xml(
                provider="Microsoft-Windows-Security-Auditing",
                computer=host,
                event_id=event_id_choice,
                timestamp=ts,
                data_fields={"TargetUserName": user, ip_field_name: attacker_ip},
            )
            triggers = i in (4, 5)
            level_tag = "_triggers_level1" if i == 4 else ("_triggers_level2" if i == 5 else "")
            records.append(
                SimulatedRecord(
                    timestamp=ts,
                    xml=xml,
                    dataset_source="splunk-attack-data-sanitized",
                    mitre_technique_id=tech_id,
                    mitre_technique_name=tech_name,
                    mitre_tactic=tactic,
                    is_malicious=True,
                    expected_signal=triggers,
                    expected_rule_ids=["AUTH-FAILURE-BURST"] if triggers else [],
                    scenario=f"windows_bruteforce_{event_id_choice}_step_{i + 1}{level_tag}",
                    scenario_key="brute_force",
                )
            )
    return records

def generate_obfuscation_campaign(
    campaign_index: int, base_time: datetime
) -> list[SimulatedRecord]:
    host = f"WS-OBF-{campaign_index:04d}"
    tech_id = "T1059.001"
    tech_name, tactic = MITRE_METADATA[tech_id]

    command_variants = (
        "powershell.exe -NoP -W Hidden -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA",
        "powershell.exe -ExecutionPolicy Bypass -enc aQBvAHgAIABbAFMAeQBzAHQAZQBtAC4AQwBvAG4AdgBlAHIAdABdADoAOgBGAHIAbwBtAEIAYQBzAGUANgA0AFMAdAByAGkAbgBnAA==",
        "powershell.exe -NoProfile -Command \"IEX ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('SUVYIChOZXctT2JqZWN0IE5ldC5XZWJDbGllbnQp')))\"; Invoke-Expression $payload",
        "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -w hidden -EncodedCommand JABjAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAFMAeQBzAHQAZQBtAC4ATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAA= -enc",
    )
    process_variants = (
        "C:\\Users\\Public\\Downloads\\updater.exe",
        "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "C:\\Users\\Admin\\AppData\\Local\\Temp\\dropper.exe",
    )
    cmd = command_variants[campaign_index % len(command_variants)]
    proc = process_variants[campaign_index % len(process_variants)]

    xml_4688 = build_windows_event_xml(
        provider="Microsoft-Windows-Security-Auditing",
        computer=host,
        event_id=4688,
        timestamp=base_time,
        data_fields={
            "NewProcessName": proc,
            "CreatorProcessName": "C:\\Windows\\System32\\cmd.exe",
            "CommandLine": cmd,
        },
    )
    records = [
        SimulatedRecord(
            timestamp=base_time,
            xml=xml_4688,
            dataset_source="evtx-attack-samples-sanitized",
            mitre_technique_id=tech_id,
            mitre_technique_name=tech_name,
            mitre_tactic=tactic,
            is_malicious=True,
            expected_signal=True,
            expected_rule_ids=["OBFUSCATED-COMMAND-LINE"],
            scenario="powershell_encoded_command_execution_4688",
            scenario_key="obfuscation",
        )
    ]

    if campaign_index % 3 == 2:
        ts_4104 = base_time + timedelta(seconds=2)
        t4104_id = "T1027.010"
        t4104_name, t4104_tactic = MITRE_METADATA[t4104_id]
        xml_4104 = build_windows_event_xml(
            provider="Microsoft-Windows-PowerShell",
            computer=host,
            event_id=4104,
            timestamp=ts_4104,
            data_fields={
                "CommandLine": "IEX ([System.Convert]::FromBase64String('SQBFAFgA')); Invoke-Expression $cmd",
            },
        )
        records.append(
            SimulatedRecord(
                timestamp=ts_4104,
                xml=xml_4104,
                dataset_source="otrf-security-datasets-sanitized",
                mitre_technique_id=t4104_id,
                mitre_technique_name=t4104_name,
                mitre_tactic=t4104_tactic,
                is_malicious=True,
                expected_signal=True,
                expected_rule_ids=["WINDOWS-4688-4104"],
                scenario="powershell_scriptblock_4104_correlated_with_4688",
                scenario_key="obfuscation",
            )
        )
    return records

def generate_persistence_campaign(
    campaign_index: int, base_time: datetime
) -> list[SimulatedRecord]:
    host = f"WS-PERSIST-{campaign_index:04d}"
    use_service = (campaign_index % 3 == 2)
    user = ("alice", "bob_admin", "svc_deploy", "it_ops")[campaign_index % 4]
    src_ip = f"185.220.101.{(campaign_index % 200) + 10}"

    if not use_service:
        tech_id = "T1053.005"
        tech_name = "Scheduled Task"
        t1 = base_time
        t2 = base_time + timedelta(seconds=5)
        t3 = base_time + timedelta(seconds=9)

        xml_1 = build_windows_event_xml(
            provider="Microsoft-Windows-Security-Auditing",
            computer=host,
            event_id=4624,
            timestamp=t1,
            data_fields={"TargetUserName": user, "IpAddress": src_ip},
        )
        xml_2 = build_windows_event_xml(
            provider="Microsoft-Windows-Security-Auditing",
            computer=host,
            event_id=4688,
            timestamp=t2,
            data_fields={
                "NewProcessName": "C:\\Windows\\System32\\schtasks.exe",
                "CommandLine": "schtasks /create /tn WinTelemetrySync /tr C:\\Users\\Public\\beacon.exe /sc onlogon",
            },
        )
        xml_3 = build_windows_event_xml(
            provider="Microsoft-Windows-Security-Auditing",
            computer=host,
            event_id=4698,
            timestamp=t3,
            data_fields={"TargetUserName": user, "TaskName": "\\Microsoft\\Windows\\WinTelemetrySync"},
        )
        return [
            SimulatedRecord(
                timestamp=t1, xml=xml_1, dataset_source="evtx-attack-samples-sanitized",
                mitre_technique_id=tech_id, mitre_technique_name=tech_name, mitre_tactic="persistence",
                is_malicious=True, expected_signal=False, expected_rule_ids=[],
                scenario="logon_before_scheduled_task_persistence", scenario_key="persistence",
            ),
            SimulatedRecord(
                timestamp=t2, xml=xml_2, dataset_source="evtx-attack-samples-sanitized",
                mitre_technique_id=tech_id, mitre_technique_name=tech_name, mitre_tactic="execution",
                is_malicious=True, expected_signal=True, expected_rule_ids=["WINDOWS-4624-4688"],
                scenario="process_creation_for_scheduled_task", scenario_key="persistence",
            ),
            SimulatedRecord(
                timestamp=t3, xml=xml_3, dataset_source="evtx-attack-samples-sanitized",
                mitre_technique_id=tech_id, mitre_technique_name=tech_name, mitre_tactic="persistence",
                is_malicious=True, expected_signal=True, expected_rule_ids=["WINDOWS-4624-4688-4698"],
                scenario="scheduled_task_persistence_completed", scenario_key="persistence",
            ),
        ]
    else:
        tech_id = "T1543.003"
        tech_name = "Windows Service"
        t1 = base_time
        t2 = base_time + timedelta(seconds=4)
        t3 = base_time + timedelta(seconds=8)

        xml_1 = build_windows_event_xml(
            provider="Microsoft-Windows-Security-Auditing",
            computer=host,
            event_id=4624,
            timestamp=t1,
            data_fields={"TargetUserName": user, "IpAddress": src_ip},
        )
        xml_2 = build_windows_event_xml(
            provider="Microsoft-Windows-Security-Auditing",
            computer=host,
            event_id=4688,
            timestamp=t2,
            data_fields={
                "NewProcessName": "C:\\Windows\\System32\\sc.exe",
                "CommandLine": "sc.exe create WinDefHealthSvc binPath= C:\\Users\\Public\\svc_host.exe start= auto",
            },
        )
        xml_3 = build_windows_event_xml(
            provider="Service Control Manager",
            computer=host,
            event_id=7045,
            timestamp=t3,
            data_fields={"ServiceName": "WinDefHealthSvc", "ServiceFileName": "C:\\Users\\Public\\svc_host.exe"},
        )
        return [
            SimulatedRecord(
                timestamp=t1, xml=xml_1, dataset_source="evtx-attack-samples-sanitized",
                mitre_technique_id=tech_id, mitre_technique_name=tech_name, mitre_tactic="persistence",
                is_malicious=True, expected_signal=False, expected_rule_ids=[],
                scenario="logon_before_service_persistence", scenario_key="persistence",
            ),
            SimulatedRecord(
                timestamp=t2, xml=xml_2, dataset_source="evtx-attack-samples-sanitized",
                mitre_technique_id=tech_id, mitre_technique_name=tech_name, mitre_tactic="privilege-escalation",
                is_malicious=True, expected_signal=True, expected_rule_ids=["WINDOWS-4624-4688"],
                scenario="process_creation_for_service_install", scenario_key="persistence",
            ),
            SimulatedRecord(
                timestamp=t3, xml=xml_3, dataset_source="evtx-attack-samples-sanitized",
                mitre_technique_id=tech_id, mitre_technique_name=tech_name, mitre_tactic="persistence",
                is_malicious=True, expected_signal=True, expected_rule_ids=["WINDOWS-4624-4688-7045"],
                scenario="service_persistence_completed", scenario_key="persistence",
            ),
        ]

def generate_privilege_escalation_campaign(
    campaign_index: int, base_time: datetime
) -> list[SimulatedRecord]:
    host = f"DC-PRIV-{campaign_index:04d}"
    group_event_id = (4732, 4732, 4728, 4756)[campaign_index % 4]
    new_user = f"svc_support_{campaign_index % 100:02d}"
    actor = "admin"

    t1 = base_time
    t2 = base_time + timedelta(seconds=5)
    t3 = base_time + timedelta(seconds=10)

    xml_1 = build_windows_event_xml(
        provider="Microsoft-Windows-Security-Auditing",
        computer=host,
        event_id=4720,
        timestamp=t1,
        data_fields={"TargetUserName": new_user, "SubjectUserName": actor},
    )
    xml_2 = build_windows_event_xml(
        provider="Microsoft-Windows-Security-Auditing",
        computer=host,
        event_id=group_event_id,
        timestamp=t2,
        data_fields={"TargetUserName": "Administrators", "SubjectUserName": actor},
    )
    xml_3 = build_windows_event_xml(
        provider="Microsoft-Windows-Security-Auditing",
        computer=host,
        event_id=4704,
        timestamp=t3,
        data_fields={"TargetUserName": new_user, "SubjectUserName": actor},
    )

    return [
        SimulatedRecord(
            timestamp=t1, xml=xml_1, dataset_source="otrf-security-datasets-sanitized",
            mitre_technique_id="T1098", mitre_technique_name="Account Manipulation", mitre_tactic="persistence",
            is_malicious=True, expected_signal=False, expected_rule_ids=[],
            scenario="account_creation_context_before_group_add", scenario_key="privilege_escalation",
        ),
        SimulatedRecord(
            timestamp=t2, xml=xml_2, dataset_source="otrf-security-datasets-sanitized",
            mitre_technique_id="T1098", mitre_technique_name="Account Manipulation", mitre_tactic="privilege-escalation",
            is_malicious=True, expected_signal=True,
            expected_rule_ids=[f"WINDOWS-4720-{group_event_id}", "PRIVILEGE-CHANGE"],
            scenario=f"group_membership_addition_{group_event_id}_after_user_creation",
            scenario_key="privilege_escalation",
        ),
        SimulatedRecord(
            timestamp=t3, xml=xml_3, dataset_source="otrf-security-datasets-sanitized",
            mitre_technique_id="T1134", mitre_technique_name="Access Token Manipulation", mitre_tactic="privilege-escalation",
            is_malicious=True, expected_signal=True,
            expected_rule_ids=[f"WINDOWS-4720-{group_event_id}-4704", "PRIVILEGE-CHANGE"],
            scenario="user_right_assignment_escalation", scenario_key="privilege_escalation",
        ),
    ]

def generate_defense_evasion_campaign(
    campaign_index: int, base_time: datetime
) -> list[SimulatedRecord]:
    host = f"SRV-EVADE-{campaign_index:04d}"
    variant = campaign_index % 4
    t1 = base_time
    t2 = base_time + timedelta(seconds=6)

    if variant in (0, 1):
        first_id = 7045
        xml_1 = build_windows_event_xml(
            provider="Service Control Manager",
            computer=host,
            event_id=7045,
            timestamp=t1,
            data_fields={"ServiceName": f"UpdaterSvc{campaign_index}", "ServiceFileName": "C:\\Users\\Public\\UpdaterSvc.exe"},
        )
        first_tech = ("T1543.003", "Windows Service", "persistence")
    else:
        first_id = 4688
        xml_1 = build_windows_event_xml(
            provider="Microsoft-Windows-Security-Auditing",
            computer=host,
            event_id=4688,
            timestamp=t1,
            data_fields={"NewProcessName": "C:\\Windows\\System32\\wevtutil.exe", "CommandLine": "wevtutil cl Security"},
        )
        first_tech = ("T1070.001", "Clear Windows Event Logs", "defense-evasion")

    if variant in (0, 2):
        second_id = 1102
        xml_2 = build_windows_event_xml(
            provider="Microsoft-Windows-Eventlog",
            computer=host,
            event_id=1102,
            timestamp=t2,
            data_fields={"SubjectUserName": "SYSTEM", "CommandLine": "wevtutil cl Security"},
        )
        second_tech = ("T1070.001", "Clear Windows Event Logs", "defense-evasion")
    else:
        second_id = 4719
        xml_2 = build_windows_event_xml(
            provider="Microsoft-Windows-Security-Auditing",
            computer=host,
            event_id=4719,
            timestamp=t2,
            data_fields={"SubjectUserName": "SYSTEM", "CommandLine": "auditpol /clear /y"},
        )
        second_tech = ("T1562.002", "Disable Windows Event Logging", "defense-evasion")

    return [
        SimulatedRecord(
            timestamp=t1, xml=xml_1, dataset_source="evtx-attack-samples-sanitized",
            mitre_technique_id=first_tech[0], mitre_technique_name=first_tech[1], mitre_tactic=first_tech[2],
            is_malicious=True, expected_signal=False, expected_rule_ids=[],
            scenario=f"evasion_precursor_{first_id}", scenario_key="defense_evasion",
        ),
        SimulatedRecord(
            timestamp=t2, xml=xml_2, dataset_source="evtx-attack-samples-sanitized",
            mitre_technique_id=second_tech[0], mitre_technique_name=second_tech[1], mitre_tactic=second_tech[2],
            is_malicious=True, expected_signal=True, expected_rule_ids=[f"WINDOWS-{first_id}-{second_id}"],
            scenario=f"defense_evasion_{first_id}_{second_id}_triggered", scenario_key="defense_evasion",
        ),
    ]

def generate_c2_beaconing_campaign(
    campaign_index: int, base_time: datetime, interval_seconds: int = 30
) -> list[SimulatedRecord]:
    records: list[SimulatedRecord] = []
    host = f"WS-C2-{campaign_index:04d}"
    c2_ip = PUBLIC_C2_IPS[campaign_index % len(PUBLIC_C2_IPS)]
    port = str((443, 8443, 8080, 4444, 9001)[campaign_index % 5])
    app = f"\\device\\harddiskvolume2\\programdata\\agent_{campaign_index:04d}.exe"

    for i in range(5):
        jitter = (-1, 0, 1, 0, 0)[i] if interval_seconds >= 20 else 0
        ts = base_time + timedelta(seconds=i * interval_seconds + jitter)
        xml = build_windows_event_xml(
            provider="Microsoft-Windows-Security-Auditing",
            computer=host,
            event_id=5156,
            timestamp=ts,
            data_fields={
                "Application": app,
                "Direction": "%%14592",
                "DestAddress": c2_ip,
                "DestPort": port,
                "Protocol": "6",
            },
        )
        triggers = (i == 4)
        records.append(
            SimulatedRecord(
                timestamp=ts, xml=xml, dataset_source="splunk-attack-data-sanitized",
                mitre_technique_id="T1071.001", mitre_technique_name="Web Protocols",
                mitre_tactic="command-and-control", is_malicious=True, expected_signal=triggers,
                expected_rule_ids=["C2-BEACONING"] if triggers else [],
                scenario=f"c2_beacon_interval_{i + 1}_triggers_signal" if triggers else f"c2_beacon_interval_{i + 1}",
                scenario_key="c2_beaconing",
            )
        )
    return records
