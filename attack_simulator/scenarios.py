from __future__ import annotations

import json
import random
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from xml.sax.saxutils import escape


@dataclass(frozen=True, slots=True)
class ScenarioSpec:
    key: str
    code: int
    title: str
    event_chain_desc: str
    expected_rules_desc: str
    mitre_ids: tuple[str, ...]


SCENARIO_CATALOG: tuple[ScenarioSpec, ...] = (
    ScenarioSpec(
        key="brute_force",
        code=1,
        title="1. Brute Force / Password Spraying",
        event_chain_desc=">=5 sự kiện 4625, 4771 hoặc 4776 từ cùng 1 IP trong 300s",
        expected_rules_desc="AUTH-FAILURE-BURST (Level 1 / Level 2)",
        mitre_ids=("T1110.003", "T1110.001", "T1110"),
    ),
    ScenarioSpec(
        key="obfuscation",
        code=2,
        title="2. Lệnh mã hóa / Làm rối (Obfuscation)",
        event_chain_desc="4688 (và 4104) có CommandLine chứa -EncodedCommand, -enc, FromBase64String, IEX",
        expected_rules_desc="OBFUSCATED-COMMAND-LINE",
        mitre_ids=("T1059.001", "T1027.010"),
    ),
    ScenarioSpec(
        key="persistence",
        code=3,
        title="3. Xâm nhập & Cắm chốt (Persistence)",
        event_chain_desc="Cùng Computer: 4624 (Logon) -> 4688 (Process) -> 4698 (Task) hoặc 7045 (Service)",
        expected_rules_desc="WINDOWS-4624-4688-4698 / logon-process-persistence",
        mitre_ids=("T1053.005", "T1543.003"),
    ),
    ScenarioSpec(
        key="privilege_escalation",
        code=4,
        title="4. Leo thang đặc quyền (Privilege Escalation)",
        event_chain_desc="4720 (Tạo user) -> 4728/4732/4756 (Thêm nhóm Admin) -> 4704 (Gán quyền)",
        expected_rules_desc="PRIVILEGE-CHANGE & WINDOWS-4720-4732-4704",
        mitre_ids=("T1098", "T1134"),
    ),
    ScenarioSpec(
        key="defense_evasion",
        code=5,
        title="5. Xóa dấu vết (Defense Evasion)",
        event_chain_desc="7045 / 4688 -> 1102 (Xóa Security Log) hoặc 4719 (Sửa Audit Policy)",
        expected_rules_desc="WINDOWS-7045-1102",
        mitre_ids=("T1070.001", "T1562.002", "T1543.003"),
    ),
    ScenarioSpec(
        key="c2_beaconing",
        code=6,
        title="6. C2 Beaconing (Kết nối điều khiển định kỳ)",
        event_chain_desc=">=5 sự kiện 5156 chiều ra (Direction=%%14592) tới cùng 1 IP Public cách đều (VD: 30s)",
        expected_rules_desc="C2-BEACONING",
        mitre_ids=("T1071.001",),
    ),
)

SCENARIO_BY_KEY: dict[str, ScenarioSpec] = {s.key: s for s in SCENARIO_CATALOG}
SCENARIO_BY_CODE: dict[int, ScenarioSpec] = {s.code: s for s in SCENARIO_CATALOG}

# Validated against GlobalBan's datasets/attack_techniques.csv
MITRE_METADATA: dict[str, tuple[str, str]] = {
    "T1110": ("Brute Force", "credential-access"),
    "T1110.001": ("Password Guessing", "credential-access"),
    "T1110.003": ("Password Spraying", "credential-access"),
    "T1059.001": ("PowerShell", "execution"),
    "T1027.010": ("Command Obfuscation", "stealth"),
    "T1053.005": ("Scheduled Task", "persistence"),
    "T1543.003": ("Windows Service", "persistence"),
    "T1098": ("Account Manipulation", "privilege-escalation"),
    "T1134": ("Access Token Manipulation", "privilege-escalation"),
    "T1070.001": ("Clear Windows Event Logs", "stealth"),
    "T1562.002": ("Disable Windows Event Logging", "defense-impairment"),
    "T1071.001": ("Web Protocols", "command-and-control"),
}

DATASET_SOURCES = (
    "evtx-attack-samples-sanitized",
    "otrf-security-datasets-sanitized",
    "splunk-attack-data-sanitized",
)

# Public routable IPs (ipaddress.ip_address(ip).is_global == True) for C2 Beaconing
# Completely disjoint from GlobalBan's built-in sample/evaluation IPs
PUBLIC_C2_IPS = (
    "45.33.32.156",
    "185.199.108.153",
    "104.16.132.229",
    "151.101.1.69",
    "172.67.74.226",
    "198.41.200.113",
    "140.82.121.4",
    "13.107.42.14",
    "34.117.59.81",
    "52.84.150.11",
    "103.224.182.210",
    "91.189.91.39",
)


@dataclass(slots=True)
class SimulatedRecord:
    timestamp: datetime
    xml: str
    dataset_source: str
    mitre_technique_id: str | None
    mitre_technique_name: str | None
    mitre_tactic: str | None
    is_malicious: bool
    expected_signal: bool
    expected_rule_ids: list[str]
    scenario: str
    scenario_key: str
    event_id: str = ""

    def to_jsonl_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "xml": self.xml,
            "dataset_source": self.dataset_source,
            "mitre_technique_id": self.mitre_technique_id,
            "mitre_technique_name": self.mitre_technique_name,
            "mitre_tactic": self.mitre_tactic,
            "is_malicious": self.is_malicious,
            "expected_signal": self.expected_signal,
            "expected_rule_ids": self.expected_rule_ids,
            "scenario": self.scenario,
        }


def build_windows_event_xml(
    *,
    provider: str,
    computer: str,
    event_id: int,
    timestamp: datetime,
    data_fields: dict[str, str],
) -> str:
    """Create a valid Windows Event XML string matching GlobalBan's XML parser."""
    ts_utc = timestamp.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    data_elements = "".join(
        f'<Data Name="{escape(str(k), {"\"": "&quot;"})}">{escape(str(v))}</Data>'
        for k, v in data_fields.items()
    )
    provider_attr = escape(provider, {'"': "&quot;"})
    return (
        '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
        "<System>"
        f'<Provider Name="{provider_attr}"/>'
        f"<Computer>{escape(computer)}</Computer>"
        f"<EventID>{event_id}</EventID>"
        f'<TimeCreated SystemTime="{ts_utc}"/>'
        "</System>"
        f"<EventData>{data_elements}</EventData>"
        "</Event>"
    )


class WindowsAttackLogGenerator:
    """Generate synthetic Windows Event XML logs (both multi-step attacks and benign background)."""

    def __init__(self, seed: int = 42) -> None:
        self.rng = random.Random(seed)
        self._ip_counter = 1

    def _next_attacker_ip(self) -> str:
        """Return a unique attacker IP for auth bursts so each campaign has isolated state."""
        idx = self._ip_counter
        self._ip_counter += 1
        # Use distinct public 91.x block completely separate from GlobalBan's fixture IPs
        b2 = (idx // 65025) % 200 + 50
        b3 = (idx // 255) % 250 + 1
        b4 = (idx % 254) + 1
        return f"91.{b2}.{b3}.{b4}"

    def generate_brute_force_campaign(
        self,
        campaign_index: int,
        base_time: datetime,
    ) -> list[SimulatedRecord]:
        """
        Scenario 1: Brute Force / Password Spraying
        >= 5 events of 4625, 4771 or 4776 from the same IP within 300s -> AUTH-FAILURE-BURST.
        Alternates between:
          - Password Spraying (Level 2: >=2 accounts, 5 failures)
          - Single-Account Brute Force Level 1 (5 failures on 1 account) + Escalation to Level 2 (2nd account on 6th failure)
        Uses 4625, 4771, and 4776 across campaigns.
        """
        records: list[SimulatedRecord] = []
        attacker_ip = self._next_attacker_ip()
        host = f"DC-AUTH-{campaign_index:04d}"
        event_id_choice = (4625, 4771, 4776)[campaign_index % 3]
        ip_field_name = "ClientAddress" if event_id_choice == 4771 else "IpAddress"

        is_spray = (campaign_index % 2 == 0)
        if is_spray:
            tech_id = "T1110.003"
            tech_name, tactic = MITRE_METADATA[tech_id]
            users = ["admin", "administrator", "svc_sql", "backup", "helpdesk", "svc_iis"]
            burst_len = self.rng.randint(5, 6)
            for i in range(burst_len):
                ts = base_time + timedelta(seconds=i * 3)
                user = users[i % len(users)]
                xml = build_windows_event_xml(
                    provider="Microsoft-Windows-Security-Auditing",
                    computer=host,
                    event_id=event_id_choice,
                    timestamp=ts,
                    data_fields={
                        "TargetUserName": user,
                        ip_field_name: attacker_ip,
                    },
                )
                # 5th failure (index 4) reaches threshold=5 with distinct_accounts=5 -> Level 2 alert
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
            # Level 1 on 5th attempt (single account), then Level 2 on 6th attempt (second account)
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
                    data_fields={
                        "TargetUserName": user,
                        ip_field_name: attacker_ip,
                    },
                )
                # Index 4 triggers Level 1 (5 failures, 1 account); Index 5 triggers Level 2 (6 failures, 2 accounts)
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
        self,
        campaign_index: int,
        base_time: datetime,
    ) -> list[SimulatedRecord]:
        """
        Scenario 2: Lệnh mã hóa / Làm rối (Obfuscation)
        4688 (and optionally 4104) with CommandLine containing -EncodedCommand, -enc,
        FromBase64String, IEX / Invoke-Expression -> OBFUSCATED-COMMAND-LINE.
        """
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

        # Every 3rd campaign also includes a correlated 4104 PowerShell ScriptBlock event on the same host
        # so 4688 -> 4104 triggers WINDOWS-4688-4104 (T1027.010 Command Obfuscation).
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
        self,
        campaign_index: int,
        base_time: datetime,
    ) -> list[SimulatedRecord]:
        """
        Scenario 3: Xâm nhập & Cắm chốt (Persistence)
        Same Computer: 4624 (Logon) -> 4688 (Process) -> 4698 (Scheduled Task) or 7045 (Service)
        Triggers WINDOWS-4624-4688 on Step 2 and WINDOWS-4624-4688-4698 (or 7045) on Step 3.
        """
        host = f"WS-PERSIST-{campaign_index:04d}"
        use_service = (campaign_index % 3 == 2)  # Majority 4698 (Scheduled Task), plus 7045 (Service)
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
                data_fields={
                    "TargetUserName": user,
                    "TaskName": "\\Microsoft\\Windows\\WinTelemetrySync",
                },
            )
            return [
                SimulatedRecord(
                    timestamp=t1,
                    xml=xml_1,
                    dataset_source="evtx-attack-samples-sanitized",
                    mitre_technique_id=tech_id,
                    mitre_technique_name=tech_name,
                    mitre_tactic="persistence",
                    is_malicious=True,
                    expected_signal=False,
                    expected_rule_ids=[],
                    scenario="logon_before_scheduled_task_persistence",
                    scenario_key="persistence",
                ),
                SimulatedRecord(
                    timestamp=t2,
                    xml=xml_2,
                    dataset_source="evtx-attack-samples-sanitized",
                    mitre_technique_id=tech_id,
                    mitre_technique_name=tech_name,
                    mitre_tactic="execution",
                    is_malicious=True,
                    expected_signal=True,
                    expected_rule_ids=["WINDOWS-4624-4688"],
                    scenario="process_creation_for_scheduled_task",
                    scenario_key="persistence",
                ),
                SimulatedRecord(
                    timestamp=t3,
                    xml=xml_3,
                    dataset_source="evtx-attack-samples-sanitized",
                    mitre_technique_id=tech_id,
                    mitre_technique_name=tech_name,
                    mitre_tactic="persistence",
                    is_malicious=True,
                    expected_signal=True,
                    expected_rule_ids=["WINDOWS-4624-4688-4698"],
                    scenario="scheduled_task_persistence_completed",
                    scenario_key="persistence",
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
                data_fields={
                    "ServiceName": "WinDefHealthSvc",
                    "ServiceFileName": "C:\\Users\\Public\\svc_host.exe",
                },
            )
            return [
                SimulatedRecord(
                    timestamp=t1,
                    xml=xml_1,
                    dataset_source="evtx-attack-samples-sanitized",
                    mitre_technique_id=tech_id,
                    mitre_technique_name=tech_name,
                    mitre_tactic="persistence",
                    is_malicious=True,
                    expected_signal=False,
                    expected_rule_ids=[],
                    scenario="logon_before_service_persistence",
                    scenario_key="persistence",
                ),
                SimulatedRecord(
                    timestamp=t2,
                    xml=xml_2,
                    dataset_source="evtx-attack-samples-sanitized",
                    mitre_technique_id=tech_id,
                    mitre_technique_name=tech_name,
                    mitre_tactic="privilege-escalation",
                    is_malicious=True,
                    expected_signal=True,
                    expected_rule_ids=["WINDOWS-4624-4688"],
                    scenario="process_creation_for_service_install",
                    scenario_key="persistence",
                ),
                SimulatedRecord(
                    timestamp=t3,
                    xml=xml_3,
                    dataset_source="evtx-attack-samples-sanitized",
                    mitre_technique_id=tech_id,
                    mitre_technique_name=tech_name,
                    mitre_tactic="persistence",
                    is_malicious=True,
                    expected_signal=True,
                    expected_rule_ids=["WINDOWS-4624-4688-7045"],
                    scenario="service_persistence_completed",
                    scenario_key="persistence",
                ),
            ]

    def generate_privilege_escalation_campaign(
        self,
        campaign_index: int,
        base_time: datetime,
    ) -> list[SimulatedRecord]:
        """
        Scenario 4: Leo thang đặc quyền (Privilege Escalation)
        4720 (Tạo user) -> 4728/4732/4756 (Thêm vào nhóm Admin) -> 4704 (Gán quyền)
        Triggers PRIVILEGE-CHANGE & WINDOWS-4720-4732-4704 (or 4728/4756).
        """
        host = f"DC-PRIV-{campaign_index:04d}"
        # Use 4732 primarily (matching WINDOWS-4720-4732-4704), while also supporting 4728 and 4756
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
                timestamp=t1,
                xml=xml_1,
                dataset_source="otrf-security-datasets-sanitized",
                mitre_technique_id="T1098",
                mitre_technique_name="Account Manipulation",
                mitre_tactic="persistence",
                is_malicious=True,
                expected_signal=False,
                expected_rule_ids=[],
                scenario="account_creation_context_before_group_add",
                scenario_key="privilege_escalation",
            ),
            SimulatedRecord(
                timestamp=t2,
                xml=xml_2,
                dataset_source="otrf-security-datasets-sanitized",
                mitre_technique_id="T1098",
                mitre_technique_name="Account Manipulation",
                mitre_tactic="privilege-escalation",
                is_malicious=True,
                expected_signal=True,
                expected_rule_ids=[f"WINDOWS-4720-{group_event_id}", "PRIVILEGE-CHANGE"],
                scenario=f"group_membership_addition_{group_event_id}_after_user_creation",
                scenario_key="privilege_escalation",
            ),
            SimulatedRecord(
                timestamp=t3,
                xml=xml_3,
                dataset_source="otrf-security-datasets-sanitized",
                mitre_technique_id="T1134",
                mitre_technique_name="Access Token Manipulation",
                mitre_tactic="privilege-escalation",
                is_malicious=True,
                expected_signal=True,
                expected_rule_ids=[
                    f"WINDOWS-4720-{group_event_id}-4704",
                    "PRIVILEGE-CHANGE",
                ],
                scenario="user_right_assignment_escalation",
                scenario_key="privilege_escalation",
            ),
        ]

    def generate_defense_evasion_campaign(
        self,
        campaign_index: int,
        base_time: datetime,
    ) -> list[SimulatedRecord]:
        """
        Scenario 5: Xóa dấu vết (Defense Evasion)
        7045 / 4688 -> 1102 (Xóa Security Log) hoặc 4719 (Sửa Audit Policy)
        Triggers WINDOWS-7045-1102 (or WINDOWS-7045-4719 / WINDOWS-4688-1102).
        """
        host = f"SRV-EVADE-{campaign_index:04d}"
        # Majority use 7045 -> 1102 (matching WINDOWS-7045-1102), plus 7045->4719 and 4688->1102
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
                data_fields={
                    "ServiceName": f"UpdaterSvc{campaign_index}",
                    "ServiceFileName": "C:\\Users\\Public\\UpdaterSvc.exe",
                },
            )
            first_tech = ("T1543.003", "Windows Service", "persistence")
        else:
            first_id = 4688
            xml_1 = build_windows_event_xml(
                provider="Microsoft-Windows-Security-Auditing",
                computer=host,
                event_id=4688,
                timestamp=t1,
                data_fields={
                    "NewProcessName": "C:\\Windows\\System32\\wevtutil.exe",
                    "CommandLine": "wevtutil cl Security",
                },
            )
            first_tech = ("T1070.001", "Clear Windows Event Logs", "stealth")

        if variant in (0, 2):
            second_id = 1102
            xml_2 = build_windows_event_xml(
                provider="Microsoft-Windows-Eventlog",
                computer=host,
                event_id=1102,
                timestamp=t2,
                data_fields={
                    "SubjectUserName": "SYSTEM",
                    "CommandLine": "wevtutil cl Security",
                },
            )
            second_tech = ("T1070.001", "Clear Windows Event Logs", "stealth")
        else:
            second_id = 4719
            xml_2 = build_windows_event_xml(
                provider="Microsoft-Windows-Security-Auditing",
                computer=host,
                event_id=4719,
                timestamp=t2,
                data_fields={
                    "SubjectUserName": "SYSTEM",
                    "CommandLine": "auditpol /clear /y",
                },
            )
            second_tech = ("T1562.002", "Disable Windows Event Logging", "defense-impairment")

        return [
            SimulatedRecord(
                timestamp=t1,
                xml=xml_1,
                dataset_source="evtx-attack-samples-sanitized",
                mitre_technique_id=first_tech[0],
                mitre_technique_name=first_tech[1],
                mitre_tactic=first_tech[2],
                is_malicious=True,
                expected_signal=False,
                expected_rule_ids=[],
                scenario=f"evasion_precursor_{first_id}",
                scenario_key="defense_evasion",
            ),
            SimulatedRecord(
                timestamp=t2,
                xml=xml_2,
                dataset_source="evtx-attack-samples-sanitized",
                mitre_technique_id=second_tech[0],
                mitre_technique_name=second_tech[1],
                mitre_tactic=second_tech[2],
                is_malicious=True,
                expected_signal=True,
                expected_rule_ids=[f"WINDOWS-{first_id}-{second_id}"],
                scenario=f"defense_evasion_{first_id}_{second_id}_triggered",
                scenario_key="defense_evasion",
            ),
        ]

    def generate_c2_beaconing_campaign(
        self,
        campaign_index: int,
        base_time: datetime,
        interval_seconds: int = 30,
    ) -> list[SimulatedRecord]:
        """
        Scenario 6: C2 Beaconing (Kết nối điều khiển định kỳ)
        >= 5 events of 5156 outbound (Direction=%%14592) to the same Public IP
        with regular interval (e.g. 30s, jitter <= 20%) -> C2-BEACONING.
        """
        records: list[SimulatedRecord] = []
        host = f"WS-C2-{campaign_index:04d}"
        c2_ip = PUBLIC_C2_IPS[campaign_index % len(PUBLIC_C2_IPS)]
        port = str((443, 8443, 8080, 4444, 9001)[campaign_index % 5])
        app = f"\\device\\harddiskvolume2\\programdata\\agent_{campaign_index:04d}.exe"

        for i in range(5):
            # Optional tiny jitter (+-1s on 30s interval = 3.3% << 20% limit)
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
                    timestamp=ts,
                    xml=xml,
                    dataset_source="splunk-attack-data-sanitized",
                    mitre_technique_id="T1071.001",
                    mitre_technique_name="Web Protocols",
                    mitre_tactic="command-and-control",
                    is_malicious=True,
                    expected_signal=triggers,
                    expected_rule_ids=["C2-BEACONING"] if triggers else [],
                    scenario=(
                        f"c2_beacon_interval_{i + 1}_triggers_signal"
                        if triggers
                        else f"c2_beacon_interval_{i + 1}"
                    ),
                    scenario_key="c2_beaconing",
                )
            )
        return records

    def generate_benign_events(
        self,
        count: int,
        start_time: datetime,
        span_seconds: int,
    ) -> list[SimulatedRecord]:
        """
        Generate normal (benign) Windows XML logs that do NOT trigger false alarms:
        - Normal user workstation logons (4624 on benign workstation hosts)
        - Internal network connections (5156 to RFC1918 10.x / 192.168.x)
        - Inbound network connections (5156 with Direction=%%14593)
        - Single isolated password typo (4625 from unique workstation IP, count=1 < 5)
        - Normal non-obfuscated process creation (4688 on process-only benign hosts)
        """
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
                # Benign workstation logon (4624)
                host = f"WS-BENIGN-LOGON-{seq_idx % 40:02d}"
                user = benign_users[seq_idx % len(benign_users)]
                ip = f"10.55.{(seq_idx // 250) % 250}.{(seq_idx % 250) + 1}"
                xml = build_windows_event_xml(
                    provider="Microsoft-Windows-Security-Auditing",
                    computer=host,
                    event_id=4624,
                    timestamp=ts,
                    data_fields={"TargetUserName": user, "IpAddress": ip},
                )
                scenario = "benign_workstation_logon"
            elif kind == 1:
                # Benign internal network connection (5156 to private IP)
                host = f"WS-BENIGN-NET-{seq_idx % 40:02d}"
                xml = build_windows_event_xml(
                    provider="Microsoft-Windows-Security-Auditing",
                    computer=host,
                    event_id=5156,
                    timestamp=ts,
                    data_fields={
                        "Application": "C:\\Windows\\System32\\svchost.exe",
                        "Direction": "%%14592",
                        "DestAddress": f"10.88.{(seq_idx // 250) % 250}.{(seq_idx % 250) + 1}",
                        "DestPort": "443",
                        "Protocol": "6",
                    },
                )
                scenario = "benign_internal_private_network_connection"
            elif kind == 2:
                # Benign single password typo (1 event per unique IP -> never reaches 5)
                host = f"WS-BENIGN-AUTH-{seq_idx % 40:02d}"
                user = benign_users[seq_idx % len(benign_users)]
                b2 = (seq_idx // 65025) % 7
                b3 = (seq_idx // 255) % 250 + 1
                b4 = (seq_idx % 254) + 1
                typo_ip = f"172.{24 + b2}.{b3}.{b4}"
                xml = build_windows_event_xml(
                    provider="Microsoft-Windows-Security-Auditing",
                    computer=host,
                    event_id=4625,
                    timestamp=ts,
                    data_fields={"TargetUserName": user, "IpAddress": typo_ip},
                )
                scenario = "benign_single_password_typo"
            elif kind == 3:
                # Benign process creation (4688 on host that only logs 4688 -> single distinct event ID)
                host = f"WS-BENIGN-PROC-{seq_idx % 40:02d}"
                proc_name, cmd_line = benign_procs[seq_idx % len(benign_procs)]
                xml = build_windows_event_xml(
                    provider="Microsoft-Windows-Security-Auditing",
                    computer=host,
                    event_id=4688,
                    timestamp=ts,
                    data_fields={
                        "NewProcessName": proc_name,
                        "CreatorProcessName": "C:\\Windows\\explorer.exe",
                        "CommandLine": cmd_line,
                    },
                )
                scenario = "benign_standard_process_creation"
            else:
                # Benign inbound network connection (Direction=%%14593)
                host = f"SRV-BENIGN-WEB-{seq_idx % 20:02d}"
                xml = build_windows_event_xml(
                    provider="Microsoft-Windows-Security-Auditing",
                    computer=host,
                    event_id=5156,
                    timestamp=ts,
                    data_fields={
                        "Application": "C:\\Windows\\System32\\inetsrv\\w3wp.exe",
                        "Direction": "%%14593",
                        "DestAddress": "45.33.32.156",
                        "DestPort": "443",
                        "Protocol": "6",
                    },
                )
                scenario = "benign_inbound_web_connection"

            records.append(
                SimulatedRecord(
                    timestamp=ts,
                    xml=xml,
                    dataset_source="otrf-security-datasets-sanitized",
                    mitre_technique_id=None,
                    mitre_technique_name=None,
                    mitre_tactic=None,
                    is_malicious=False,
                    expected_signal=False,
                    expected_rule_ids=[],
                    scenario=scenario,
                    scenario_key="benign",
                )
            )
        return records

    def generate_ambiguous_admin_noise(
        self,
        count: int,
        start_time: datetime,
        span_seconds: int,
        *,
        unfiltered_fp: bool = False,
    ) -> list[SimulatedRecord]:
        """
        False-Positive Resilience Test (Nhiễu Admin hợp lệ):
        By default (`unfiltered_fp=False`), generates realistic sysadmin edge-case activity
        that resembles sensitive operations (admin LOLBin CLI diagnostics, special logon 4672,
        standalone user provisioning 4720 without group escalation, irregular outbound HTTPS 5156,
        or single admin password mistype 4771) that GlobalBan's false-positive filters must
        accurately ignore (expected_signal=False -> True Negative).
        If `unfiltered_fp=True`, generates raw 4732 group-addition events labeled as
        expected_signal=False to intentionally force False Positives in negative unit tests.
        """
        records: list[SimulatedRecord] = []
        admin_cli_commands = (
            ("C:\\Windows\\System32\\whoami.exe", "whoami.exe /groups"),
            ("C:\\Windows\\System32\\ipconfig.exe", "ipconfig.exe /all"),
            ("C:\\Windows\\System32\\certutil.exe", "certutil.exe -store my"),
            ("C:\\Windows\\System32\\bitsadmin.exe", "bitsadmin.exe /list /allusers"),
            ("C:\\Windows\\System32\\wbem\\WMIC.exe", "wmic.exe logicaldisk get name,freespace,size"),
            ("C:\\Windows\\System32\\gpresult.exe", "gpresult.exe /scope computer /r"),
            (
                "C:\\Windows\\System32\\schtasks.exe",
                'schtasks.exe /query /tn "microsoft\\windows\\defrag\\scheduleddefrag"',
            ),
            (
                "C:\\Windows\\System32\\reg.exe",
                "reg.exe query hkcu\\software\\microsoft\\windows\\currentversion\\explorer",
            ),
        )

        for i in range(count):
            offset = int((i / max(1, count)) * max(60, span_seconds))
            ts = start_time + timedelta(seconds=offset)
            host = f"SRV-ADMIN-NOISE-{i:04d}"

            if unfiltered_fp:
                xml = build_windows_event_xml(
                    provider="Microsoft-Windows-Security-Auditing",
                    computer=host,
                    event_id=4732,
                    timestamp=ts,
                    data_fields={
                        "TargetUserName": "Backup Operators",
                        "SubjectUserName": "it_helpdesk_authorized",
                    },
                )
                scenario = "benign_authorized_admin_group_change_fp_test"
            else:
                noise_kind = i % 5
                seq_idx = i // 5
                if noise_kind == 0:
                    # Legitimate sysadmin CLI / LOLBin diagnostic command (filtered by parser allowlist)
                    proc_name, cmd_line = admin_cli_commands[seq_idx % len(admin_cli_commands)]
                    xml = build_windows_event_xml(
                        provider="Microsoft-Windows-Security-Auditing",
                        computer=host,
                        event_id=4688,
                        timestamp=ts,
                        data_fields={
                            "NewProcessName": proc_name,
                            "CreatorProcessName": "C:\\Windows\\System32\\cmd.exe",
                            "CommandLine": cmd_line,
                        },
                    )
                    scenario = "benign_admin_diagnostic_cli_4688"
                elif noise_kind == 1:
                    # Admin special logon 4672 without suspicious persistence/privilege sequence
                    xml = build_windows_event_xml(
                        provider="Microsoft-Windows-Security-Auditing",
                        computer=host,
                        event_id=4672,
                        timestamp=ts,
                        data_fields={
                            "SubjectUserName": "sysadmin_oncall",
                            "TargetUserName": "sysadmin_oncall",
                        },
                    )
                    scenario = "benign_admin_special_logon_4672"
                elif noise_kind == 2:
                    # IT Helpdesk standalone user provisioning (4720) without group/privilege escalation
                    xml = build_windows_event_xml(
                        provider="Microsoft-Windows-Security-Auditing",
                        computer=host,
                        event_id=4720,
                        timestamp=ts,
                        data_fields={
                            "TargetUserName": f"new_hire_{seq_idx:04d}",
                            "SubjectUserName": "hr_provisioning_svc",
                        },
                    )
                    scenario = "benign_admin_standalone_user_creation_4720"
                elif noise_kind == 3:
                    # Admin single outbound HTTPS check to public endpoint (count=1 < 5 C2 minimum)
                    xml = build_windows_event_xml(
                        provider="Microsoft-Windows-Security-Auditing",
                        computer=host,
                        event_id=5156,
                        timestamp=ts,
                        data_fields={
                            "Application": "C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe",
                            "Direction": "%%14592",
                            "DestAddress": "13.107.42.14",
                            "DestPort": "443",
                            "Protocol": "6",
                        },
                    )
                    scenario = "benign_admin_single_outbound_https_5156"
                else:
                    # Admin single Kerberos pre-auth typo (4771 from unique admin IP, count=1 < 5)
                    b3 = (seq_idx // 254) % 255
                    b4 = (seq_idx % 254) + 1
                    admin_ip = f"10.250.{b3}.{b4}"
                    xml = build_windows_event_xml(
                        provider="Microsoft-Windows-Security-Auditing",
                        computer=host,
                        event_id=4771,
                        timestamp=ts,
                        data_fields={
                            "TargetUserName": "sysadmin_oncall",
                            "ClientAddress": admin_ip,
                        },
                    )
                    scenario = "benign_admin_isolated_kerberos_typo_4771"

            records.append(
                SimulatedRecord(
                    timestamp=ts,
                    xml=xml,
                    dataset_source="otrf-security-datasets-sanitized",
                    mitre_technique_id=None,
                    mitre_technique_name=None,
                    mitre_tactic=None,
                    is_malicious=False,
                    expected_signal=False,
                    expected_rule_ids=[],
                    scenario=scenario,
                    scenario_key="benign_noise",
                )
            )
        return records

    def generate_dataset(
        self,
        *,
        selected_scenarios: list[str] | tuple[str, ...] | None = None,
        campaigns_per_scenario: int = 15,
        benign_count: int = 500,
        fp_noise_count: int = 0,
        unfiltered_fp: bool = False,
        start_time: datetime | None = None,
    ) -> list[SimulatedRecord]:
        """
        Generate a mixed dataset of attack campaigns and benign Windows Event XML logs,
        sorted chronologically and assigned sequential event_ids.
        """
        if selected_scenarios is None:
            selected_scenarios = [s.key for s in SCENARIO_CATALOG]
        base = start_time or datetime(2026, 1, 15, 8, 0, 0, tzinfo=timezone.utc)

        all_records: list[SimulatedRecord] = []
        cursor = base

        for c_idx in range(campaigns_per_scenario):
            for key in selected_scenarios:
                if key == "brute_force":
                    all_records.extend(self.generate_brute_force_campaign(c_idx, cursor))
                    cursor += timedelta(seconds=25)
                elif key == "obfuscation":
                    all_records.extend(self.generate_obfuscation_campaign(c_idx, cursor))
                    cursor += timedelta(seconds=10)
                elif key == "persistence":
                    all_records.extend(self.generate_persistence_campaign(c_idx, cursor))
                    cursor += timedelta(seconds=15)
                elif key == "privilege_escalation":
                    all_records.extend(self.generate_privilege_escalation_campaign(c_idx, cursor))
                    cursor += timedelta(seconds=15)
                elif key == "defense_evasion":
                    all_records.extend(self.generate_defense_evasion_campaign(c_idx, cursor))
                    cursor += timedelta(seconds=12)
                elif key == "c2_beaconing":
                    all_records.extend(self.generate_c2_beaconing_campaign(c_idx, cursor))
                    cursor += timedelta(seconds=130)

        total_span = max(300, int((cursor - base).total_seconds()))
        if benign_count > 0:
            all_records.extend(self.generate_benign_events(benign_count, base, total_span))
        if fp_noise_count > 0:
            all_records.extend(
                self.generate_ambiguous_admin_noise(
                    fp_noise_count,
                    base,
                    total_span,
                    unfiltered_fp=unfiltered_fp,
                )
            )

        # Sort chronologically so sliding windows in GlobalBan operate realistically
        all_records.sort(key=lambda r: r.timestamp)
        for idx, rec in enumerate(all_records, start=1):
            rec.event_id = f"win-sim-{idx:05d}"

        return all_records


def export_dataset_files(
    records: list[SimulatedRecord],
    jsonl_path: str | Path,
    xml_path: str | Path | None = None,
) -> tuple[Path, Path | None]:
    """Write records to a GlobalBan-compatible .jsonl file and optionally an <Events> .xml file."""
    j_path = Path(jsonl_path)
    j_path.parent.mkdir(parents=True, exist_ok=True)
    with j_path.open("w", encoding="utf-8", newline="\n") as f:
        for rec in records:
            f.write(json.dumps(rec.to_jsonl_dict(), ensure_ascii=False) + "\n")

    x_path: Path | None = None
    if xml_path is not None:
        x_path = Path(xml_path)
        x_path.parent.mkdir(parents=True, exist_ok=True)
        with x_path.open("w", encoding="utf-8", newline="\n") as f:
            f.write('<?xml version="1.0" encoding="utf-8"?>\n<Events>\n')
            for rec in records:
                f.write(f"  {rec.xml}\n")
            f.write("</Events>\n")

    return j_path, x_path

