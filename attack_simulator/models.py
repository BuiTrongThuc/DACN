"""
attack_simulator.models
=======================
Data models, MITRE ATT&CK catalogs, scenario definitions, and record schemas.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass(frozen=True, slots=True)
class ScenarioSpec:
    key: str
    code: int
    title: str
    short_name: str
    event_chain_desc: str
    expected_rules_desc: str
    mitre_ids: tuple[str, ...]
    accent_color: str


SCENARIO_CATALOG: tuple[ScenarioSpec, ...] = (
    ScenarioSpec(
        key="brute_force",
        code=1,
        title="1. Brute Force / Password Spraying",
        short_name="Brute Force & Spraying",
        event_chain_desc=">=5 sự kiện 4625, 4771 hoặc 4776 từ cùng 1 IP trong 300s",
        expected_rules_desc="AUTH-FAILURE-BURST (Level 1 / Level 2)",
        mitre_ids=("T1110.003", "T1110.001", "T1110"),
        accent_color="#F43F5E",
    ),
    ScenarioSpec(
        key="obfuscation",
        code=2,
        title="2. Lệnh mã hóa / Làm rối (Obfuscation)",
        short_name="PowerShell Obfuscation",
        event_chain_desc="4688 (và 4104) có CommandLine chứa -EncodedCommand, -enc, FromBase64String, IEX",
        expected_rules_desc="OBFUSCATED-COMMAND-LINE / WINDOWS-4688-4104",
        mitre_ids=("T1059.001", "T1027.010"),
        accent_color="#FB923C",
    ),
    ScenarioSpec(
        key="persistence",
        code=3,
        title="3. Xâm nhập & Cắm chốt (Persistence)",
        short_name="Task & Service Persistence",
        event_chain_desc="Cùng Computer: 4624 (Logon) -> 4688 (Process) -> 4698 (Task) hoặc 7045 (Service)",
        expected_rules_desc="WINDOWS-4624-4688-4698 / WINDOWS-4624-4688-7045",
        mitre_ids=("T1053.005", "T1543.003"),
        accent_color="#EAB308",
    ),
    ScenarioSpec(
        key="privilege_escalation",
        code=4,
        title="4. Leo thang đặc quyền (Privilege Escalation)",
        short_name="Privilege Escalation",
        event_chain_desc="4720 (Tạo user) -> 4728/4732/4756 (Thêm nhóm Admin) -> 4704 (Gán quyền)",
        expected_rules_desc="PRIVILEGE-CHANGE & WINDOWS-4720-4732-4704",
        mitre_ids=("T1098", "T1134"),
        accent_color="#EC4899",
    ),
    ScenarioSpec(
        key="defense_evasion",
        code=5,
        title="5. Xóa dấu vết (Defense Evasion)",
        short_name="Log Clearing & Tampering",
        event_chain_desc="7045 / 4688 -> 1102 (Xóa Security Log) hoặc 4719 (Sửa Audit Policy)",
        expected_rules_desc="WINDOWS-7045-1102 / WINDOWS-4688-1102",
        mitre_ids=("T1070.001", "T1562.002", "T1543.003"),
        accent_color="#A855F7",
    ),
    ScenarioSpec(
        key="c2_beaconing",
        code=6,
        title="6. C2 Beaconing (Kết nối điều khiển định kỳ)",
        short_name="C2 Periodic Beaconing",
        event_chain_desc=">=5 sự kiện 5156 chiều ra (Direction=%%14592) tới cùng 1 IP Public cách đều (30s)",
        expected_rules_desc="C2-BEACONING",
        mitre_ids=("T1071.001",),
        accent_color="#06B6D4",
    ),
)

SCENARIO_BY_KEY: dict[str, ScenarioSpec] = {s.key: s for s in SCENARIO_CATALOG}
SCENARIO_BY_CODE: dict[int, ScenarioSpec] = {s.code: s for s in SCENARIO_CATALOG}

MITRE_METADATA: dict[str, tuple[str, str]] = {
    "T1110": ("Brute Force", "credential-access"),
    "T1110.001": ("Password Guessing", "credential-access"),
    "T1110.003": ("Password Spraying", "credential-access"),
    "T1059.001": ("PowerShell", "execution"),
    "T1027.010": ("Command Obfuscation", "defense-evasion"),
    "T1053.005": ("Scheduled Task", "persistence"),
    "T1543.003": ("Windows Service", "persistence"),
    "T1098": ("Account Manipulation", "privilege-escalation"),
    "T1134": ("Access Token Manipulation", "privilege-escalation"),
    "T1070.001": ("Clear Windows Event Logs", "defense-evasion"),
    "T1562.002": ("Disable Windows Event Logging", "defense-evasion"),
    "T1071.001": ("Web Protocols", "command-and-control"),
    "T1078": ("Valid Accounts", "initial-access"),
    "T1033": ("System Owner/User Discovery", "discovery"),
    "T1105": ("Ingress Tool Transfer", "command-and-control"),
    "T1218": ("System Binary Proxy Execution", "defense-evasion"),
    "T1218.005": ("Mshta", "defense-evasion"),
    "T1218.010": ("Regsvr32", "defense-evasion"),
    "T1218.011": ("Rundll32", "defense-evasion"),
}

PUBLIC_C2_IPS: tuple[str, ...] = (
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
