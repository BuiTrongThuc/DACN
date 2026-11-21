"""
attack_simulator.engine
=======================
Self-contained, faithful GlobalBan Detection & UEBA Behavior Engine:
  - EventAggregator: AUTH-FAILURE-BURST (Level 1 & Level 2)
  - WindowsBehaviorDetectors: OBFUSCATED-COMMAND-LINE, PRIVILEGE-CHANGE, C2-BEACONING
  - WindowsSequenceDetector: Multi-stage attack correlation chains
  - BuiltinUEBAEngine: 7-day BehavioralProfileStore & ProfileAnomalyDetector
Ensures 100% functionality with zero external dependencies, never crashing on missing paths.
"""

from __future__ import annotations

import ipaddress
import re
import statistics
from collections import defaultdict
from datetime import datetime
from typing import Any

from attack_simulator.core.xml_utils import ParsedWinEvent


class BuiltinGlobalBanEngine:
    """
    Faithful standalone implementation of GlobalBan's core detectors:
      - EventAggregator (AUTH-FAILURE-BURST Level 1 & Level 2)
      - WindowsSequenceDetector (4624->4688->4698/7045, 4720->4728/4732/4756->4704, 7045/4688->1102/4719, 4688->4104)
      - WindowsBehaviorDetectors (OBFUSCATED-COMMAND-LINE, PRIVILEGE-CHANGE, C2-BEACONING)
      - BehavioralProfileStore & ProfileAnomalyDetector (UEBA-BEHAVIOR-DEVIATION)
    Ensures 100% functionality even when external GlobalBan repo is on another VM.
    """

    OBF_PATTERNS = re.compile(
        r"(-encodedcommand|\s-enc\b|frombase64string|\biex\b|invoke-expression)",
        re.IGNORECASE,
    )

    def __init__(self, window_seconds: int = 300) -> None:
        self.window_seconds = window_seconds
        self.auth_failures: dict[str, list[tuple[datetime, str]]] = defaultdict(list)
        self.auth_level2_alerted: dict[str, datetime] = {}
        self.host_history: dict[str, list[ParsedWinEvent]] = defaultdict(list)
        self.outbound_flows: dict[tuple[str, str], list[datetime]] = defaultdict(list)

    def process_event(self, ev: ParsedWinEvent) -> list[dict[str, str]]:
        signals: list[dict[str, str]] = []
        now = ev.timestamp

        # 1. EventAggregator: AUTH-FAILURE-BURST (4625, 4771, 4776)
        if ev.event_id in (4625, 4771, 4776) and ev.source_ip:
            ip = ev.source_ip
            user = (ev.data.get("TargetUserName") or "unknown").lower()
            hist = [
                (t, u)
                for (t, u) in self.auth_failures[ip]
                if (now - t).total_seconds() <= self.window_seconds
            ]
            hist.append((now, user))
            self.auth_failures[ip] = hist
            distinct_users = {u for _, u in hist}
            if len(hist) >= 5:
                level = 2 if (len(distinct_users) >= 2 or len(hist) >= 10) else 1
                last_l2 = self.auth_level2_alerted.get(ip)
                if level == 2 and last_l2 and (now - last_l2).total_seconds() <= self.window_seconds:
                    pass
                else:
                    if level == 2:
                        self.auth_level2_alerted[ip] = now
                    signals.append(
                        {
                            "detector": "EventAggregator",
                            "rule_id": "AUTH-FAILURE-BURST",
                            "display_rule": f"AUTH-FAILURE-BURST (Level {level})",
                            "level": str(level),
                            "target": ip,
                            "explanation": (
                                f"Phát hiện {len(hist)} lần đăng nhập thất bại (Event {ev.event_id}) "
                                f"từ IP {ip} trên {len(distinct_users)} tài khoản trong {self.window_seconds}s."
                            ),
                        }
                    )

        # 2. WindowsBehaviorDetectors: OBFUSCATED-COMMAND-LINE
        if ev.event_id == 4688:
            cmd = ev.data.get("CommandLine", "")
            if cmd and self.OBF_PATTERNS.search(cmd):
                signals.append(
                    {
                        "detector": "WindowsBehaviorDetectors",
                        "rule_id": "OBFUSCATED-COMMAND-LINE",
                        "display_rule": "OBFUSCATED-COMMAND-LINE",
                        "level": "2",
                        "target": ev.computer,
                        "explanation": f"Lệnh PowerShell làm rối/mã hóa Base64 trên {ev.computer}: {cmd[:90]}...",
                    }
                )

        # 3. WindowsBehaviorDetectors: C2-BEACONING (5156 outbound public IP)
        if ev.event_id == 5156 and ev.data.get("Direction") == "%%14592":
            dest_ip = ev.data.get("DestAddress", "")
            try:
                ip_obj = ipaddress.ip_address(dest_ip)
                is_public = ip_obj.is_global
            except ValueError:
                is_public = False

            if is_public:
                key = (ev.computer, dest_ip)
                flows = [
                    t
                    for t in self.outbound_flows[key]
                    if (now - t).total_seconds() <= 600
                ]
                flows.append(now)
                self.outbound_flows[key] = flows
                if len(flows) >= 5:
                    intervals = [
                        (flows[i] - flows[i - 1]).total_seconds()
                        for i in range(1, len(flows))
                    ]
                    mean_iv = statistics.mean(intervals)
                    std_iv = statistics.pstdev(intervals) if len(intervals) > 1 else 0.0
                    jitter_ratio = (std_iv / mean_iv) if mean_iv > 0 else 1.0
                    if mean_iv >= 10 and jitter_ratio <= 0.25:
                        signals.append(
                            {
                                "detector": "WindowsBehaviorDetectors",
                                "rule_id": "C2-BEACONING",
                                "display_rule": "C2-BEACONING",
                                "level": "2",
                                "target": f"{ev.computer} -> {dest_ip}",
                                "explanation": (
                                    f"Kết nối C2 định kỳ {len(flows)} nhịp tới {dest_ip} "
                                    f"(chu kỳ TB {mean_iv:.1f}s, jitter {jitter_ratio*100:.1f}%)."
                                ),
                            }
                        )

        # 4. WindowsSequenceDetector & PRIVILEGE-CHANGE
        h_events = [
            e
            for e in self.host_history[ev.computer]
            if (now - e.timestamp).total_seconds() <= self.window_seconds
        ]
        prior_ids = {e.event_id for e in h_events}

        # Obfuscation correlation: 4688 -> 4104
        if ev.event_id == 4104 and 4688 in prior_ids:
            cmd = ev.data.get("CommandLine", "") or ev.data.get("ScriptBlockText", "")
            if self.OBF_PATTERNS.search(cmd):
                signals.append(
                    {
                        "detector": "WindowsSequenceDetector",
                        "rule_id": "WINDOWS-4688-4104",
                        "display_rule": "WINDOWS-4688-4104",
                        "level": "2",
                        "target": ev.computer,
                        "explanation": f"Tương quan tiến trình 4688 và ScriptBlock 4104 làm rối trên {ev.computer}.",
                    }
                )

        # Persistence correlation: 4624 -> 4688 -> 4698 / 7045
        if ev.event_id == 4688 and 4624 in prior_ids:
            cmd_lower = ev.data.get("CommandLine", "").lower()
            if "schtasks" in cmd_lower or "sc.exe" in cmd_lower or "sc " in cmd_lower:
                signals.append(
                    {
                        "detector": "WindowsSequenceDetector",
                        "rule_id": "WINDOWS-4624-4688",
                        "display_rule": "WINDOWS-4624-4688",
                        "level": "1",
                        "target": ev.computer,
                        "explanation": f"Đăng nhập từ xa (4624) sau đó khởi chạy công cụ hệ thống (4688) trên {ev.computer}.",
                    }
                )

        if ev.event_id in (4698, 7045) and 4624 in prior_ids and 4688 in prior_ids:
            rule = f"WINDOWS-4624-4688-{ev.event_id}"
            signals.append(
                {
                    "detector": "WindowsSequenceDetector",
                    "rule_id": rule,
                    "display_rule": rule,
                    "level": "2",
                    "target": ev.computer,
                    "explanation": f"Chuỗi xâm nhập & cắm chốt hoàn chỉnh (4624 -> 4688 -> {ev.event_id}) trên {ev.computer}.",
                }
            )

        # Privilege Escalation: 4720 -> 4728/4732/4756 -> 4704
        if ev.event_id in (4728, 4732, 4756) and 4720 in prior_ids:
            signals.append(
                {
                    "detector": "WindowsBehaviorDetectors",
                    "rule_id": "PRIVILEGE-CHANGE",
                    "display_rule": "PRIVILEGE-CHANGE",
                    "level": "2",
                    "target": ev.computer,
                    "explanation": f"Thêm tài khoản mới tạo vào nhóm quản trị (Event {ev.event_id}) trên {ev.computer}.",
                }
            )
            signals.append(
                {
                    "detector": "WindowsSequenceDetector",
                    "rule_id": f"WINDOWS-4720-{ev.event_id}",
                    "display_rule": f"WINDOWS-4720-{ev.event_id}",
                    "level": "2",
                    "target": ev.computer,
                    "explanation": f"Chuỗi leo thang đặc quyền 4720 -> {ev.event_id} trên {ev.computer}.",
                }
            )

        if ev.event_id == 4704 and 4720 in prior_ids:
            grp_id = next((gid for gid in (4732, 4728, 4756) if gid in prior_ids), None)
            if grp_id is not None:
                signals.append(
                    {
                        "detector": "WindowsBehaviorDetectors",
                        "rule_id": "PRIVILEGE-CHANGE",
                        "display_rule": "PRIVILEGE-CHANGE",
                        "level": "2",
                        "target": ev.computer,
                        "explanation": f"Gán quyền đặc biệt hệ thống (Event 4704) cho tài khoản mới trên {ev.computer}.",
                    }
                )
                signals.append(
                    {
                        "detector": "WindowsSequenceDetector",
                        "rule_id": f"WINDOWS-4720-{grp_id}-4704",
                        "display_rule": f"WINDOWS-4720-{grp_id}-4704",
                        "level": "2",
                        "target": ev.computer,
                        "explanation": f"Chuỗi leo thang hoàn chỉnh 4720 -> {grp_id} -> 4704 trên {ev.computer}.",
                    }
                )

        # Defense Evasion: 7045 / 4688 -> 1102 / 4719
        if ev.event_id in (1102, 4719):
            first_id = 7045 if 7045 in prior_ids else (4688 if 4688 in prior_ids else None)
            if first_id is not None:
                rule = f"WINDOWS-{first_id}-{ev.event_id}"
                signals.append(
                    {
                        "detector": "WindowsSequenceDetector",
                        "rule_id": rule,
                        "display_rule": rule,
                        "level": "2",
                        "target": ev.computer,
                        "explanation": f"Chuỗi xóa dấu vết / tắt giám sát ({first_id} -> {ev.event_id}) trên {ev.computer}.",
                    }
                )

        h_events.append(ev)
        self.host_history[ev.computer] = h_events
        return signals


class BuiltinUEBAEngine:
    """Standalone 7-Day BehavioralProfileStore & ProfileAnomalyDetector."""

    def __init__(self) -> None:
        self.user_profiles: dict[str, dict[str, Any]] = {}
        self.machine_profiles: dict[str, dict[str, Any]] = {}
        self.baseline_event_count = 0

    def _ensure_user(self, user: str) -> dict[str, Any]:
        if user not in self.user_profiles:
            self.user_profiles[user] = {
                "hours": set(),
                "machines": set(),
                "processes": set(),
                "ps_commands": set(),
                "destinations": set(),
                "event_count": 0,
            }
        return self.user_profiles[user]

    def _ensure_machine(self, host: str) -> dict[str, Any]:
        if host not in self.machine_profiles:
            self.machine_profiles[host] = {
                "hours": set(),
                "users": set(),
                "processes": set(),
                "destinations": set(),
                "event_count": 0,
            }
        return self.machine_profiles[host]

    def learn_events(self, events: list[ParsedWinEvent]) -> None:
        for ev in events:
            self.baseline_event_count += 1
            hour = ev.timestamp.hour
            host = ev.computer.upper()
            user = ev.username

            m_prof = self._ensure_machine(host)
            m_prof["hours"].add(hour)
            m_prof["event_count"] += 1
            if user:
                m_prof["users"].add(user)
                u_prof = self._ensure_user(user)
                u_prof["hours"].add(hour)
                u_prof["machines"].add(host)
                u_prof["event_count"] += 1

            proc = ev.data.get("NewProcessName") or ev.data.get("Image")
            if proc:
                proc_name = proc.split("\\")[-1].lower()
                m_prof["processes"].add(proc_name)
                if user:
                    self._ensure_user(user)["processes"].add(proc_name)

            ps_text = ev.data.get("ScriptBlockText") or ev.data.get("CommandLine")
            if ps_text and user and ev.event_id in (4104, 4688):
                self._ensure_user(user)["ps_commands"].add(ps_text.strip().lower())

            dest_ip = ev.data.get("DestAddress") or ev.data.get("DestinationIp")
            dest_port = ev.data.get("DestPort") or ev.data.get("DestinationPort")
            if dest_ip and dest_port:
                endpoint = f"{dest_ip}:{dest_port}"
                m_prof["destinations"].add(endpoint)
                if user:
                    self._ensure_user(user)["destinations"].add(endpoint)

    def to_serializable(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "baseline_event_count": self.baseline_event_count,
            "users": {
                u: {
                    "hours": sorted(p["hours"]),
                    "machines": sorted(p["machines"]),
                    "processes": sorted(p["processes"]),
                    "ps_commands": sorted(p["ps_commands"]),
                    "destinations": sorted(p["destinations"]),
                    "event_count": p["event_count"],
                }
                for u, p in sorted(self.user_profiles.items())
            },
            "machines": {
                m: {
                    "hours": sorted(p["hours"]),
                    "users": sorted(p["users"]),
                    "processes": sorted(p["processes"]),
                    "destinations": sorted(p["destinations"]),
                    "event_count": p["event_count"],
                }
                for m, p in sorted(self.machine_profiles.items())
            },
        }

    def evaluate_event(self, ev: ParsedWinEvent) -> list[str]:
        tags: list[str] = []
        hour = ev.timestamp.hour
        host = ev.computer.upper()
        user = ev.username
        u_prof = self.user_profiles.get(user) if user else None
        m_prof = self.machine_profiles.get(host)

        if ev.event_id == 4624:
            if u_prof and hour not in u_prof["hours"]:
                tags.append("unusual_login_hour")
            if m_prof and hour not in m_prof["hours"]:
                tags.append("unusual_machine_activity_hour")
            if u_prof and host not in u_prof["machines"]:
                tags.append("unusual_machine_for_user")
            if m_prof and user and user not in m_prof["users"]:
                tags.append("unusual_user_for_machine")

        proc = ev.data.get("NewProcessName") or ev.data.get("Image")
        if proc and ev.event_id in (4688, 1):
            proc_name = proc.split("\\")[-1].lower()
            if u_prof and hour not in u_prof["hours"]:
                tags.append("unusual_user_activity_hour")
            if u_prof and proc_name not in u_prof["processes"]:
                tags.append("unusual_process_for_user")
            if m_prof and proc_name not in m_prof["processes"]:
                tags.append("unusual_process_for_machine")

        ps_text = ev.data.get("ScriptBlockText") or ev.data.get("CommandLine")
        if ps_text and (ev.event_id == 4104 or "powershell" in (proc or "").lower()):
            lower_ps = ps_text.strip().lower()
            if u_prof and lower_ps not in u_prof["ps_commands"]:
                if not any((known in lower_ps or lower_ps in known) for known in u_prof["ps_commands"] if known):
                    tags.append("unusual_powershell_command")
            if any(k in lower_ps for k in ("invoke-webrequest", "downloadstring", "curl ", "wget ", "bitsadmin")):
                tags.append("download_or_transfer_marker")
            if any(k in lower_ps for k in ("-encodedcommand", " -enc ", "frombase64string", "iex")):
                tags.append("encoded_or_obfuscated_script_marker")

        dest_ip = ev.data.get("DestAddress") or ev.data.get("DestinationIp")
        dest_port = ev.data.get("DestPort") or ev.data.get("DestinationPort")
        if dest_ip and dest_port and ev.event_id in (5156, 3):
            endpoint = f"{dest_ip}:{dest_port}"
            if m_prof and endpoint not in m_prof["destinations"]:
                tags.append("unusual_network_connection")

        return list(dict.fromkeys(tags))
