"""
globalban.detector.ueba_scorer
==============================
Anomaly Scoring Engine (Bộ tính điểm lệch chuẩn hành vi UEBA).

Tính điểm lệch chuẩn hành vi (Behavioral Deviation Score: 0–100) cho từng sự kiện và chuỗi sự kiện
trong cửa sổ thời gian (5 phút) dựa trên độ hiếm (Rarity / Surprise Score) so với hồ sơ thói quen
của đúng cặp (Host, User) đó.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Iterable

from globalban.baseline.entity_profiler import EntityProfile, EntityProfiler


RECON_COMMANDS = {
    "whoami", "systeminfo", "hostname", "net", "net1", "ipconfig",
    "arp", "netstat", "query", "tasklist", "route", "nltest",
}

OBFUSCATION_INDICATORS = [
    "-encodedcommand", "-enc ", "-e ", "frombase64string",
    "invoke-expression", "iex", "downloadstring", "iwr ", "bypass",
]


@dataclass
class UEBAAnomalyResult:
    """Kết quả chấm điểm lệch chuẩn hành vi cho một chuỗi sự kiện của (Host, User)."""
    score: int  # 0 to 100
    is_anomaly: bool  # True nếu score >= threshold (mặc định 60)
    host: str
    username: str
    event_count: int
    deviation_factors: list[str] = field(default_factory=list)
    primary_technique: str | None = None
    window_start: datetime | None = None
    window_end: datetime | None = None
    trigger_commands: list[str] = field(default_factory=list)
    mitre_tactic: str = "defense-evasion"

    def summary(self) -> str:
        status = "ANOMALY DETECTED" if self.is_anomaly else "NORMAL"
        return f"[{status}] Score={self.score}/100 on ({self.host}, {self.username}) | Tech={self.primary_technique or 'None'} | Reasons={'; '.join(self.deviation_factors[:2])}"


class UEBAScorer:
    """Bộ chấm điểm hành vi lệch chuẩn theo ngữ cảnh (Contextual UEBA Scorer)."""

    def __init__(self, profiler: EntityProfiler, threshold: int = 60, window_seconds: int = 300) -> None:
        self.profiler = profiler
        self.threshold = threshold
        self.window = timedelta(seconds=window_seconds)

    def score_event_chain(self, events: list[Any], host: str = "", username: str = "") -> UEBAAnomalyResult:
        """Chấm điểm lệch chuẩn cho một chuỗi sự kiện xảy ra trong một cửa sổ thời gian."""
        if not events:
            return UEBAAnomalyResult(0, False, host, username, 0)

        # Lấy thông tin host/user đại diện
        sample_ev = events[0]
        h = host or getattr(sample_ev, "host", "") or (sample_ev.get("host") if isinstance(sample_ev, dict) else "")
        u = username or getattr(sample_ev, "username", "") or (sample_ev.get("username") if isinstance(sample_ev, dict) else "")
        fields_sample = getattr(sample_ev, "fields", {}) or (sample_ev.get("fields", {}) if isinstance(sample_ev, dict) else {})
        if not u:
            u = fields_sample.get("TargetUserName") or fields_sample.get("SubjectUserName") or "unknown"
        if "\\" in u:
            u = u.split("\\")[-1]

        profile = self.profiler.get_profile(h, u)

        score = 0
        deviation_factors: list[str] = []
        trigger_cmds: list[str] = []
        primary_technique: str | None = None
        tactic = "unknown"

        # Trích xuất timestamps
        timestamps: list[datetime] = []
        for ev in events:
            t = getattr(ev, "timestamp", None) or (ev.get("timestamp") if isinstance(ev, dict) else None)
            if isinstance(t, str):
                try:
                    t = datetime.fromisoformat(t.replace("Z", "+00:00"))
                except ValueError:
                    t = datetime.now()
            if isinstance(t, datetime):
                timestamps.append(t)
        timestamps.sort()
        w_start = timestamps[0] if timestamps else datetime.now()
        w_end = timestamps[-1] if timestamps else datetime.now()

        # -------------------------------------------------------------
        # Yếu tố 1: Khung giờ hoạt động bất thường (Time Anomaly: +20 đến +30đ)
        # -------------------------------------------------------------
        off_hours_events = 0
        for t in timestamps:
            if profile and profile.is_off_hours(t.hour):
                off_hours_events += 1
            elif not profile and (t.hour < 6 or t.hour > 20):
                off_hours_events += 1

        if off_hours_events > 0:
            time_penalty = 25
            score += time_penalty
            sample_hour = timestamps[0].strftime("%H:%M")
            if profile:
                normal_start, normal_end = profile.working_hours_range
                deviation_factors.append(
                    f"Hoạt động trái khung giờ lịch sử ({sample_hour} ngoài giờ chuẩn {normal_start:02d}:00–{normal_end:02d}:00 của user {u})"
                )
            else:
                deviation_factors.append(f"Hoạt động vào ban đêm / ngoài giờ ({sample_hour})")

        # -------------------------------------------------------------
        # Yếu tố 2: Tiến trình lạ và Chuỗi Parent -> Child (+15 đến +25đ)
        # -------------------------------------------------------------
        rare_procs: set[str] = set()
        rare_chains: set[str] = set()
        admin_cmd_count = 0

        for ev in events:
            f = getattr(ev, "fields", {}) or (ev.get("fields", {}) if isinstance(ev, dict) else {})
            parent = f.get("ParentImage") or f.get("ParentProcessName") or ""
            child = f.get("NewProcessName") or f.get("Image") or f.get("ProcessName") or ""
            cmd = f.get("CommandLine") or ""

            if child:
                child_name = Path(child).name.lower()
                if profile and profile.is_rare_executable(child_name):
                    rare_procs.add(child_name)
                elif not profile and child_name in RECON_COMMANDS:
                    rare_procs.add(child_name)

            if parent and child and profile and profile.is_rare_chain(parent, child):
                rare_chains.add(f"{Path(parent).name.lower()} -> {Path(child).name.lower()}")

            # ---------------------------------------------------------
            # Yếu tố 3: Dòng lệnh đặc trưng kỹ thuật tấn công (+15 đến +30đ)
            # ---------------------------------------------------------
            if cmd:
                cmd_lower = cmd.lower()
                trigger_cmds.append(cmd)

                # Obfuscation / Encoded PowerShell (T1059.001)
                if any(ind in cmd_lower for ind in OBFUSCATION_INDICATORS):
                    score += 35
                    primary_technique = "T1059.001"
                    tactic = "execution"
                    deviation_factors.append("Phát hiện lệnh PowerShell làm rối/mã hóa Base64 (-EncodedCommand / IEX)")

                # Scheduled Task Persistence (T1053.005)
                elif "schtasks" in cmd_lower and ("/create" in cmd_lower or "/run" in cmd_lower):
                    score += 30
                    primary_technique = "T1053.005"
                    tactic = "persistence"
                    deviation_factors.append("Tạo tác vụ chạy ngầm Scheduled Task (schtasks /create)")

                # Archive Exfiltration Staging (T1560.001)
                elif "compress-archive" in cmd_lower or "zip" in cmd_lower:
                    score += 25
                    primary_technique = "T1560.001"
                    tactic = "collection"
                    deviation_factors.append("Nén dữ liệu vào thư mục tạm (Compress-Archive / Staging)")

                # Reconnaissance: System Discovery (T1082)
                elif any(re_cmd in cmd_lower for re_cmd in ["systeminfo", "hostname", " ver"]):
                    admin_cmd_count += 1
                    if not primary_technique:
                        primary_technique = "T1082"
                        tactic = "discovery"

                # Reconnaissance: User Discovery (T1033 & T1087.001)
                elif "whoami" in cmd_lower or "net user" in cmd_lower or "query user" in cmd_lower:
                    admin_cmd_count += 1
                    if not primary_technique:
                        primary_technique = "T1033" if "whoami" in cmd_lower else "T1087.001"
                        tactic = "discovery"

                # Reconnaissance: Network Discovery (T1016 & T1049)
                elif "ipconfig" in cmd_lower or "arp -a" in cmd_lower or "netstat" in cmd_lower:
                    admin_cmd_count += 1
                    if not primary_technique:
                        primary_technique = "T1016"
                        tactic = "discovery"

        # Cộng điểm nếu tiến trình lạ đối với user văn phòng
        if rare_procs:
            if profile and profile.role == "vanphong":
                score += 25
                deviation_factors.append(f"Tiến trình mới chưa từng có trong lịch sử user văn phòng: {', '.join(list(rare_procs)[:3])}")
            elif profile and profile.role == "dev":
                # Đối với dev, nếu là lệnh lập trình quen thuộc thì giảm phạt, chỉ phạt nhẹ
                score += 10
                deviation_factors.append(f"Tiến trình mới với user dev: {', '.join(list(rare_procs)[:3])}")
            else:
                score += 15
                deviation_factors.append(f"Tiến trình lạ: {', '.join(list(rare_procs)[:3])}")

        # Cộng điểm nếu có chuỗi Parent -> Child lạ
        if rare_chains:
            score += 15
            deviation_factors.append(f"Chuỗi tiến trình bất thường: {', '.join(list(rare_chains)[:2])}")

        # -------------------------------------------------------------
        # Yếu tố 4: Dồn dập lệnh trinh sát (Burst Recon: +15 đến +25đ)
        # -------------------------------------------------------------
        if admin_cmd_count >= 2:
            burst_penalty = min(25, admin_cmd_count * 10)
            score += burst_penalty
            deviation_factors.append(f"Thực thi dồn dập {admin_cmd_count} lệnh trinh sát hệ thống trong thời gian ngắn")

        # Giới hạn điểm từ 0 đến 100
        score = min(100, max(0, score))
        is_anomaly = score >= self.threshold

        return UEBAAnomalyResult(
            score=score,
            is_anomaly=is_anomaly,
            host=h,
            username=u,
            event_count=len(events),
            deviation_factors=deviation_factors,
            primary_technique=primary_technique,
            window_start=w_start,
            window_end=w_end,
            trigger_commands=trigger_cmds[:5],
            mitre_tactic=tactic,
        )
