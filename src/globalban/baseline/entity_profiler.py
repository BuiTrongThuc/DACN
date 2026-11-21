"""
globalban.baseline.entity_profiler
==================================
Per-User & Per-Host Behavioral Profiler (Mô hình hóa thói quen theo từng User và từng Máy tính).

Mỗi thực thể (Host, User) được theo dõi một hồ sơ thói quen độc lập, bao gồm:
- Phân phối khung giờ làm việc và nhịp độ sự kiện.
- Chuỗi tiến trình đặc trưng (ParentImage -> Image).
- Thói quen sử dụng dòng lệnh (CommandLine) và tỷ lệ công cụ quản trị (Admin Tools).
- Thư mục làm việc quen thuộc và các đích kết nối mạng (IP/Port).
"""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable


ADMIN_TOOL_NAMES = {
    "powershell.exe", "pwsh.exe", "cmd.exe", "net.exe", "net1.exe",
    "schtasks.exe", "reg.exe", "wmic.exe", "tasklist.exe", "whoami.exe",
    "systeminfo.exe", "ipconfig.exe", "arp.exe", "netstat.exe", "certutil.exe",
    "rundll32.exe", "regsvr32.exe", "mshta.exe", "bitsadmin.exe", "vssadmin.exe",
}


@dataclass
class EntityProfile:
    """Hồ sơ hành vi chuẩn của một cặp (Host, User) qua nhiều ngày bình thường."""
    host: str
    username: str
    role: str = "general"
    total_events: int = 0
    active_days: set[str] = field(default_factory=set)
    hourly_distribution: Counter[int] = field(default_factory=Counter)
    working_hours_range: tuple[int, int] = (8, 18)
    process_chain_counts: Counter[str] = field(default_factory=Counter)
    executables: Counter[str] = field(default_factory=Counter)
    commandline_patterns: Counter[str] = field(default_factory=Counter)
    working_directories: Counter[str] = field(default_factory=Counter)
    network_destinations: Counter[str] = field(default_factory=Counter)
    admin_tools_count: int = 0

    @property
    def admin_tools_ratio(self) -> float:
        """Tỷ lệ sử dụng công cụ quản trị trong tổng số tiến trình."""
        if self.total_events == 0:
            return 0.0
        return round(self.admin_tools_count / self.total_events, 4)

    def is_off_hours(self, hour: int) -> bool:
        """Kiểm tra một khung giờ có phải là giờ bất thường (ngoài giờ làm việc) hay không."""
        start, end = self.working_hours_range
        # Nếu khung giờ này có tần suất lịch sử < 2% tổng số sự kiện thì coi là giờ lạ
        count = self.hourly_distribution.get(hour, 0)
        if self.total_events > 50 and (count / self.total_events) < 0.01:
            return True
        if start <= end:
            return not (start <= hour <= end)
        return False

    def is_rare_executable(self, exe: str) -> bool:
        """Kiểm tra một tiến trình có phải là tiến trình mới chưa từng thấy hay không."""
        if not exe:
            return False
        clean = Path(exe).name.lower()
        return clean not in self.executables

    def is_rare_chain(self, parent: str, child: str) -> bool:
        """Kiểm tra cặp ParentImage -> Image có phải là chuỗi chưa từng xuất hiện hay không."""
        if not parent or not child:
            return False
        key = f"{Path(parent).name.lower()} -> {Path(child).name.lower()}"
        return key not in self.process_chain_counts

    def to_dict(self) -> dict[str, Any]:
        """Chuyển đổi hồ sơ sang dạng dictionary có thể serialize JSON."""
        return {
            "host": self.host,
            "username": self.username,
            "role": self.role,
            "total_events": self.total_events,
            "active_days": sorted(list(self.active_days)),
            "hourly_distribution": dict(self.hourly_distribution),
            "working_hours_range": list(self.working_hours_range),
            "top_executables": dict(self.executables.most_common(10)),
            "top_process_chains": dict(self.process_chain_counts.most_common(10)),
            "admin_tools_ratio": self.admin_tools_ratio,
            "admin_tools_count": self.admin_tools_count,
            "top_directories": dict(self.working_directories.most_common(5)),
            "top_destinations": dict(self.network_destinations.most_common(5)),
        }


class EntityProfiler:
    """Bộ xây dựng và lưu trữ hồ sơ thói quen cho từng cặp (Host, User)."""

    def __init__(self) -> None:
        self.profiles: dict[tuple[str, str], EntityProfile] = {}

    def _get_or_create(self, host: str, username: str) -> EntityProfile:
        h = (host or "UNKNOWN-HOST").upper().strip()
        u = (username or "UNKNOWN-USER").lower().strip()
        # Loại bỏ domain prefix nếu có (ví dụ LAB\user_vanphong -> user_vanphong)
        if "\\" in u:
            u = u.split("\\")[-1]
        key = (h, u)
        if key not in self.profiles:
            # Tự động gán role ban đầu nếu username có chứa từ khóa
            role = "vanphong" if "vanphong" in u or "office" in u else ("dev" if "dev" in u or "developer" in u else "general")
            hours = (8, 17) if role == "vanphong" else ((9, 19) if role == "dev" else (8, 18))
            self.profiles[key] = EntityProfile(host=h, username=u, role=role, working_hours_range=hours)
        return self.profiles[key]

    def fit_event(self, event: Any) -> None:
        """Học thói quen từ 1 sự kiện Windows Event (WindowsEvent hoặc dict)."""
        # Trích xuất host và username
        host = getattr(event, "host", "") or (event.get("host") if isinstance(event, dict) else "")
        user = getattr(event, "username", "") or (event.get("username") if isinstance(event, dict) else "")
        fields = getattr(event, "fields", {}) or (event.get("fields", {}) if isinstance(event, dict) else {})

        # Trích xuất timestamp
        ts = getattr(event, "timestamp", None)
        if ts is None and isinstance(event, dict):
            ts = event.get("timestamp")
        if isinstance(ts, str):
            try:
                ts = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            except ValueError:
                ts = datetime.now()
        elif not isinstance(ts, datetime):
            ts = datetime.now()

        # Bỏ qua tài khoản hệ thống (SYSTEM, LOCAL SERVICE, NETWORK SERVICE) khi xây dựng hồ sơ người dùng
        u_clean = (user or fields.get("TargetUserName") or fields.get("SubjectUserName") or "").lower()
        if "\\" in u_clean:
            u_clean = u_clean.split("\\")[-1]
        if not u_clean or u_clean in {"system", "local service", "network service", "-"}:
            return

        profile = self._get_or_create(host, u_clean)
        profile.total_events += 1
        profile.active_days.add(ts.strftime("%Y-%m-%d"))
        profile.hourly_distribution[ts.hour] += 1

        # Trích xuất tiến trình cha và con
        parent = fields.get("ParentImage") or fields.get("ParentProcessName") or ""
        child = fields.get("NewProcessName") or fields.get("Image") or fields.get("ProcessName") or ""
        cmdline = fields.get("CommandLine") or ""

        if child:
            child_name = Path(child).name.lower()
            profile.executables[child_name] += 1
            if child_name in ADMIN_TOOL_NAMES:
                profile.admin_tools_count += 1
            try:
                dir_path = str(Path(child).parent).lower()
                profile.working_directories[dir_path] += 1
            except Exception:
                pass

        if parent and child:
            chain_key = f"{Path(parent).name.lower()} -> {Path(child).name.lower()}"
            profile.process_chain_counts[chain_key] += 1

        if cmdline:
            # Rút gọn token lệnh
            short_cmd = cmdline.strip().split()[0].lower() if cmdline.strip() else ""
            if short_cmd:
                profile.commandline_patterns[short_cmd] += 1

        dest_ip = fields.get("DestinationIp") or fields.get("IpAddress")
        dest_port = fields.get("DestinationPort")
        if dest_ip and dest_ip != "-":
            dest_key = f"{dest_ip}:{dest_port}" if dest_port else dest_ip
            profile.network_destinations[dest_key] += 1

    def fit(self, events: Iterable[Any]) -> None:
        """Học toàn bộ sự kiện bình thường qua nhiều ngày."""
        for ev in events:
            self.fit_event(ev)

    def get_profile(self, host: str, username: str) -> EntityProfile | None:
        """Lấy hồ sơ thói quen của một (Host, User)."""
        h = (host or "").upper().strip()
        u = (username or "").lower().strip()
        if "\\" in u:
            u = u.split("\\")[-1]
        return self.profiles.get((h, u))

    def save(self, path: Path | str) -> None:
        """Lưu toàn bộ hồ sơ ra file JSON."""
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        data = {f"{h}|{u}": prof.to_dict() for (h, u), prof in self.profiles.items()}
        p.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")

    def load(self, path: Path | str) -> None:
        """Nạp hồ sơ từ file JSON đã học."""
        p = Path(path)
        if not p.exists():
            return
        data = json.loads(p.read_text(encoding="utf-8"))
        for key_str, d in data.items():
            if "|" in key_str:
                h, u = key_str.split("|", 1)
            else:
                h, u = d.get("host", "HOST"), d.get("username", "user")
            prof = EntityProfile(
                host=h,
                username=u,
                role=d.get("role", "general"),
                total_events=d.get("total_events", 0),
                active_days=set(d.get("active_days", [])),
                hourly_distribution=Counter({int(k): v for k, v in d.get("hourly_distribution", {}).items()}),
                working_hours_range=tuple(d.get("working_hours_range", [8, 18])),
                executables=Counter(d.get("top_executables", {})),
                process_chain_counts=Counter(d.get("top_process_chains", {})),
                admin_tools_count=d.get("admin_tools_count", 0),
                working_directories=Counter(d.get("top_directories", {})),
                network_destinations=Counter(d.get("top_destinations", {})),
            )
            self.profiles[(h.upper(), u.lower())] = prof

    def export_summary(self) -> dict[str, Any]:
        """Tóm tắt tổng quan các hồ sơ đã học."""
        return {
            "total_entities": len(self.profiles),
            "entities": [prof.to_dict() for prof in self.profiles.values()],
        }
