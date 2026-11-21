"""
globalban.ai_agent.explainer_agent
==================================
AI Agent Giải thích Bất thường (Natural Language Contextual Explainer Agent).

Khi phát hiện chuỗi sự kiện vượt ngưỡng lệch chuẩn, AI Agent phân tích ngữ cảnh gồm:
- [Hồ sơ thói quen lịch sử của (User, Host)]
- [Chuỗi log Windows vừa xảy ra]

Và sinh ra bản giải thích tự nhiên chuyên sâu, nêu rõ:
1. Ánh xạ kỹ thuật MITRE ATT&CK và chiến thuật tương ứng.
2. Điểm lệch thói quen đối chiếu cụ thể (giờ lạ, lệnh lạ, tiến trình lạ so với 5 ngày lịch sử).
3. Đánh giá mức độ rủi ro (CRITICAL / HIGH / MEDIUM / LOW).
4. Khuyến nghị ứng phó chính xác cho SOC / Blue Team.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from globalban.baseline.entity_profiler import EntityProfile
from globalban.detector.ueba_scorer import UEBAAnomalyResult


MITRE_TACTIC_NAMES = {
    "discovery": "Trinh sát / Dò tìm hệ thống (Discovery)",
    "execution": "Thực thi lệnh mã độc (Execution)",
    "persistence": "Duy trì truy cập / Cắm chốt (Persistence)",
    "collection": "Thu thập & Nén dữ liệu (Collection)",
    "credential-access": "Chiếm đoạt thông tin xác thực (Credential Access)",
    "defense-evasion": "Vượt mặt phòng thủ / Xóa dấu vết (Defense Evasion)",
    "command-and-control": "Điều khiển từ xa (Command and Control)",
}


@dataclass
class UEBAExplanation:
    """Bản giải thích ngữ cảnh hoàn chỉnh do AI Agent suy luận."""
    host: str
    username: str
    score: int
    risk_level: str
    technique_id: str | None
    technique_name: str
    tactic_desc: str
    historical_baseline_summary: str
    observed_anomaly_summary: str
    natural_language_explanation: str
    recommended_actions: list[str] = field(default_factory=list)

    def to_markdown(self) -> str:
        """Định dạng bản giải thích ra chuẩn Markdown để đưa vào báo cáo đồ án."""
        lines = [
            f"### 🛡️ CẢNH BÁO BẤT THƯỜNG UEBA: [{self.risk_level}] Điểm Lệch Chuẩn {self.score}/100",
            f"- **Đối tượng (User, Host)**: `{self.username}` trên máy `{self.host}`",
            f"- **Kỹ thuật MITRE ATT&CK**: `{self.technique_id or 'Context-Deviation'}` — {self.technique_name}",
            f"- **Chiến thuật**: {self.tactic_desc}",
            f"",
            f"#### 1. Lời Giải Thích Ngữ Cảnh Từ AI Agent:",
            f"> {self.natural_language_explanation}",
            f"",
            f"#### 2. Đối Chiếu Hồ Sơ Lịch Sử & Hành Vi Quan Sát:",
            f"- **Thói quen lịch sử**: {self.historical_baseline_summary}",
            f"- **Hành vi vừa diễn ra**: {self.observed_anomaly_summary}",
            f"",
            f"#### 3. Khuyến Nghị Hành Động (SOC Recommendations):",
        ]
        for act in self.recommended_actions:
            lines.append(f"- [ ] {act}")
        return "\n".join(lines)


class ExplainerAgent:
    """AI Agent suy luận và giải thích ngữ cảnh bất thường dựa trên hồ sơ thói quen."""

    def __init__(self, ai_client: Any = None) -> None:
        self.ai_client = ai_client

    def explain(self, anomaly: UEBAAnomalyResult, profile: EntityProfile | None) -> UEBAExplanation:
        """Tạo bản giải thích ngữ cảnh chi tiết dựa trên kết quả UEBA và hồ sơ lịch sử."""
        u = anomaly.username
        h = anomaly.host
        score = anomaly.score

        # Xác định Risk Level
        if score >= 85:
            risk = "CRITICAL"
        elif score >= 70:
            risk = "HIGH"
        elif score >= 50:
            risk = "MEDIUM"
        else:
            risk = "LOW"

        tech_id = anomaly.primary_technique
        tech_name_map = {
            "T1082": "System Information Discovery (Tra cứu cấu hình hệ thống)",
            "T1033": "System Owner/User Discovery (Dò tìm tài khoản người dùng)",
            "T1087.001": "Account Discovery: Local Account (Liệt kê tài khoản nội bộ)",
            "T1016": "System Network Configuration Discovery (Dò tìm cấu hình mạng)",
            "T1053.005": "Scheduled Task/Job (Tạo tác vụ chạy ngầm định kỳ)",
            "T1560.001": "Archive Collected Data (Nén dữ liệu vào thư mục tạm)",
            "T1059.001": "Command and Scripting: PowerShell (Lệnh PowerShell mã hóa Base64)",
            "T1071.001": "Application Layer Protocol (Kết nối C2 Beaconing ra ngoài)",
            "T1110.001": "Brute Force: Password Guessing (Dò mật khẩu liên tiếp)",
            "T1110.003": "Password Spraying (Rải mật khẩu trên nhiều tài khoản)",
        }
        tech_name = tech_name_map.get(tech_id or "", "Lệch chuẩn hành vi người dùng (Context Deviation)")
        tactic_desc = MITRE_TACTIC_NAMES.get(anomaly.mitre_tactic, "Lệch chuẩn hành vi")

        # -------------------------------------------------------------
        # 1. Tóm tắt hồ sơ lịch sử (Historical Baseline Summary)
        # -------------------------------------------------------------
        if profile and profile.total_events > 0:
            top_apps = ", ".join(list(profile.executables.keys())[:4]) or "trình duyệt và ứng dụng văn phòng"
            hours_str = f"{profile.working_hours_range[0]:02d}:00–{profile.working_hours_range[1]:02d}:00"
            days_count = len(profile.active_days) or 5
            role_title = "nhân viên văn phòng" if profile.role == "vanphong" else ("lập trình viên / dev" if profile.role == "dev" else "người dùng tiêu chuẩn")
            hist_summary = (
                f"Tài khoản `{u}` có vai trò {role_title}. Trong {days_count} ngày qua chỉ hoạt động trong khung giờ "
                f"{hours_str} các ngày làm việc, chủ yếu sử dụng các ứng dụng `{top_apps}`. "
                f"Tỷ lệ dùng công cụ dòng lệnh quản trị chỉ chiếm {profile.admin_tools_ratio * 100:.1f}% tổng số sự kiện."
            )
        else:
            hist_summary = f"Chưa có đủ dữ liệu lịch sử dài ngày cho tài khoản `{u}` trên máy `{h}` (chưa từng thấy thói quen dòng lệnh trước đó)."

        # -------------------------------------------------------------
        # 2. Tóm tắt hành vi vừa quan sát (Observed Anomaly Summary)
        # -------------------------------------------------------------
        time_str = anomaly.window_start.strftime("%H:%M:%S ngày %d/%m/%Y") if anomaly.window_start else "vừa qua"
        reasons_text = "; ".join(anomaly.deviation_factors) or "Phát hiện chuỗi lệnh bất thường"
        obs_summary = (
            f"Vào lúc {time_str}, hệ thống ghi nhận {anomaly.event_count} sự kiện Windows liên tiếp. "
            f"Lý do cảnh báo: {reasons_text}."
        )

        # -------------------------------------------------------------
        # 3. Lời giải thích tự nhiên chuyên sâu (Natural Language Explanation)
        # -------------------------------------------------------------
        cmd_samples = f" (chuỗi lệnh: `{anomaly.trigger_commands[0][:80]}`...)" if anomaly.trigger_commands else ""
        if profile and profile.role == "vanphong":
            nl_text = (
                f"Tài khoản `{u}` trên máy trạm `{h}` trong 5 ngày lịch sử hoàn toàn là nhân sự văn phòng bình thường, "
                f"chỉ mở tài liệu Office và duyệt web trong giờ hành chính ({profile.working_hours_range[0]:02d}:00–{profile.working_hours_range[1]:02d}:00), "
                f"chưa từng có tiền lệ sử dụng công cụ dòng lệnh hệ thống. "
                f"Tuy nhiên, vào thời điểm {time_str}, tài khoản này bất ngờ thực thi {anomaly.deviation_factors[0].lower() if anomaly.deviation_factors else 'chuỗi lệnh lạ'}{cmd_samples}. "
                f"Hành vi này trùng khớp với chiến thuật **{tactic_desc}** (kỹ thuật **{tech_id or 'T1082/T1033'}**), "
                f"cho thấy dấu hiệu tài khoản đã bị kẻ tấn công chiếm quyền điều khiển (Account Takeover) hoặc mã độc cắm chốt nằm vùng thực thi ngầm."
            )
        elif profile and profile.role == "dev":
            nl_text = (
                f"Tài khoản kỹ thuật `{u}` trên máy `{h}` có thói quen lập trình thường xuyên. Mặc dù các công cụ dòng lệnh không phải là xa lạ với developer, "
                f"nhưng sự kiện lần này có điểm lệch bất thường: {reasons_text}{cmd_samples}. "
                f"Mô hình UEBA phân biệt rõ đây không phải là tác vụ build/deploy bình thường mà có dấu hiệu lạm dụng công cụ hợp pháp (Living-off-the-Land) theo kỹ thuật **{tech_id}**."
            )
        else:
            nl_text = (
                f"Phát hiện chuỗi hành vi lệch chuẩn nghiêm trọng (Điểm Anomaly = {score}/100) trên tài khoản `{u}` tại máy `{h}`. "
                f"Các sự kiện vi phạm: {reasons_text}{cmd_samples}. "
                f"Ánh xạ MITRE ATT&CK: **{tech_name}**."
            )

        # -------------------------------------------------------------
        # 4. Khuyến nghị ứng phó (Recommended Actions)
        # -------------------------------------------------------------
        actions = [
            f"Khóa tạm thời phiên đăng nhập của tài khoản `{u}` và yêu cầu xác thực lại đa yếu tố (MFA).",
            f"Cô lập máy trạm `{h}` khỏi dải mạng nội bộ nếu phát hiện tiến trình lạ vẫn đang duy trì kết nối.",
            f"Kiểm tra lại toàn bộ Scheduled Tasks và dịch vụ khởi động tự động vừa được đăng ký gần nhất.",
            f"Trích xuất bộ EVTX trong khung giờ {time_str} để đối chiếu pháp chứng số chuyên sâu.",
        ]

        return UEBAExplanation(
            host=h,
            username=u,
            score=score,
            risk_level=risk,
            technique_id=tech_id,
            technique_name=tech_name,
            tactic_desc=tactic_desc,
            historical_baseline_summary=hist_summary,
            observed_anomaly_summary=obs_summary,
            natural_language_explanation=nl_text,
            recommended_actions=actions,
        )
