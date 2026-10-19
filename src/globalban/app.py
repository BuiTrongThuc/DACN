"""Small Windows desktop dashboard for the GlobalBan monitor."""

import queue
import subprocess
import sys
import threading
import time
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

import yaml

from globalban.config import load_config


class GlobalBanApp:
    def __init__(self, root: tk.Tk) -> None:
        self._root = root
        self._language = tk.StringVar(value="vi")
        self._status_key = "stopped"
        self._status_detail: str | None = None
        self._text_vars: dict[str, tk.StringVar] = {}
        self._root.title(self._translate("window_title"))
        self._root.geometry("920x620")
        self._root.minsize(760, 480)
        self._process: subprocess.Popen[str] | None = None
        self._output_queue: queue.Queue[str] = queue.Queue()
        self._log_lines: list[str] = []
        self._alert_count = 0
        self._event_count = 0
        self._config_path = tk.StringVar(value="config/config.yaml")
        self._ai_enabled = tk.BooleanVar(value=False)
        self._ai_model = tk.StringVar(value="gemini-2.5-flash")
        self._ai_base_url = tk.StringVar(value="http://192.168.52.131:8080/v1")
        self._status = tk.StringVar(value="Đã dừng")
        self._ai_status = tk.StringVar(value=self._translate("ai_off"))
        self._alerts = tk.StringVar(value="0")
        self._events = tk.StringVar(value="0")
        self._log_filter = tk.StringVar()
        self._started_at: float | None = None
        self._load_ai_settings()
        self._build_ui()
        self._root.after(200, self._drain_output)
        self._root.protocol("WM_DELETE_WINDOW", self._close)

    _TEXT = {
        "vi": {
            "window_title": "GlobalBan | Giám sát hành vi Windows",
            "subtitle": "Giám sát hành vi Windows và phản hồi có kiểm soát",
            "config": "Cấu hình",
            "browse": "Chọn file",
            "start": "Bắt đầu giám sát",
            "stop": "Dừng",
            "status": "TRẠNG THÁI",
            "events": "SỰ KIỆN",
            "alerts": "CẢNH BÁO",
            "live_activity": "Hoạt động trực tiếp",
            "language": "Ngôn ngữ",
            "stopped": "Đã dừng",
            "running": "Đang chạy",
            "exited": "Đã thoát",
            "config_not_found": "Không tìm thấy cấu hình",
            "cannot_find": "Không tìm thấy {path}",
            "console": "BẢNG ĐIỀU KHIỂN",
            "monitor": "Giám sát",
            "telemetry": "Dữ liệu hoạt động",
            "audit": "Nhật ký kiểm tra",
            "system_ready": "HỆ THỐNG SẴN SÀNG",
            "security_console": "SECURITY CONSOLE",
            "events_today": "Sự kiện hôm nay",
            "alerts_detected": "Cảnh báo phát hiện",
            "configuration": "CẤU HÌNH GIÁM SÁT",
            "source": "Nguồn dữ liệu",
            "dry_run": "Chế độ an toàn",
            "enabled": "ĐANG BẬT",
            "activity": "NHẬT KÝ HOẠT ĐỘNG",
            "filter_logs": "Lọc nhật ký...",
            "clear": "Xóa nhật ký",
            "export": "Xuất file",
            "no_activity": "Chưa có hoạt động. Bấm Bắt đầu giám sát để kết nối.",
            "all_logs": "Tất cả",
            "events_logs": "Sự kiện",
            "warnings_logs": "Cảnh báo",
            "log_exported": "Đã xuất nhật ký",
            "log_polling": "Đang đọc các kênh Windows Event Log:",
            "log_suspicious": "Sự kiện Windows đáng ngờ:",
            "log_failed_logon": "Phát hiện đăng nhập Windows thất bại:",
            "log_following": "Đang theo dõi nhật ký xác thực:",
            "log_skipped": "Bỏ qua",
            "log_would_block": "Sẽ chặn",
            "log_blocked": "Đã chặn",
            "log_no_events": "Chưa nhận được sự kiện Windows nào trong",
            "log_channel_unavailable": "Kênh GlobalBan không khả dụng:",
            "log_warning_level": "CẢNH BÁO:",
            "log_missing_channel": "Không có nhật ký sự kiện trên máy này khớp với",
            "log_rpc_unavailable": "Máy chủ RPC không khả dụng.",
            "log_event_observed": "Đã nhận sự kiện Windows:",
            "log_threat_recorded": "Đã ghi nhận mối nguy:",
            "log_ai_disabled": "AI agent: đã tắt tư vấn; chỉ ghi nhận mối nguy vào audit",
            "log_ai_processed": "AI agent đã phân tích mối nguy:",
            "log_policy_handled": "Policy đã xử lý candidate: từ chối trước khi tác động firewall",
            "ai_management": "Quản lý AI",
            "ai_enabled": "Bật AI advisory",
            "ai_model": "Model",
            "ai_endpoint": "AI endpoint",
            "save": "Lưu cấu hình",
            "ai_advisory_only": "AI chỉ tư vấn, không tự thực thi hành động",
            "ai_saved": "Đã lưu cấu hình AI",
            "ai_invalid": "Endpoint AI không hợp lệ",
            "ai_on": "AI: ĐANG BẬT",
            "ai_off": "AI: ĐANG TẮT",
            "config_invalid": "Cấu hình không hợp lệ",
            "config_valid": "Cấu hình hợp lệ",
            "session_reset": "Đã bắt đầu phiên giám sát mới",
        },
        "en": {
            "window_title": "GlobalBan | Windows Behavior Monitor",
            "subtitle": "Windows behavior monitoring and controlled response",
            "config": "Config",
            "browse": "Browse",
            "start": "Start monitor",
            "stop": "Stop",
            "status": "STATUS",
            "events": "EVENTS",
            "alerts": "ALERTS",
            "live_activity": "Live activity",
            "language": "Language",
            "stopped": "Stopped",
            "running": "Running",
            "exited": "Exited",
            "config_not_found": "Config not found",
            "cannot_find": "Cannot find {path}",
            "console": "CONTROL CENTER",
            "monitor": "Monitor",
            "telemetry": "Telemetry",
            "audit": "Audit log",
            "system_ready": "SYSTEM READY",
            "security_console": "SECURITY CONSOLE",
            "events_today": "Events today",
            "alerts_detected": "Alerts detected",
            "configuration": "MONITOR CONFIGURATION",
            "source": "Data source",
            "dry_run": "Safe mode",
            "enabled": "ENABLED",
            "activity": "ACTIVITY LOG",
            "filter_logs": "Filter logs...",
            "clear": "Clear log",
            "export": "Export file",
            "no_activity": "No activity yet. Start the monitor to connect.",
            "all_logs": "All",
            "events_logs": "Events",
            "warnings_logs": "Warnings",
            "log_exported": "Log exported",
            "log_polling": "Polling Windows Event Log channels:",
            "log_suspicious": "Suspicious Windows event:",
            "log_failed_logon": "Windows failed logon observed:",
            "log_following": "Following authentication log:",
            "log_skipped": "Skipped",
            "log_would_block": "Would block",
            "log_blocked": "Blocked",
            "log_no_events": "No Windows events received in the last",
            "log_channel_unavailable": "GlobalBan channel unavailable:",
            "log_warning_level": "WARNING:",
            "log_missing_channel": "There is not an event log on the localhost computer that matches",
            "log_rpc_unavailable": "The RPC server is unavailable.",
            "log_event_observed": "Windows event observed:",
            "log_threat_recorded": "Threat recorded:",
            "log_ai_disabled": "AI agent: advisory disabled; threat recorded for audit only",
            "log_ai_processed": "AI agent processed Windows risk:",
            "log_policy_handled": "Policy handled candidate: rejected before firewall action",
            "ai_management": "AI management",
            "ai_enabled": "Enable AI advisory",
            "ai_model": "Model",
            "ai_endpoint": "AI endpoint",
            "save": "Save configuration",
            "ai_advisory_only": "AI provides advice only and cannot execute actions",
            "ai_saved": "AI configuration saved",
            "ai_invalid": "Invalid AI endpoint",
            "ai_on": "AI: ENABLED",
            "ai_off": "AI: DISABLED",
            "config_invalid": "Invalid configuration",
            "config_valid": "Configuration valid",
            "session_reset": "New monitoring session started",
        },
    }

    def _translate(self, key: str, **values: str) -> str:
        return self._TEXT[self._language.get()][key].format(**values)

    def _load_ai_settings(self) -> None:
        try:
            data = yaml.safe_load(self._resolve_config_path().read_text(encoding="utf-8")) or {}
            ai = data.get("ai", {}) if isinstance(data, dict) else {}
            if isinstance(ai, dict):
                self._ai_enabled.set(bool(ai.get("enabled", False)))
                self._ai_model.set(str(ai.get("model", self._ai_model.get())))
                self._ai_base_url.set(str(ai.get("base_url", self._ai_base_url.get())))
                self._ai_status.set(self._translate("ai_on" if self._ai_enabled.get() else "ai_off"))
        except (OSError, yaml.YAMLError):
            return

    def _resolve_config_path(self) -> Path:
        path = Path(self._config_path.get())
        if path.is_absolute():
            return path
        return Path(__file__).resolve().parents[2] / path

    def _text(self, key: str) -> tk.StringVar:
        existing = self._text_vars.get(key)
        if existing is not None:
            return existing
        variable = tk.StringVar(value=self._translate(key))
        self._text_vars[key] = variable
        return variable

    def _set_status(self, key: str, *, detail: str | None = None) -> None:
        self._status_key = key
        self._status_detail = detail
        self._status.set(self._status_text())

    def _status_text(self) -> str:
        text = self._translate(self._status_key)
        if self._status_detail is not None:
            text = f"{text} ({self._status_detail})"
        return text

    def _change_language(self, _event: object | None = None) -> None:
        for key, variable in self._text_vars.items():
            variable.set(self._translate(key))
        self._root.title(self._translate("window_title"))
        self._status.set(self._status_text())
        self._ai_status.set(self._translate("ai_on" if self._ai_enabled.get() else "ai_off"))
        self._refresh_log()

    def _build_ui(self) -> None:
        palette = {
            "bg": "#0b1117",
            "sidebar": "#111b24",
            "panel": "#14232d",
            "panel_alt": "#182b37",
            "line": "#25404d",
            "text": "#edf5f7",
            "muted": "#8299a5",
            "cyan": "#55d6d2",
            "amber": "#f2bd68",
            "red": "#f17b86",
            "green": "#73d6a0",
        }
        self._palette = palette
        self._root.configure(bg=palette["bg"])
        self._root.option_add("*Font", "{Segoe UI} 10")

        style = ttk.Style(self._root)
        style.theme_use("clam")
        style.configure(
            "GlobalBan.TCombobox",
            fieldbackground=palette["panel_alt"],
            background=palette["panel_alt"],
            foreground=palette["text"],
            bordercolor=palette["line"],
            lightcolor=palette["line"],
            darkcolor=palette["line"],
            arrowcolor=palette["cyan"],
        )

        sidebar = tk.Frame(self._root, bg=palette["sidebar"], width=214, padx=18, pady=22)
        sidebar.pack(side="left", fill="y")
        sidebar.pack_propagate(False)
        brand = tk.Frame(sidebar, bg=palette["sidebar"])
        brand.pack(fill="x", pady=(0, 34))
        tk.Label(brand, text="G", fg=palette["cyan"], bg=palette["sidebar"], font=("Segoe UI", 25, "bold")).pack(side="left")
        brand_text = tk.Frame(brand, bg=palette["sidebar"])
        brand_text.pack(side="left", padx=(8, 0))
        tk.Label(brand_text, text="GLOBALBAN", fg=palette["text"], bg=palette["sidebar"], font=("Segoe UI", 13, "bold")).pack(anchor="w")
        tk.Label(brand_text, textvariable=self._text("security_console"), fg=palette["muted"], bg=palette["sidebar"], font=("Segoe UI", 7, "bold")).pack(anchor="w", pady=(2, 0))
        tk.Label(sidebar, textvariable=self._text("console"), fg=palette["muted"], bg=palette["sidebar"], font=("Segoe UI", 8, "bold")).pack(anchor="w", pady=(0, 10))
        self._nav_item(sidebar, "01", "monitor", active=True)
        self._nav_item(sidebar, "02", "telemetry")
        self._nav_item(sidebar, "03", "audit")
        spacer = tk.Frame(sidebar, bg=palette["sidebar"])
        spacer.pack(fill="both", expand=True)
        status_box = tk.Frame(sidebar, bg="#172c31", padx=12, pady=12)
        status_box.pack(fill="x")
        tk.Label(status_box, text="●", fg=palette["green"], bg="#172c31", font=("Segoe UI", 13)).pack(side="left")
        tk.Label(status_box, textvariable=self._text("system_ready"), fg=palette["green"], bg="#172c31", font=("Segoe UI", 8, "bold")).pack(side="left", padx=(7, 0))

        content = tk.Frame(self._root, bg=palette["bg"], padx=28, pady=24)
        content.pack(side="left", fill="both", expand=True)
        header = tk.Frame(content, bg=palette["bg"])
        header.pack(fill="x", pady=(0, 22))
        heading = tk.Frame(header, bg=palette["bg"])
        heading.pack(side="left")
        tk.Label(heading, textvariable=self._text("monitor"), fg=palette["text"], bg=palette["bg"], font=("Segoe UI", 23, "bold")).pack(anchor="w")
        tk.Label(heading, textvariable=self._text("subtitle"), fg=palette["muted"], bg=palette["bg"], font=("Segoe UI", 10)).pack(anchor="w", pady=(3, 0))
        header_right = tk.Frame(header, bg=palette["bg"])
        header_right.pack(side="right", anchor="n")
        tk.Label(header_right, textvariable=self._status, fg=palette["cyan"], bg="#17333a", padx=12, pady=6, font=("Segoe UI", 9, "bold")).pack(side="left")
        language = ttk.Combobox(header_right, textvariable=self._language, values=("vi", "en"), state="readonly", width=5, style="GlobalBan.TCombobox")
        language.pack(side="left", padx=(10, 0))
        language.bind("<<ComboboxSelected>>", self._change_language)

        self._start_button = tk.Button(
            header_right,
            textvariable=self._text("start"),
            command=self._start,
            bg=palette["green"],
            fg="white",
            relief="flat",
            padx=14,
        )
        self._start_button.pack(side="left", padx=(10, 0))
        self._stop_button = tk.Button(
            header_right,
            textvariable=self._text("stop"),
            command=self._stop,
            state="disabled",
            bg=palette["red"],
            fg="white",
            relief="flat",
            padx=14,
        )
        self._stop_button.pack(side="left", padx=(6, 0))

        cards = tk.Frame(content, bg=palette["bg"])
        cards.pack(fill="x")
        self._card(cards, self._text("status"), self._status, palette["cyan"], 0)
        self._card(cards, self._text("events_today"), self._events, palette["amber"], 1)
        self._card(cards, self._text("alerts_detected"), self._alerts, palette["red"], 2)

        config = tk.Frame(content, bg=palette["panel"], padx=16, pady=13)
        config.pack(fill="x", pady=(18, 14))
        tk.Label(config, textvariable=self._text("configuration"), fg=palette["muted"], bg=palette["panel"], font=("Segoe UI", 8, "bold")).pack(anchor="w")
        config_row = tk.Frame(config, bg=palette["panel"])
        config_row.pack(fill="x", pady=(8, 0))
        tk.Label(config_row, textvariable=self._text("source"), fg=palette["text"], bg=palette["panel"], font=("Segoe UI", 9, "bold")).pack(side="left")
        tk.Entry(config_row, textvariable=self._config_path, bg=palette["panel_alt"], fg=palette["text"], insertbackground=palette["text"], relief="flat", width=38).pack(side="left", padx=12, ipady=6)
        tk.Button(config_row, textvariable=self._text("browse"), command=self._browse, bg=palette["panel_alt"], fg=palette["text"], activebackground=palette["line"], activeforeground=palette["text"], relief="flat", padx=12).pack(side="left")
        tk.Button(config_row, textvariable=self._text("ai_management"), command=self._open_ai_settings, bg=palette["cyan"], fg="#071417", activebackground="#82e6e2", relief="flat", padx=12).pack(side="left", padx=(8, 0))
        tk.Label(config_row, textvariable=self._ai_status, fg=palette["cyan"], bg=palette["panel"], font=("Segoe UI", 8, "bold")).pack(side="left", padx=(10, 0))
        tk.Label(config_row, textvariable=self._text("dry_run"), fg=palette["muted"], bg=palette["panel"], font=("Segoe UI", 9)).pack(side="right", padx=(8, 0))
        tk.Label(config_row, textvariable=self._text("enabled"), fg=palette["green"], bg=palette["panel"], font=("Segoe UI", 8, "bold")).pack(side="right")

        body = tk.Frame(content, bg=palette["panel"], padx=16, pady=14)
        body.pack(fill="both", expand=True)
        activity_header = tk.Frame(body, bg=palette["panel"])
        activity_header.pack(fill="x", pady=(0, 10))
        tk.Label(activity_header, textvariable=self._text("activity"), fg=palette["text"], bg=palette["panel"], font=("Segoe UI", 11, "bold")).pack(side="left")
        tk.Button(activity_header, textvariable=self._text("export"), command=self._export_log, bg=palette["panel_alt"], fg=palette["text"], activebackground=palette["line"], activeforeground=palette["text"], relief="flat", padx=10).pack(side="right")
        tk.Button(activity_header, textvariable=self._text("clear"), command=self._clear_log, bg=palette["panel_alt"], fg=palette["muted"], activebackground=palette["line"], activeforeground=palette["text"], relief="flat", padx=10).pack(side="right", padx=(0, 7))
        filter_entry = tk.Entry(activity_header, textvariable=self._log_filter, bg=palette["panel_alt"], fg=palette["text"], insertbackground=palette["text"], relief="flat", width=22)
        filter_entry.pack(side="right", padx=(0, 10), ipady=5)
        filter_entry.insert(0, self._translate("filter_logs"))
        filter_entry.configure(fg=palette["muted"])
        filter_entry.bind("<FocusIn>", lambda _event: self._clear_filter_hint(filter_entry))
        filter_entry.bind("<KeyRelease>", lambda _event: self._refresh_log())
        self._log = tk.Text(
            body,
            bg=palette["bg"],
            fg="#c9d7df",
            insertbackground=palette["text"],
            relief="flat",
            wrap="word",
            state="disabled",
            font=("Consolas", 9),
        )
        self._log.pack(fill="both", expand=True)
        self._log.tag_configure("warning", foreground=palette["red"])
        self._log.tag_configure("event", foreground=palette["cyan"])
        self._log.tag_configure("normal", foreground="#b6c8cf")

    def _nav_item(self, parent: tk.Frame, number: str, key: str, *, active: bool = False) -> None:
        color = self._palette["cyan"] if active else self._palette["muted"]
        item = tk.Frame(parent, bg="#19323a" if active else self._palette["sidebar"], padx=9, pady=9)
        item.pack(fill="x", pady=2)
        tk.Label(item, text=number, fg=color, bg=item["bg"], font=("Consolas", 8, "bold")).pack(side="left")
        tk.Label(item, textvariable=self._text(key), fg=self._palette["text"] if active else color, bg=item["bg"], font=("Segoe UI", 9, "bold" if active else "normal")).pack(side="left", padx=(10, 0))

    def _clear_filter_hint(self, entry: tk.Entry) -> None:
        if self._log_filter.get() == self._translate("filter_logs"):
            self._log_filter.set("")
            entry.configure(fg=self._palette["text"])

    def _refresh_log(self) -> None:
        query = self._log_filter.get().strip().lower()
        if query == self._translate("filter_logs").lower():
            query = ""
        self._log.configure(state="normal")
        self._log.delete("1.0", "end")
        for line in self._log_lines:
            display_line = self._localize_log_line(line)
            if query and query not in display_line.lower():
                continue
            tag = "warning" if "warning" in display_line.lower() or "risk" in display_line.lower() or "cảnh báo" in display_line.lower() else "event" if "event" in display_line.lower() or "sự kiện" in display_line.lower() else "normal"
            self._log.insert("end", display_line + "\n", tag)
        self._log.see("end")
        self._log.configure(state="disabled")

    def _clear_log(self) -> None:
        self._log_lines.clear()
        self._refresh_log()

    def _localize_log_line(self, line: str) -> str:
        if self._language.get() == "en":
            return line
        replacements = (
            (self._TEXT["en"]["log_polling"], self._TEXT["vi"]["log_polling"]),
            (self._TEXT["en"]["log_suspicious"], self._TEXT["vi"]["log_suspicious"]),
            (self._TEXT["en"]["log_failed_logon"], self._TEXT["vi"]["log_failed_logon"]),
            (self._TEXT["en"]["log_following"], self._TEXT["vi"]["log_following"]),
            (self._TEXT["en"]["log_skipped"], self._TEXT["vi"]["log_skipped"]),
            (self._TEXT["en"]["log_would_block"], self._TEXT["vi"]["log_would_block"]),
            (self._TEXT["en"]["log_blocked"], self._TEXT["vi"]["log_blocked"]),
            (self._TEXT["en"]["log_no_events"], self._TEXT["vi"]["log_no_events"]),
            (self._TEXT["en"]["log_channel_unavailable"], self._TEXT["vi"]["log_channel_unavailable"]),
            ("WARNING globalban.ingestion.windows_source:", self._TEXT["vi"]["log_warning_level"]),
            (self._TEXT["en"]["log_missing_channel"], self._TEXT["vi"]["log_missing_channel"]),
            (self._TEXT["en"]["log_rpc_unavailable"], self._TEXT["vi"]["log_rpc_unavailable"]),
            (self._TEXT["en"]["log_event_observed"], self._TEXT["vi"]["log_event_observed"]),
            (self._TEXT["en"]["log_threat_recorded"], self._TEXT["vi"]["log_threat_recorded"]),
            (self._TEXT["en"]["log_ai_disabled"], self._TEXT["vi"]["log_ai_disabled"]),
            (self._TEXT["en"]["log_ai_processed"], self._TEXT["vi"]["log_ai_processed"]),
            (self._TEXT["en"]["log_policy_handled"], self._TEXT["vi"]["log_policy_handled"]),
        )
        for source, target in replacements:
            line = line.replace(source, target)
        return line

    def _export_log(self) -> None:
        target = filedialog.asksaveasfilename(
            defaultextension=".log",
            filetypes=[("Log files", "*.log"), ("Text files", "*.txt"), ("All files", "*.*")],
        )
        if not target:
            return
        Path(target).write_text("\n".join(self._log_lines), encoding="utf-8")
        messagebox.showinfo(self._translate("export"), self._translate("log_exported"))

    def _open_ai_settings(self) -> None:
        dialog = tk.Toplevel(self._root)
        dialog.title(self._translate("ai_management"))
        dialog.configure(bg=self._palette["panel"])
        dialog.resizable(False, False)
        dialog.transient(self._root)
        dialog.grab_set()
        body = tk.Frame(dialog, bg=self._palette["panel"], padx=22, pady=20)
        body.pack(fill="both", expand=True)
        tk.Label(body, textvariable=self._text("ai_management"), fg=self._palette["text"], bg=self._palette["panel"], font=("Segoe UI", 15, "bold")).pack(anchor="w")
        tk.Label(body, textvariable=self._text("ai_advisory_only"), fg=self._palette["muted"], bg=self._palette["panel"], font=("Segoe UI", 9)).pack(anchor="w", pady=(4, 16))
        tk.Checkbutton(body, textvariable=self._text("ai_enabled"), variable=self._ai_enabled, onvalue=True, offvalue=False, fg=self._palette["text"], bg=self._palette["panel"], activebackground=self._palette["panel"], activeforeground=self._palette["text"], selectcolor=self._palette["panel_alt"]).pack(anchor="w", pady=(0, 12))
        self._ai_field(body, "ai_model", self._ai_model)
        self._ai_field(body, "ai_endpoint", self._ai_base_url)
        tk.Button(body, textvariable=self._text("save"), command=lambda: self._save_ai_settings(dialog), bg=self._palette["green"], fg="white", relief="flat", padx=14, pady=6).pack(anchor="e", pady=(18, 0))

    def _ai_field(self, parent: tk.Frame, key: str, variable: tk.StringVar) -> None:
        tk.Label(parent, textvariable=self._text(key), fg=self._palette["muted"], bg=self._palette["panel"], font=("Segoe UI", 9, "bold")).pack(anchor="w", pady=(0, 4))
        tk.Entry(parent, textvariable=variable, width=48, bg=self._palette["panel_alt"], fg=self._palette["text"], insertbackground=self._palette["text"], relief="flat").pack(fill="x", ipady=6, pady=(0, 10))

    def _save_ai_settings(self, dialog: tk.Toplevel) -> None:
        if not self._ai_base_url.get().startswith(("http://", "https://")):
            messagebox.showerror(self._translate("ai_management"), self._translate("ai_invalid"), parent=dialog)
            return
        config_path = self._resolve_config_path()
        try:
            data = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
            if not isinstance(data, dict):
                raise ValueError("configuration root must be a mapping")
            ai = data.setdefault("ai", {})
            if not isinstance(ai, dict):
                raise ValueError("ai configuration must be a mapping")
            ai.update({"enabled": self._ai_enabled.get(), "model": self._ai_model.get().strip(), "base_url": self._ai_base_url.get().strip()})
            config_path.write_text(yaml.safe_dump(data, sort_keys=False, allow_unicode=True), encoding="utf-8")
        except (OSError, ValueError, yaml.YAMLError) as exc:
            messagebox.showerror(self._translate("ai_management"), str(exc), parent=dialog)
            return
        dialog.destroy()
        self._ai_status.set(self._translate("ai_on" if self._ai_enabled.get() else "ai_off"))
        messagebox.showinfo(self._translate("ai_management"), self._translate("ai_saved"))

    def _card(
        self, parent: tk.Frame, title: tk.StringVar, value: tk.StringVar, color: str, column: int
    ) -> None:
        card = tk.Frame(parent, bg=self._palette["panel"], padx=16, pady=14)
        card.grid(row=0, column=column, sticky="nsew", padx=(0, 10 if column < 2 else 0))
        parent.grid_columnconfigure(column, weight=1)
        tk.Label(card, textvariable=title, fg=self._palette["muted"], bg=self._palette["panel"], font=("Segoe UI", 8, "bold")).pack(anchor="w")
        tk.Label(card, textvariable=value, fg=color, bg=self._palette["panel"], font=("Segoe UI", 18, "bold")).pack(anchor="w", pady=(5, 0))

    def _browse(self) -> None:
        selected = filedialog.askopenfilename(filetypes=[("YAML files", "*.yaml"), ("All files", "*.*")])
        if selected:
            self._config_path.set(str(Path(selected)))
            self._load_ai_settings()

    def _start(self) -> None:
        if self._process is not None:
            return
        config = self._resolve_config_path()
        if not config.exists():
            messagebox.showerror(
                self._translate("config_not_found"),
                self._translate("cannot_find", path=str(config)),
            )
            return
        try:
            load_config(config)
        except (OSError, ValueError, yaml.YAMLError) as exc:
            messagebox.showerror(self._translate("config_invalid"), str(exc))
            return
        try:
            self._process = subprocess.Popen(
                [sys.executable, "-m", "globalban.main", "--config", str(config), "--dry-run"],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                cwd=Path(__file__).resolve().parents[2],
            )
        except OSError as exc:
            messagebox.showerror(self._translate("config_invalid"), str(exc))
            return
        self._log_lines.clear()
        self._event_count = 0
        self._alert_count = 0
        self._events.set("0")
        self._alerts.set("0")
        self._refresh_log()
        self._started_at = time.monotonic()
        self._log_lines.append(self._translate("session_reset"))
        self._refresh_log()
        self._set_status("running")
        self._start_button.configure(state="disabled")
        self._stop_button.configure(state="normal")
        threading.Thread(target=self._read_output, daemon=True).start()

    def _read_output(self) -> None:
        if self._process is None or self._process.stdout is None:
            return
        for line in self._process.stdout:
            self._output_queue.put(line.rstrip())

    def _drain_output(self) -> None:
        try:
            while True:
                line = self._output_queue.get_nowait()
                self._log_lines.append(line)
                self._event_count += int(
                    "Windows event observed" in line
                    or "Windows failed logon observed" in line
                    or "Suspicious Windows event" in line
                )
                self._alert_count += int("WARNING" in line or "risk" in line.lower())
                self._events.set(str(self._event_count))
                self._alerts.set(str(self._alert_count))
                self._refresh_log()
        except queue.Empty:
            pass
        if self._process is not None and self._process.poll() is not None:
            self._set_status("exited", detail=str(self._process.returncode))
            self._process = None
            self._start_button.configure(state="normal")
            self._stop_button.configure(state="disabled")
        self._root.after(200, self._drain_output)

    def _stop(self) -> None:
        if self._process is not None and self._process.poll() is None:
            self._process.terminate()
        self._set_status("stopped")
        self._start_button.configure(state="normal")
        self._stop_button.configure(state="disabled")
        self._process = None

    def _close(self) -> None:
        self._stop()
        self._root.destroy()


def main() -> None:
    root = tk.Tk()
    GlobalBanApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()