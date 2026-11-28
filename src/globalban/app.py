"""Small Windows desktop dashboard for the GlobalBan monitor."""

import queue
import json
import re
import os
import socket
import subprocess
import sys
import threading
import time
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from collections import Counter

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
        self._root.geometry("1280x860")
        self._root.minsize(1040, 820)
        self._process: subprocess.Popen[str] | None = None
        self._proxy_process: subprocess.Popen[str] | None = None
        self._proxy_output_queue: queue.Queue[str] = queue.Queue()
        self._proxy_lines: list[str] = []
        self._proxy_window: tk.Toplevel | None = None
        self._proxy_log: tk.Text | None = None
        self._telemetry_window: tk.Toplevel | None = None
        self._telemetry_tree: ttk.Treeview | None = None
        self._audit_window: tk.Toplevel | None = None
        self._audit_tree: ttk.Treeview | None = None
        self._live_window: tk.Frame | None = None
        self._live_tree: ttk.Treeview | None = None
        self._live_alert_count_var: tk.StringVar | None = None
        self._live_last_seen: int = 0
        self._live_refresh_job: str | None = None
        self._chat_window: tk.Frame | None = None
        self._chat_log: tk.Text | None = None
        self._chat_entry: tk.Entry | None = None
        self._chat_input: tk.StringVar = tk.StringVar()
        self._chat_suggestions_frame: tk.Frame | None = None
        self._chat_feedback_frame: tk.Frame | None = None
        self._chat_last_qa: dict[str, str] = {}
        self._nl_agent: object | None = None
        self._pages: dict[str, tk.Frame] = {}
        self._monitor_page: tk.Frame | None = None
        self._proxy_bind = tk.StringVar(value="127.0.0.1")
        self._proxy_port = tk.StringVar(value="8080")
        self._proxy_upstream = tk.StringVar(
            value="https://generativelanguage.googleapis.com/v1beta/openai"
        )
        self._proxy_status = tk.StringVar(value="Đã tắt")
        self._output_queue: queue.Queue[str] = queue.Queue()
        self._log_lines: list[str] = []
        self._alert_count = 0
        self._event_count = 0
        self._config_path = tk.StringVar(value="config/config.yaml")
        self._ai_enabled = tk.BooleanVar(value=False)
        self._ai_model = tk.StringVar(value="gemini-2.5-flash")
        self._ai_base_url = tk.StringVar(
            value="https://generativelanguage.googleapis.com/v1beta/openai"
        )
        self._status = tk.StringVar(value="Đã dừng")
        self._ai_status = tk.StringVar(value=self._translate("ai_off"))
        self._alerts = tk.StringVar(value="0")
        self._events = tk.StringVar(value="0")
        self._log_filter = tk.StringVar()
        self._started_at: float | None = None
        self._live_mode = tk.BooleanVar(value=False)
        self._source_counts: Counter[str] = Counter()
        self._event_rows: list[tuple[str, ...]] = []
        self._pulse_state = False
        self._pulse_job: str | None = None
        self._ai_autosave_job: str | None = None
        self._load_ai_settings()
        self._build_ui()
        for variable in (self._ai_enabled, self._ai_model, self._ai_base_url):
            variable.trace_add("write", self._schedule_ai_settings_autosave)
        # Chặn phím Alt hoặc Alt+Space kích hoạt System Menu của Windows khi đang gõ tiếng Việt (Unikey/EVKey)
        self._root.bind_all("<Alt-space>", lambda _e: "break")
        self._root.bind_all("<KeyPress-Alt_L>", lambda _e: "break")
        self._root.bind_all("<KeyRelease-Alt_L>", lambda _e: "break")
        self._root.bind_all("<KeyPress-Alt_R>", lambda _e: "break")
        self._root.bind_all("<KeyRelease-Alt_R>", lambda _e: "break")
        self._root.bind_all("<KeyPress-F10>", lambda _e: "break")
        self._win32_wndproc_cb: object | None = None
        self._root.after(100, self._install_win32_keymenu_blocker)
        self._root.protocol("WM_DELETE_WINDOW", self._close)
        self._root.after(200, self._drain_output)

    def _install_win32_keymenu_blocker(self) -> None:
        """Chặn trực tiếp thông điệp Win32 WM_SYSCOMMAND (SC_KEYMENU) mở System Menu khi gõ Space/Alt."""
        if sys.platform != "win32":
            return
        try:
            import ctypes
            import ctypes.wintypes as wt

            user32 = ctypes.windll.user32
            WNDPROC = ctypes.WINFUNCTYPE(
                ctypes.c_ssize_t, wt.HWND, wt.UINT, wt.WPARAM, wt.LPARAM
            )
            user32.CallWindowProcW.argtypes = [
                ctypes.c_void_p,
                wt.HWND,
                wt.UINT,
                wt.WPARAM,
                wt.LPARAM,
            ]
            user32.CallWindowProcW.restype = ctypes.c_ssize_t
            set_window_long = getattr(
                user32, "SetWindowLongPtrW", getattr(user32, "SetWindowLongW", None)
            )
            get_window_long = getattr(
                user32, "GetWindowLongPtrW", getattr(user32, "GetWindowLongW", None)
            )
            if set_window_long is None or get_window_long is None:
                return
            set_window_long.argtypes = [wt.HWND, ctypes.c_int, ctypes.c_void_p]
            set_window_long.restype = ctypes.c_void_p
            get_window_long.argtypes = [wt.HWND, ctypes.c_int]
            get_window_long.restype = ctypes.c_void_p

            self._root.update_idletasks()
            hwnd = user32.GetAncestor(self._root.winfo_id(), 2) or self._root.winfo_id()
            old_proc = get_window_long(hwnd, -4)  # GWL_WNDPROC = -4
            if not old_proc:
                return

            WM_SYSCOMMAND = 0x0112
            SC_KEYMENU = 0xF100
            WM_SYSKEYDOWN = 0x0104
            WM_SYSKEYUP = 0x0105
            WM_SYSCHAR = 0x0106
            VK_SPACE = 0x20
            VK_MENU = 0x12
            VK_F10 = 0x79

            def _wnd_proc(h: int, msg: int, wp: int, lp: int) -> int:
                # Chặn mọi lệnh mở System Menu từ bàn phím (Alt+Space, Alt đơn lẻ + Space, F10)
                if msg == WM_SYSCOMMAND and (wp & 0xFFF0) == SC_KEYMENU:
                    return 0
                if msg in (WM_SYSKEYDOWN, WM_SYSKEYUP, WM_SYSCHAR) and wp in (
                    VK_SPACE,
                    VK_MENU,
                    VK_F10,
                ):
                    return 0
                return int(user32.CallWindowProcW(old_proc, h, msg, wp, lp))

            self._win32_wndproc_cb = WNDPROC(_wnd_proc)
            set_window_long(hwnd, -4, ctypes.cast(self._win32_wndproc_cb, ctypes.c_void_p))
        except Exception:
            pass

    def _toggle_live(self) -> None:
        if self._live_mode.get() and not messagebox.askyesno(
            "Xác nhận LIVE", "Bật LIVE có thể chặn IP trên Windows Firewall. Tiếp tục?",
            icon="warning", parent=self._root,
        ):
            self._live_mode.set(False)

    def _ingest_ui_event(self, line: str) -> None:
        if "Windows event observed" not in line and "Windows failed logon observed" not in line and "Suspicious Windows event" not in line:
            return
        event_match = re.search(r"(?:id|event_id|event)=([0-9]+)", line, re.IGNORECASE)
        source_match = re.search(r"(?:source|source_network)=([0-9a-fA-F:./-]+)", line)
        user_match = re.search(r"user(?:name)?=([^ ]+)", line)
        event_id = event_match.group(1) if event_match else "-"
        source = source_match.group(1) if source_match else "-"
        user = user_match.group(1) if user_match else "-"
        severity = "ALERT" if "Suspicious" in line or "WARNING" in line else "EVENT"
        self._source_counts[source] += 1
        row = (time.strftime("%H:%M:%S"), event_id, source, user, severity, line[:120])
        self._event_rows.append(row)
        self._event_rows = self._event_rows[-100:]
        for item in self._event_table.get_children():
            self._event_table.delete(item)
        for item in self._event_rows[-10:]:
            tree_item = self._event_table.insert("", "end", values=item, tags=("fresh",))
            self._root.after(1200, lambda item_id=tree_item: self._clear_fresh_event(item_id))
        self._top_sources.set(" | ".join(f"{ip}: {count}" for ip, count in self._source_counts.most_common(5)))
        self._refresh_telemetry_view()

    def _clear_fresh_event(self, item_id: str) -> None:
        if self._event_table.exists(item_id):
            self._event_table.item(item_id, tags=())

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
            "proxy": "Proxy egress",
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
            "proxy": "Egress proxy",
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
            cfg_path = self._resolve_config_path()
            if not cfg_path.exists():
                example = cfg_path.parent / "config.example.yaml"
                if example.exists():
                    cfg_path = example
            data = yaml.safe_load(cfg_path.read_text(encoding="utf-8")) or {}
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

    _LANG_LABELS = {
        "vi": "🌐 Tiếng Việt (VI)",
        "en": "🌐 English (EN)",
    }
    _LANG_CODES = {
        "🌐 Tiếng Việt (VI)": "vi",
        "🌐 English (EN)": "en",
    }

    def _change_language(self, _event: object | None = None) -> None:
        if hasattr(self, "_language_display"):
            selected_label = self._language_display.get()
            code = self._LANG_CODES.get(selected_label, "vi")
            self._language.set(code)
        for key, variable in self._text_vars.items():
            variable.set(self._translate(key))
        self._root.title(self._translate("window_title"))
        self._status.set(self._status_text())
        self._ai_status.set(self._translate("ai_on" if self._ai_enabled.get() else "ai_off"))
        self._refresh_log()

    def _build_ui(self) -> None:
        palette = {
            "bg": "#080b10",
            "sidebar": "#0d1219",
            "panel": "#111720",
            "panel_alt": "#171e29",
            "line": "#222c3a",
            "text": "#f1f5f9",
            "muted": "#8290a3",
            "cyan": "#49a6ff",
            "amber": "#f2c65c",
            "red": "#ff6b78",
            "green": "#36d58b",
        }
        self._palette = palette
        self._root.configure(bg=palette["bg"])
        self._root.option_add("*Font", "{Segoe UI} 10")
        self._root.option_add("*TCombobox*Listbox.background", palette["panel_alt"])
        self._root.option_add("*TCombobox*Listbox.foreground", palette["text"])
        self._root.option_add("*TCombobox*Listbox.selectBackground", "#1c4166")
        self._root.option_add("*TCombobox*Listbox.selectForeground", palette["cyan"])
        self._root.option_add("*TCombobox*Listbox.font", "{Segoe UI} 10")

        style = ttk.Style(self._root)
        style.theme_use("clam")
        style.configure(
            "GlobalBan.TCombobox",
            fieldbackground=palette["panel_alt"],
            background=palette["panel_alt"],
            foreground=palette["text"],
            bordercolor=palette["cyan"],
            lightcolor=palette["line"],
            darkcolor=palette["line"],
            arrowcolor=palette["cyan"],
            arrowsize=14,
            padding=(10, 6, 10, 6),
        )
        style.map(
            "GlobalBan.TCombobox",
            fieldbackground=[("readonly", palette["panel_alt"]), ("focus", "#1c2838")],
            background=[("readonly", palette["panel_alt"]), ("active", "#1c2838")],
            foreground=[("readonly", palette["text"])],
            bordercolor=[("focus", palette["cyan"]), ("readonly", palette["line"])],
            arrowcolor=[("active", "#82e6e2"), ("readonly", palette["cyan"])],
        )
        style.configure(
            "GlobalBan.Treeview",
            background=palette["panel_alt"],
            fieldbackground=palette["panel_alt"],
            foreground=palette["text"],
            bordercolor=palette["line"],
            rowheight=27,
            font=("Segoe UI", 9),
        )
        style.configure(
            "GlobalBan.Treeview.Heading",
            background=palette["panel"],
            foreground=palette["muted"],
            bordercolor=palette["line"],
            font=("Segoe UI", 8, "bold"),
        )
        style.map(
            "GlobalBan.Treeview",
            background=[("selected", "#1c4166")],
            foreground=[("selected", palette["text"])],
        )

        sidebar = tk.Frame(self._root, bg=palette["sidebar"], width=260, padx=22, pady=28)
        sidebar.pack(side="left", fill="y")
        sidebar.pack_propagate(False)
        brand = tk.Frame(sidebar, bg=palette["sidebar"])
        brand.pack(fill="x", pady=(0, 34))
        tk.Label(brand, text="◈", fg=palette["cyan"], bg=palette["sidebar"], font=("Segoe UI", 24, "bold")).pack(side="left")
        brand_text = tk.Frame(brand, bg=palette["sidebar"])
        brand_text.pack(side="left", padx=(8, 0))
        tk.Label(brand_text, text="GLOBALBAN", fg=palette["text"], bg=palette["sidebar"], font=("Bahnschrift", 13, "bold")).pack(anchor="w")
        tk.Label(brand_text, textvariable=self._text("security_console"), fg=palette["muted"], bg=palette["sidebar"], font=("Segoe UI", 7, "bold")).pack(anchor="w", pady=(2, 0))
        tk.Label(sidebar, textvariable=self._text("console"), fg=palette["muted"], bg=palette["sidebar"], font=("Segoe UI", 8, "bold")).pack(anchor="w", pady=(0, 18))
        tk.Label(sidebar, text="WORKSPACE", fg="#536579", bg=palette["sidebar"], font=("Consolas", 7, "bold")).pack(anchor="w", pady=(0, 7))
        self._nav_item(sidebar, "01", "monitor", active=True, command=self._show_monitor_page)
        # Tab LIVE RED TEAM — nổi bật màu đỏ
        live_btn_frame = tk.Frame(sidebar, bg=palette["sidebar"], pady=3)
        live_btn_frame.pack(fill="x")
        self._live_tab_btn = tk.Button(
            live_btn_frame,
            text="🔴  05  LIVE RED TEAM",
            command=self._open_live_panel,
            fg=palette["red"],
            bg="#1a0d0d",
            activebackground="#2a1010",
            activeforeground=palette["red"],
            relief="flat",
            padx=10,
            pady=10,
            font=("Segoe UI", 9, "bold"),
            anchor="w",
        )
        self._live_tab_btn.pack(fill="x")
        # Tab AI SOC CHAT — giao tiếp ngôn ngữ tự nhiên
        chat_btn_frame = tk.Frame(sidebar, bg=palette["sidebar"], pady=3)
        chat_btn_frame.pack(fill="x")
        self._chat_tab_btn = tk.Button(
            chat_btn_frame,
            text="💬  06  AI SOC CHAT",
            command=self._open_chat_panel,
            fg=palette["cyan"],
            bg="#0d1e2a",
            activebackground="#153144",
            activeforeground=palette["cyan"],
            relief="flat",
            padx=10,
            pady=10,
            font=("Segoe UI", 9, "bold"),
            anchor="w",
        )
        self._chat_tab_btn.pack(fill="x")
        tk.Label(sidebar, text="DỮ LIỆU & KIỂM SOÁT", fg="#536579", bg=palette["sidebar"], font=("Consolas", 7, "bold")).pack(anchor="w", pady=(18, 7))
        self._nav_item(sidebar, "02", "telemetry", command=self._open_telemetry_panel)
        self._nav_item(sidebar, "03", "audit", command=self._open_audit_panel)
        self._nav_item(sidebar, "04", "proxy", command=self._open_proxy_panel)
        spacer = tk.Frame(sidebar, bg=palette["sidebar"])
        spacer.pack(fill="both", expand=True)
        status_box = tk.Frame(sidebar, bg="#10251f", padx=12, pady=12, highlightthickness=1, highlightbackground="#1d493a")
        status_box.pack(fill="x")
        self._status_dot = tk.Label(status_box, text="●", fg=palette["green"], bg="#10251f", font=("Segoe UI", 13))
        self._status_dot.pack(side="left")
        tk.Label(status_box, textvariable=self._text("system_ready"), fg=palette["green"], bg="#172c31", font=("Segoe UI", 8, "bold")).pack(side="left", padx=(7, 0))

        content = tk.Frame(self._root, bg=palette["bg"], padx=44, pady=40)
        content.pack(side="left", fill="both", expand=True)
        self._monitor_page = content
        self._pages["monitor"] = content
        header = tk.Frame(content, bg=palette["bg"])
        header.pack(fill="x", pady=(0, 22))
        heading = tk.Frame(header, bg=palette["bg"])
        heading.pack(side="left")
        tk.Label(heading, textvariable=self._text("monitor"), fg=palette["text"], bg=palette["bg"], font=("Segoe UI", 23, "bold")).pack(anchor="w")
        tk.Label(heading, textvariable=self._text("subtitle"), fg=palette["muted"], bg=palette["bg"], font=("Segoe UI", 10)).pack(anchor="w", pady=(3, 0))
        header_right = tk.Frame(header, bg=palette["bg"])
        header_right.pack(side="right", anchor="n")
        tk.Label(header_right, textvariable=self._status, fg=palette["cyan"], bg="#17333a", padx=12, pady=6, font=("Segoe UI", 9, "bold")).pack(side="left")
        self._language_display = tk.StringVar(
            value=self._LANG_LABELS.get(self._language.get(), "🌐 Tiếng Việt (VI)")
        )
        language = ttk.Combobox(
            header_right,
            textvariable=self._language_display,
            values=tuple(self._LANG_LABELS.values()),
            state="readonly",
            width=18,
            font=("Segoe UI", 9, "bold"),
            style="GlobalBan.TCombobox",
        )
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
        self._bind_hover(self._start_button, palette["green"], "#58e7a0")
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
        self._bind_hover(self._stop_button, palette["red"], "#ff8b95")

        cards = tk.Frame(content, bg=palette["bg"])
        cards.pack(fill="x")
        self._card(cards, self._text("status"), self._status, palette["cyan"], 0)
        self._card(cards, self._text("events_today"), self._events, palette["amber"], 1)
        self._card(cards, self._text("alerts_detected"), self._alerts, palette["red"], 2)
        self._card(cards, self._text("ai_management"), self._ai_status, palette["green"], 3)

        pipeline = tk.Frame(content, bg=palette["panel"], padx=16, pady=14,
                            highlightthickness=1, highlightbackground=palette["line"])
        pipeline.pack(fill="x", pady=(16, 14))
        pipeline_header = tk.Frame(pipeline, bg=palette["panel"])
        pipeline_header.pack(fill="x", pady=(0, 10))
        tk.Label(
            pipeline_header,
            text="LUỒNG PHÂN TÍCH / ANALYSIS PIPELINE",
            fg=palette["text"],
            bg=palette["panel"],
            font=("Segoe UI", 9, "bold"),
        ).pack(side="left")
        tk.Label(
            pipeline_header,
            text="Policy-first response",
            fg=palette["green"],
            bg=palette["panel"],
            font=("Consolas", 8, "bold"),
        ).pack(side="right")
        stages = (
            ("01", "Thu thập", "Event Log / SSH", palette["cyan"]),
            ("02", "Chuẩn hóa", "Parser", palette["cyan"]),
            ("03", "Tương quan", "Behavior + sequence", palette["amber"]),
            ("04", "Tư vấn", "AI advisory", palette["green"]),
            ("05", "Kiểm soát", "Allowlist + gate", palette["red"]),
            ("06", "Audit", "Traceable record", palette["green"]),
        )
        pipeline_steps = tk.Frame(pipeline, bg=palette["panel"])
        pipeline_steps.pack(fill="x")
        for index, (number, title, detail, color) in enumerate(stages):
            stage = tk.Frame(
                pipeline_steps,
                bg=palette["panel_alt"],
                padx=12,
                pady=9,
                highlightthickness=1,
                highlightbackground=palette["line"],
            )
            stage.grid(row=0, column=index, sticky="nsew", padx=(0, 6 if index < len(stages) - 1 else 0))
            pipeline_steps.grid_columnconfigure(index, weight=1)
            tk.Label(stage, text=number, fg=color, bg=palette["panel_alt"], font=("Consolas", 8, "bold")).pack(anchor="w")
            tk.Label(stage, text=title, fg=palette["text"], bg=palette["panel_alt"], font=("Segoe UI", 9, "bold")).pack(anchor="w", pady=(3, 0))
            tk.Label(stage, text=detail, fg=palette["muted"], bg=palette["panel_alt"], font=("Segoe UI", 8)).pack(anchor="w", pady=(2, 0))

        config = tk.Frame(content, bg=palette["panel"], padx=16, pady=13,
                  highlightthickness=1, highlightbackground=palette["line"])
        config.pack(fill="x", pady=(18, 14))
        tk.Label(config, textvariable=self._text("configuration"), fg=palette["muted"], bg=palette["panel"], font=("Segoe UI", 8, "bold")).pack(anchor="w")
        config_row = tk.Frame(config, bg=palette["panel"])
        config_row.pack(fill="x", pady=(8, 0))
        tk.Label(config_row, textvariable=self._text("source"), fg=palette["text"], bg=palette["panel"], font=("Segoe UI", 9, "bold")).pack(side="left")
        tk.Entry(config_row, textvariable=self._config_path, bg=palette["panel_alt"], fg=palette["text"], insertbackground=palette["text"], relief="flat", width=38).pack(side="left", padx=12, ipady=6)
        tk.Button(config_row, textvariable=self._text("browse"), command=self._browse, bg=palette["panel_alt"], fg=palette["text"], activebackground=palette["line"], activeforeground=palette["text"], relief="flat", padx=12).pack(side="left")
        tk.Button(config_row, textvariable=self._text("ai_management"), command=self._open_ai_settings, bg=palette["cyan"], fg="#071417", activebackground="#82e6e2", relief="flat", padx=12).pack(side="left", padx=(8, 0))
        tk.Label(config_row, textvariable=self._ai_status, fg=palette["cyan"], bg=palette["panel"], font=("Segoe UI", 8, "bold")).pack(side="left", padx=(10, 0))
        tk.Checkbutton(config_row, text="LIVE / Firewall thật", variable=self._live_mode, command=self._toggle_live,
                       fg=palette["red"], bg=palette["panel"], selectcolor=palette["panel_alt"],
                       activebackground=palette["panel"], activeforeground=palette["red"]).pack(side="right", padx=(8, 0))
        tk.Label(config_row, textvariable=self._text("dry_run"), fg=palette["muted"], bg=palette["panel"], font=("Segoe UI", 9)).pack(side="right", padx=(8, 0))
        tk.Label(config_row, textvariable=self._text("enabled"), fg=palette["green"], bg=palette["panel"], font=("Segoe UI", 8, "bold")).pack(side="right")

        body = tk.Frame(content, bg=palette["panel"], padx=16, pady=14,
                highlightthickness=1, highlightbackground=palette["line"])
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
        table_frame = tk.Frame(body, bg=palette["panel"])
        table_frame.pack(fill="x", pady=(12, 0))
        tk.Label(table_frame, text="SỰ KIỆN GẦN NHẤT / RECENT EVENTS", fg=palette["muted"], bg=palette["panel"],
                 font=("Segoe UI", 8, "bold")).pack(anchor="w", pady=(0, 5))
        columns = ("time", "event", "source", "user", "severity", "details")
        self._event_table = ttk.Treeview(table_frame, columns=columns, show="headings", height=6, style="GlobalBan.Treeview")
        headings = {"time": "Time", "event": "Event ID", "source": "Source IP", "user": "User",
                    "severity": "Severity", "details": "Details"}
        widths = {"time": 72, "event": 70, "source": 130, "user": 120, "severity": 85, "details": 430}
        for column in columns:
            self._event_table.heading(column, text=headings[column])
            self._event_table.column(column, width=widths[column], anchor="w")
        self._event_table.pack(fill="x")
        tk.Label(table_frame, text="Top nguồn: ", fg=palette["muted"], bg=palette["panel"]).pack(anchor="w", pady=(5, 0))
        self._top_sources = tk.StringVar(value="Chưa có dữ liệu")
        tk.Label(table_frame, textvariable=self._top_sources, fg=palette["amber"], bg=palette["panel"],
                 font=("Consolas", 9)).pack(anchor="w")
        self._event_table.tag_configure("fresh", background="#17344e", foreground=palette["text"])
        self._pulse_job = self._root.after(700, self._animate_status)

    def _nav_item(
        self,
        parent: tk.Frame,
        number: str,
        key: str,
        *,
        active: bool = False,
        command=None,
    ) -> None:
        color = self._palette["cyan"] if active else self._palette["muted"]
        background = "#17323b" if active else self._palette["sidebar"]
        item = tk.Frame(
            parent,
            padx=0,
            pady=0,
            bg=background,
            highlightthickness=1 if active else 0,
            highlightbackground="#245766" if active else self._palette["sidebar"],
        )
        item.pack(fill="x", pady=3)
        accent = tk.Frame(item, bg=self._palette["cyan"] if active else background, width=3)
        accent.pack(side="left", fill="y")
        content = tk.Frame(item, bg=background, padx=10, pady=10)
        content.pack(side="left", fill="x", expand=True)
        icon = {"monitor": "◉", "telemetry": "▦", "audit": "≡", "proxy": "↗"}.get(key, "•")
        tk.Label(content, text=icon, fg=color, bg=background, font=("Segoe UI", 11, "bold")).pack(side="left")
        tk.Label(content, text=number, fg=color, bg=background, font=("Consolas", 8, "bold")).pack(side="left", padx=(10, 0))
        if command is not None:
            button = tk.Button(
                content,
                textvariable=self._text(key),
                command=command,
                anchor="w",
                fg=self._palette["text"],
                bg=background,
                activebackground="#203f4a",
                activeforeground=self._palette["cyan"],
                relief="flat",
                borderwidth=0,
                padx=9,
                font=("Segoe UI", 9),
            )
            button.pack(side="left", fill="x", expand=True)
            self._bind_hover(button, background, "#203f4a")
        else:
            tk.Label(content, textvariable=self._text(key), fg=self._palette["text"], bg=background, font=("Segoe UI", 9, "bold")).pack(side="left", padx=(9, 0))

    def _bind_hover(self, widget: tk.Button, normal: str, hover: str) -> None:
        widget.bind("<Enter>", lambda _event: widget.configure(bg=hover))
        widget.bind("<Leave>", lambda _event: widget.configure(bg=normal))

    def _animate_status(self) -> None:
        active = self._process is not None or self._proxy_process is not None
        if active:
            self._pulse_state = not self._pulse_state
            self._status_dot.configure(fg="#8cf5bd" if self._pulse_state else self._palette["green"])
        else:
            self._status_dot.configure(fg=self._palette["muted"])
        self._pulse_job = self._root.after(700, self._animate_status)

    def _show_page(self, key: str) -> tk.Frame:
        page = self._pages.get(key)
        if page is None or not page.winfo_exists():
            page = tk.Frame(self._root, bg=self._palette["bg"], padx=44, pady=40)
            self._pages[key] = page
        for current in self._pages.values():
            if current.winfo_exists():
                current.pack_forget()
        page.pack(side="left", fill="both", expand=True)
        return page

    def _show_monitor_page(self) -> None:
        if self._monitor_page is not None:
            self._show_page("monitor")

    def _new_page(self, key: str) -> tk.Frame:
        old_page = self._pages.get(key)
        if old_page is not None and old_page.winfo_exists():
            old_page.destroy()
        page = tk.Frame(self._root, bg=self._palette["bg"], padx=44, pady=40)
        self._pages[key] = page
        self._show_page(key)
        return page

    def _open_telemetry_panel(self) -> None:
        if self._telemetry_window is not None and self._telemetry_window.winfo_exists():
            self._show_page("telemetry")
            self._refresh_telemetry_view()
            return
        palette = self._palette
        window = self._new_page("telemetry")
        self._telemetry_window = window

        header = tk.Frame(window, bg=palette["bg"], padx=24, pady=20)
        header.pack(fill="x")
        tk.Label(header, text="Dữ liệu hoạt động", fg=palette["text"], bg=palette["bg"], font=("Bahnschrift", 22, "bold")).pack(side="left")
        tk.Label(header, text="Realtime telemetry", fg=palette["cyan"], bg=palette["bg"], font=("Consolas", 9, "bold")).pack(side="right", pady=(8, 0))

        summary = tk.Frame(window, bg=palette["bg"], padx=24)
        summary.pack(fill="x")
        self._telemetry_cards = {}
        for column, (key, label, color) in enumerate((
            ("events", "EVENTS OBSERVED", palette["cyan"]),
            ("alerts", "RISK SIGNALS", palette["red"]),
            ("sources", "UNIQUE SOURCES", palette["amber"]),
        )):
            card = tk.Frame(summary, bg=palette["panel"], padx=16, pady=12, highlightthickness=1, highlightbackground=palette["line"])
            card.grid(row=0, column=column, sticky="nsew", padx=(0, 10 if column < 3 else 0))
            summary.grid_columnconfigure(column, weight=1)
            tk.Label(card, text=label, fg=palette["muted"], bg=palette["panel"], font=("Segoe UI", 8, "bold")).pack(anchor="w")
            value = tk.StringVar(value="0")
            self._telemetry_cards[key] = value
            tk.Label(card, textvariable=value, fg=color, bg=palette["panel"], font=("Bahnschrift", 20, "bold")).pack(anchor="w", pady=(5, 0))

        body = tk.Frame(window, bg=palette["panel"], padx=16, pady=14, highlightthickness=1, highlightbackground=palette["line"])
        body.pack(fill="both", expand=True, padx=24, pady=(16, 24))
        top = tk.Frame(body, bg=palette["panel"])
        top.pack(fill="x", pady=(0, 8))
        tk.Label(top, text="EVENT STREAM", fg=palette["text"], bg=palette["panel"], font=("Segoe UI", 9, "bold")).pack(side="left")
        tk.Label(top, textvariable=self._top_sources, fg=palette["amber"], bg=palette["panel"], font=("Consolas", 8)).pack(side="right")
        columns = ("time", "event", "source", "user", "severity", "details")
        self._telemetry_tree = ttk.Treeview(body, columns=columns, show="headings", style="GlobalBan.Treeview")
        headings = {"time": "Time", "event": "Event ID", "source": "Source", "user": "User", "severity": "Severity", "details": "Details"}
        widths = {"time": 80, "event": 80, "source": 150, "user": 130, "severity": 90, "details": 470}
        for column in columns:
            self._telemetry_tree.heading(column, text=headings[column])
            self._telemetry_tree.column(column, width=widths[column], anchor="w")
        self._telemetry_tree.pack(fill="both", expand=True)
        self._refresh_telemetry_view()

    def _refresh_telemetry_view(self) -> None:
        if self._telemetry_window is None or not self._telemetry_window.winfo_exists():
            return
        cards = getattr(self, "_telemetry_cards", {})
        if cards:
            cards["events"].set(str(self._event_count))
            cards["alerts"].set(str(self._alert_count))
            cards["sources"].set(str(len(self._source_counts)))
        if self._telemetry_tree is None:
            return
        for item in self._telemetry_tree.get_children():
            self._telemetry_tree.delete(item)
        for row in self._event_rows[-50:]:
            self._telemetry_tree.insert("", "end", values=row)

    def _close_telemetry_panel(self) -> None:
        if self._telemetry_window is not None:
            self._telemetry_window.destroy()
        self._telemetry_window = None
        self._telemetry_tree = None

    def _open_audit_panel(self) -> None:
        if self._audit_window is not None and self._audit_window.winfo_exists():
            self._show_page("audit")
            self._refresh_audit_view()
            return
        palette = self._palette
        window = self._new_page("audit")
        self._audit_window = window

        header = tk.Frame(window, bg=palette["bg"], padx=24, pady=20)
        header.pack(fill="x")
        tk.Label(header, text="Nhật ký kiểm tra", fg=palette["text"], bg=palette["bg"], font=("Bahnschrift", 22, "bold")).pack(side="left")
        tk.Button(header, text="Làm mới", command=self._refresh_audit_view, bg=palette["cyan"], fg="#071417", relief="flat", padx=14, pady=6).pack(side="right")

        body = tk.Frame(window, bg=palette["panel"], padx=16, pady=14, highlightthickness=1, highlightbackground=palette["line"])
        body.pack(fill="both", expand=True, padx=24, pady=(0, 24))
        tk.Label(body, text="AUDIT TRAIL / JSON-LINES", fg=palette["muted"], bg=palette["panel"], font=("Segoe UI", 8, "bold")).pack(anchor="w", pady=(0, 8))
        columns = ("timestamp", "event", "details")
        self._audit_tree = ttk.Treeview(body, columns=columns, show="headings", style="GlobalBan.Treeview")
        self._audit_tree.heading("timestamp", text="Timestamp")
        self._audit_tree.heading("event", text="Event")
        self._audit_tree.heading("details", text="Details")
        self._audit_tree.column("timestamp", width=210, anchor="w")
        self._audit_tree.column("event", width=220, anchor="w")
        self._audit_tree.column("details", width=620, anchor="w")
        self._audit_tree.pack(fill="both", expand=True)
        self._refresh_audit_view()

    def _audit_path(self) -> Path:
        config_path = self._resolve_config_path()
        if not config_path.exists():
            return Path("globalban-audit.jsonl")
        try:
            data = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
            audit = data.get("audit", {}) if isinstance(data, dict) else {}
            path = audit.get("path", "globalban-audit.jsonl") if isinstance(audit, dict) else "globalban-audit.jsonl"
            return Path(path)
        except (OSError, ValueError, yaml.YAMLError):
            return Path("globalban-audit.jsonl")

    def _refresh_audit_view(self) -> None:
        if self._audit_window is None or not self._audit_window.winfo_exists() or self._audit_tree is None:
            return
        for item in self._audit_tree.get_children():
            self._audit_tree.delete(item)
        path = self._audit_path()
        if not path.exists():
            self._audit_tree.insert("", "end", values=("-", "No audit file", str(path)))
            return
        try:
            lines = path.read_text(encoding="utf-8").splitlines()[-300:]
        except OSError as exc:
            self._audit_tree.insert("", "end", values=("-", "Read error", str(exc)))
            return
        for line in lines:
            try:
                record = json.loads(line)
                details = {key: value for key, value in record.items() if key not in {"timestamp", "event"}}
                self._audit_tree.insert(
                    "", "end", values=(record.get("timestamp", "-"), record.get("event", "-"), json.dumps(details, ensure_ascii=False, default=str)[:700])
                )
            except json.JSONDecodeError:
                self._audit_tree.insert("", "end", values=("-", "Invalid JSON", line[:700]))

    def _close_audit_panel(self) -> None:
        if self._audit_window is not None:
            self._audit_window.destroy()
        self._audit_window = None
        self._audit_tree = None

    def _open_proxy_panel(self) -> None:
        if self._proxy_window is not None and self._proxy_window.winfo_exists():
            self._show_page("proxy")
            return

        palette = self._palette
        window = self._new_page("proxy")
        self._proxy_window = window

        header = tk.Frame(window, bg=palette["bg"], padx=24, pady=20)
        header.pack(fill="x")
        title_block = tk.Frame(header, bg=palette["bg"])
        title_block.pack(side="left")
        tk.Label(title_block, text="UBUNTU PROXY NODE / CONTROL CENTER", fg=palette["cyan"], bg=palette["bg"], font=("Consolas", 8, "bold")).pack(anchor="w")
        tk.Label(title_block, text="Egress Proxy", fg=palette["text"], bg=palette["bg"], font=("Bahnschrift", 26, "bold")).pack(anchor="w", pady=(4, 0))
        tk.Label(title_block, text="Kiểm soát luồng AI outbound qua privacy allowlist", fg=palette["muted"], bg=palette["bg"], font=("Segoe UI", 9)).pack(anchor="w", pady=(3, 0))
        tk.Label(
            header,
            textvariable=self._proxy_status,
            fg=palette["green"],
            bg="#10251f",
            padx=12,
            pady=6,
            font=("Segoe UI", 9, "bold"),
        ).pack(side="right")

        node = tk.Frame(window, bg=palette["panel"], padx=18, pady=12, highlightthickness=1, highlightbackground=palette["line"])
        node.pack(fill="x", padx=24, pady=(0, 14))
        node_left = tk.Frame(node, bg=palette["panel"])
        node_left.pack(side="left")
        tk.Label(node_left, text="PROXY SERVER", fg=palette["muted"], bg=palette["panel"], font=("Consolas", 7, "bold")).pack(anchor="w")
        tk.Label(node_left, text="ubuntu@192.168.52.131", fg=palette["text"], bg=palette["panel"], font=("Consolas", 10, "bold")).pack(anchor="w", pady=(4, 0))
        tk.Label(node_left, text="Ubuntu 22.04.5 LTS  ·  DataSource DataSourceNone", fg=palette["muted"], bg=palette["panel"], font=("Segoe UI", 8)).pack(anchor="w", pady=(2, 0))
        node_status = tk.Frame(node, bg=palette["panel"])
        node_status.pack(side="right", anchor="center")
        tk.Label(node_status, text="SSH", fg=palette["muted"], bg=palette["panel"], font=("Consolas", 8, "bold")).pack(side="left", padx=(0, 8))
        tk.Label(node_status, text="CHƯA KẾT NỐI", fg=palette["amber"], bg="#2b2414", padx=10, pady=5, font=("Segoe UI", 8, "bold")).pack(side="left")

        signal_row = tk.Frame(window, bg=palette["bg"], padx=24)
        signal_row.pack(fill="x", pady=(0, 16))
        for column, title, value, color in (
            (0, "LISTEN MODE", "Local process", palette["cyan"]),
            (1, "PRIVACY GATE", "Allowlisted only", palette["green"]),
            (2, "UPSTREAM", "AI API relay", palette["amber"]),
            (3, "REQUESTS", "Chưa có dữ liệu", palette["muted"]),
        ):
            card = tk.Frame(signal_row, bg=palette["panel"], padx=14, pady=10, highlightthickness=1, highlightbackground=palette["line"])
            card.grid(row=0, column=column, sticky="nsew", padx=(0, 10 if column < 2 else 0))
            signal_row.grid_columnconfigure(column, weight=1)
            tk.Label(card, text=title, fg=palette["muted"], bg=palette["panel"], font=("Consolas", 7, "bold")).pack(anchor="w")
            tk.Label(card, text=value, fg=color, bg=palette["panel"], font=("Segoe UI", 10, "bold")).pack(anchor="w", pady=(5, 0))

        config = tk.Frame(
            window,
            bg=palette["panel"],
            padx=18,
            pady=16,
            highlightthickness=1,
            highlightbackground=palette["line"],
        )
        config.pack(fill="x", padx=24)
        tk.Label(
            config,
            text="CẤU HÌNH KẾT NỐI",
            fg=palette["muted"],
            bg=palette["panel"],
            font=("Segoe UI", 8, "bold"),
        ).pack(anchor="w", pady=(0, 10))
        fields = tk.Frame(config, bg=palette["panel"])
        fields.pack(fill="x")
        self._proxy_field(fields, "Bind host (IP máy này)", self._proxy_bind, 16, 0)
        self._proxy_field(fields, "Port", self._proxy_port, 8, 1)
        self._proxy_field(fields, "Upstream", self._proxy_upstream, 48, 2)
        actions = tk.Frame(config, bg=palette["panel"])
        actions.pack(fill="x", pady=(14, 0))
        self._proxy_start_button = tk.Button(
            actions,
            text="Bật proxy",
            command=self._start_proxy,
            bg=palette["green"],
            fg="#07130e",
            activebackground="#6ee8ad",
            relief="flat",
            padx=16,
            pady=7,
            font=("Segoe UI", 9, "bold"),
        )
        self._proxy_start_button.pack(side="left")
        self._proxy_stop_button = tk.Button(
            actions,
            text="Tắt proxy",
            command=self._stop_proxy,
            state="disabled",
            bg=palette["red"],
            fg="white",
            activebackground="#ff8e98",
            relief="flat",
            padx=16,
            pady=7,
            font=("Segoe UI", 9, "bold"),
        )
        self._proxy_stop_button.pack(side="left", padx=(8, 0))
        tk.Button(
            actions,
            text="Dùng proxy cho AI",
            command=self._use_proxy_for_ai,
            bg=palette["cyan"],
            fg="#071417",
            activebackground="#82e6e2",
            relief="flat",
            padx=14,
            pady=7,
            font=("Segoe UI", 9, "bold"),
        ).pack(side="left", padx=(8, 0))
        tk.Label(
            actions,
            text="SSH control chưa kết nối · local proxy vẫn có thể chạy độc lập",
            fg=palette["muted"],
            bg=palette["panel"],
            font=("Segoe UI", 8),
        ).pack(side="right")

        terminal = tk.Frame(
            window,
            bg=palette["panel"],
            padx=14,
            pady=14,
            highlightthickness=1,
            highlightbackground=palette["line"],
        )
        terminal.pack(fill="both", expand=True, padx=24, pady=(16, 24))
        terminal_header = tk.Frame(terminal, bg=palette["panel"])
        terminal_header.pack(fill="x", pady=(0, 8))
        tk.Label(terminal_header, text="●", fg=palette["green"], bg=palette["panel"], font=("Segoe UI", 11)).pack(side="left")
        tk.Label(terminal_header, text="PROXY TERMINAL / LIVE OUTPUT", fg=palette["text"], bg=palette["panel"], font=("Segoe UI", 9, "bold")).pack(side="left", padx=(7, 0))
        tk.Label(terminal_header, text="stdout + stderr", fg=palette["muted"], bg=palette["panel"], font=("Consolas", 8)).pack(side="right")
        self._proxy_log = tk.Text(
            terminal,
            bg="#080b10",
            fg="#b9c9d8",
            insertbackground=palette["text"],
            relief="flat",
            wrap="word",
            state="disabled",
            font=("Cascadia Mono", 9),
        )
        self._proxy_log.pack(fill="both", expand=True)
        self._proxy_log.tag_configure("error", foreground=palette["red"])
        self._proxy_log.tag_configure("ok", foreground=palette["green"])
        self._proxy_log.tag_configure("normal", foreground="#b9c9d8")
        for line in self._proxy_lines:
            self._append_proxy_log(line)
        if self._proxy_process is not None:
            self._proxy_status.set("Đang chạy")

    def _proxy_field(
        self, parent: tk.Frame, label: str, variable: tk.StringVar, width: int, column: int
    ) -> None:
        frame = tk.Frame(parent, bg=self._palette["panel"])
        frame.grid(row=0, column=column, sticky="ew", padx=(0, 10 if column < 2 else 0))
        parent.grid_columnconfigure(column, weight=1 if column == 2 else 0)
        tk.Label(
            frame,
            text=label,
            fg=self._palette["muted"],
            bg=self._palette["panel"],
            font=("Segoe UI", 8, "bold"),
        ).pack(anchor="w", pady=(0, 4))
        tk.Entry(
            frame,
            textvariable=variable,
            width=width,
            bg=self._palette["panel_alt"],
            fg=self._palette["text"],
            insertbackground=self._palette["text"],
            relief="flat",
        ).pack(fill="x", ipady=6)

    def _append_proxy_log(self, line: str) -> None:
        if self._proxy_log is None or not self._proxy_log.winfo_exists():
            return
        tag = "error" if "error" in line.lower() or "traceback" in line.lower() else "ok" if "listening" in line.lower() else "normal"
        self._proxy_log.configure(state="normal")
        self._proxy_log.insert("end", line + "\n", tag)
        self._proxy_log.see("end")
        self._proxy_log.configure(state="disabled")

    def _start_proxy(self) -> None:
        if self._proxy_process is not None and self._proxy_process.poll() is None:
            return
        try:
            port = int(self._proxy_port.get().strip())
            if not 1 <= port <= 65535:
                raise ValueError("Port phải nằm trong khoảng 1 đến 65535")
            bind_host = self._proxy_bind.get().strip()
            upstream = self._proxy_upstream.get().strip()
            if not bind_host or not upstream.startswith(("http://", "https://")):
                raise ValueError("Bind host và upstream phải hợp lệ")
            self._validate_proxy_bind_host(bind_host)
        except ValueError as exc:
            messagebox.showerror("Cấu hình proxy", str(exc), parent=self._proxy_window)
            return
        env = os.environ.copy()
        env.update(
            {
                "GLOBALBAN_PROXY_BIND": bind_host,
                "GLOBALBAN_PROXY_PORT": str(port),
                "GLOBALBAN_PROXY_UPSTREAM": upstream,
            }
        )
        try:
            self._proxy_process = subprocess.Popen(
                [sys.executable, "-m", "globalban.proxy"],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                cwd=Path(__file__).resolve().parents[2],
                env=env,
            )
        except OSError as exc:
            self._append_proxy_log(f"[ERROR] Không thể khởi động proxy: {exc}")
            return
        self._proxy_status.set("Đang khởi động")
        self._proxy_lines.append(f"[INFO] Starting proxy on {bind_host}:{port}")
        self._append_proxy_log(self._proxy_lines[-1])
        self._proxy_start_button.configure(state="disabled")
        self._proxy_stop_button.configure(state="normal")
        threading.Thread(target=self._read_proxy_output, daemon=True).start()

    @staticmethod
    def _validate_proxy_bind_host(bind_host: str) -> None:
        try:
            addresses = socket.getaddrinfo(bind_host, 0, type=socket.SOCK_STREAM)
            for family, socktype, protocol, _canonname, sockaddr in addresses:
                with socket.socket(family, socktype, protocol) as probe:
                    probe.bind(sockaddr)
                    return
        except (OSError, socket.gaierror) as exc:
            raise ValueError(
                f"Bind host '{bind_host}' không thuộc máy này. "
                "Dùng 127.0.0.1 hoặc một IP local của máy Windows."
            ) from exc
        raise ValueError(f"Không thể kiểm tra bind host '{bind_host}'")

    def _read_proxy_output(self) -> None:
        if self._proxy_process is None or self._proxy_process.stdout is None:
            return
        for line in self._proxy_process.stdout:
            self._proxy_output_queue.put(line.rstrip())

    def _stop_proxy(self) -> None:
        process = self._proxy_process
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
        self._proxy_process = None
        self._proxy_status.set("Đã tắt")
        if self._proxy_window is not None and self._proxy_window.winfo_exists():
            self._proxy_start_button.configure(state="normal")
            self._proxy_stop_button.configure(state="disabled")

    def _use_proxy_for_ai(self) -> None:
        if self._proxy_process is None or self._proxy_process.poll() is not None:
            messagebox.showwarning(
                "Proxy chưa chạy",
                "Hãy bật proxy trước khi route AI qua endpoint local.",
                parent=self._proxy_window,
            )
            return
        try:
            port = int(self._proxy_port.get().strip())
            bind_host = self._proxy_bind.get().strip()
            endpoint = f"http://{bind_host}:{port}/v1"
            config_path = self._resolve_config_path()
            if config_path.exists():
                data = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
            else:
                example = config_path.parent / "config.example.yaml"
                data = yaml.safe_load(example.read_text(encoding="utf-8")) if example.exists() else {}
            if not isinstance(data, dict):
                raise ValueError("configuration root must be a mapping")
            ai = data.setdefault("ai", {})
            if not isinstance(ai, dict):
                raise ValueError("ai configuration must be a mapping")
            ai["base_url"] = endpoint
            config_path.parent.mkdir(parents=True, exist_ok=True)
            config_path.write_text(
                yaml.safe_dump(data, sort_keys=False, allow_unicode=True),
                encoding="utf-8",
            )
            self._ai_base_url.set(endpoint)
            self._proxy_lines.append(f"[INFO] AI endpoint routed through {endpoint}")
            self._append_proxy_log(self._proxy_lines[-1])
            messagebox.showinfo(
                "AI đã route qua proxy",
                f"Endpoint đã lưu: {endpoint}\nKhởi động lại monitor để áp dụng.",
                parent=self._proxy_window,
            )
        except (OSError, ValueError, yaml.YAMLError) as exc:
            messagebox.showerror("Không thể route AI", str(exc), parent=self._proxy_window)

    def _close_proxy_panel(self) -> None:
        if self._proxy_window is not None:
            self._proxy_window.destroy()
        self._proxy_window = None
        self._proxy_log = None

    # ── LIVE RED TEAM PANEL ────────────────────────────────────────────────

    def _open_live_panel(self) -> None:
        """Mở/hiển thị bảng cảnh báo realtime từ live_monitor.py."""
        palette = self._palette
        if self._live_window is not None and self._live_window.winfo_exists():
            self._show_page("live")
            self._refresh_live_view()
            return
        window = self._new_page("live")
        self._live_window = window
        # Header
        header = tk.Frame(window, bg=palette["bg"])
        header.pack(fill="x", pady=(0, 16))
        left = tk.Frame(header, bg=palette["bg"])
        left.pack(side="left")
        tk.Label(left, text="🔴  LIVE RED TEAM DETECTOR", fg=palette["red"],
                 bg=palette["bg"], font=("Bahnschrift", 22, "bold")).pack(anchor="w")
        tk.Label(left, text="Cảnh báo realtime từ live_monitor.py — tự động làm mới mỗi 3 giây",
                 fg=palette["muted"], bg=palette["bg"], font=("Segoe UI", 9)).pack(anchor="w", pady=(3, 0))
        btn_frame = tk.Frame(header, bg=palette["bg"])
        btn_frame.pack(side="right", anchor="n")
        self._live_monitor_status = tk.StringVar(value="Chưa chạy")
        tk.Label(btn_frame, textvariable=self._live_monitor_status,
                 fg=palette["amber"], bg=palette["bg"], font=("Consolas", 8, "bold")).pack(side="left", padx=(0, 10))
        tk.Button(btn_frame, text="▶  Khởi động Live Monitor",
                  command=self._start_live_monitor,
                  bg=palette["red"], fg="white", relief="flat",
                  padx=14, pady=6, font=("Segoe UI", 9, "bold")).pack(side="left")
        tk.Button(btn_frame, text="↺  Làm mới",
                  command=self._refresh_live_view,
                  bg=palette["panel_alt"], fg=palette["text"], relief="flat",
                  padx=10, pady=6).pack(side="left", padx=(8, 0))
        # Cards thống kê
        cards_frame = tk.Frame(window, bg=palette["bg"])
        cards_frame.pack(fill="x", pady=(0, 14))
        self._live_alert_count_var = tk.StringVar(value="0")
        self._live_critical_var = tk.StringVar(value="0")
        self._live_high_var = tk.StringVar(value="0")
        self._live_last_event_var = tk.StringVar(value="—")
        for col, (label, var, color) in enumerate([
            ("TỔNG CẢNH BÁO", self._live_alert_count_var, palette["red"]),
            ("CRITICAL (>=90)", self._live_critical_var, "#ff3355"),
            ("HIGH (60-89)", self._live_high_var, palette["amber"]),
            ("SU KIEN GAN NHAT", self._live_last_event_var, palette["cyan"]),
        ]):
            card = tk.Frame(cards_frame, bg=palette["panel"], padx=14, pady=12,
                            highlightthickness=1, highlightbackground=palette["line"])
            card.grid(row=0, column=col, sticky="nsew", padx=(0, 10 if col < 3 else 0))
            cards_frame.grid_columnconfigure(col, weight=1)
            tk.Label(card, text=label, fg=palette["muted"], bg=palette["panel"],
                     font=("Segoe UI", 8, "bold")).pack(anchor="w")
            tk.Label(card, textvariable=var, fg=color, bg=palette["panel"],
                     font=("Bahnschrift", 20, "bold")).pack(anchor="w", pady=(5, 0))
        # Bảng cảnh báo chính
        body = tk.Frame(window, bg=palette["panel"], padx=16, pady=14,
                        highlightthickness=1, highlightbackground=palette["line"])
        body.pack(fill="both", expand=True)
        top_row = tk.Frame(body, bg=palette["panel"])
        top_row.pack(fill="x", pady=(0, 8))
        self._live_pulse_dot = tk.Label(top_row, text="●", fg=palette["red"],
                                         bg=palette["panel"], font=("Segoe UI", 13))
        self._live_pulse_dot.pack(side="left")
        tk.Label(top_row, text="BANG CANH BAO REALTIME",
                 fg=palette["text"], bg=palette["panel"],
                 font=("Segoe UI", 10, "bold")).pack(side="left", padx=(7, 0))
        self._live_file_label = tk.StringVar(value="globalban-live-alerts.jsonl")
        tk.Label(top_row, textvariable=self._live_file_label,
                 fg=palette["muted"], bg=palette["panel"],
                 font=("Consolas", 8)).pack(side="right")
        cols_def = ("time", "severity", "score", "host", "user", "events", "reasons")
        self._live_tree = ttk.Treeview(body, columns=cols_def, show="headings",
                                        style="GlobalBan.Treeview")
        heads = {"time": "Thoi gian", "severity": "Muc do", "score": "Score",
                 "host": "Host", "user": "User", "events": "Event IDs", "reasons": "Ly do"}
        widths = {"time": 85, "severity": 80, "score": 60, "host": 160,
                  "user": 110, "events": 100, "reasons": 450}
        for c in cols_def:
            self._live_tree.heading(c, text=heads[c])
            self._live_tree.column(c, width=widths[c], anchor="w")
        self._live_tree.tag_configure("critical", background="#2d0a0d", foreground="#ff6b78")
        self._live_tree.tag_configure("high",     background="#1e1800", foreground="#f2c65c")
        self._live_tree.tag_configure("event",    background="#0d1a2a", foreground="#49a6ff")
        scrollbar = ttk.Scrollbar(body, orient="vertical", command=self._live_tree.yview)
        self._live_tree.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")
        self._live_tree.pack(fill="both", expand=True)
        self._live_prev_critical = 0
        self._refresh_live_view()
        self._schedule_live_refresh()

    def _schedule_live_refresh(self) -> None:
        if self._live_window is None or not self._live_window.winfo_exists():
            return
        self._refresh_live_view()
        try:
            current = self._live_pulse_dot.cget("fg")
            next_color = "#ff3355" if current == self._palette["red"] else self._palette["red"]
            self._live_pulse_dot.configure(fg=next_color)
        except Exception:
            pass
        self._root.after(3000, self._schedule_live_refresh)

    def _refresh_live_view(self) -> None:
        import json as _json
        from pathlib import Path as _Path
        if self._live_tree is None or not self._live_tree.winfo_exists():
            return
        alert_file = _Path(__file__).resolve().parents[2] / "globalban-live-alerts.jsonl"
        if hasattr(self, "_live_file_label") and self._live_file_label is not None:
            self._live_file_label.set(str(alert_file.resolve()))
        rows_alert: list[tuple] = []
        rows_event: list[tuple] = []
        total_alerts = 0
        critical_count = 0
        high_count = 0
        last_event_id = "—"
        if alert_file.exists():
            try:
                lines = alert_file.read_text(encoding="utf-8").splitlines()
                for line in lines:
                    try:
                        rec = _json.loads(line)
                    except _json.JSONDecodeError:
                        continue
                    evt = rec.get("event", "")
                    ts = rec.get("timestamp", "")[:19].replace("T", " ")
                    if evt == "LIVE_ALERT":
                        total_alerts += 1
                        score = rec.get("score", 0)
                        severity = rec.get("severity", "HIGH")
                        if severity == "CRITICAL":
                            critical_count += 1
                        else:
                            high_count += 1
                        rows_alert.append((
                            ts, severity, str(score),
                            rec.get("host", "-"), rec.get("username", "-"),
                            str(rec.get("event_ids", [])),
                            " | ".join(rec.get("reasons", [])),
                        ))
                    elif evt == "WINDOWS_EVENT":
                        last_event_id = f"EID {rec.get('event_id','?')} {ts[11:]}"
                        rows_event.append((
                            ts, "EVENT", "-",
                            rec.get("host", "-"), rec.get("username", "-"),
                            str(rec.get("event_id", "")),
                            rec.get("detail", "")[:120],
                        ))
            except OSError:
                pass
        if self._live_alert_count_var is not None:
            self._live_alert_count_var.set(str(total_alerts))
        if hasattr(self, "_live_critical_var") and self._live_critical_var is not None:
            self._live_critical_var.set(str(critical_count))
        if hasattr(self, "_live_high_var") and self._live_high_var is not None:
            self._live_high_var.set(str(high_count))
        if hasattr(self, "_live_last_event_var") and self._live_last_event_var is not None:
            self._live_last_event_var.set(last_event_id)
        for item in self._live_tree.get_children():
            self._live_tree.delete(item)
        for row in list(reversed(rows_alert[-50:])):
            tag = "critical" if row[1] == "CRITICAL" else "high"
            self._live_tree.insert("", "end", values=row, tags=(tag,))
        for row in list(reversed(rows_event[-20:])):
            self._live_tree.insert("", "end", values=row, tags=("event",))
        new_critical = critical_count
        prev = getattr(self, "_live_prev_critical", 0)
        if new_critical > prev and new_critical > 0 and rows_alert:
            self._show_critical_popup(rows_alert[-1])
        self._live_prev_critical = new_critical

    def _show_critical_popup(self, row: tuple) -> None:
        try:
            popup = tk.Toplevel(self._root)
            popup.title("CRITICAL ALERT — RED TEAM DETECTED")
            popup.configure(bg="#1a0505")
            popup.geometry("520x220")
            popup.resizable(False, False)
            popup.attributes("-topmost", True)
            info = f"Host: {row[3]}  |  User: {row[4]}\nScore: {row[2]}/100  |  Events: {row[5]}\n{row[6][:80]}"
            tk.Label(popup, text="PHAT HIEN TAN CONG!",
                     fg="#ff3355", bg="#1a0505",
                     font=("Bahnschrift", 20, "bold")).pack(pady=(22, 8))
            tk.Label(popup, text=info, fg="#ffcccc", bg="#1a0505",
                     font=("Consolas", 10), justify="left").pack(padx=22)
            tk.Button(popup, text="OK — Da biet", command=popup.destroy,
                      bg="#ff3355", fg="white", relief="flat",
                      padx=20, pady=8, font=("Segoe UI", 10, "bold")).pack(pady=(18, 0))
            self._root.after(15000, lambda: popup.destroy() if popup.winfo_exists() else None)
        except Exception:
            pass

    def _start_live_monitor(self) -> None:
        import subprocess as _sp
        import sys as _sys
        from pathlib import Path as _Path
        monitor_script = _Path(__file__).resolve().parents[2] / "live_monitor.py"
        if not monitor_script.exists():
            messagebox.showerror("Live Monitor",
                                 f"Khong tim thay live_monitor.py tai:\n{monitor_script}")
            return
        try:
            _sp.Popen(
                [_sys.executable, str(monitor_script)],
                cwd=str(monitor_script.parent),
                creationflags=getattr(_sp, "CREATE_NEW_CONSOLE", 0),
            )
            if hasattr(self, "_live_monitor_status") and self._live_monitor_status is not None:
                self._live_monitor_status.set("DANG CHAY")
        except OSError as exc:
            messagebox.showerror("Live Monitor", f"Khong the khoi dong: {exc}")

    # ── AI SOC CHAT PANEL (NATURAL LANGUAGE) ───────────────────────────────

    def _open_chat_panel(self) -> None:
        """Mở giao diện Chat bằng ngôn ngữ tự nhiên với GlobalBan AI SOC Agent."""
        palette = self._palette
        if self._chat_window is not None and self._chat_window.winfo_exists():
            self._show_page("chat")
            if self._chat_entry is not None and self._chat_entry.winfo_exists():
                self._root.after(50, self._chat_entry.focus_set)
            return
        window = self._new_page("chat")
        self._chat_window = window

        header = tk.Frame(window, bg=palette["bg"])
        header.pack(fill="x", pady=(0, 14))
        left = tk.Frame(header, bg=palette["bg"])
        left.pack(side="left")
        tk.Label(
            left,
            text="💬  AI SOC AGENT ",
            fg=palette["cyan"],
            bg=palette["bg"],
            font=("Bahnschrift", 22, "bold"),
        ).pack(anchor="w")
        tk.Label(
            left,
            text="Đặt câu hỏi bằng Tiếng Việt hoặc Tiếng Anh về cảnh báo Windows, UEBA Baseline, 12 Tools và kho RAG (AD-GEN, LOLBin, MITRE)",
            fg=palette["muted"],
            bg=palette["bg"],
            font=("Segoe UI", 9),
        ).pack(anchor="w", pady=(3, 0))

        # Khung hội thoại
        body = tk.Frame(
            window,
            bg=palette["panel"],
            padx=16,
            pady=14,
            highlightthickness=1,
            highlightbackground=palette["line"],
        )
        body.pack(fill="both", expand=True)

        self._chat_log = tk.Text(
            body,
            bg="#080b10",
            fg=palette["text"],
            insertbackground=palette["text"],
            relief="flat",
            wrap="word",
            state="disabled",
            font=("Segoe UI", 10),
            padx=12,
            pady=10,
        )
        scrollbar = ttk.Scrollbar(body, orient="vertical", command=self._chat_log.yview)
        self._chat_log.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")
        self._chat_log.pack(fill="both", expand=True)

        self._chat_log.tag_configure("user", foreground=palette["amber"], font=("Segoe UI", 10, "bold"))
        self._chat_log.tag_configure("agent_header", foreground=palette["cyan"], font=("Consolas", 9, "bold"))
        self._chat_log.tag_configure("agent_body", foreground="#dbe7f0", font=("Segoe UI", 10))
        self._chat_log.tag_configure("meta", foreground=palette["green"], font=("Consolas", 8))

        # Thanh công cụ thông minh: Nút gợi ý câu hỏi tiếp theo + Phản hồi 👍/👎
        smart_bar = tk.Frame(window, bg=palette["bg"])
        smart_bar.pack(fill="x", pady=(10, 0))
        self._chat_suggestions_frame = tk.Frame(smart_bar, bg=palette["bg"])
        self._chat_suggestions_frame.pack(side="left", fill="x", expand=True)
        self._chat_feedback_frame = tk.Frame(smart_bar, bg=palette["bg"])
        self._chat_feedback_frame.pack(side="right")

        self._render_follow_up_suggestions(
            (
                "Hôm nay có hành vi gì bất thường không?",
                "Trạng thái hồ sơ UEBA Baseline hiện tại thế nào?",
                "Phân tích kỹ thuật MITRE T1059.001 PowerShell",
            )
        )

        # Thanh nhập câu hỏi
        input_bar = tk.Frame(window, bg=palette["panel"], padx=14, pady=12, highlightthickness=1, highlightbackground=palette["line"])
        input_bar.pack(fill="x", pady=(10, 0))
        entry = tk.Entry(
            input_bar,
            textvariable=self._chat_input,
            bg=palette["panel_alt"],
            fg=palette["text"],
            insertbackground=palette["text"],
            relief="flat",
            font=("Segoe UI", 10),
        )
        self._chat_entry = entry
        entry.pack(side="left", fill="x", expand=True, ipady=8, padx=(0, 10))
        entry.bind("<Return>", lambda _e: self._submit_chat())
        entry.bind("<Alt-space>", lambda _e: "break")
        tk.Button(
            input_bar,
            text="Gửi câu hỏi ➔",
            command=self._submit_chat,
            bg=palette["cyan"],
            fg="#071417",
            activebackground="#82e6e2",
            relief="flat",
            padx=18,
            pady=7,
            font=("Segoe UI", 9, "bold"),
        ).pack(side="left")
        tk.Button(
            input_bar,
            text="Xóa hội thoại",
            command=self._clear_chat,
            bg=palette["panel_alt"],
            fg=palette["muted"],
            relief="flat",
            padx=12,
            pady=7,
            font=("Segoe UI", 9),
        ).pack(side="left", padx=(8, 0))
        self._root.after(50, entry.focus_set)

    def _render_follow_up_suggestions(self, suggestions: tuple[str, ...]) -> None:
        if self._chat_suggestions_frame is None or not self._chat_suggestions_frame.winfo_exists():
            return
        for child in self._chat_suggestions_frame.winfo_children():
            child.destroy()
        if not suggestions:
            return
        palette = self._palette
        tk.Label(
            self._chat_suggestions_frame,
            text="💡 Gợi ý hỏi tiếp:",
            fg=palette["muted"],
            bg=palette["bg"],
            font=("Segoe UI", 8, "bold"),
        ).pack(side="left", padx=(0, 6))
        for q in suggestions[:3]:
            btn = tk.Button(
                self._chat_suggestions_frame,
                text=q,
                command=lambda prompt=q: self._ask_suggested_question(prompt),
                bg=palette["panel_alt"],
                fg=palette["cyan"],
                activebackground="#1c3448",
                activeforeground=palette["text"],
                relief="flat",
                padx=10,
                pady=4,
                font=("Segoe UI", 8),
                cursor="hand2",
            )
            btn.pack(side="left", padx=(0, 6))

    def _ask_suggested_question(self, prompt: str) -> None:
        self._chat_input.set(prompt)
        self._submit_chat()

    def _render_feedback_buttons(self) -> None:
        if self._chat_feedback_frame is None or not self._chat_feedback_frame.winfo_exists():
            return
        for child in self._chat_feedback_frame.winfo_children():
            child.destroy()
        if not self._chat_last_qa:
            return
        palette = self._palette
        tk.Label(
            self._chat_feedback_frame,
            text="Đánh giá câu trả lời:",
            fg=palette["muted"],
            bg=palette["bg"],
            font=("Segoe UI", 8),
        ).pack(side="left", padx=(0, 6))
        tk.Button(
            self._chat_feedback_frame,
            text="👍 Hữu ích",
            command=lambda: self._submit_feedback("up"),
            bg="#10251f",
            fg=palette["green"],
            activebackground="#1d493a",
            activeforeground=palette["green"],
            relief="flat",
            padx=9,
            pady=3,
            font=("Segoe UI", 8, "bold"),
            cursor="hand2",
        ).pack(side="left", padx=(0, 4))
        tk.Button(
            self._chat_feedback_frame,
            text="👎 Chưa tốt",
            command=lambda: self._submit_feedback("down"),
            bg="#261216",
            fg=palette["red"],
            activebackground="#3d1a21",
            activeforeground=palette["red"],
            relief="flat",
            padx=9,
            pady=3,
            font=("Segoe UI", 8, "bold"),
            cursor="hand2",
        ).pack(side="left")

    def _submit_feedback(self, rating: str) -> None:
        if not self._chat_last_qa or self._nl_agent is None:
            return
        try:
            self._nl_agent.record_feedback(  # type: ignore[attr-defined]
                query=self._chat_last_qa.get("query", ""),
                answer=self._chat_last_qa.get("answer", ""),
                rating=rating,
                intent=self._chat_last_qa.get("intent", ""),
                model_used=self._chat_last_qa.get("model", ""),
            )
            if self._chat_feedback_frame is not None and self._chat_feedback_frame.winfo_exists():
                for child in self._chat_feedback_frame.winfo_children():
                    child.destroy()
                msg = "✓ Đã ghi nhận 👍" if rating == "up" else "✓ Đã ghi nhận 👎 (Sẽ tự động tối ưu prompt)"
                color = self._palette["green"] if rating == "up" else self._palette["amber"]
                tk.Label(
                    self._chat_feedback_frame,
                    text=msg,
                    fg=color,
                    bg=self._palette["bg"],
                    font=("Segoe UI", 8, "bold"),
                ).pack(side="left")
        except Exception:
            pass

    def _clear_chat(self) -> None:
        if self._chat_log is None or not self._chat_log.winfo_exists():
            return
        if self._nl_agent is not None and hasattr(self._nl_agent, "clear_memory"):
            self._nl_agent.clear_memory()  # type: ignore[attr-defined]
        self._chat_last_qa.clear()
        self._chat_log.configure(state="normal")
        self._chat_log.delete("1.0", "end")
        self._chat_log.configure(state="disabled")
        if self._chat_feedback_frame is not None and self._chat_feedback_frame.winfo_exists():
            for child in self._chat_feedback_frame.winfo_children():
                child.destroy()
        if self._chat_entry is not None and self._chat_entry.winfo_exists():
            self._chat_entry.focus_set()

    def _append_chat_message(self, sender: str, text: str, *, meta: str = "") -> None:
        if self._chat_log is None or not self._chat_log.winfo_exists():
            return
        self._chat_log.configure(state="normal")
        ts = time.strftime("%H:%M:%S")
        if sender == "Bạn":
            self._chat_log.insert("end", f"\n[{ts}] 👤 BẠN (SOC Analyst):\n", "user")
            self._chat_log.insert("end", f"{text}\n", "agent_body")
        else:
            self._chat_log.insert("end", f"\n[{ts}] 🛡️ CHUYÊN GIA AI SOC", "agent_header")
            if meta:
                self._chat_log.insert("end", f"  ({meta})", "meta")
            self._chat_log.insert("end", "\n", "agent_header")
            self._chat_log.insert("end", f"{text}\n", "agent_body")
            self._chat_log.insert("end", "─" * 85 + "\n", "meta")
        self._chat_log.see("end")
        self._chat_log.configure(state="disabled")

    def _stream_agent_response(
        self,
        *,
        question: str,
        clean_answer: str,
        meta: str,
        intent: str,
        model_used: str,
        suggestions: tuple[str, ...],
    ) -> None:
        """Hiệu ứng Streaming: chữ hiện dần tự nhiên từng cụm từ trên giao diện Chat."""
        if self._chat_log is None or not self._chat_log.winfo_exists():
            return
        ts = time.strftime("%H:%M:%S")
        self._chat_log.configure(state="normal")
        self._chat_log.insert("end", f"\n[{ts}] 🛡️ CHUYÊN GIA AI SOC", "agent_header")
        if meta:
            self._chat_log.insert("end", f"  ({meta})", "meta")
        self._chat_log.insert("end", "\n", "agent_header")
        self._chat_log.configure(state="disabled")

        tokens = re.findall(r"\S+\s*|\n", clean_answer)
        step_size = 2

        def _insert_chunk(idx: int) -> None:
            if self._chat_log is None or not self._chat_log.winfo_exists():
                return
            self._chat_log.configure(state="normal")
            if idx < len(tokens):
                chunk = "".join(tokens[idx : idx + step_size])
                self._chat_log.insert("end", chunk, "agent_body")
                self._chat_log.see("end")
                self._chat_log.configure(state="disabled")
                self._root.after(18, lambda: _insert_chunk(idx + step_size))
            else:
                self._chat_log.insert("end", "\n" + "─" * 85 + "\n", "meta")
                self._chat_log.see("end")
                self._chat_log.configure(state="disabled")
                self._chat_last_qa = {
                    "query": question,
                    "answer": clean_answer,
                    "intent": intent,
                    "model": model_used,
                }
                self._render_follow_up_suggestions(suggestions)
                self._render_feedback_buttons()

        _insert_chunk(0)

    def _submit_chat(self) -> None:
        question = self._chat_input.get().strip()
        if not question:
            return
        self._chat_input.set("")
        if self._chat_entry is not None and self._chat_entry.winfo_exists():
            self._chat_entry.focus_set()
        self._append_chat_message("Bạn", question)
        threading.Thread(target=self._run_chat_query, args=(question,), daemon=True).start()

    def _run_chat_query(self, question: str) -> None:
        from globalban.agent.assistant import NaturalLanguageAgent
        try:
            if self._nl_agent is None:
                self._nl_agent = NaturalLanguageAgent()
            response = self._nl_agent.ask(question)  # type: ignore[attr-defined]
            clean_answer = response.answer.replace("**", "").replace("`", "")
            mem_turns = len(self._nl_agent.history) // 2  # type: ignore[attr-defined]
            meta = (
                f"Model: {response.model_used} [{response.complexity}] | "
                f"Bộ nhớ: {mem_turns} lượt | Bằng chứng: {response.evidence_count}"
            )
            self._root.after(
                0,
                lambda: self._stream_agent_response(
                    question=question,
                    clean_answer=clean_answer,
                    meta=meta,
                    intent=response.intent,
                    model_used=response.model_used,
                    suggestions=response.follow_up_suggestions,
                ),
            )
        except Exception as exc:
            self._root.after(0, lambda: self._append_chat_message("AI SOC Agent", f"[Lỗi xử lý câu hỏi]: {exc}"))

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
        try:
            self._write_ai_settings()
        except (OSError, ValueError, yaml.YAMLError) as exc:
            messagebox.showerror(self._translate("ai_management"), str(exc), parent=dialog)
            return
        dialog.destroy()
        self._ai_status.set(self._translate("ai_on" if self._ai_enabled.get() else "ai_off"))
        messagebox.showinfo(self._translate("ai_management"), self._translate("ai_saved"))

    def _schedule_ai_settings_autosave(self, *_args: str) -> None:
        if self._ai_autosave_job is not None:
            self._root.after_cancel(self._ai_autosave_job)
        self._ai_autosave_job = self._root.after(600, self._autosave_ai_settings)

    def _autosave_ai_settings(self) -> None:
        self._ai_autosave_job = None
        if not self._ai_base_url.get().startswith(("http://", "https://")):
            return
        try:
            self._write_ai_settings()
            self._ai_status.set(self._translate("ai_on" if self._ai_enabled.get() else "ai_off"))
        except (OSError, ValueError, yaml.YAMLError):
            return

    def _write_ai_settings(self) -> None:
        config_path = self._resolve_config_path()
        if not config_path.exists():
            example = config_path.parent / "config.example.yaml"
            if example.exists():
                data = yaml.safe_load(example.read_text(encoding="utf-8")) or {}
            else:
                data = {}
        else:
            data = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
        if not isinstance(data, dict):
            raise ValueError("configuration root must be a mapping")
        ai = data.setdefault("ai", {})
        if not isinstance(ai, dict):
            raise ValueError("ai configuration must be a mapping")
        ai.update({"enabled": self._ai_enabled.get(), "model": self._ai_model.get().strip(), "base_url": self._ai_base_url.get().strip()})
        config_path.parent.mkdir(parents=True, exist_ok=True)
        config_path.write_text(yaml.safe_dump(data, sort_keys=False, allow_unicode=True), encoding="utf-8")

    def _card(
        self, parent: tk.Frame, title: tk.StringVar, value: tk.StringVar, color: str, column: int
    ) -> None:
        card = tk.Frame(
            parent,
            bg=self._palette["panel"],
            padx=16,
            pady=14,
            highlightthickness=1,
            highlightbackground=self._palette["line"],
        )
        card.grid(row=0, column=column, sticky="nsew", padx=(0, 10 if column < 3 else 0))
        parent.grid_columnconfigure(column, weight=1)
        tk.Label(card, textvariable=title, fg=self._palette["muted"], bg=self._palette["panel"], font=("Segoe UI", 8, "bold")).pack(anchor="w")
        tk.Label(card, textvariable=value, fg=color, bg=self._palette["panel"], font=("Bahnschrift", 19, "bold")).pack(anchor="w", pady=(7, 0))

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
        if self._live_mode.get() and not messagebox.askyesno(
            "Xác nhận LIVE",
            "LIVE sẽ có thể thay đổi Windows Firewall và cần quyền Administrator. Tiếp tục?",
            icon="warning",
            parent=self._root,
        ):
            self._live_mode.set(False)
            return
        try:
            command = [sys.executable, "-m", "globalban.main", "--config", str(config)]
            command.append("--live" if self._live_mode.get() else "--dry-run")
            self._process = subprocess.Popen(
                command,
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
                line = self._proxy_output_queue.get_nowait()
                self._proxy_lines.append(line)
                self._proxy_lines = self._proxy_lines[-300:]
                self._append_proxy_log(line)
                if "listening" in line.lower():
                    self._proxy_status.set("Đang chạy")
        except queue.Empty:
            pass
        if self._proxy_process is not None and self._proxy_process.poll() is not None:
            return_code = self._proxy_process.returncode
            self._proxy_process = None
            self._proxy_status.set(f"Đã dừng ({return_code})")
            if self._proxy_window is not None and self._proxy_window.winfo_exists():
                self._proxy_start_button.configure(state="normal")
                self._proxy_stop_button.configure(state="disabled")
        try:
            while True:
                line = self._output_queue.get_nowait()
                self._log_lines.append(line)
                self._ingest_ui_event(line)
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
        self._stop_proxy()
        self._close_telemetry_panel()
        self._close_audit_panel()
        if self._live_refresh_job is not None:
            try:
                self._root.after_cancel(self._live_refresh_job)
            except Exception:
                pass
        self._root.destroy()


def main() -> None:
    root = tk.Tk()
    GlobalBanApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()