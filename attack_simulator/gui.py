"""
attack_simulator.gui
====================
Ultra-Modern Dark Cybersecurity SOC & Red-Team Adversary Emulation GUI (Tkinter):
  - 6 Real-time KPI Cards (Total XML, Precision, Recall, F1, FPR, Rule Accuracy)
  - 6 Interactive Tabs:
      1. Overview Analytics & MITRE ATT&CK Chart + Confusion Matrix
      2. Live Alert & Signal Table with filter
      3. XML Event Inspector & Ground Truth Metadata
      4. UEBA 7-Day Behavioral Profile Explorer & Atomic Red Team results
      5. Full Evaluation Report with Markdown Export
      6. VMware EVTX & Sigma Toolkit Guide
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tkinter as tk
import webbrowser
from io import StringIO
from pathlib import Path
from tkinter import filedialog, messagebox, scrolledtext, ttk
from typing import Any

from attack_simulator.evaluator import (
    DetailedEvaluationReport,
    format_report_text,
    resolve_default_globalban_root,
    run_unified_evaluation,
)
from attack_simulator.generator import (
    WindowsAttackLogGenerator,
    export_dataset_files,
)
from attack_simulator.models import SCENARIO_CATALOG, SimulatedRecord

PALETTE: dict[str, str] = {
    "bg_root": "#090D16",
    "bg_header": "#0F1626",
    "bg_card": "#111827",
    "bg_card_alt": "#162033",
    "bg_input": "#1E293B",
    "border": "#243147",
    "text_primary": "#F8FAFC",
    "text_secondary": "#94A3B8",
    "text_muted": "#64748B",
    "cyan": "#06B6D4",
    "cyan_dark": "#0891B2",
    "crimson": "#F43F5E",
    "crimson_dark": "#E11D48",
    "emerald": "#10B981",
    "amber": "#F59E0B",
    "violet": "#8B5CF6",
}


class ModernRedTeamStudioApp:
    """Executive-grade SOC / Red-Team Adversary Emulation & Benchmark Studio."""

    def __init__(
        self,
        root: tk.Tk,
        output_dir: Path | None = None,
        globalban_root: Path | None = None,
    ) -> None:
        self.root = root
        self.root.title("GlobalBan Red-Team Adversary Studio & SIEM/UEBA Benchmark Suite")
        self.root.geometry("1380x880")
        self.root.minsize(1180, 760)
        self.root.configure(bg=PALETTE["bg_root"])

        default_out = output_dir or (Path(__file__).resolve().parent.parent / "output")
        self.output_dir_var = tk.StringVar(value=str(default_out))
        detected_gb = globalban_root or resolve_default_globalban_root()
        self.globalban_dir_var = tk.StringVar(value=str(detected_gb) if detected_gb else "")

        self.last_records: list[SimulatedRecord] = []
        self.last_xml_path: Path | None = None
        self.last_jsonl_path: Path | None = None
        self.last_report: DetailedEvaluationReport | None = None

        self.scenario_vars: dict[str, tk.BooleanVar] = {}
        self.ueba_var = tk.BooleanVar(value=True)
        self.lolbin_var = tk.BooleanVar(value=True)
        self.campaigns_var = tk.IntVar(value=25)
        self.benign_var = tk.IntVar(value=600)
        self.fp_noise_var = tk.IntVar(value=30)
        self.seed_var = tk.IntVar(value=42)

        self.status_var = tk.StringVar(value="Sẵn sàng — Nhấn 'Chạy Mô Phỏng & Chấm Điểm' để bắt đầu")
        self.engine_badge_var = tk.StringVar(value="")

        self.kpi_vars: dict[str, tk.StringVar] = {
            "total": tk.StringVar(value="0"),
            "total_sub": tk.StringVar(value="Attack: 0 | Benign: 0"),
            "precision": tk.StringVar(value="0.00%"),
            "recall": tk.StringVar(value="0.00%"),
            "f1": tk.StringVar(value="0.00%"),
            "fpr": tk.StringVar(value="0.00%"),
            "rule_acc": tk.StringVar(value="0.00%"),
        }

        self._configure_ttk_styles()
        self._build_layout()
        self._refresh_engine_badge()
        self.root.after(180, self.run_generate_and_evaluate)

    def _configure_ttk_styles(self) -> None:
        style = ttk.Style(self.root)
        style.theme_use("clam")

        style.configure(".", background=PALETTE["bg_root"], foreground=PALETTE["text_primary"], font=("Segoe UI", 10))
        style.configure("TFrame", background=PALETTE["bg_root"])
        style.configure("Card.TFrame", background=PALETTE["bg_card"])
        style.configure("Header.TFrame", background=PALETTE["bg_header"])

        style.configure(
            "TNotebook",
            background=PALETTE["bg_root"],
            borderwidth=0,
            tabmargins=[0, 4, 0, 0],
        )
        style.configure(
            "TNotebook.Tab",
            background=PALETTE["bg_card"],
            foreground=PALETTE["text_secondary"],
            padding=[16, 8],
            font=("Segoe UI", 10, "bold"),
            borderwidth=0,
        )
        style.map(
            "TNotebook.Tab",
            background=[("selected", PALETTE["bg_card_alt"])],
            foreground=[("selected", PALETTE["cyan"])],
        )

        style.configure(
            "Dark.Treeview",
            background=PALETTE["bg_card"],
            foreground=PALETTE["text_primary"],
            fieldbackground=PALETTE["bg_card"],
            rowheight=28,
            borderwidth=0,
            font=("Segoe UI", 9),
        )
        style.configure(
            "Dark.Treeview.Heading",
            background=PALETTE["bg_card_alt"],
            foreground=PALETTE["cyan"],
            font=("Segoe UI", 9, "bold"),
            borderwidth=0,
            padding=[8, 6],
        )
        style.map(
            "Dark.Treeview",
            background=[("selected", "#1E3A5F")],
            foreground=[("selected", "#FFFFFF")],
        )

    def _make_btn(
        self,
        parent: tk.Widget,
        text: str,
        command: Any,
        bg: str,
        hover_bg: str,
        fg: str = "#FFFFFF",
        font: tuple[str, int, str] = ("Segoe UI", 9, "bold"),
        padx: int = 14,
        pady: int = 7,
    ) -> tk.Button:
        btn = tk.Button(
            parent,
            text=text,
            command=command,
            bg=bg,
            fg=fg,
            activebackground=hover_bg,
            activeforeground=fg,
            relief=tk.FLAT,
            bd=0,
            cursor="hand2",
            font=font,
            padx=padx,
            pady=pady,
        )
        btn.bind("<Enter>", lambda _e: btn.configure(bg=hover_bg))
        btn.bind("<Leave>", lambda _e: btn.configure(bg=bg))
        return btn

    def _build_layout(self) -> None:
        # --- TOP HEADER BAR ---
        header = tk.Frame(self.root, bg=PALETTE["bg_header"], height=64, highlightbackground=PALETTE["border"], highlightthickness=1)
        header.pack(fill=tk.X, side=tk.TOP)
        header.pack_propagate(False)

        left_hdr = tk.Frame(header, bg=PALETTE["bg_header"])
        left_hdr.pack(side=tk.LEFT, padx=18, pady=8)

        title_row = tk.Frame(left_hdr, bg=PALETTE["bg_header"])
        title_row.pack(anchor=tk.W)
        tk.Label(
            title_row,
            text="⚡ GLOBALBAN RED-TEAM STUDIO",
            font=("Segoe UI", 14, "bold"),
            bg=PALETTE["bg_header"],
            fg=PALETTE["text_primary"],
        ).pack(side=tk.LEFT)
        tk.Label(
            title_row,
            text="  ADVERSARY EMULATION & SIEM/UEBA BENCHMARK",
            font=("Segoe UI", 9, "bold"),
            bg=PALETTE["bg_header"],
            fg=PALETTE["cyan"],
        ).pack(side=tk.LEFT, pady=(3, 0))

        tk.Label(
            left_hdr,
            text="Bộ sinh dữ liệu tấn công Windows XML đa bước • Học hành vi UEBA 7 ngày • Kiểm định chống báo động giả (FPR)",
            font=("Segoe UI", 8),
            bg=PALETTE["bg_header"],
            fg=PALETTE["text_secondary"],
        ).pack(anchor=tk.W)

        right_hdr = tk.Frame(header, bg=PALETTE["bg_header"])
        right_hdr.pack(side=tk.RIGHT, padx=18)

        self.badge_label = tk.Label(
            right_hdr,
            textvariable=self.engine_badge_var,
            font=("Segoe UI", 8, "bold"),
            bg="#132A2E",
            fg=PALETTE["emerald"],
            padx=10,
            pady=4,
        )
        self.badge_label.pack(side=tk.RIGHT, padx=(8, 0))

        self._make_btn(
            right_hdr,
            "📂 Chọn GlobalBan",
            self._browse_globalban_dir,
            bg=PALETTE["bg_input"],
            hover_bg="#2D3B52",
            fg=PALETTE["text_primary"],
            font=("Segoe UI", 8, "bold"),
            padx=10,
            pady=4,
        ).pack(side=tk.RIGHT, padx=4)

        self._make_btn(
            right_hdr,
            "📁 Thư mục Output",
            self._open_output_folder,
            bg=PALETTE["bg_input"],
            hover_bg="#2D3B52",
            fg=PALETTE["text_primary"],
            font=("Segoe UI", 8, "bold"),
            padx=10,
            pady=4,
        ).pack(side=tk.RIGHT, padx=4)

        # --- MAIN WORKSPACE (LEFT SIDEBAR + RIGHT DASHBOARD) ---
        body = tk.Frame(self.root, bg=PALETTE["bg_root"])
        body.pack(fill=tk.BOTH, expand=True, padx=14, pady=12)

        # LEFT SIDEBAR: SCENARIO & PARAMETER CONTROLS
        sidebar = tk.Frame(
            body,
            bg=PALETTE["bg_card"],
            width=360,
            highlightbackground=PALETTE["border"],
            highlightthickness=1,
        )
        sidebar.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 12))
        sidebar.pack_propagate(False)

        sb_inner = tk.Frame(sidebar, bg=PALETTE["bg_card"], padx=14, pady=12)
        sb_inner.pack(fill=tk.BOTH, expand=True)

        tk.Label(
            sb_inner,
            text="KỊCH BẢN TẤN CÔNG & ĐÁNH GIÁ (8 MODULES)",
            font=("Segoe UI", 9, "bold"),
            bg=PALETTE["bg_card"],
            fg=PALETTE["cyan"],
        ).pack(anchor=tk.W, pady=(0, 6))

        for spec in SCENARIO_CATALOG:
            var = tk.BooleanVar(value=True)
            self.scenario_vars[spec.key] = var
            row = tk.Frame(sb_inner, bg=PALETTE["bg_card_alt"], pady=4, padx=8)
            row.pack(fill=tk.X, pady=2)

            dot = tk.Label(row, text="●", fg=spec.accent_color, bg=PALETTE["bg_card_alt"], font=("Segoe UI", 9))
            dot.pack(side=tk.LEFT, padx=(0, 4))

            cb = tk.Checkbutton(
                row,
                text=spec.title,
                variable=var,
                bg=PALETTE["bg_card_alt"],
                fg=PALETTE["text_primary"],
                selectcolor=PALETTE["bg_input"],
                activebackground=PALETTE["bg_card_alt"],
                activeforeground=PALETTE["text_primary"],
                font=("Segoe UI", 9, "bold"),
                anchor=tk.W,
            )
            cb.pack(side=tk.LEFT, fill=tk.X, expand=True)

        # Scenario 7 & 8
        for title_txt, var_obj, color in (
            ("7. UEBA 7-Day Baseline & Atomic Red Team", self.ueba_var, PALETTE["violet"]),
            ("8. WinLOLBIN-GT Living Off The Land", self.lolbin_var, PALETTE["emerald"]),
        ):
            row = tk.Frame(sb_inner, bg=PALETTE["bg_card_alt"], pady=4, padx=8)
            row.pack(fill=tk.X, pady=2)
            tk.Label(row, text="●", fg=color, bg=PALETTE["bg_card_alt"], font=("Segoe UI", 9)).pack(side=tk.LEFT, padx=(0, 4))
            tk.Checkbutton(
                row,
                text=title_txt,
                variable=var_obj,
                bg=PALETTE["bg_card_alt"],
                fg=PALETTE["text_primary"],
                selectcolor=PALETTE["bg_input"],
                activebackground=PALETTE["bg_card_alt"],
                activeforeground=PALETTE["text_primary"],
                font=("Segoe UI", 9, "bold"),
                anchor=tk.W,
            ).pack(side=tk.LEFT, fill=tk.X, expand=True)

        sel_row = tk.Frame(sb_inner, bg=PALETTE["bg_card"])
        sel_row.pack(fill=tk.X, pady=(6, 10))
        self._make_btn(
            sel_row,
            "✓ Chọn tất cả",
            lambda: ([v.set(True) for v in self.scenario_vars.values()], self.ueba_var.set(True), self.lolbin_var.set(True)),
            bg=PALETTE["bg_input"],
            hover_bg="#2D3B52",
            font=("Segoe UI", 8, "bold"),
            padx=8,
            pady=4,
        ).pack(side=tk.LEFT, expand=True, fill=tk.X, padx=(0, 4))
        self._make_btn(
            sel_row,
            "✕ Bỏ chọn",
            lambda: ([v.set(False) for v in self.scenario_vars.values()], self.ueba_var.set(False), self.lolbin_var.set(False)),
            bg=PALETTE["bg_input"],
            hover_bg="#2D3B52",
            font=("Segoe UI", 8, "bold"),
            padx=8,
            pady=4,
        ).pack(side=tk.LEFT, expand=True, fill=tk.X, padx=(4, 0))

        # Divider
        tk.Frame(sb_inner, bg=PALETTE["border"], height=1).pack(fill=tk.X, pady=4)

        tk.Label(
            sb_inner,
            text="THAM SỐ SINH DỮ LIỆU KIỂM CHUẨN",
            font=("Segoe UI", 9, "bold"),
            bg=PALETTE["bg_card"],
            fg=PALETTE["cyan"],
        ).pack(anchor=tk.W, pady=(6, 6))

        params_grid = tk.Frame(sb_inner, bg=PALETTE["bg_card"])
        params_grid.pack(fill=tk.X)

        param_specs = [
            ("Chiến dịch / mỗi kịch bản:", self.campaigns_var, 1, 500, 5),
            ("Log bình thường (Benign):", self.benign_var, 0, 20000, 100),
            ("Nhiễu Admin (Test FPR):", self.fp_noise_var, 0, 1000, 5),
            ("Random Seed tái lập:", self.seed_var, 1, 99999, 1),
        ]
        for r_idx, (lbl, var_obj, mn, mx, inc) in enumerate(param_specs):
            tk.Label(
                params_grid,
                text=lbl,
                bg=PALETTE["bg_card"],
                fg=PALETTE["text_secondary"],
                font=("Segoe UI", 9),
            ).grid(row=r_idx, column=0, sticky=tk.W, pady=4)
            sb = tk.Spinbox(
                params_grid,
                from_=mn,
                to=mx,
                increment=inc,
                textvariable=var_obj,
                width=10,
                bg=PALETTE["bg_input"],
                fg=PALETTE["text_primary"],
                buttonbackground=PALETTE["bg_card_alt"],
                insertbackground=PALETTE["text_primary"],
                relief=tk.FLAT,
                font=("Consolas", 10, "bold"),
            )
            sb.grid(row=r_idx, column=1, sticky=tk.E, pady=4)
        params_grid.columnconfigure(0, weight=1)

        # Primary Action Buttons
        tk.Frame(sb_inner, bg=PALETTE["border"], height=1).pack(fill=tk.X, pady=(10, 10))

        self._make_btn(
            sb_inner,
            "▶ 1. SINH LOG XML + JSONL & CHẤM ĐIỂM",
            self.run_generate_and_evaluate,
            bg=PALETTE["crimson"],
            hover_bg=PALETTE["crimson_dark"],
            font=("Segoe UI", 9, "bold"),
            pady=9,
        ).pack(fill=tk.X, pady=(0, 6))

        self._make_btn(
            sb_inner,
            "⚡ 2. ĐẨY LOG VÀO GLOBALBAN CLI",
            self.run_push_xml_cli,
            bg=PALETTE["cyan_dark"],
            hover_bg=PALETTE["cyan"],
            font=("Segoe UI", 9, "bold"),
            pady=8,
        ).pack(fill=tk.X, pady=(0, 6))

        self._make_btn(
            sb_inner,
            "🖥 3. MỞ GLOBALBAN DASHBOARD",
            self.open_globalban_dashboard,
            bg=PALETTE["bg_input"],
            hover_bg="#2D3B52",
            fg=PALETTE["cyan"],
            font=("Segoe UI", 9, "bold"),
            pady=8,
        ).pack(fill=tk.X)

        # --- RIGHT CONTENT AREA ---
        right_area = tk.Frame(body, bg=PALETTE["bg_root"])
        right_area.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

        # KPI CARDS ROW
        kpi_row = tk.Frame(right_area, bg=PALETTE["bg_root"])
        kpi_row.pack(fill=tk.X, pady=(0, 10))

        kpi_defs = [
            ("TỔNG SỰ KIỆN XML", "total", PALETTE["cyan"], "total_sub"),
            ("PRECISION", "precision", PALETTE["emerald"], None),
            ("RECALL (ĐỘ PHỦ)", "recall", PALETTE["emerald"], None),
            ("F1-SCORE", "f1", PALETTE["violet"], None),
            ("FALSE POSITIVE RATE", "fpr", PALETTE["amber"], None),
            ("RULE MATCH ACC", "rule_acc", PALETTE["cyan"], None),
        ]
        for idx, (title, key, color, sub_key) in enumerate(kpi_defs):
            card = tk.Frame(
                kpi_row,
                bg=PALETTE["bg_card"],
                highlightbackground=PALETTE["border"],
                highlightthickness=1,
                padx=12,
                pady=8,
            )
            card.grid(row=0, column=idx, sticky="nsew", padx=(0 if idx == 0 else 6, 0))
            kpi_row.columnconfigure(idx, weight=1)

            tk.Label(
                card,
                text=title,
                font=("Segoe UI", 8, "bold"),
                bg=PALETTE["bg_card"],
                fg=PALETTE["text_secondary"],
            ).pack(anchor=tk.W)
            tk.Label(
                card,
                textvariable=self.kpi_vars[key],
                font=("Segoe UI", 15, "bold"),
                bg=PALETTE["bg_card"],
                fg=color,
            ).pack(anchor=tk.W, pady=(2, 0))
            if sub_key:
                tk.Label(
                    card,
                    textvariable=self.kpi_vars[sub_key],
                    font=("Segoe UI", 8),
                    bg=PALETTE["bg_card"],
                    fg=PALETTE["text_muted"],
                ).pack(anchor=tk.W)

        # NOTEBOOK TABS
        self.notebook = ttk.Notebook(right_area)
        self.notebook.pack(fill=tk.BOTH, expand=True)

        # TAB 1: OVERVIEW ANALYTICS (CONFUSION MATRIX + MITRE CHART)
        tab_overview = tk.Frame(self.notebook, bg=PALETTE["bg_root"], padx=4, pady=8)
        self.notebook.add(tab_overview, text="📊 Tổng Quan & Biểu Đồ MITRE")

        top_charts = tk.Frame(tab_overview, bg=PALETTE["bg_root"])
        top_charts.pack(fill=tk.BOTH, expand=True)

        # Left: Confusion Matrix Canvas
        cm_card = tk.Frame(
            top_charts,
            bg=PALETTE["bg_card"],
            highlightbackground=PALETTE["border"],
            highlightthickness=1,
            width=370,
            padx=12,
            pady=10,
        )
        cm_card.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 10))
        cm_card.pack_propagate(False)
        tk.Label(
            cm_card,
            text="MA TRẬN NHẦM LẪN (CONFUSION MATRIX)",
            font=("Segoe UI", 9, "bold"),
            bg=PALETTE["bg_card"],
            fg=PALETTE["cyan"],
        ).pack(anchor=tk.W, pady=(0, 8))
        self.cm_canvas = tk.Canvas(cm_card, bg=PALETTE["bg_card"], highlightthickness=0, height=280)
        self.cm_canvas.pack(fill=tk.BOTH, expand=True)

        # Right: MITRE ATT&CK Coverage Bar Chart Canvas
        mitre_card = tk.Frame(
            top_charts,
            bg=PALETTE["bg_card"],
            highlightbackground=PALETTE["border"],
            highlightthickness=1,
            padx=12,
            pady=10,
        )
        mitre_card.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)
        tk.Label(
            mitre_card,
            text="ĐỘ PHỦ PHÁT HIỆN THEO KỸ THUẬT MITRE ATT&CK & RULE",
            font=("Segoe UI", 9, "bold"),
            bg=PALETTE["bg_card"],
            fg=PALETTE["cyan"],
        ).pack(anchor=tk.W, pady=(0, 8))
        self.mitre_canvas = tk.Canvas(mitre_card, bg=PALETTE["bg_card"], highlightthickness=0)
        self.mitre_canvas.pack(fill=tk.BOTH, expand=True)
        self.mitre_canvas.bind("<Configure>", lambda _e: self._draw_charts())

        # TAB 2: ALERTS & DETECTIONS TABLE
        tab_alerts = tk.Frame(self.notebook, bg=PALETTE["bg_card"], padx=10, pady=10)
        self.notebook.add(tab_alerts, text="🚨 Cảnh Báo Phát Hiện (Detections)")

        filter_bar = tk.Frame(tab_alerts, bg=PALETTE["bg_card"])
        filter_bar.pack(fill=tk.X, pady=(0, 8))
        tk.Label(filter_bar, text="Lọc Rule / Kịch bản:", bg=PALETTE["bg_card"], fg=PALETTE["text_secondary"]).pack(side=tk.LEFT)
        self.alert_filter_var = tk.StringVar()
        self.alert_filter_var.trace_add("write", lambda *_: self._refresh_alerts_table())
        tk.Entry(
            filter_bar,
            textvariable=self.alert_filter_var,
            bg=PALETTE["bg_input"],
            fg=PALETTE["text_primary"],
            insertbackground=PALETTE["text_primary"],
            relief=tk.FLAT,
            width=36,
            font=("Segoe UI", 9),
        ).pack(side=tk.LEFT, padx=8, ipady=4)

        cols = ("event_id", "detector", "rule_id", "target", "scenario", "explanation")
        self.alerts_tree = ttk.Treeview(tab_alerts, columns=cols, show="headings", style="Dark.Treeview")
        headings = {
            "event_id": "Event ID",
            "detector": "Detector",
            "rule_id": "Rule Kích Hoạt",
            "target": "Host / Source IP",
            "scenario": "Kịch Bản",
            "explanation": "Phân Tích Chi Tiết",
        }
        widths = {"event_id": 105, "detector": 165, "rule_id": 210, "target": 150, "scenario": 210, "explanation": 420}
        for c in cols:
            self.alerts_tree.heading(c, text=headings[c])
            self.alerts_tree.column(c, width=widths[c], anchor=tk.W)
        y_sc = ttk.Scrollbar(tab_alerts, orient=tk.VERTICAL, command=self.alerts_tree.yview)
        self.alerts_tree.configure(yscrollcommand=y_sc.set)
        self.alerts_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        y_sc.pack(side=tk.RIGHT, fill=tk.Y)

        # TAB 3: XML EVENT INSPECTOR
        tab_xml = tk.Frame(self.notebook, bg=PALETTE["bg_card"], padx=10, pady=10)
        self.notebook.add(tab_xml, text="🔍 Soi Log XML & Ground Truth")

        xml_top = tk.Frame(tab_xml, bg=PALETTE["bg_card"])
        xml_top.pack(fill=tk.X, pady=(0, 6))
        tk.Label(xml_top, text="Tìm kiếm Event (ID / Kịch bản / MITRE):", bg=PALETTE["bg_card"], fg=PALETTE["text_secondary"]).pack(side=tk.LEFT)
        self.xml_search_var = tk.StringVar()
        self.xml_search_var.trace_add("write", lambda *_: self._refresh_events_table())
        tk.Entry(
            xml_top,
            textvariable=self.xml_search_var,
            bg=PALETTE["bg_input"],
            fg=PALETTE["text_primary"],
            insertbackground=PALETTE["text_primary"],
            relief=tk.FLAT,
            width=32,
        ).pack(side=tk.LEFT, padx=8, ipady=4)

        self.only_malicious_var = tk.BooleanVar(value=False)
        tk.Checkbutton(
            xml_top,
            text="Chỉ hiện sự kiện Tấn công (Malicious)",
            variable=self.only_malicious_var,
            command=self._refresh_events_table,
            bg=PALETTE["bg_card"],
            fg=PALETTE["text_primary"],
            selectcolor=PALETTE["bg_input"],
            activebackground=PALETTE["bg_card"],
        ).pack(side=tk.LEFT, padx=10)

        xml_split = tk.PanedWindow(tab_xml, orient=tk.VERTICAL, bg=PALETTE["border"], sashwidth=4)
        xml_split.pack(fill=tk.BOTH, expand=True)

        ev_frame = tk.Frame(xml_split, bg=PALETTE["bg_card"])
        ev_cols = ("event_id", "timestamp", "type", "mitre", "scenario", "expected_rules")
        self.events_tree = ttk.Treeview(ev_frame, columns=ev_cols, show="headings", style="Dark.Treeview", height=10)
        ev_heads = {
            "event_id": "Event ID",
            "timestamp": "Thời gian (UTC)",
            "type": "Phân loại",
            "mitre": "MITRE ID",
            "scenario": "Kịch bản",
            "expected_rules": "Rule Kỳ Vọng",
        }
        ev_widths = {"event_id": 110, "timestamp": 165, "type": 110, "mitre": 100, "scenario": 280, "expected_rules": 240}
        for c in ev_cols:
            self.events_tree.heading(c, text=ev_heads[c])
            self.events_tree.column(c, width=ev_widths[c], anchor=tk.W)
        ev_scroll = ttk.Scrollbar(ev_frame, orient=tk.VERTICAL, command=self.events_tree.yview)
        self.events_tree.configure(yscrollcommand=ev_scroll.set)
        self.events_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        ev_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.events_tree.bind("<<TreeviewSelect>>", self._on_event_selected)
        xml_split.add(ev_frame)

        raw_frame = tk.Frame(xml_split, bg=PALETTE["bg_card"])
        self.xml_viewer = scrolledtext.ScrolledText(
            raw_frame,
            bg="#080C14",
            fg="#38BDF8",
            insertbackground="#FFFFFF",
            font=("Consolas", 10),
            height=9,
            relief=tk.FLAT,
            padx=10,
            pady=8,
        )
        self.xml_viewer.pack(fill=tk.BOTH, expand=True)
        xml_split.add(raw_frame)

        # TAB 4: UEBA 7-DAY PROFILES & ATOMIC RED TEAM
        tab_ueba = tk.Frame(self.notebook, bg=PALETTE["bg_card"], padx=10, pady=10)
        self.notebook.add(tab_ueba, text="🧠 Hồ Sơ UEBA 7 Ngày & Atomic")
        self.ueba_text = scrolledtext.ScrolledText(
            tab_ueba,
            bg="#080C14",
            fg="#E2E8F0",
            font=("Consolas", 10),
            relief=tk.FLAT,
            padx=12,
            pady=10,
        )
        self.ueba_text.pack(fill=tk.BOTH, expand=True)

        # TAB 5: FULL EVALUATION REPORT & EXPORT
        tab_report = tk.Frame(self.notebook, bg=PALETTE["bg_card"], padx=10, pady=10)
        self.notebook.add(tab_report, text="📑 Báo Cáo Chấm Điểm Chi Tiết")

        rep_actions = tk.Frame(tab_report, bg=PALETTE["bg_card"])
        rep_actions.pack(fill=tk.X, pady=(0, 8))
        self._make_btn(
            rep_actions,
            "📋 Sao chép Báo cáo",
            self._copy_report_to_clipboard,
            bg=PALETTE["bg_input"],
            hover_bg="#2D3B52",
            font=("Segoe UI", 8, "bold"),
            padx=10,
            pady=5,
        ).pack(side=tk.LEFT, padx=(0, 6))
        self._make_btn(
            rep_actions,
            "💾 Xuất Báo Cáo Markdown (.md)",
            self._export_markdown_report,
            bg=PALETTE["emerald"],
            hover_bg="#059669",
            font=("Segoe UI", 8, "bold"),
            padx=10,
            pady=5,
        ).pack(side=tk.LEFT)

        self.report_text = scrolledtext.ScrolledText(
            tab_report,
            bg="#080C14",
            fg="#A7F3D0",
            font=("Consolas", 10),
            relief=tk.FLAT,
            padx=12,
            pady=10,
        )
        self.report_text.pack(fill=tk.BOTH, expand=True)

        # TAB 6: VMWARE EVTX & SIGMA TOOLKIT COMMANDS
        tab_vm = tk.Frame(self.notebook, bg=PALETTE["bg_card"], padx=10, pady=10)
        self.notebook.add(tab_vm, text="🖥 Quy Trình EVTX & Sigma (VM)")
        self.vm_text = scrolledtext.ScrolledText(
            tab_vm,
            bg="#080C14",
            fg="#FDE68A",
            font=("Consolas", 10),
            relief=tk.FLAT,
            padx=12,
            pady=10,
        )
        self.vm_text.pack(fill=tk.BOTH, expand=True)
        self._populate_vm_guide()

        # --- BOTTOM STATUS BAR ---
        status_bar = tk.Frame(self.root, bg=PALETTE["bg_header"], height=28, highlightbackground=PALETTE["border"], highlightthickness=1)
        status_bar.pack(fill=tk.X, side=tk.BOTTOM)
        status_bar.pack_propagate(False)
        tk.Label(
            status_bar,
            textvariable=self.status_var,
            bg=PALETTE["bg_header"],
            fg=PALETTE["text_secondary"],
            font=("Segoe UI", 8),
        ).pack(side=tk.LEFT, padx=14)
        tk.Label(
            status_bar,
            textvariable=self.output_dir_var,
            bg=PALETTE["bg_header"],
            fg=PALETTE["cyan"],
            font=("Consolas", 8),
        ).pack(side=tk.RIGHT, padx=14)

    def _refresh_engine_badge(self) -> None:
        gb_str = self.globalban_dir_var.get().strip()
        gb_path = Path(gb_str) if gb_str else None
        if gb_path and (gb_path / "src" / "globalban").is_dir():
            self.engine_badge_var.set("● GLOBALBAN LINKED")
            self.badge_label.configure(bg="#132A2E", fg=PALETTE["emerald"])
        else:
            self.engine_badge_var.set("● STANDALONE ENGINE ACTIVE")
            self.badge_label.configure(bg="#1E1B4B", fg=PALETTE["cyan"])

    def _browse_globalban_dir(self) -> None:
        chosen = filedialog.askdirectory(title="Chọn thư mục gốc dự án GlobalBan (chứa thư mục src/)")
        if chosen:
            self.globalban_dir_var.set(chosen)
            self._refresh_engine_badge()
            self.status_var.set(f"Đã cập nhật đường dẫn GlobalBan: {chosen}")

    def _open_output_folder(self) -> None:
        out_dir = Path(self.output_dir_var.get())
        out_dir.mkdir(parents=True, exist_ok=True)
        if sys.platform.startswith("win"):
            os.startfile(str(out_dir))  # type: ignore[attr-defined]
        else:
            webbrowser.open(out_dir.as_uri())

    def run_generate_and_evaluate(self) -> None:
        selected = [k for k, v in self.scenario_vars.items() if v.get()]
        if not selected and self.benign_var.get() <= 0 and not self.ueba_var.get() and not self.lolbin_var.get():
            messagebox.showwarning("Chưa chọn kịch bản", "Vui lòng chọn ít nhất 1 kịch bản.", parent=self.root)
            return

        self.status_var.set("⏳ Đang sinh dữ liệu Windows XML, học hồ sơ UEBA 7 ngày và chấm điểm...")
        self.root.update_idletasks()

        try:
            out_dir = Path(self.output_dir_var.get())
            gb_str = self.globalban_dir_var.get().strip()
            gb_root = Path(gb_str) if gb_str else None

            gen = WindowsAttackLogGenerator(seed=int(self.seed_var.get()))
            records = gen.generate_dataset(
                selected_scenarios=selected,
                campaigns_per_scenario=max(1, int(self.campaigns_var.get())) if selected else 0,
                benign_count=max(0, int(self.benign_var.get())),
                fp_noise_count=max(0, int(self.fp_noise_var.get())),
            )
            self.last_records = records

            jsonl_path = out_dir / "simulated_windows_eval.jsonl"
            xml_path = out_dir / "simulated_windows_events.xml"
            report_json_path = out_dir / "evaluation_report.json"
            export_dataset_files(records, jsonl_path, xml_path)
            self.last_jsonl_path = jsonl_path
            self.last_xml_path = xml_path

            report = run_unified_evaluation(
                jsonl_path=jsonl_path,
                xml_path=xml_path,
                globalban_root=gb_root,
                evaluate_ueba=bool(self.ueba_var.get()),
                evaluate_lolbin=bool(self.lolbin_var.get()),
                output_dir=out_dir,
            )
            self.last_report = report
            report_json_path.write_text(
                json.dumps(report.to_dict(), indent=2, ensure_ascii=False), encoding="utf-8"
            )

            self._update_all_views(report)
            self.status_var.set(
                f"✓ Hoàn tất! Đã sinh {report.total_events:,} sự kiện XML & xuất 7 file vào {out_dir}"
            )
        except Exception as exc:
            self.status_var.set(f"✕ Lỗi: {exc}")
            messagebox.showerror("Lỗi thực thi", str(exc), parent=self.root)

    def _update_all_views(self, report: DetailedEvaluationReport) -> None:
        self.kpi_vars["total"].set(f"{report.total_events:,}")
        self.kpi_vars["total_sub"].set(f"Attack: {report.malicious_events:,} | Clean: {report.benign_events:,}")
        self.kpi_vars["precision"].set(f"{report.precision * 100:.2f}%")
        self.kpi_vars["recall"].set(f"{report.recall * 100:.2f}%")
        self.kpi_vars["f1"].set(f"{report.f1 * 100:.2f}%")
        self.kpi_vars["fpr"].set(f"{report.false_positive_rate * 100:.2f}%")
        self.kpi_vars["rule_acc"].set(f"{report.rule_match_accuracy * 100:.2f}%")

        self._draw_charts()
        self._refresh_alerts_table()
        self._refresh_events_table()
        self._refresh_ueba_view(report)

        self.report_text.delete("1.0", tk.END)
        self.report_text.insert(tk.END, format_report_text(report))

    def _draw_charts(self) -> None:
        report = self.last_report
        if report is None:
            return

        # 1. Confusion Matrix 2x2 Heatmap
        c = self.cm_canvas
        c.delete("all")
        w = max(320, c.winfo_width() or 340)
        h = max(250, c.winfo_height() or 270)
        pad = 12
        cell_w = (w - pad * 3) / 2
        cell_h = (h - pad * 3) / 2

        cells = [
            (0, 0, "TRUE POSITIVE (TP)", f"{report.true_positive:,}", "Bắt trúng tấn công", "#064E3B", PALETTE["emerald"]),
            (1, 0, "FALSE POSITIVE (FP)", f"{report.false_positive:,}", "Báo giả (Mục tiêu = 0)", "#451A03" if report.false_positive else "#1E293B", PALETTE["amber"] if report.false_positive else PALETTE["text_secondary"]),
            (0, 1, "FALSE NEGATIVE (FN)", f"{report.false_negative:,}", "Bỏ lọt (Mục tiêu = 0)", "#4C0519" if report.false_negative else "#1E293B", PALETTE["crimson"] if report.false_negative else PALETTE["text_secondary"]),
            (1, 1, "TRUE NEGATIVE (TN)", f"{report.true_negative:,}", "Bỏ qua đúng log sạch", "#172554", PALETTE["cyan"]),
        ]
        for col, row, title, val, sub, fill_bg, accent in cells:
            x0 = pad + col * (cell_w + pad)
            y0 = pad + row * (cell_h + pad)
            x1 = x0 + cell_w
            y1 = y0 + cell_h
            c.create_rectangle(x0, y0, x1, y1, fill=fill_bg, outline=accent, width=1.5)
            c.create_text(x0 + 10, y0 + 16, text=title, anchor=tk.W, fill=accent, font=("Segoe UI", 8, "bold"))
            c.create_text(x0 + 10, y0 + cell_h * 0.54, text=val, anchor=tk.W, fill="#FFFFFF", font=("Segoe UI", 18, "bold"))
            c.create_text(x0 + 10, y1 - 14, text=sub, anchor=tk.W, fill="#CBD5E1", font=("Segoe UI", 8))

        # 2. Rule Trigger & MITRE Horizontal Bar Chart
        mc = self.mitre_canvas
        mc.delete("all")
        mw = max(420, mc.winfo_width() or 540)
        mh = max(250, mc.winfo_height() or 270)

        items = list(report.triggered_rule_counts.items())
        if not items:
            mc.create_text(mw / 2, mh / 2, text="Chưa có rule nào được kích hoạt", fill=PALETTE["text_secondary"])
            return

        max_val = max(v for _, v in items) or 1
        top_pad = 10
        row_h = min(34, (mh - top_pad * 2) / max(1, len(items)))
        label_w = 235
        bar_max_w = max(80, mw - label_w - 85)
        bar_colors = [PALETTE["cyan"], PALETTE["crimson"], PALETTE["emerald"], PALETTE["violet"], PALETTE["amber"], "#38BDF8"]

        for idx, (rule_id, cnt) in enumerate(items[:10]):
            y_center = top_pad + idx * row_h + row_h / 2
            color = bar_colors[idx % len(bar_colors)]
            mc.create_text(
                10, y_center, text=rule_id, anchor=tk.W, fill=PALETTE["text_primary"], font=("Consolas", 9, "bold")
            )
            bar_w = (cnt / max_val) * bar_max_w
            y0 = y_center - row_h * 0.30
            y1 = y_center + row_h * 0.30
            mc.create_rectangle(label_w, y0, label_w + bar_max_w, y1, fill=PALETTE["bg_input"], outline="")
            mc.create_rectangle(label_w, y0, label_w + max(4, bar_w), y1, fill=color, outline="")
            mc.create_text(
                label_w + bar_w + 8, y_center, text=f"{cnt:,} alerts", anchor=tk.W, fill=color, font=("Segoe UI", 8, "bold")
            )

    def _refresh_alerts_table(self) -> None:
        for item in self.alerts_tree.get_children():
            self.alerts_tree.delete(item)
        if self.last_report is None:
            return
        q = self.alert_filter_var.get().strip().lower()
        for det in self.last_report.sample_detections:
            blob = f"{det['event_id']} {det['rule_id']} {det['scenario']} {det['target']}".lower()
            if q and q not in blob:
                continue
            self.alerts_tree.insert(
                "",
                tk.END,
                values=(
                    det["event_id"],
                    det["detector"],
                    det["rule_id"],
                    det["target"],
                    det["scenario"],
                    det["explanation"],
                ),
            )

    def _refresh_events_table(self) -> None:
        for item in self.events_tree.get_children():
            self.events_tree.delete(item)
        q = self.xml_search_var.get().strip().lower()
        only_mal = self.only_malicious_var.get()

        shown = 0
        for idx, rec in enumerate(self.last_records):
            if only_mal and not rec.is_malicious:
                continue
            blob = f"{rec.event_id} {rec.scenario} {rec.mitre_technique_id or ''}".lower()
            if q and q not in blob:
                continue
            kind_lbl = "🔴 ATTACK" if rec.is_malicious else "🟢 BENIGN"
            self.events_tree.insert(
                "",
                tk.END,
                iid=str(idx),
                values=(
                    rec.event_id,
                    rec.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                    kind_lbl,
                    rec.mitre_technique_id or "-",
                    rec.scenario,
                    ", ".join(rec.expected_rule_ids) or "(None)",
                ),
            )
            shown += 1
            if shown >= 400:
                break

    def _on_event_selected(self, _event: Any = None) -> None:
        sel = self.events_tree.selection()
        if not sel:
            return
        idx = int(sel[0])
        if 0 <= idx < len(self.last_records):
            rec = self.last_records[idx]
            pretty_xml = rec.xml.replace("><", ">\n  <")
            meta_json = json.dumps(rec.to_jsonl_dict(), indent=2, ensure_ascii=False)
            self.xml_viewer.delete("1.0", tk.END)
            self.xml_viewer.insert(
                tk.END,
                f"=== WINDOWS EVENT XML ({rec.event_id}) ===\n{pretty_xml}\n\n=== GROUND TRUTH METADATA ===\n{meta_json}",
            )

    def _refresh_ueba_view(self, report: DetailedEvaluationReport) -> None:
        self.ueba_text.delete("1.0", tk.END)
        u = report.ueba_evaluation
        if not u:
            self.ueba_text.insert(tk.END, "UEBA Evaluation đang tắt. Hãy tích chọn mục 7 ở thanh bên trái và chạy lại.")
            return

        prof = u.get("profile_summary", {})
        lines = [
            "================================================================================",
            "  HỒ SƠ HÀNH VI 7 NGÀY (BEHAVIORAL PROFILE STORE) & KẾT QUẢ ATOMIC RED TEAM",
            "================================================================================",
            f"Tổng sự kiện học Baseline 7 ngày : {u['baseline_event_count']:,} events",
            f"Số User đã lập hồ sơ             : {u['learned_user_count']} (nguyen.an, tran.binh, admin.it)",
            f"Số Machine đã lập hồ sơ          : {u['learned_machine_count']} (PC-01, PC-02, SRV-FILE01)",
            f"Precision / Recall / F1-Score    : {u['metrics']['precision']*100:.2f}% / {u['metrics']['recall']*100:.2f}% / {u['metrics']['f1_score']*100:.2f}%",
            f"Deviation Tag Match Rate         : {u['metrics']['deviation_tag_match_rate']*100:.2f}%",
            "\n--- CHI TIẾT HỒ SƠ THÓI QUEN TỪNG NGƯỜI DÙNG ---",
        ]
        for uname, udata in prof.get("users", {}).items():
            lines.append(
                f"  • User '{uname}': Giờ làm={udata['hours']} | Máy={udata['machines']} | "
                f"Tiến trình={udata['processes']} | Đích mạng={udata['destinations']}"
            )
        lines.append("\n--- 8 ĐÒN TẤN CÔNG ATOMIC RED TEAM BỊ BẮT TRÚNG (UEBA-BEHAVIOR-DEVIATION) ---")
        for det in u.get("sample_detections", []):
            lines.append(f"  [!] {det['event_id']} | {det['target']:<22} | {det['scenario']:<34} -> {det['explanation']}")
        self.ueba_text.insert(tk.END, "\n".join(lines))

    def _populate_vm_guide(self) -> None:
        guide = """================================================================================
  QUY TRÌNH THU THẬP LOG .EVTX THẬT & QUÉT SIGMA TRÊN MÁY ẢO WINDOWS (VMWARE)
================================================================================
Khi triển khai trên 2 máy ảo VMware (Red Team VM <-> Blue Team GlobalBan VM), chạy
các lệnh PowerShell sau bằng quyền Administrator tại thư mục dự án:

1. Kiểm tra cấu hình máy ảo & trạng thái 4 kênh log (Security, Sysmon, PowerShell, Defender):
   .\\scripts\\preflight.ps1

2. Thu thập dữ liệu hoạt động bình thường Baseline (mỗi ngày 1 case_id):
   .\\scripts\\collect_windows_logs.ps1 -CaseId baseline-day-01 -Kind baseline
   .\\scripts\\collect_windows_logs.ps1 -CaseId baseline-day-02 -Kind baseline
   .\\scripts\\collect_windows_logs.ps1 -CaseId baseline-day-03 -Kind baseline

3. Chạy kỹ thuật Atomic Red Team có phê duyệt (-Approved) & tự động dọn dẹp (Cleanup):
   .\\scripts\\run_approved_atomic.ps1 -CaseId atomic-T1059-001-test-01 -TechniqueId T1059.001 -TestNumbers 1 -Approved
   .\\scripts\\run_approved_atomic.ps1 -CaseId atomic-T1053-005-test-01 -TechniqueId T1053.005 -TestNumbers 1 -Approved

4. Trích xuất trực tiếp Event Viewer thật sang file XML hợp nhất cho GlobalBan:
   .\\scripts\\collect_windows_vm_logs.ps1

5. Quét đối chiếu luật Sigma & đóng gói bàn giao chuẩn Pháp chứng số (SHA256):
   .\\scripts\\run_sigma_on_evtx.ps1
   .\\scripts\\validate_handoff.ps1
================================================================================
"""
        self.vm_text.insert(tk.END, guide)

    def run_push_xml_cli(self) -> None:
        if self.last_xml_path is None or not self.last_xml_path.is_file():
            self.run_generate_and_evaluate()
        if self.last_xml_path is None or self.last_report is None:
            return

        gb_str = self.globalban_dir_var.get().strip()
        gb_root = Path(gb_str) if gb_str else None
        if gb_root and (gb_root / "src" / "globalban").is_dir():
            src_str = str((gb_root / "src").resolve())
            if src_str not in sys.path:
                sys.path.insert(0, src_str)
            try:
                from globalban.main import main as globalban_main

                argv = ["--windows-xml", str(self.last_xml_path.resolve())]
                if self.last_report.ueba_baseline_xml_path:
                    argv.extend(["--learn-baseline", str(self.last_report.ueba_baseline_xml_path.resolve())])
                if self.last_report.ueba_profile_json_path:
                    argv.extend(["--profile-path", str(self.last_report.ueba_profile_json_path.resolve())])
                buf = StringIO()
                with redirect_stdout(buf):
                    globalban_main(argv)
                messagebox.showinfo(
                    "Đã đẩy XML vào GlobalBan CLI",
                    f"Đã gửi thành công {self.last_xml_path.name} vào GlobalBan CLI!\n"
                    f"Kiểm tra chi tiết tại tab 'Báo Cáo Chấm Điểm Chi Tiết'.",
                    parent=self.root,
                )
                return
            except Exception as exc:
                messagebox.showerror("Lỗi GlobalBan CLI", str(exc), parent=self.root)
                return

        # Standalone mode feedback
        total_alerts = sum(self.last_report.triggered_rule_counts.values())
        messagebox.showinfo(
            "Đã kiểm định trên Standalone GlobalBan Engine",
            f"Thư mục GlobalBan ngoài chưa được gắn trên máy này, hệ thống đã chạy kiểm định "
            f"trực tiếp trên Built-in GlobalBan Engine:\n\n"
            f"• File XML: {self.last_xml_path.name}\n"
            f"• Tổng tín hiệu cảnh báo phát hiện: {total_alerts:,}\n"
            f"• Precision: {self.last_report.precision*100:.2f}% | Recall: {self.last_report.recall*100:.2f}% | FPR: {self.last_report.false_positive_rate*100:.2f}%\n\n"
            f"Bạn có thể copy thư mục output/ sang máy ảo GlobalBan hoặc bấm 'Chọn GlobalBan' ở góc trên.",
            parent=self.root,
        )

    def open_globalban_dashboard(self) -> None:
        if self.last_xml_path is None or not self.last_xml_path.is_file():
            self.run_generate_and_evaluate()

        gb_str = self.globalban_dir_var.get().strip()
        gb_root = Path(gb_str) if gb_str else None
        if gb_root and (gb_root / "src" / "globalban").is_dir():
            venv_py = gb_root / ".venv" / "Scripts" / "python.exe"
            py_exe = str(venv_py) if venv_py.is_file() else sys.executable
            cmd = [py_exe, "-m", "globalban.main", "--dashboard"]
            demo_cfg = gb_root / "config" / "demo.config.json"
            if demo_cfg.is_file():
                cmd.extend(["--config", str(demo_cfg)])
            if self.last_report and self.last_report.ueba_baseline_xml_path:
                cmd.extend(["--learn-baseline", str(self.last_report.ueba_baseline_xml_path.resolve())])
            if self.last_report and self.last_report.ueba_profile_json_path:
                cmd.extend(["--profile-path", str(self.last_report.ueba_profile_json_path.resolve())])
            if self.last_xml_path:
                xml_s = str(self.last_xml_path.resolve())
                cmd.extend(["--windows-xml", xml_s, "--watch-windows-xml", xml_s])
            env = os.environ.copy()
            src_p = str((gb_root / "src").resolve())
            env["PYTHONPATH"] = f"{src_p}{os.pathsep}{env['PYTHONPATH']}" if env.get("PYTHONPATH") else src_p
            subprocess.Popen(cmd, cwd=str(gb_root), env=env)
            self.status_var.set("🚀 Đã khởi chạy cửa sổ GlobalBan Security & UEBA Dashboard!")
        else:
            self.notebook.select(3)
            messagebox.showinfo(
                "Chế độ Standalone Dashboard",
                "Không tìm thấy mã nguồn GlobalBan ngoài trên máy cục bộ (ví dụ đang chạy trên máy ảo Red Team riêng).\n\n"
                "Hệ thống đã chuyển sang tab 'Hồ Sơ UEBA 7 Ngày & Atomic' để bạn theo dõi trực tiếp các cảnh báo và hồ sơ hành vi ngay tại đây!",
                parent=self.root,
            )

    def _copy_report_to_clipboard(self) -> None:
        txt = self.report_text.get("1.0", tk.END).strip()
        self.root.clipboard_clear()
        self.root.clipboard_append(txt)
        self.status_var.set("📋 Đã sao chép toàn bộ báo cáo vào Clipboard!")

    def _export_markdown_report(self) -> None:
        if self.last_report is None:
            return
        out_dir = Path(self.output_dir_var.get())
        out_dir.mkdir(parents=True, exist_ok=True)
        md_path = out_dir / "BAO_CAO_CHAM_DIEM_GLOBALBAN.md"
        md_content = "# BÁO CÁO ĐÁNH GIÁ HỆ THỐNG PHÒNG THỦ GLOBALBAN\n\n```text\n" + format_report_text(self.last_report) + "\n```\n"
        md_path.write_text(md_content, encoding="utf-8")
        self.status_var.set(f"💾 Đã xuất báo cáo Markdown tại: {md_path}")
        messagebox.showinfo("Xuất báo cáo thành công", f"Đã lưu file báo cáo tại:\n{md_path}", parent=self.root)


def launch_gui(output_dir: Path | None = None, globalban_root: Path | None = None) -> None:
    root = tk.Tk()
    ModernRedTeamStudioApp(root, output_dir=output_dir, globalban_root=globalban_root)
    root.mainloop()
