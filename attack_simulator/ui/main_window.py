# -*- coding: utf-8 -*-
"""
attack_simulator.ui.main_window
===============================
Cửa sổ chính GlobalBan Red-Team Studio:
  - Thanh tiêu đề chuyên nghiệp
  - Sidebar điều khiển kịch bản + tham số
  - 6 thẻ KPI (Precision / Recall / F1 / FPR / Rule Acc / Tổng sự kiện)
  - 6 Tabs nội dung chi tiết
  - Thanh trạng thái phía dưới
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tkinter as tk
import webbrowser
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from typing import Any

from attack_simulator.core.evaluator import (
    DetailedEvaluationReport,
    format_report_text,
    resolve_default_globalban_root,
    run_unified_evaluation,
)
from attack_simulator.core.models import SCENARIO_CATALOG, SimulatedRecord
from attack_simulator.generator import WindowsAttackLogGenerator, export_dataset_files
from attack_simulator.ui.charts import draw_confusion_matrix, draw_mitre_bar_chart
from attack_simulator.ui.tabs import (
    build_detections_tab,
    build_overview_tab,
    build_report_tab,
    build_ueba_atomic_tab,
    build_vm_guide_tab,
    build_xml_inspector_tab,
)
from attack_simulator.ui.theme import PALETTE, configure_ttk_styles, make_btn
from config import (
    DEFAULT_BENIGN_COUNT,
    DEFAULT_CAMPAIGNS_PER_SCENARIO,
    DEFAULT_FP_NOISE_COUNT,
    DEFAULT_OUTPUT_DIR,
    DEFAULT_SEED,
)


# ═══════════════════════════════════════════════════════════════════════
#  Hằng số giao diện
# ═══════════════════════════════════════════════════════════════════════
_SIDEBAR_W = 300
_HDR_H      = 58
_STATUS_H   = 26

_FONT_TITLE  = ("Segoe UI", 13, "bold")
_FONT_SUB    = ("Segoe UI",  8)
_FONT_LABEL  = ("Segoe UI",  9)
_FONT_LABEL_B= ("Segoe UI",  9, "bold")
_FONT_KPI    = ("Segoe UI", 16, "bold")
_FONT_KPI_SM = ("Segoe UI",  8)
_FONT_SECT   = ("Segoe UI",  8, "bold")
_FONT_BTN    = ("Segoe UI",  9, "bold")
_FONT_BTN_SM = ("Segoe UI",  8, "bold")
_FONT_MONO   = ("Consolas",  9)


# ═══════════════════════════════════════════════════════════════════════
#  Lớp ứng dụng chính
# ═══════════════════════════════════════════════════════════════════════
class ModernRedTeamStudioApp:
    """Giao diện SOC-style Red-Team Adversary Emulation & Benchmark Studio."""

    # ──────────────────────────────────────────────────────────────────
    #  Khởi tạo
    # ──────────────────────────────────────────────────────────────────
    def __init__(
        self,
        root: tk.Tk,
        output_dir: Path | None = None,
        globalban_root: Path | None = None,
    ) -> None:
        self.root = root
        self.root.title(
            "GlobalBan Red-Team Studio  ·  MITRE ATT&CK Adversary Emulation & UEBA Benchmark"
        )
        self.root.geometry("1420x900")
        self.root.minsize(1200, 760)
        self.root.configure(bg=PALETTE["bg_root"])

        # Đường dẫn
        self.output_dir_var    = tk.StringVar(value=str(output_dir or DEFAULT_OUTPUT_DIR))
        detected_gb            = globalban_root or resolve_default_globalban_root()
        self.globalban_dir_var = tk.StringVar(value=str(detected_gb) if detected_gb else "")

        # Trạng thái dữ liệu
        self.last_records:    list[SimulatedRecord]         = []
        self.last_xml_path:   Path | None                   = None
        self.last_jsonl_path: Path | None                   = None
        self.last_report:     DetailedEvaluationReport | None = None

        # Biến điều khiển kịch bản
        self.scenario_vars: dict[str, tk.BooleanVar] = {}
        self.ueba_var    = tk.BooleanVar(value=True)
        self.lolbin_var  = tk.BooleanVar(value=True)
        self.campaigns_var = tk.IntVar(value=DEFAULT_CAMPAIGNS_PER_SCENARIO)
        self.benign_var    = tk.IntVar(value=DEFAULT_BENIGN_COUNT)
        self.fp_noise_var  = tk.IntVar(value=DEFAULT_FP_NOISE_COUNT)
        self.seed_var      = tk.IntVar(value=DEFAULT_SEED)

        # Biến trạng thái hiển thị
        self.status_var       = tk.StringVar(value="Sẵn sàng  —  Nhấn [▶ Sinh Log & Chấm Điểm] để bắt đầu")
        self.engine_badge_var = tk.StringVar(value="")

        # Biến KPI
        self.kpi_vars: dict[str, tk.StringVar] = {
            "total":     tk.StringVar(value="0"),
            "total_sub": tk.StringVar(value="Tấn công: 0  |  Bình thường: 0"),
            "precision": tk.StringVar(value="—"),
            "recall":    tk.StringVar(value="—"),
            "f1":        tk.StringVar(value="—"),
            "fpr":       tk.StringVar(value="—"),
            "rule_acc":  tk.StringVar(value="—"),
        }

        configure_ttk_styles(self.root)
        self._build_layout()
        self._refresh_engine_badge()
        self.root.after(200, self.run_generate_and_evaluate)

    # ──────────────────────────────────────────────────────────────────
    #  Xây dựng bố cục tổng thể
    # ──────────────────────────────────────────────────────────────────
    def _build_layout(self) -> None:
        self._build_header()
        self._build_status_bar()      # pack bottom trước để không bị chèn
        self._build_body()

    # ──────────────────────────────────────────────────────────────────
    #  Thanh tiêu đề (Header)
    # ──────────────────────────────────────────────────────────────────
    def _build_header(self) -> None:
        hdr = tk.Frame(
            self.root,
            bg=PALETTE["bg_header"],
            height=_HDR_H,
            highlightbackground=PALETTE["border"],
            highlightthickness=1,
        )
        hdr.pack(fill=tk.X, side=tk.TOP)
        hdr.pack_propagate(False)

        # ── Trái: Logo + tiêu đề ──────────────────────────────────────
        left = tk.Frame(hdr, bg=PALETTE["bg_header"])
        left.pack(side=tk.LEFT, padx=16, pady=0)

        # Dải màu đỏ bên trái (accent bar)
        accent = tk.Frame(hdr, bg=PALETTE["crimson"], width=3)
        accent.pack(side=tk.LEFT, fill=tk.Y, pady=10)

        logo_frame = tk.Frame(hdr, bg=PALETTE["bg_header"])
        logo_frame.pack(side=tk.LEFT, padx=(10, 0))

        tk.Label(
            logo_frame,
            text="⚡",
            font=("Segoe UI Emoji", 18),
            bg=PALETTE["bg_header"],
            fg=PALETTE["crimson"],
        ).pack(side=tk.LEFT)

        title_col = tk.Frame(logo_frame, bg=PALETTE["bg_header"])
        title_col.pack(side=tk.LEFT, padx=(6, 0))

        tk.Label(
            title_col,
            text="GLOBALBAN  RED-TEAM STUDIO",
            font=_FONT_TITLE,
            bg=PALETTE["bg_header"],
            fg=PALETTE["text_accent"],
        ).pack(anchor="w")
        tk.Label(
            title_col,
            text="MITRE ATT&CK Adversary Emulation  ·  UEBA Benchmark  ·  Purple Team Lab",
            font=_FONT_SUB,
            bg=PALETTE["bg_header"],
            fg=PALETTE["text_secondary"],
        ).pack(anchor="w")

        # ── Phải: Badge + nút ────────────────────────────────────────
        right = tk.Frame(hdr, bg=PALETTE["bg_header"])
        right.pack(side=tk.RIGHT, padx=14)

        self.badge_label = tk.Label(
            right,
            textvariable=self.engine_badge_var,
            font=("Segoe UI", 8, "bold"),
            bg=PALETTE["bg_header"],
            fg=PALETTE["emerald"],
            padx=10,
            pady=4,
            relief=tk.FLAT,
        )
        self.badge_label.pack(side=tk.RIGHT, padx=(8, 0))

        make_btn(
            right, "📂  Chọn GlobalBan", self._browse_globalban_dir,
            bg=PALETTE["bg_input"], hover_bg=PALETTE["border_light"],
            fg=PALETTE["sky"], font=_FONT_BTN_SM, padx=10, pady=4,
        ).pack(side=tk.RIGHT, padx=3)

        make_btn(
            right, "📁  Thư mục Output", self._open_output_folder,
            bg=PALETTE["bg_input"], hover_bg=PALETTE["border_light"],
            fg=PALETTE["text_secondary"], font=_FONT_BTN_SM, padx=10, pady=4,
        ).pack(side=tk.RIGHT, padx=3)

    # ──────────────────────────────────────────────────────────────────
    #  Thanh trạng thái (Status Bar)
    # ──────────────────────────────────────────────────────────────────
    def _build_status_bar(self) -> None:
        sb = tk.Frame(
            self.root,
            bg=PALETTE["bg_header"],
            height=_STATUS_H,
            highlightbackground=PALETTE["border"],
            highlightthickness=1,
        )
        sb.pack(fill=tk.X, side=tk.BOTTOM)
        sb.pack_propagate(False)

        # Chấm trạng thái
        tk.Label(sb, text="●", font=("Segoe UI", 10), bg=PALETTE["bg_header"],
                 fg=PALETTE["emerald"]).pack(side=tk.LEFT, padx=(12, 4))
        tk.Label(
            sb, textvariable=self.status_var,
            font=_FONT_SUB, bg=PALETTE["bg_header"], fg=PALETTE["text_secondary"],
        ).pack(side=tk.LEFT)

        # Đường dẫn output bên phải
        tk.Label(
            sb, textvariable=self.output_dir_var,
            font=("Consolas", 8), bg=PALETTE["bg_header"], fg=PALETTE["text_muted"],
        ).pack(side=tk.RIGHT, padx=12)
        tk.Label(
            sb, text="📂", font=_FONT_SUB, bg=PALETTE["bg_header"],
            fg=PALETTE["text_muted"],
        ).pack(side=tk.RIGHT)

    # ──────────────────────────────────────────────────────────────────
    #  Vùng nội dung chính
    # ──────────────────────────────────────────────────────────────────
    def _build_body(self) -> None:
        body = tk.Frame(self.root, bg=PALETTE["bg_root"])
        body.pack(fill=tk.BOTH, expand=True)

        self._build_sidebar(body)
        self._build_right_area(body)

    # ──────────────────────────────────────────────────────────────────
    #  Sidebar bên trái
    # ──────────────────────────────────────────────────────────────────
    def _build_sidebar(self, parent: tk.Widget) -> None:
        sidebar = tk.Frame(
            parent,
            bg=PALETTE["bg_sidebar"],
            width=_SIDEBAR_W,
            highlightbackground=PALETTE["border"],
            highlightthickness=1,
        )
        sidebar.pack(side=tk.LEFT, fill=tk.Y)
        sidebar.pack_propagate(False)

        # Canvas + Scrollbar để cuộn khi màn hình nhỏ
        canvas = tk.Canvas(
            sidebar, bg=PALETTE["bg_sidebar"], highlightthickness=0, bd=0,
        )
        vsb = tk.Scrollbar(sidebar, orient=tk.VERTICAL, command=canvas.yview)
        canvas.configure(yscrollcommand=vsb.set)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)
        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        inner = tk.Frame(canvas, bg=PALETTE["bg_sidebar"])
        win_id = canvas.create_window((0, 0), window=inner, anchor="nw")

        def _on_resize(e: Any) -> None:
            canvas.itemconfig(win_id, width=e.width)
        canvas.bind("<Configure>", _on_resize)

        def _on_inner_resize(e: Any) -> None:
            canvas.configure(scrollregion=canvas.bbox("all"))
        inner.bind("<Configure>", _on_inner_resize)

        # Nội dung sidebar
        pad = dict(padx=12, pady=0)

        # ── Tiêu đề sidebar ───────────────────────────────────────────
        title_bar = tk.Frame(inner, bg=PALETTE["crimson_dim"], pady=6)
        title_bar.pack(fill=tk.X)
        tk.Label(
            title_bar, text="⚔  ĐIỀU KHIỂN CHIẾN DỊCH",
            font=_FONT_SECT, bg=PALETTE["crimson_dim"], fg=PALETTE["crimson"],
        ).pack(padx=12, anchor="w")

        # ── Phân cách ─────────────────────────────────────────────────
        def _divider(text: str = "", color: str = PALETTE["cyan"]) -> None:
            d = tk.Frame(inner, bg=PALETTE["bg_sidebar"], pady=2)
            d.pack(fill=tk.X, **pad)
            tk.Frame(d, bg=PALETTE["border"], height=1).pack(fill=tk.X)
            if text:
                tk.Label(
                    inner, text=text,
                    font=_FONT_SECT, bg=PALETTE["bg_sidebar"], fg=color,
                ).pack(anchor="w", padx=12, pady=(6, 2))

        # ── Danh sách kịch bản ────────────────────────────────────────
        _divider("KỊCH BẢN TẤN CÔNG MITRE ATT&CK")

        for spec in SCENARIO_CATALOG:
            var = tk.BooleanVar(value=True)
            self.scenario_vars[spec.key] = var
            row = tk.Frame(inner, bg=PALETTE["bg_card_alt"], pady=3, padx=8)
            row.pack(fill=tk.X, padx=10, pady=2)

            dot = tk.Label(
                row, text="◆", fg=spec.accent_color,
                bg=PALETTE["bg_card_alt"], font=("Segoe UI", 7),
            )
            dot.pack(side=tk.LEFT, padx=(0, 5))

            cb = tk.Checkbutton(
                row,
                text=spec.title,
                variable=var,
                bg=PALETTE["bg_card_alt"],
                fg=PALETTE["text_primary"],
                selectcolor=PALETTE["bg_input"],
                activebackground=PALETTE["bg_card_alt"],
                activeforeground=PALETTE["text_primary"],
                font=("Segoe UI", 9),
                anchor=tk.W,
                bd=0,
                highlightthickness=0,
            )
            cb.pack(side=tk.LEFT, fill=tk.X, expand=True)

        # Thêm 2 kịch bản UEBA & LotL
        for label, var_obj, color in (
            ("7. UEBA 7-Day Baseline & Atomic Red Team", self.ueba_var,   PALETTE["violet"]),
            ("8. WinLOLBIN-GT Living Off The Land",      self.lolbin_var, PALETTE["emerald"]),
        ):
            row = tk.Frame(inner, bg=PALETTE["bg_card_alt"], pady=3, padx=8)
            row.pack(fill=tk.X, padx=10, pady=2)
            tk.Label(row, text="◆", fg=color, bg=PALETTE["bg_card_alt"], font=("Segoe UI", 7)).pack(side=tk.LEFT, padx=(0, 5))
            tk.Checkbutton(
                row, text=label, variable=var_obj,
                bg=PALETTE["bg_card_alt"], fg=PALETTE["text_primary"],
                selectcolor=PALETTE["bg_input"],
                activebackground=PALETTE["bg_card_alt"],
                activeforeground=PALETTE["text_primary"],
                font=("Segoe UI", 9), anchor=tk.W, bd=0, highlightthickness=0,
            ).pack(side=tk.LEFT, fill=tk.X, expand=True)

        # Nút chọn / bỏ chọn
        sel_row = tk.Frame(inner, bg=PALETTE["bg_sidebar"])
        sel_row.pack(fill=tk.X, padx=10, pady=(6, 0))

        def _select_all():
            for v in self.scenario_vars.values(): v.set(True)
            self.ueba_var.set(True); self.lolbin_var.set(True)

        def _clear_all():
            for v in self.scenario_vars.values(): v.set(False)
            self.ueba_var.set(False); self.lolbin_var.set(False)

        make_btn(sel_row, "✓  Chọn tất cả", _select_all,
                 bg=PALETTE["bg_input"], hover_bg=PALETTE["border_light"],
                 fg=PALETTE["emerald"], font=_FONT_BTN_SM, padx=8, pady=4,
        ).pack(side=tk.LEFT, expand=True, fill=tk.X, padx=(0, 3))
        make_btn(sel_row, "✕  Bỏ chọn", _clear_all,
                 bg=PALETTE["bg_input"], hover_bg=PALETTE["border_light"],
                 fg=PALETTE["crimson"], font=_FONT_BTN_SM, padx=8, pady=4,
        ).pack(side=tk.LEFT, expand=True, fill=tk.X, padx=(3, 0))

        # ── Tham số sinh dữ liệu ─────────────────────────────────────
        _divider("THAM SỐ SINH DỮ LIỆU KIỂM CHUẨN", PALETTE["amber"])

        params_frame = tk.Frame(inner, bg=PALETTE["bg_sidebar"])
        params_frame.pack(fill=tk.X, padx=12, pady=(0, 4))
        params_frame.columnconfigure(1, weight=1)

        param_specs = [
            ("Chiến dịch / kịch bản:",   self.campaigns_var, 1,     500,   5),
            ("Log bình thường (Benign):", self.benign_var,    0,  20000, 100),
            ("Nhiễu Admin (Test FPR):",   self.fp_noise_var,  0,   1000,   5),
            ("Random Seed tái lập:",      self.seed_var,      1,  99999,   1),
        ]
        for r, (lbl, var_obj, mn, mx, inc) in enumerate(param_specs):
            tk.Label(
                params_frame, text=lbl,
                bg=PALETTE["bg_sidebar"], fg=PALETTE["text_secondary"],
                font=_FONT_LABEL,
            ).grid(row=r, column=0, sticky="w", pady=5, padx=(0, 6))

            sb = tk.Spinbox(
                params_frame,
                from_=mn, to=mx, increment=inc,
                textvariable=var_obj, width=8,
                bg=PALETTE["bg_input"], fg=PALETTE["text_primary"],
                buttonbackground=PALETTE["bg_card_alt"],
                insertbackground=PALETTE["text_primary"],
                relief=tk.FLAT,
                font=_FONT_MONO,
                highlightthickness=1,
                highlightbackground=PALETTE["border"],
                highlightcolor=PALETTE["cyan"],
            )
            sb.grid(row=r, column=1, sticky="e", pady=5)

        # ── Các nút hành động chính ───────────────────────────────────
        _divider()

        btn_frame = tk.Frame(inner, bg=PALETTE["bg_sidebar"])
        btn_frame.pack(fill=tk.X, padx=10, pady=4)

        make_btn(
            btn_frame,
            "▶  SINH LOG XML & CHẤM ĐIỂM",
            self.run_generate_and_evaluate,
            bg=PALETTE["crimson"], hover_bg=PALETTE["crimson_dark"],
            font=_FONT_BTN, pady=10,
        ).pack(fill=tk.X, pady=(0, 5))

        make_btn(
            btn_frame,
            "⚡  ĐẨY LOG VÀO GLOBALBAN CLI",
            self.run_push_xml_cli,
            bg=PALETTE["cyan_dark"], hover_bg=PALETTE["cyan"],
            font=_FONT_BTN, pady=8,
        ).pack(fill=tk.X, pady=(0, 5))

        make_btn(
            btn_frame,
            "🖥  MỞ GLOBALBAN DASHBOARD",
            self.open_globalban_dashboard,
            bg=PALETTE["bg_input"], hover_bg=PALETTE["border_light"],
            fg=PALETTE["sky"], font=_FONT_BTN, pady=8,
        ).pack(fill=tk.X, pady=(0, 5))

        # Padding cuối
        tk.Frame(inner, bg=PALETTE["bg_sidebar"], height=16).pack()

    # ──────────────────────────────────────────────────────────────────
    #  Vùng bên phải: KPI + Tabs
    # ──────────────────────────────────────────────────────────────────
    def _build_right_area(self, parent: tk.Widget) -> None:
        right = tk.Frame(parent, bg=PALETTE["bg_root"])
        right.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=(1, 0))

        self._build_kpi_row(right)
        self._build_notebook(right)

    # ──────────────────────────────────────────────────────────────────
    #  Hàng thẻ KPI
    # ──────────────────────────────────────────────────────────────────
    def _build_kpi_row(self, parent: tk.Widget) -> None:
        kpi_row = tk.Frame(parent, bg=PALETTE["bg_root"])
        kpi_row.pack(fill=tk.X, padx=10, pady=(8, 6))

        kpi_defs = [
            ("TỔNG SỰ KIỆN",     "total",     PALETTE["sky"],     "total_sub"),
            ("PRECISION",        "precision", PALETTE["emerald"], None),
            ("RECALL (ĐỘ PHỦ)", "recall",    PALETTE["emerald"], None),
            ("F1-SCORE",         "f1",        PALETTE["violet"],  None),
            ("FALSE POS. RATE",  "fpr",       PALETTE["amber"],   None),
            ("RULE MATCH ACC",   "rule_acc",  PALETTE["cyan"],    None),
        ]

        for idx, (title, key, color, sub_key) in enumerate(kpi_defs):
            card = tk.Frame(
                kpi_row,
                bg=PALETTE["bg_card"],
                highlightbackground=PALETTE["border"],
                highlightthickness=1,
                padx=14,
                pady=8,
            )
            card.grid(row=0, column=idx, sticky="nsew", padx=(0 if idx == 0 else 6, 0))
            kpi_row.columnconfigure(idx, weight=1)

            # Chữ nhỏ tiêu đề KPI
            tk.Label(
                card, text=title,
                font=("Segoe UI", 7, "bold"),
                bg=PALETTE["bg_card"], fg=PALETTE["text_muted"],
                anchor="w",
            ).pack(anchor="w")

            # Giá trị lớn
            tk.Label(
                card, textvariable=self.kpi_vars[key],
                font=_FONT_KPI,
                bg=PALETTE["bg_card"], fg=color,
            ).pack(anchor="w", pady=(1, 0))

            # Phụ đề (chỉ KPI tổng)
            if sub_key:
                tk.Label(
                    card, textvariable=self.kpi_vars[sub_key],
                    font=_FONT_KPI_SM,
                    bg=PALETTE["bg_card"], fg=PALETTE["text_muted"],
                ).pack(anchor="w")

            # Gạch màu dưới thẻ
            tk.Frame(card, bg=color, height=2).pack(fill=tk.X, side=tk.BOTTOM)

    # ──────────────────────────────────────────────────────────────────
    #  Notebook (tabs)
    # ──────────────────────────────────────────────────────────────────
    def _build_notebook(self, parent: tk.Widget) -> None:
        self.notebook = ttk.Notebook(parent)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 6))

        build_overview_tab(self.notebook, self)
        build_detections_tab(self.notebook, self)
        build_xml_inspector_tab(self.notebook, self)
        build_ueba_atomic_tab(self.notebook, self)
        build_report_tab(self.notebook, self)
        build_vm_guide_tab(self.notebook, self)

    # ══════════════════════════════════════════════════════════════════
    #  Cập nhật engine badge
    # ══════════════════════════════════════════════════════════════════
    def _refresh_engine_badge(self) -> None:
        gb_str  = self.globalban_dir_var.get().strip()
        gb_path = Path(gb_str) if gb_str else None
        if gb_path and (gb_path / "src" / "globalban").is_dir():
            self.engine_badge_var.set("● GLOBALBAN LINKED")
            self.badge_label.configure(fg=PALETTE["emerald"], bg=PALETTE["bg_header"])
        else:
            self.engine_badge_var.set("● STANDALONE ENGINE")
            self.badge_label.configure(fg=PALETTE["cyan"], bg=PALETTE["bg_header"])

    # ══════════════════════════════════════════════════════════════════
    #  Hành động nút
    # ══════════════════════════════════════════════════════════════════
    def _browse_globalban_dir(self) -> None:
        chosen = filedialog.askdirectory(
            title="Chọn thư mục gốc GlobalBan (chứa thư mục src/)"
        )
        if chosen:
            self.globalban_dir_var.set(chosen)
            self._refresh_engine_badge()
            self.status_var.set(f"✓ Đã cập nhật đường dẫn GlobalBan: {chosen}")

    def _open_output_folder(self) -> None:
        out_dir = Path(self.output_dir_var.get())
        out_dir.mkdir(parents=True, exist_ok=True)
        if sys.platform.startswith("win"):
            os.startfile(str(out_dir))  # type: ignore[attr-defined]
        else:
            webbrowser.open(out_dir.as_uri())

    # ══════════════════════════════════════════════════════════════════
    #  Chạy sinh log & chấm điểm
    # ══════════════════════════════════════════════════════════════════
    def run_generate_and_evaluate(self) -> None:
        selected = [k for k, v in self.scenario_vars.items() if v.get()]
        if not selected and self.benign_var.get() <= 0 and not self.ueba_var.get() and not self.lolbin_var.get():
            messagebox.showwarning("Chưa chọn kịch bản",
                                   "Vui lòng chọn ít nhất 1 kịch bản tấn công.",
                                   parent=self.root)
            return

        self.status_var.set("⏳  Đang sinh dữ liệu Windows XML, học hồ sơ UEBA và chấm điểm…")
        self.root.update_idletasks()

        try:
            out_dir = Path(self.output_dir_var.get())
            gb_str  = self.globalban_dir_var.get().strip()
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
            xml_path   = out_dir / "simulated_windows_events.xml"
            export_dataset_files(records, jsonl_path, xml_path)
            self.last_jsonl_path = jsonl_path
            self.last_xml_path   = xml_path

            report = run_unified_evaluation(
                jsonl_path=jsonl_path,
                xml_path=xml_path,
                globalban_root=gb_root,
                evaluate_ueba=bool(self.ueba_var.get()),
                evaluate_lolbin=bool(self.lolbin_var.get()),
                output_dir=out_dir,
            )
            self.last_report = report
            (out_dir / "evaluation_report.json").write_text(
                json.dumps(report.to_dict(), indent=2, ensure_ascii=False), encoding="utf-8"
            )

            self._update_all_views(report)
            self.status_var.set(
                f"✓  Hoàn tất!  Đã sinh {report.total_events:,} sự kiện XML  •  "
                f"Precision {report.precision*100:.1f}%  Recall {report.recall*100:.1f}%  "
                f"F1 {report.f1*100:.1f}%  •  Xuất {out_dir}"
            )
        except Exception as exc:
            self.status_var.set(f"✕  Lỗi: {exc}")
            messagebox.showerror("Lỗi thực thi", str(exc), parent=self.root)

    # ══════════════════════════════════════════════════════════════════
    #  Cập nhật toàn bộ views
    # ══════════════════════════════════════════════════════════════════
    def _update_all_views(self, report: DetailedEvaluationReport) -> None:
        self.kpi_vars["total"].set(f"{report.total_events:,}")
        self.kpi_vars["total_sub"].set(
            f"Tấn công: {report.malicious_events:,}  |  Bình thường: {report.benign_events:,}"
        )
        self.kpi_vars["precision"].set(f"{report.precision * 100:.2f}%")
        self.kpi_vars["recall"].set(f"{report.recall * 100:.2f}%")
        self.kpi_vars["f1"].set(f"{report.f1 * 100:.2f}%")
        self.kpi_vars["fpr"].set(f"{report.false_positive_rate * 100:.2f}%")
        self.kpi_vars["rule_acc"].set(f"{report.rule_match_accuracy * 100:.2f}%")

        self._draw_charts()
        self._refresh_alerts_table()
        self._refresh_events_table()
        self._refresh_ueba_view(report)

        self.report_text.configure(state=tk.NORMAL)
        self.report_text.delete("1.0", tk.END)
        self.report_text.insert(tk.END, format_report_text(report))

    def _draw_charts(self) -> None:
        if self.last_report is None:
            return
        draw_confusion_matrix(self.cm_canvas, self.last_report)
        draw_mitre_bar_chart(self.mitre_canvas, self.last_report)

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
            self.alerts_tree.insert("", tk.END, values=(
                det["event_id"], det["detector"], det["rule_id"],
                det["target"], det["scenario"], det["explanation"],
            ))

    def _refresh_events_table(self) -> None:
        for item in self.events_tree.get_children():
            self.events_tree.delete(item)
        q        = self.xml_search_var.get().strip().lower()
        only_mal = self.only_malicious_var.get()
        shown    = 0
        for idx, rec in enumerate(self.last_records):
            if only_mal and not rec.is_malicious:
                continue
            blob = f"{rec.event_id} {rec.scenario} {rec.mitre_technique_id or ''}".lower()
            if q and q not in blob:
                continue
            kind_lbl = "🔴 TẤN CÔNG" if rec.is_malicious else "🟢 BÌNH THƯỜNG"
            self.events_tree.insert("", tk.END, iid=str(idx), values=(
                rec.event_id,
                rec.timestamp.strftime("%d/%m/%Y  %H:%M:%S"),
                kind_lbl,
                rec.mitre_technique_id or "—",
                rec.scenario,
                ", ".join(rec.expected_rule_ids) or "(Không có)",
            ))
            shown += 1
            if shown >= 500:
                break

    def _on_event_selected(self, _event: Any = None) -> None:
        sel = self.events_tree.selection()
        if not sel:
            return
        idx = int(sel[0])
        if 0 <= idx < len(self.last_records):
            rec = self.last_records[idx]
            pretty_xml = rec.xml.replace("><", ">\n  <")
            meta_json  = json.dumps(rec.to_jsonl_dict(), indent=2, ensure_ascii=False)
            self.xml_viewer.configure(state=tk.NORMAL)
            self.xml_viewer.delete("1.0", tk.END)
            self.xml_viewer.insert(
                tk.END,
                f"═══ WINDOWS EVENT XML (ID: {rec.event_id}) ═══\n"
                f"{pretty_xml}\n\n"
                f"═══ GROUND TRUTH METADATA ═══\n"
                f"{meta_json}",
            )

    def _refresh_ueba_view(self, report: DetailedEvaluationReport) -> None:
        self.ueba_text.configure(state=tk.NORMAL)
        self.ueba_text.delete("1.0", tk.END)
        u = report.ueba_evaluation
        if not u:
            self.ueba_text.insert(
                tk.END,
                "⚠  UEBA Evaluation đang tắt.\n"
                "   Hãy tích chọn mục 7 ở thanh bên trái và chạy lại.",
            )
            return

        prof  = u.get("profile_summary", {})
        lines = [
            "═" * 80,
            "  HỒ SƠ HÀNH VI 7 NGÀY (BEHAVIORAL PROFILE STORE) & KẾT QUẢ ATOMIC RED TEAM",
            "═" * 80,
            f"  Sự kiện học Baseline 7 ngày  : {u['baseline_event_count']:,} sự kiện",
            f"  Số User đã lập hồ sơ         : {u['learned_user_count']} người dùng (nguyen.an, tran.binh, admin.it)",
            f"  Số Machine đã lập hồ sơ      : {u['learned_machine_count']} máy (PC-01, PC-02, SRV-FILE01)",
            f"  Precision / Recall / F1-Score : {u['metrics']['precision']*100:.2f}% / {u['metrics']['recall']*100:.2f}% / {u['metrics']['f1_score']*100:.2f}%",
            f"  Deviation Tag Match Rate      : {u['metrics']['deviation_tag_match_rate']*100:.2f}%",
            "",
            "── CHI TIẾT HỒ SƠ THÓI QUEN TỪNG NGƯỜI DÙNG ──",
        ]
        for uname, udata in prof.get("users", {}).items():
            lines.append(
                f"  • {uname:<18}  Giờ làm={udata['hours']}  "
                f"Máy={udata['machines']}  "
                f"Tiến trình={udata['processes']}  "
                f"Đích mạng={udata['destinations']}"
            )
        lines += [
            "",
            "── CÁC ĐÒN TẤN CÔNG ATOMIC RED TEAM BỊ BẮT (UEBA-BEHAVIOR-DEVIATION) ──",
        ]
        for det in u.get("sample_detections", []):
            lines.append(
                f"  [!]  {det['event_id']:<10}  {det['target']:<22}  "
                f"{det['scenario']:<34}  →  {det['explanation']}"
            )
        self.ueba_text.insert(tk.END, "\n".join(lines))

    def _populate_vm_guide(self) -> None:
        guide = (
            "═" * 80 + "\n"
            "  QUY TRÌNH THU THẬP LOG .EVTX THẬT & QUÉT SIGMA\n"
            "  TRÊN MÁY ẢO WINDOWS (VMWARE)  —  PURPLE TEAM LAB\n"
            + "═" * 80 + "\n\n"
            "BƯỚC 1  —  Kiểm tra cấu hình máy ảo & trạng thái 4 kênh log:\n"
            "   .\\scripts\\preflight.ps1\n\n"
            "BƯỚC 2  —  Thu thập log hành vi Baseline bình thường (mỗi ngày 1 lần):\n"
            "   .\\scripts\\collect_windows_logs.ps1 -CaseId baseline-day-01 -Kind baseline\n"
            "   .\\scripts\\collect_windows_logs.ps1 -CaseId baseline-day-02 -Kind baseline\n"
            "   .\\scripts\\collect_windows_logs.ps1 -CaseId baseline-day-03 -Kind baseline\n\n"
            "BƯỚC 3  —  Thực thi kỹ thuật Atomic Red Team (cần phê duyệt):\n"
            "   .\\scripts\\run_approved_atomic.ps1 -CaseId atomic-T1059-001 -TechniqueId T1059.001 -TestNumbers 1 -Approved\n"
            "   .\\scripts\\run_approved_atomic.ps1 -CaseId atomic-T1053-005 -TechniqueId T1053.005 -TestNumbers 1 -Approved\n\n"
            "BƯỚC 4  —  Trích xuất Event Viewer thật sang XML hợp nhất cho GlobalBan:\n"
            "   .\\scripts\\collect_windows_vm_logs.ps1\n\n"
            "BƯỚC 5  —  Quét luật Sigma & đóng gói bàn giao (SHA-256 checksum):\n"
            "   .\\scripts\\run_sigma_on_evtx.ps1\n"
            "   .\\scripts\\validate_handoff.ps1\n\n"
            + "═" * 80 + "\n"
            "Địa chỉ lab:\n"
            "   Red Team  : 192.168.52.134  (máy này)\n"
            "   Blue Team : 192.168.52.136  (Windows 11 VM — GlobalBan + Sysmon)\n"
            + "═" * 80 + "\n"
        )
        self.vm_text.configure(state=tk.NORMAL)
        self.vm_text.insert(tk.END, guide)

    # ══════════════════════════════════════════════════════════════════
    #  Đẩy XML vào GlobalBan CLI
    # ══════════════════════════════════════════════════════════════════
    def run_push_xml_cli(self) -> None:
        if self.last_xml_path is None or not self.last_xml_path.is_file():
            self.run_generate_and_evaluate()
        if self.last_xml_path is None or self.last_report is None:
            return

        gb_str  = self.globalban_dir_var.get().strip()
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
                    f"Thành công! File {self.last_xml_path.name} đã được gửi vào GlobalBan CLI.\n"
                    f"Xem kết quả tại tab 'Báo Cáo Chấm Điểm Chi Tiết'.",
                    parent=self.root,
                )
                return
            except Exception as exc:
                messagebox.showerror("Lỗi GlobalBan CLI", str(exc), parent=self.root)
                return

        total_alerts = sum(self.last_report.triggered_rule_counts.values())
        messagebox.showinfo(
            "Standalone GlobalBan Engine",
            f"Chưa gắn thư mục GlobalBan ngoài — hệ thống đã chạy kiểm định trực tiếp.\n\n"
            f"  • File XML       : {self.last_xml_path.name}\n"
            f"  • Cảnh báo phát hiện : {total_alerts:,}\n"
            f"  • Precision      : {self.last_report.precision*100:.2f}%\n"
            f"  • Recall         : {self.last_report.recall*100:.2f}%\n"
            f"  • False POS Rate : {self.last_report.false_positive_rate*100:.2f}%\n\n"
            f"Bạn có thể chọn thư mục GlobalBan ở nút góc trên phải.",
            parent=self.root,
        )

    # ══════════════════════════════════════════════════════════════════
    #  Mở GlobalBan Dashboard
    # ══════════════════════════════════════════════════════════════════
    def open_globalban_dashboard(self) -> None:
        if self.last_xml_path is None or not self.last_xml_path.is_file():
            self.run_generate_and_evaluate()

        gb_str  = self.globalban_dir_var.get().strip()
        gb_root = Path(gb_str) if gb_str else None

        if gb_root and (gb_root / "src" / "globalban").is_dir():
            venv_py = gb_root / ".venv" / "Scripts" / "python.exe"
            py_exe  = str(venv_py) if venv_py.is_file() else sys.executable
            cmd     = [py_exe, "-m", "globalban.main", "--dashboard"]

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

            env     = os.environ.copy()
            src_p   = str((gb_root / "src").resolve())
            env["PYTHONPATH"] = f"{src_p}{os.pathsep}{env.get('PYTHONPATH', '')}"
            subprocess.Popen(cmd, cwd=str(gb_root), env=env)
            self.status_var.set("🚀  Đã khởi chạy cửa sổ GlobalBan Security & UEBA Dashboard!")
        else:
            self.notebook.select(3)
            messagebox.showinfo(
                "Chế độ Standalone Dashboard",
                "Không tìm thấy mã nguồn GlobalBan trên máy cục bộ.\n\n"
                "Hệ thống đã chuyển sang tab 'Hồ Sơ UEBA 7 Ngày & Atomic'\n"
                "để bạn theo dõi trực tiếp cảnh báo và hồ sơ hành vi.",
                parent=self.root,
            )

    # ══════════════════════════════════════════════════════════════════
    #  Xuất báo cáo
    # ══════════════════════════════════════════════════════════════════
    def _copy_report_to_clipboard(self) -> None:
        txt = self.report_text.get("1.0", tk.END).strip()
        self.root.clipboard_clear()
        self.root.clipboard_append(txt)
        self.status_var.set("📋  Đã sao chép toàn bộ báo cáo vào Clipboard!")

    def _export_markdown_report(self) -> None:
        if self.last_report is None:
            messagebox.showwarning("Chưa có dữ liệu", "Hãy chạy mô phỏng trước.", parent=self.root)
            return
        out_dir  = Path(self.output_dir_var.get())
        out_dir.mkdir(parents=True, exist_ok=True)
        md_path  = out_dir / "BAO_CAO_CHAM_DIEM_GLOBALBAN.md"
        md_content = (
            "# BÁO CÁO ĐÁNH GIÁ HỆ THỐNG PHÒNG THỦ GLOBALBAN\n\n"
            f"**Precision:** {self.last_report.precision*100:.2f}%  |  "
            f"**Recall:** {self.last_report.recall*100:.2f}%  |  "
            f"**F1:** {self.last_report.f1*100:.2f}%\n\n"
            "```text\n" + format_report_text(self.last_report) + "\n```\n"
        )
        md_path.write_text(md_content, encoding="utf-8")
        self.status_var.set(f"💾  Đã xuất báo cáo Markdown: {md_path}")
        messagebox.showinfo("Xuất thành công", f"Báo cáo đã lưu tại:\n{md_path}", parent=self.root)
