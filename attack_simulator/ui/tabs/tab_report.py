# -*- coding: utf-8 -*-
"""
attack_simulator.ui.tabs.tab_report
=====================================
Tab 5 — Báo cáo chấm điểm chi tiết & xuất Markdown.
"""
from __future__ import annotations
import tkinter as tk
from tkinter import scrolledtext, ttk
from typing import Any
from attack_simulator.ui.theme import PALETTE, make_btn


def build_report_tab(notebook: ttk.Notebook, app: Any) -> None:
    tab = tk.Frame(notebook, bg=PALETTE["bg_card"])
    notebook.add(tab, text="📑  Báo Cáo Chấm Điểm Chi Tiết")

    # ── Thanh hành động ──────────────────────────────────────────────
    actions = tk.Frame(tab, bg=PALETTE["bg_card_alt"], pady=6)
    actions.pack(fill=tk.X)
    tk.Label(actions, text="  📊  XUẤT BÁO CÁO:",
             font=("Segoe UI", 8, "bold"),
             bg=PALETTE["bg_card_alt"], fg=PALETTE["text_muted"],
             ).pack(side=tk.LEFT, padx=(8, 4))

    make_btn(
        actions, "📋  Sao chép vào Clipboard",
        app._copy_report_to_clipboard,
        bg=PALETTE["bg_input"], hover_bg=PALETTE["border_light"],
        fg=PALETTE["text_primary"], font=("Segoe UI", 8, "bold"), padx=12, pady=4,
    ).pack(side=tk.LEFT, padx=(4, 6))

    make_btn(
        actions, "💾  Xuất Báo Cáo Markdown (.md)",
        app._export_markdown_report,
        bg=PALETTE["emerald_dark"], hover_bg=PALETTE["emerald"],
        fg="#FFFFFF", font=("Segoe UI", 8, "bold"), padx=12, pady=4,
    ).pack(side=tk.LEFT)

    # ── Vùng văn bản ─────────────────────────────────────────────────
    app.report_text = scrolledtext.ScrolledText(
        tab,
        bg="#06080F",
        fg="#A7F3D0",
        insertbackground=PALETTE["emerald"],
        font=("Consolas", 9),
        relief=tk.FLAT,
        padx=14,
        pady=10,
        state=tk.DISABLED,
    )
    app.report_text.pack(fill=tk.BOTH, expand=True)
