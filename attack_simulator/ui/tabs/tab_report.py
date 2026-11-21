"""
attack_simulator.ui.tabs.tab_report
===================================
Tab 5: Báo cáo chấm điểm & nút xuất Markdown.
"""

from __future__ import annotations

import tkinter as tk
from tkinter import scrolledtext, ttk
from typing import Any

from attack_simulator.ui.theme import PALETTE, make_btn


def build_report_tab(notebook: ttk.Notebook, app: Any) -> None:
    tab_report = tk.Frame(notebook, bg=PALETTE["bg_card"], padx=10, pady=10)
    notebook.add(tab_report, text="📑 Báo Cáo Chấm Điểm Chi Tiết")

    rep_actions = tk.Frame(tab_report, bg=PALETTE["bg_card"])
    rep_actions.pack(fill=tk.X, pady=(0, 8))
    make_btn(
        rep_actions,
        "📋 Sao chép Báo cáo",
        app._copy_report_to_clipboard,
        bg=PALETTE["bg_input"],
        hover_bg="#2D3B52",
        font=("Segoe UI", 8, "bold"),
        padx=10,
        pady=5,
    ).pack(side=tk.LEFT, padx=(0, 6))
    make_btn(
        rep_actions,
        "💾 Xuất Báo Cáo Markdown (.md)",
        app._export_markdown_report,
        bg=PALETTE["emerald"],
        hover_bg="#059669",
        font=("Segoe UI", 8, "bold"),
        padx=10,
        pady=5,
    ).pack(side=tk.LEFT)

    app.report_text = scrolledtext.ScrolledText(
        tab_report,
        bg="#080C14",
        fg="#A7F3D0",
        font=("Consolas", 10),
        relief=tk.FLAT,
        padx=12,
        pady=10,
    )
    app.report_text.pack(fill=tk.BOTH, expand=True)
