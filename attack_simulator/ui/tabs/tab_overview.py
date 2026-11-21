"""
attack_simulator.ui.tabs.tab_overview
=====================================
Tab 1: Tổng quan & Biểu đồ MITRE ATT&CK + Confusion Matrix.
"""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk
from typing import Any

from attack_simulator.ui.theme import PALETTE


def build_overview_tab(notebook: ttk.Notebook, app: Any) -> None:
    tab_overview = tk.Frame(notebook, bg=PALETTE["bg_root"], padx=4, pady=8)
    notebook.add(tab_overview, text="📊 Tổng Quan & Biểu Đồ MITRE")

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
    app.cm_canvas = tk.Canvas(cm_card, bg=PALETTE["bg_card"], highlightthickness=0, height=280)
    app.cm_canvas.pack(fill=tk.BOTH, expand=True)

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
    app.mitre_canvas = tk.Canvas(mitre_card, bg=PALETTE["bg_card"], highlightthickness=0)
    app.mitre_canvas.pack(fill=tk.BOTH, expand=True)
    app.mitre_canvas.bind("<Configure>", lambda _e: app._draw_charts())
