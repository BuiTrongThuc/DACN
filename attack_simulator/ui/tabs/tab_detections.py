"""
attack_simulator.ui.tabs.tab_detections
=======================================
Tab 2: Bảng Cảnh báo phát hiện & bộ lọc tìm kiếm.
"""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk
from typing import Any

from attack_simulator.ui.theme import PALETTE


def build_detections_tab(notebook: ttk.Notebook, app: Any) -> None:
    tab_alerts = tk.Frame(notebook, bg=PALETTE["bg_card"], padx=10, pady=10)
    notebook.add(tab_alerts, text="🚨 Cảnh Báo Phát Hiện (Detections)")

    filter_bar = tk.Frame(tab_alerts, bg=PALETTE["bg_card"])
    filter_bar.pack(fill=tk.X, pady=(0, 8))
    tk.Label(filter_bar, text="Lọc Rule / Kịch bản:", bg=PALETTE["bg_card"], fg=PALETTE["text_secondary"]).pack(side=tk.LEFT)
    app.alert_filter_var = tk.StringVar()
    app.alert_filter_var.trace_add("write", lambda *_: app._refresh_alerts_table())
    tk.Entry(
        filter_bar,
        textvariable=app.alert_filter_var,
        bg=PALETTE["bg_input"],
        fg=PALETTE["text_primary"],
        insertbackground=PALETTE["text_primary"],
        relief=tk.FLAT,
        width=36,
        font=("Segoe UI", 9),
    ).pack(side=tk.LEFT, padx=8, ipady=4)

    cols = ("event_id", "detector", "rule_id", "target", "scenario", "explanation")
    app.alerts_tree = ttk.Treeview(tab_alerts, columns=cols, show="headings", style="Dark.Treeview")
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
        app.alerts_tree.heading(c, text=headings[c])
        app.alerts_tree.column(c, width=widths[c], anchor=tk.W)
    y_sc = ttk.Scrollbar(tab_alerts, orient=tk.VERTICAL, command=app.alerts_tree.yview)
    app.alerts_tree.configure(yscrollcommand=y_sc.set)
    app.alerts_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    y_sc.pack(side=tk.RIGHT, fill=tk.Y)
