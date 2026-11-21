# -*- coding: utf-8 -*-
"""
attack_simulator.ui.tabs.tab_detections
========================================
Tab 2 — Bảng Cảnh báo phát hiện & bộ lọc tìm kiếm.
"""
from __future__ import annotations
import tkinter as tk
from tkinter import ttk
from typing import Any
from attack_simulator.ui.theme import PALETTE


def build_detections_tab(notebook: ttk.Notebook, app: Any) -> None:
    tab = tk.Frame(notebook, bg=PALETTE["bg_card"])
    notebook.add(tab, text="🚨  Cảnh Báo Phát Hiện")

    # ── Thanh lọc ────────────────────────────────────────────────────
    filter_bar = tk.Frame(tab, bg=PALETTE["bg_card_alt"], pady=6)
    filter_bar.pack(fill=tk.X)

    tk.Label(filter_bar, text="  🔎  Lọc theo Rule / Kịch bản / Host:",
             font=("Segoe UI", 9), bg=PALETTE["bg_card_alt"],
             fg=PALETTE["text_secondary"]).pack(side=tk.LEFT, padx=(8, 4))

    app.alert_filter_var = tk.StringVar()
    app.alert_filter_var.trace_add("write", lambda *_: app._refresh_alerts_table())

    entry = tk.Entry(
        filter_bar, textvariable=app.alert_filter_var,
        bg=PALETTE["bg_input"], fg=PALETTE["text_primary"],
        insertbackground=PALETTE["cyan"],
        relief=tk.FLAT, width=40,
        font=("Segoe UI", 9),
        highlightthickness=1,
        highlightbackground=PALETTE["border"],
        highlightcolor=PALETTE["cyan"],
    )
    entry.pack(side=tk.LEFT, padx=6, ipady=5)

    # Nút xóa lọc
    def _clear():
        app.alert_filter_var.set("")
    tk.Button(
        filter_bar, text="✕", command=_clear,
        bg=PALETTE["bg_input"], fg=PALETTE["text_muted"],
        relief=tk.FLAT, bd=0, cursor="hand2",
        font=("Segoe UI", 9), padx=6, pady=2,
    ).pack(side=tk.LEFT)

    # Đếm kết quả
    app.alert_count_var = tk.StringVar(value="0 cảnh báo")
    tk.Label(filter_bar, textvariable=app.alert_count_var,
             font=("Segoe UI", 8), bg=PALETTE["bg_card_alt"],
             fg=PALETTE["text_muted"]).pack(side=tk.RIGHT, padx=12)

    # ── Bảng cảnh báo ─────────────────────────────────────────────────
    tree_frame = tk.Frame(tab, bg=PALETTE["bg_card"])
    tree_frame.pack(fill=tk.BOTH, expand=True)

    cols = ("event_id", "detector", "rule_id", "target", "scenario", "explanation")
    app.alerts_tree = ttk.Treeview(
        tree_frame, columns=cols, show="headings",
        style="Dark.Treeview",
    )
    headings = {
        "event_id":    "Event ID",
        "detector":    "Bộ Phát Hiện",
        "rule_id":     "Rule Kích Hoạt",
        "target":      "Host / Nguồn IP",
        "scenario":    "Kịch Bản",
        "explanation": "Phân Tích Chi Tiết",
    }
    widths = {
        "event_id": 95, "detector": 155, "rule_id": 200,
        "target": 140, "scenario": 200, "explanation": 400,
    }
    for c in cols:
        app.alerts_tree.heading(c, text=headings[c], anchor="w")
        app.alerts_tree.column(c, width=widths[c], anchor="w", stretch=(c == "explanation"))

    vsb = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL,   command=app.alerts_tree.yview)
    hsb = ttk.Scrollbar(tree_frame, orient=tk.HORIZONTAL, command=app.alerts_tree.xview)
    app.alerts_tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

    app.alerts_tree.pack(side=tk.LEFT,   fill=tk.BOTH, expand=True)
    vsb.pack(side=tk.RIGHT,  fill=tk.Y)
    hsb.pack(side=tk.BOTTOM, fill=tk.X)

    # Màu xen kẽ
    app.alerts_tree.tag_configure("attack", background="#180A14", foreground=PALETTE["crimson"])
    app.alerts_tree.tag_configure("rule",   background=PALETTE["bg_card"])

    # Patch _refresh_alerts_table để cập nhật bộ đếm
    _orig = app._refresh_alerts_table

    def _patched():
        _orig()
        n = len(app.alerts_tree.get_children())
        app.alert_count_var.set(f"{n:,} cảnh báo")

    app._refresh_alerts_table = _patched
