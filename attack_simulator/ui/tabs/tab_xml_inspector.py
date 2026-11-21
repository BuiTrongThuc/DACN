# -*- coding: utf-8 -*-
"""
attack_simulator.ui.tabs.tab_xml_inspector
===========================================
Tab 3 — Kiểm tra Log XML & Ground Truth JSON.
"""
from __future__ import annotations
import tkinter as tk
from tkinter import scrolledtext, ttk
from typing import Any
from attack_simulator.ui.theme import PALETTE


def build_xml_inspector_tab(notebook: ttk.Notebook, app: Any) -> None:
    tab = tk.Frame(notebook, bg=PALETTE["bg_card"])
    notebook.add(tab, text="🔍  Soi Log XML & Ground Truth")

    # ── Thanh công cụ ────────────────────────────────────────────────
    toolbar = tk.Frame(tab, bg=PALETTE["bg_card_alt"], pady=6)
    toolbar.pack(fill=tk.X)

    tk.Label(toolbar, text="  🔎  Tìm kiếm (Event ID / Kịch bản / MITRE):",
             font=("Segoe UI", 9), bg=PALETTE["bg_card_alt"],
             fg=PALETTE["text_secondary"]).pack(side=tk.LEFT, padx=(8, 4))

    app.xml_search_var = tk.StringVar()
    app.xml_search_var.trace_add("write", lambda *_: app._refresh_events_table())

    tk.Entry(
        toolbar, textvariable=app.xml_search_var,
        bg=PALETTE["bg_input"], fg=PALETTE["text_primary"],
        insertbackground=PALETTE["cyan"],
        relief=tk.FLAT, width=34,
        font=("Segoe UI", 9),
        highlightthickness=1,
        highlightbackground=PALETTE["border"],
        highlightcolor=PALETTE["cyan"],
    ).pack(side=tk.LEFT, padx=6, ipady=5)

    app.only_malicious_var = tk.BooleanVar(value=False)
    tk.Checkbutton(
        toolbar,
        text="Chỉ hiện sự kiện Tấn công",
        variable=app.only_malicious_var,
        command=app._refresh_events_table,
        bg=PALETTE["bg_card_alt"], fg=PALETTE["crimson"],
        selectcolor=PALETTE["bg_input"],
        activebackground=PALETTE["bg_card_alt"],
        activeforeground=PALETTE["crimson"],
        font=("Segoe UI", 9, "bold"),
        bd=0, highlightthickness=0,
    ).pack(side=tk.LEFT, padx=12)

    app.xml_count_var = tk.StringVar(value="0 sự kiện")
    tk.Label(toolbar, textvariable=app.xml_count_var,
             font=("Segoe UI", 8), bg=PALETTE["bg_card_alt"],
             fg=PALETTE["text_muted"]).pack(side=tk.RIGHT, padx=12)

    # ── PanedWindow: bảng trên / viewer dưới ─────────────────────────
    split = tk.PanedWindow(tab, orient=tk.VERTICAL, bg=PALETTE["border"],
                           sashwidth=4, sashrelief=tk.FLAT)
    split.pack(fill=tk.BOTH, expand=True, padx=0, pady=0)

    # Bảng sự kiện
    ev_frame = tk.Frame(split, bg=PALETTE["bg_card"])
    ev_cols  = ("event_id", "timestamp", "type", "mitre", "scenario", "expected_rules")
    app.events_tree = ttk.Treeview(
        ev_frame, columns=ev_cols, show="headings",
        style="Dark.Treeview", height=12,
    )
    heads  = {
        "event_id": "Event ID", "timestamp": "Thời Gian",
        "type": "Phân Loại", "mitre": "MITRE ID",
        "scenario": "Kịch Bản", "expected_rules": "Rule Kỳ Vọng",
    }
    widths = {"event_id": 100, "timestamp": 155, "type": 115,
              "mitre": 105, "scenario": 270, "expected_rules": 220}
    for c in ev_cols:
        app.events_tree.heading(c, text=heads[c], anchor="w")
        app.events_tree.column(c, width=widths[c], anchor="w")

    app.events_tree.tag_configure("attack",  background="#180A14", foreground=PALETTE["crimson"])
    app.events_tree.tag_configure("benign",  background=PALETTE["bg_card"])

    ev_vsb = ttk.Scrollbar(ev_frame, orient=tk.VERTICAL,   command=app.events_tree.yview)
    ev_hsb = ttk.Scrollbar(ev_frame, orient=tk.HORIZONTAL, command=app.events_tree.xview)
    app.events_tree.configure(yscrollcommand=ev_vsb.set, xscrollcommand=ev_hsb.set)
    app.events_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    ev_vsb.pack(side=tk.RIGHT, fill=tk.Y)
    ev_hsb.pack(side=tk.BOTTOM, fill=tk.X)
    app.events_tree.bind("<<TreeviewSelect>>", app._on_event_selected)
    split.add(ev_frame)

    # Viewer XML
    raw_frame = tk.Frame(split, bg=PALETTE["bg_card"])
    _lbl = tk.Frame(raw_frame, bg=PALETTE["bg_card_alt"], pady=4)
    _lbl.pack(fill=tk.X)
    tk.Label(_lbl, text="  ◈  NỘI DUNG XML & GROUND TRUTH JSON (nhấn chọn dòng bên trên)",
             font=("Segoe UI", 8, "bold"),
             bg=PALETTE["bg_card_alt"], fg=PALETTE["sky"], anchor="w",
             ).pack(anchor="w", padx=8)

    app.xml_viewer = scrolledtext.ScrolledText(
        raw_frame,
        bg="#06080F", fg=PALETTE["sky"],
        insertbackground="#FFFFFF",
        font=("Consolas", 9),
        relief=tk.FLAT, padx=12, pady=8,
        state=tk.DISABLED,
    )
    app.xml_viewer.pack(fill=tk.BOTH, expand=True)
    split.add(raw_frame)

    # Patch để cập nhật bộ đếm
    _orig = app._refresh_events_table
    def _patched():
        _orig()
        n = len(app.events_tree.get_children())
        app.xml_count_var.set(f"{n:,} sự kiện")
    app._refresh_events_table = _patched
