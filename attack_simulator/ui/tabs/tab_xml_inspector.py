"""
attack_simulator.ui.tabs.tab_xml_inspector
==========================================
Tab 3: Soi Log XML & Ground Truth JSON.
"""

from __future__ import annotations

import tkinter as tk
from tkinter import scrolledtext, ttk
from typing import Any

from attack_simulator.ui.theme import PALETTE


def build_xml_inspector_tab(notebook: ttk.Notebook, app: Any) -> None:
    tab_xml = tk.Frame(notebook, bg=PALETTE["bg_card"], padx=10, pady=10)
    notebook.add(tab_xml, text="🔍 Soi Log XML & Ground Truth")

    xml_top = tk.Frame(tab_xml, bg=PALETTE["bg_card"])
    xml_top.pack(fill=tk.X, pady=(0, 6))
    tk.Label(xml_top, text="Tìm kiếm Event (ID / Kịch bản / MITRE):", bg=PALETTE["bg_card"], fg=PALETTE["text_secondary"]).pack(side=tk.LEFT)
    app.xml_search_var = tk.StringVar()
    app.xml_search_var.trace_add("write", lambda *_: app._refresh_events_table())
    tk.Entry(
        xml_top,
        textvariable=app.xml_search_var,
        bg=PALETTE["bg_input"],
        fg=PALETTE["text_primary"],
        insertbackground=PALETTE["text_primary"],
        relief=tk.FLAT,
        width=32,
    ).pack(side=tk.LEFT, padx=8, ipady=4)

    app.only_malicious_var = tk.BooleanVar(value=False)
    tk.Checkbutton(
        xml_top,
        text="Chỉ hiện sự kiện Tấn công (Malicious)",
        variable=app.only_malicious_var,
        command=app._refresh_events_table,
        bg=PALETTE["bg_card"],
        fg=PALETTE["text_primary"],
        selectcolor=PALETTE["bg_input"],
        activebackground=PALETTE["bg_card"],
    ).pack(side=tk.LEFT, padx=10)

    xml_split = tk.PanedWindow(tab_xml, orient=tk.VERTICAL, bg=PALETTE["border"], sashwidth=4)
    xml_split.pack(fill=tk.BOTH, expand=True)

    ev_frame = tk.Frame(xml_split, bg=PALETTE["bg_card"])
    ev_cols = ("event_id", "timestamp", "type", "mitre", "scenario", "expected_rules")
    app.events_tree = ttk.Treeview(ev_frame, columns=ev_cols, show="headings", style="Dark.Treeview", height=10)
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
        app.events_tree.heading(c, text=ev_heads[c])
        app.events_tree.column(c, width=ev_widths[c], anchor=tk.W)
    ev_scroll = ttk.Scrollbar(ev_frame, orient=tk.VERTICAL, command=app.events_tree.yview)
    app.events_tree.configure(yscrollcommand=ev_scroll.set)
    app.events_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    ev_scroll.pack(side=tk.RIGHT, fill=tk.Y)
    app.events_tree.bind("<<TreeviewSelect>>", app._on_event_selected)
    xml_split.add(ev_frame)

    raw_frame = tk.Frame(xml_split, bg=PALETTE["bg_card"])
    app.xml_viewer = scrolledtext.ScrolledText(
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
    app.xml_viewer.pack(fill=tk.BOTH, expand=True)
    xml_split.add(raw_frame)
