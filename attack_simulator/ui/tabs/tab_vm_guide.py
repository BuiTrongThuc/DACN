# -*- coding: utf-8 -*-
"""
attack_simulator.ui.tabs.tab_vm_guide
======================================
Tab 6 — Quy trình 5 bước thu thập EVTX & quét Sigma trên VMware.
"""
from __future__ import annotations
import tkinter as tk
from tkinter import scrolledtext, ttk
from typing import Any
from attack_simulator.ui.theme import PALETTE


def build_vm_guide_tab(notebook: ttk.Notebook, app: Any) -> None:
    tab = tk.Frame(notebook, bg=PALETTE["bg_card"])
    notebook.add(tab, text="🖥  Quy Trình EVTX & Sigma (VM)")

    # Tiêu đề
    hdr = tk.Frame(tab, bg=PALETTE["amber_dim"], pady=6)
    hdr.pack(fill=tk.X)
    tk.Label(
        hdr,
        text="  🖥  QUY TRÌNH THU THẬP LOG .EVTX THẬT & QUÉT SIGMA  —  Purple Team Lab (VMware NAT 192.168.52.0/24)",
        font=("Segoe UI", 8, "bold"),
        bg=PALETTE["amber_dim"], fg=PALETTE["amber"],
        anchor="w",
    ).pack(anchor="w", padx=8)

    app.vm_text = scrolledtext.ScrolledText(
        tab,
        bg="#06080F",
        fg="#FDE68A",
        insertbackground=PALETTE["amber"],
        font=("Consolas", 9),
        relief=tk.FLAT,
        padx=14,
        pady=10,
        state=tk.DISABLED,
    )
    app.vm_text.pack(fill=tk.BOTH, expand=True)
    app._populate_vm_guide()
