# -*- coding: utf-8 -*-
"""
attack_simulator.ui.tabs.tab_ueba_atomic
=========================================
Tab 4 — Hồ sơ UEBA 7 ngày & Kết quả Atomic Red Team.
"""
from __future__ import annotations
import tkinter as tk
from tkinter import scrolledtext, ttk
from typing import Any
from attack_simulator.ui.theme import PALETTE


def build_ueba_atomic_tab(notebook: ttk.Notebook, app: Any) -> None:
    tab = tk.Frame(notebook, bg=PALETTE["bg_card"])
    notebook.add(tab, text="🧠  Hồ Sơ UEBA 7 Ngày & Atomic")

    # Tiêu đề section
    hdr = tk.Frame(tab, bg=PALETTE["violet_dim"], pady=6)
    hdr.pack(fill=tk.X)
    tk.Label(
        hdr,
        text="  🧠  HỒ SƠ HÀNH VI NGƯỜI DÙNG & KẾT QUẢ PHÁT HIỆN ATOMIC RED TEAM  (UEBA Behavioral Profile Store)",
        font=("Segoe UI", 8, "bold"),
        bg=PALETTE["violet_dim"], fg=PALETTE["violet"],
        anchor="w",
    ).pack(anchor="w", padx=8)

    app.ueba_text = scrolledtext.ScrolledText(
        tab,
        bg="#06080F",
        fg="#C4B5FD",
        insertbackground=PALETTE["violet"],
        font=("Consolas", 9),
        relief=tk.FLAT,
        padx=14,
        pady=10,
        state=tk.DISABLED,
    )
    app.ueba_text.pack(fill=tk.BOTH, expand=True)
