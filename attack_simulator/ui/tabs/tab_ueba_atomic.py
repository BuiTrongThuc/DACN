"""
attack_simulator.ui.tabs.tab_ueba_atomic
========================================
Tab 4: Hồ sơ UEBA 7 ngày & 8 đòn Atomic Red Team.
"""

from __future__ import annotations

import tkinter as tk
from tkinter import scrolledtext, ttk
from typing import Any

from attack_simulator.ui.theme import PALETTE


def build_ueba_atomic_tab(notebook: ttk.Notebook, app: Any) -> None:
    tab_ueba = tk.Frame(notebook, bg=PALETTE["bg_card"], padx=10, pady=10)
    notebook.add(tab_ueba, text="🧠 Hồ Sơ UEBA 7 Ngày & Atomic")
    app.ueba_text = scrolledtext.ScrolledText(
        tab_ueba,
        bg="#080C14",
        fg="#E2E8F0",
        font=("Consolas", 10),
        relief=tk.FLAT,
        padx=12,
        pady=10,
    )
    app.ueba_text.pack(fill=tk.BOTH, expand=True)
