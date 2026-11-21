"""
attack_simulator.ui.tabs.tab_vm_guide
=====================================
Tab 6: Quy trình 5 bước EVTX & Sigma trên VMware.
"""

from __future__ import annotations

import tkinter as tk
from tkinter import scrolledtext, ttk
from typing import Any

from attack_simulator.ui.theme import PALETTE


def build_vm_guide_tab(notebook: ttk.Notebook, app: Any) -> None:
    tab_vm = tk.Frame(notebook, bg=PALETTE["bg_card"], padx=10, pady=10)
    notebook.add(tab_vm, text="🖥 Quy Trình EVTX & Sigma (VM)")
    app.vm_text = scrolledtext.ScrolledText(
        tab_vm,
        bg="#080C14",
        fg="#FDE68A",
        font=("Consolas", 10),
        relief=tk.FLAT,
        padx=12,
        pady=10,
    )
    app.vm_text.pack(fill=tk.BOTH, expand=True)
    app._populate_vm_guide()
