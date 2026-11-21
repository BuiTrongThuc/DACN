# -*- coding: utf-8 -*-
"""
attack_simulator.ui.tabs.tab_overview
======================================
Tab 1 — Tổng quan & Biểu đồ MITRE ATT&CK + Confusion Matrix.
"""
from __future__ import annotations
import tkinter as tk
from tkinter import ttk
from typing import Any
from attack_simulator.ui.theme import PALETTE


def build_overview_tab(notebook: ttk.Notebook, app: Any) -> None:
    tab = tk.Frame(notebook, bg=PALETTE["bg_root"])
    notebook.add(tab, text="📊  Tổng Quan & Biểu Đồ MITRE")

    # Phân chia ngang: trái (Confusion Matrix) + phải (MITRE Bar)
    pane = tk.PanedWindow(tab, orient=tk.HORIZONTAL, bg=PALETTE["border"],
                          sashwidth=3, sashrelief=tk.FLAT)
    pane.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)

    # ── Trái: Confusion Matrix ─────────────────────────────────────────
    cm_card = tk.Frame(pane, bg=PALETTE["bg_card"],
                       highlightbackground=PALETTE["border"], highlightthickness=1)
    _card_title(cm_card, "MA TRẬN NHẦM LẪN  (CONFUSION MATRIX)")
    app.cm_canvas = tk.Canvas(cm_card, bg=PALETTE["bg_card"], highlightthickness=0)
    app.cm_canvas.pack(fill=tk.BOTH, expand=True, padx=8, pady=(0, 8))
    pane.add(cm_card, minsize=320)

    # ── Phải: MITRE Coverage ──────────────────────────────────────────
    mitre_card = tk.Frame(pane, bg=PALETTE["bg_card"],
                          highlightbackground=PALETTE["border"], highlightthickness=1)
    _card_title(mitre_card, "ĐỘ PHỦ PHÁT HIỆN THEO KỸ THUẬT MITRE ATT&CK")
    app.mitre_canvas = tk.Canvas(mitre_card, bg=PALETTE["bg_card"], highlightthickness=0)
    app.mitre_canvas.pack(fill=tk.BOTH, expand=True, padx=8, pady=(0, 8))
    app.mitre_canvas.bind("<Configure>", lambda _e: app._draw_charts())
    pane.add(mitre_card, minsize=400)


def _card_title(parent: tk.Widget, text: str) -> None:
    hdr = tk.Frame(parent, bg=PALETTE["bg_card_alt"], pady=6)
    hdr.pack(fill=tk.X)
    tk.Label(hdr, text=f"  {text}",
             font=("Segoe UI", 8, "bold"),
             bg=PALETTE["bg_card_alt"], fg=PALETTE["cyan"],
             anchor="w").pack(anchor="w", padx=8)
