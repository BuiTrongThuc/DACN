"""
attack_simulator.ui.theme
=========================
Bảng màu Dark Cybersecurity (PALETTE), cấu hình ttk styles và factory tạo nút phẳng hiện đại.
"""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk
from typing import Any

PALETTE: dict[str, str] = {
    "bg_root": "#090D16",
    "bg_header": "#0F1626",
    "bg_card": "#111827",
    "bg_card_alt": "#162033",
    "bg_input": "#1E293B",
    "border": "#243147",
    "text_primary": "#F8FAFC",
    "text_secondary": "#94A3B8",
    "text_muted": "#64748B",
    "cyan": "#06B6D4",
    "cyan_dark": "#0891B2",
    "crimson": "#F43F5E",
    "crimson_dark": "#E11D48",
    "emerald": "#10B981",
    "amber": "#F59E0B",
    "violet": "#8B5CF6",
}


def configure_ttk_styles(root: tk.Tk) -> None:
    style = ttk.Style(root)
    style.theme_use("clam")

    style.configure(".", background=PALETTE["bg_root"], foreground=PALETTE["text_primary"], font=("Segoe UI", 10))
    style.configure("TFrame", background=PALETTE["bg_root"])
    style.configure("Card.TFrame", background=PALETTE["bg_card"])
    style.configure("Header.TFrame", background=PALETTE["bg_header"])

    style.configure(
        "TNotebook",
        background=PALETTE["bg_root"],
        borderwidth=0,
        tabmargins=[0, 4, 0, 0],
    )
    style.configure(
        "TNotebook.Tab",
        background=PALETTE["bg_card"],
        foreground=PALETTE["text_secondary"],
        padding=[16, 8],
        font=("Segoe UI", 10, "bold"),
        borderwidth=0,
    )
    style.map(
        "TNotebook.Tab",
        background=[("selected", PALETTE["bg_card_alt"])],
        foreground=[("selected", PALETTE["cyan"])],
    )

    style.configure(
        "Dark.Treeview",
        background=PALETTE["bg_card"],
        foreground=PALETTE["text_primary"],
        fieldbackground=PALETTE["bg_card"],
        rowheight=28,
        borderwidth=0,
        font=("Segoe UI", 9),
    )
    style.configure(
        "Dark.Treeview.Heading",
        background=PALETTE["bg_card_alt"],
        foreground=PALETTE["cyan"],
        font=("Segoe UI", 9, "bold"),
        borderwidth=0,
        padding=[8, 6],
    )
    style.map(
        "Dark.Treeview",
        background=[("selected", "#1E3A5F")],
        foreground=[("selected", "#FFFFFF")],
    )


def make_btn(
    parent: tk.Widget,
    text: str,
    command: Any,
    bg: str,
    hover_bg: str,
    fg: str = "#FFFFFF",
    font: tuple[str, int, str] = ("Segoe UI", 9, "bold"),
    padx: int = 14,
    pady: int = 7,
) -> tk.Button:
    btn = tk.Button(
        parent,
        text=text,
        command=command,
        bg=bg,
        fg=fg,
        activebackground=hover_bg,
        activeforeground=fg,
        relief=tk.FLAT,
        bd=0,
        cursor="hand2",
        font=font,
        padx=padx,
        pady=pady,
    )
    btn.bind("<Enter>", lambda _e: btn.configure(bg=hover_bg))
    btn.bind("<Leave>", lambda _e: btn.configure(bg=bg))
    return btn
