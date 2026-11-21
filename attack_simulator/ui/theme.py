# -*- coding: utf-8 -*-
"""
attack_simulator.ui.theme
=========================
Bảng màu Dark Cybersecurity SOC-style, cấu hình ttk styles
và factory tạo nút phẳng hiện đại với hiệu ứng hover.
"""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk
from typing import Any

PALETTE: dict[str, str] = {
    # Nền chính
    "bg_root":      "#080D1A",
    "bg_header":    "#0C1428",
    "bg_card":      "#0F1A2E",
    "bg_card_alt":  "#142038",
    "bg_input":     "#1C2D47",
    "bg_sidebar":   "#0A1220",

    # Viền & phân cách
    "border":       "#1E3050",
    "border_light": "#243B5E",

    # Chữ
    "text_primary":   "#F0F4FF",
    "text_secondary": "#8BA3C7",
    "text_muted":     "#4A6080",
    "text_accent":    "#FFFFFF",

    # Màu nhấn chính
    "cyan":         "#00D4FF",
    "cyan_dark":    "#0099BB",
    "cyan_dim":     "#003344",

    # Màu trạng thái
    "crimson":      "#F43F5E",
    "crimson_dark": "#C41540",
    "crimson_dim":  "#3A0A14",

    "emerald":      "#10B981",
    "emerald_dark": "#059669",
    "emerald_dim":  "#063320",

    "amber":        "#F59E0B",
    "amber_dark":   "#D97706",
    "amber_dim":    "#3A2500",

    "violet":       "#8B5CF6",
    "violet_dark":  "#7C3AED",
    "violet_dim":   "#1E0D44",

    "gold":         "#FFD700",
    "sky":          "#38BDF8",
}


def configure_ttk_styles(root: tk.Tk) -> None:
    style = ttk.Style(root)
    style.theme_use("clam")

    # Reset toàn cục
    style.configure(".",
        background=PALETTE["bg_root"],
        foreground=PALETTE["text_primary"],
        font=("Segoe UI", 10),
        borderwidth=0,
        relief="flat",
    )

    style.configure("TFrame",   background=PALETTE["bg_root"])
    style.configure("Card.TFrame",    background=PALETTE["bg_card"])
    style.configure("CardAlt.TFrame", background=PALETTE["bg_card_alt"])
    style.configure("Header.TFrame",  background=PALETTE["bg_header"])
    style.configure("Sidebar.TFrame", background=PALETTE["bg_sidebar"])

    # Notebook
    style.configure("TNotebook",
        background=PALETTE["bg_root"],
        borderwidth=0,
        tabmargins=[0, 0, 0, 0],
    )
    style.configure("TNotebook.Tab",
        background=PALETTE["bg_card"],
        foreground=PALETTE["text_secondary"],
        padding=[18, 10],
        font=("Segoe UI", 9, "bold"),
        borderwidth=0,
    )
    style.map("TNotebook.Tab",
        background=[
            ("selected", PALETTE["bg_card_alt"]),
            ("active",   PALETTE["bg_input"]),
        ],
        foreground=[
            ("selected", PALETTE["cyan"]),
            ("active",   PALETTE["text_primary"]),
        ],
    )

    # Treeview (bảng dữ liệu)
    style.configure("Dark.Treeview",
        background=PALETTE["bg_card"],
        foreground=PALETTE["text_primary"],
        fieldbackground=PALETTE["bg_card"],
        rowheight=30,
        borderwidth=0,
        font=("Segoe UI", 9),
    )
    style.configure("Dark.Treeview.Heading",
        background=PALETTE["bg_sidebar"],
        foreground=PALETTE["cyan"],
        font=("Segoe UI", 9, "bold"),
        borderwidth=0,
        padding=[10, 8],
        relief="flat",
    )
    style.map("Dark.Treeview",
        background=[("selected", "#0D2A50")],
        foreground=[("selected", "#FFFFFF")],
    )

    # Scrollbar mỏng
    style.configure("Slim.Vertical.TScrollbar",
        background=PALETTE["bg_card_alt"],
        troughcolor=PALETTE["bg_card"],
        arrowcolor=PALETTE["text_muted"],
        borderwidth=0,
        width=8,
    )
    style.configure("Slim.Horizontal.TScrollbar",
        background=PALETTE["bg_card_alt"],
        troughcolor=PALETTE["bg_card"],
        arrowcolor=PALETTE["text_muted"],
        borderwidth=0,
        width=8,
    )

    # Separator
    style.configure("TSeparator", background=PALETTE["border"])

    # Label
    style.configure("TLabel",
        background=PALETTE["bg_root"],
        foreground=PALETTE["text_primary"],
    )
    style.configure("Muted.TLabel",
        foreground=PALETTE["text_muted"],
        font=("Segoe UI", 8),
    )

    # Spinbox / Entry
    style.configure("TSpinbox",
        fieldbackground=PALETTE["bg_input"],
        background=PALETTE["bg_card_alt"],
        foreground=PALETTE["text_primary"],
        arrowcolor=PALETTE["text_secondary"],
        bordercolor=PALETTE["border"],
        lightcolor=PALETTE["border"],
        darkcolor=PALETTE["border"],
    )


def make_btn(
    parent: tk.Widget,
    text: str,
    command: Any,
    bg: str,
    hover_bg: str,
    fg: str = "#FFFFFF",
    font: tuple = ("Segoe UI", 9, "bold"),
    padx: int = 14,
    pady: int = 8,
    width: int = 0,
) -> tk.Button:
    """Tạo nút phẳng hiện đại với hiệu ứng hover."""
    kw: dict[str, Any] = dict(
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
    if width:
        kw["width"] = width
    btn = tk.Button(parent, **kw)
    btn.bind("<Enter>", lambda _e: btn.configure(bg=hover_bg))
    btn.bind("<Leave>", lambda _e: btn.configure(bg=bg))
    return btn


def section_label(parent: tk.Widget, text: str, color: str | None = None) -> tk.Label:
    """Nhãn tiêu đề section với gạch ngang."""
    return tk.Label(
        parent,
        text=f"  {text}",
        font=("Segoe UI", 8, "bold"),
        bg=PALETTE["bg_card"],
        fg=color or PALETTE["cyan"],
        anchor="w",
    )
