"""
attack_simulator.ui.charts
==========================
Vẽ biểu đồ Canvas: Ma trận nhầm lẫn 2x2 (Confusion Matrix) & Biểu đồ cột ngang MITRE ATT&CK / Rule.
"""

from __future__ import annotations

import tkinter as tk
from attack_simulator.core.evaluator import DetailedEvaluationReport
from attack_simulator.ui.theme import PALETTE


def draw_confusion_matrix(canvas: tk.Canvas, report: DetailedEvaluationReport) -> None:
    canvas.delete("all")
    w = max(320, canvas.winfo_width() or 340)
    h = max(250, canvas.winfo_height() or 270)
    pad = 12
    cell_w = (w - pad * 3) / 2
    cell_h = (h - pad * 3) / 2

    cells = [
        (0, 0, "TRUE POSITIVE (TP)", f"{report.true_positive:,}", "Bắt trúng tấn công", "#064E3B", PALETTE["emerald"]),
        (1, 0, "FALSE POSITIVE (FP)", f"{report.false_positive:,}", "Báo giả (Mục tiêu = 0)", "#451A03" if report.false_positive else "#1E293B", PALETTE["amber"] if report.false_positive else PALETTE["text_secondary"]),
        (0, 1, "FALSE NEGATIVE (FN)", f"{report.false_negative:,}", "Bỏ lọt (Mục tiêu = 0)", "#4C0519" if report.false_negative else "#1E293B", PALETTE["crimson"] if report.false_negative else PALETTE["text_secondary"]),
        (1, 1, "TRUE NEGATIVE (TN)", f"{report.true_negative:,}", "Bỏ qua đúng log sạch", "#172554", PALETTE["cyan"]),
    ]
    for col, row, title, val, sub, fill_bg, accent in cells:
        x0 = pad + col * (cell_w + pad)
        y0 = pad + row * (cell_h + pad)
        x1 = x0 + cell_w
        y1 = y0 + cell_h
        canvas.create_rectangle(x0, y0, x1, y1, fill=fill_bg, outline=accent, width=1.5)
        canvas.create_text(x0 + 10, y0 + 16, text=title, anchor=tk.W, fill=accent, font=("Segoe UI", 8, "bold"))
        canvas.create_text(x0 + 10, y0 + cell_h * 0.54, text=val, anchor=tk.W, fill="#FFFFFF", font=("Segoe UI", 18, "bold"))
        canvas.create_text(x0 + 10, y1 - 14, text=sub, anchor=tk.W, fill="#CBD5E1", font=("Segoe UI", 8))


def draw_mitre_bar_chart(canvas: tk.Canvas, report: DetailedEvaluationReport) -> None:
    canvas.delete("all")
    mw = max(420, canvas.winfo_width() or 540)
    mh = max(250, canvas.winfo_height() or 270)

    items = list(report.triggered_rule_counts.items())
    if not items:
        canvas.create_text(mw / 2, mh / 2, text="Chưa có rule nào được kích hoạt", fill=PALETTE["text_secondary"])
        return

    max_val = max(v for _, v in items) or 1
    top_pad = 10
    row_h = min(34, (mh - top_pad * 2) / max(1, len(items)))
    label_w = 235
    bar_max_w = max(80, mw - label_w - 85)
    bar_colors = [PALETTE["cyan"], PALETTE["crimson"], PALETTE["emerald"], PALETTE["violet"], PALETTE["amber"], "#38BDF8"]

    for idx, (rule_id, cnt) in enumerate(items[:10]):
        y_center = top_pad + idx * row_h + row_h / 2
        color = bar_colors[idx % len(bar_colors)]
        canvas.create_text(
            10, y_center, text=rule_id, anchor=tk.W, fill=PALETTE["text_primary"], font=("Consolas", 9, "bold")
        )
        bar_w = (cnt / max_val) * bar_max_w
        y0 = y_center - row_h * 0.30
        y1 = y_center + row_h * 0.30
        canvas.create_rectangle(label_w, y0, label_w + bar_max_w, y1, fill=PALETTE["bg_input"], outline="")
        canvas.create_rectangle(label_w, y0, label_w + max(4, bar_w), y1, fill=color, outline="")
        canvas.create_text(
            label_w + bar_w + 8, y_center, text=f"{cnt:,} alerts", anchor=tk.W, fill=color, font=("Segoe UI", 8, "bold")
        )
