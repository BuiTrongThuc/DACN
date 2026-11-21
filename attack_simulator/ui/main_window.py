"""
attack_simulator.ui.main_window
===============================
Khung chính ModernRedTeamStudioApp: Header, Sidebar, 6 thẻ KPI và điều phối 6 Tabs.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tkinter as tk
import webbrowser
from io import StringIO
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from typing import Any

from attack_simulator.core.evaluator import (
    DetailedEvaluationReport,
    format_report_text,
    resolve_default_globalban_root,
    run_unified_evaluation,
)
from attack_simulator.core.models import SCENARIO_CATALOG, SimulatedRecord
from attack_simulator.generator import WindowsAttackLogGenerator, export_dataset_files
from attack_simulator.ui.charts import draw_confusion_matrix, draw_mitre_bar_chart
from attack_simulator.ui.tabs import (
    build_detections_tab,
    build_overview_tab,
    build_report_tab,
    build_ueba_atomic_tab,
    build_vm_guide_tab,
    build_xml_inspector_tab,
)
from attack_simulator.ui.theme import PALETTE, configure_ttk_styles, make_btn
from config import (
    DEFAULT_BENIGN_COUNT,
    DEFAULT_CAMPAIGNS_PER_SCENARIO,
    DEFAULT_FP_NOISE_COUNT,
    DEFAULT_OUTPUT_DIR,
    DEFAULT_SEED,
)


class ModernRedTeamStudioApp:
    """Executive-grade SOC / Red-Team Adversary Emulation & Benchmark Studio."""

    def __init__(
        self,
        root: tk.Tk,
        output_dir: Path | None = None,
        globalban_root: Path | None = None,
    ) -> None:
        self.root = root
        self.root.title("GlobalBan Red-Team Adversary Studio & SIEM/UEBA Benchmark Suite")
        self.root.geometry("1380x880")
        self.root.minsize(1180, 760)
        self.root.configure(bg=PALETTE["bg_root"])

        default_out = output_dir or DEFAULT_OUTPUT_DIR
        self.output_dir_var = tk.StringVar(value=str(default_out))
        detected_gb = globalban_root or resolve_default_globalban_root()
        self.globalban_dir_var = tk.StringVar(value=str(detected_gb) if detected_gb else "")

        self.last_records: list[SimulatedRecord] = []
        self.last_xml_path: Path | None = None
        self.last_jsonl_path: Path | None = None
        self.last_report: DetailedEvaluationReport | None = None

        self.scenario_vars: dict[str, tk.BooleanVar] = {}
        self.ueba_var = tk.BooleanVar(value=True)
        self.lolbin_var = tk.BooleanVar(value=True)
        self.campaigns_var = tk.IntVar(value=DEFAULT_CAMPAIGNS_PER_SCENARIO)
        self.benign_var = tk.IntVar(value=DEFAULT_BENIGN_COUNT)
        self.fp_noise_var = tk.IntVar(value=DEFAULT_FP_NOISE_COUNT)
        self.seed_var = tk.IntVar(value=DEFAULT_SEED)

        self.status_var = tk.StringVar(value="Sẵn sàng — Nhấn 'Chạy Mô Phỏng & Chấm Điểm' để bắt đầu")
        self.engine_badge_var = tk.StringVar(value="")

        self.kpi_vars: dict[str, tk.StringVar] = {
            "total": tk.StringVar(value="0"),
            "total_sub": tk.StringVar(value="Attack: 0 | Benign: 0"),
            "precision": tk.StringVar(value="0.00%"),
            "recall": tk.StringVar(value="0.00%"),
            "f1": tk.StringVar(value="0.00%"),
            "fpr": tk.StringVar(value="0.00%"),
            "rule_acc": tk.StringVar(value="0.00%"),
        }

        configure_ttk_styles(self.root)
        self._build_layout()
        self._refresh_engine_badge()
        self.root.after(180, self.run_generate_and_evaluate)

    def _build_layout(self) -> None:
        # --- TOP HEADER BAR ---
        header = tk.Frame(self.root, bg=PALETTE["bg_header"], height=64, highlightbackground=PALETTE["border"], highlightthickness=1)
        header.pack(fill=tk.X, side=tk.TOP)
        header.pack_propagate(False)

        left_hdr = tk.Frame(header, bg=PALETTE["bg_header"])
        left_hdr.pack(side=tk.LEFT, padx=18, pady=8)

        title_row = tk.Frame(left_hdr, bg=PALETTE["bg_header"])
        title_row.pack(anchor=tk.W)
        tk.Label(
            title_row,
            text="⚡ GLOBALBAN RED-TEAM STUDIO",
            font=("Segoe UI", 14, "bold"),
            bg=PALETTE["bg_header"],
            fg=PALETTE["text_primary"],
        ).pack(side=tk.LEFT)
        tk.Label(
            title_row,
            text="  ADVERSARY EMULATION & SIEM/UEBA BENCHMARK",
            font=("Segoe UI", 9, "bold"),
            bg=PALETTE["bg_header"],
            fg=PALETTE["cyan"],
        ).pack(side=tk.LEFT, pady=(3, 0))

        tk.Label(
            left_hdr,
            text="Bộ sinh dữ liệu tấn công Windows XML đa bước • Học hành vi UEBA 7 ngày • Kiểm định chống báo động giả (FPR)",
            font=("Segoe UI", 8),
            bg=PALETTE["bg_header"],
            fg=PALETTE["text_secondary"],
        ).pack(anchor=tk.W)

        right_hdr = tk.Frame(header, bg=PALETTE["bg_header"])
        right_hdr.pack(side=tk.RIGHT, padx=18)

        self.badge_label = tk.Label(
            right_hdr,
            textvariable=self.engine_badge_var,
            font=("Segoe UI", 8, "bold"),
            bg="#132A2E",
            fg=PALETTE["emerald"],
            padx=10,
            pady=4,
        )
        self.badge_label.pack(side=tk.RIGHT, padx=(8, 0))

        make_btn(
            right_hdr,
            "📂 Chọn GlobalBan",
            self._browse_globalban_dir,
            bg=PALETTE["bg_input"],
            hover_bg="#2D3B52",
            fg=PALETTE["text_primary"],
            font=("Segoe UI", 8, "bold"),
            padx=10,
            pady=4,
        ).pack(side=tk.RIGHT, padx=4)

        make_btn(
            right_hdr,
            "📁 Thư mục Output",
            self._open_output_folder,
            bg=PALETTE["bg_input"],
            hover_bg="#2D3B52",
            fg=PALETTE["text_primary"],
            font=("Segoe UI", 8, "bold"),
            padx=10,
            pady=4,
        ).pack(side=tk.RIGHT, padx=4)

        # --- MAIN WORKSPACE ---
        body = tk.Frame(self.root, bg=PALETTE["bg_root"])
        body.pack(fill=tk.BOTH, expand=True, padx=14, pady=12)

        # LEFT SIDEBAR
        sidebar = tk.Frame(
            body,
            bg=PALETTE["bg_card"],
            width=360,
            highlightbackground=PALETTE["border"],
            highlightthickness=1,
        )
        sidebar.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 12))
        sidebar.pack_propagate(False)

        sb_inner = tk.Frame(sidebar, bg=PALETTE["bg_card"], padx=14, pady=12)
        sb_inner.pack(fill=tk.BOTH, expand=True)

        tk.Label(
            sb_inner,
            text="KỊCH BẢN TẤN CÔNG & ĐÁNH GIÁ (8 MODULES)",
            font=("Segoe UI", 9, "bold"),
            bg=PALETTE["bg_card"],
            fg=PALETTE["cyan"],
        ).pack(anchor=tk.W, pady=(0, 6))

        for spec in SCENARIO_CATALOG:
            var = tk.BooleanVar(value=True)
            self.scenario_vars[spec.key] = var
            row = tk.Frame(sb_inner, bg=PALETTE["bg_card_alt"], pady=4, padx=8)
            row.pack(fill=tk.X, pady=2)

            tk.Label(row, text="●", fg=spec.accent_color, bg=PALETTE["bg_card_alt"], font=("Segoe UI", 9)).pack(side=tk.LEFT, padx=(0, 4))
            tk.Checkbutton(
                row,
                text=spec.title,
                variable=var,
                bg=PALETTE["bg_card_alt"],
                fg=PALETTE["text_primary"],
                selectcolor=PALETTE["bg_input"],
                activebackground=PALETTE["bg_card_alt"],
                activeforeground=PALETTE["text_primary"],
                font=("Segoe UI", 9, "bold"),
                anchor=tk.W,
            ).pack(side=tk.LEFT, fill=tk.X, expand=True)

        for title_txt, var_obj, color in (
            ("7. UEBA 7-Day Baseline & Atomic Red Team", self.ueba_var, PALETTE["violet"]),
            ("8. WinLOLBIN-GT Living Off The Land", self.lolbin_var, PALETTE["emerald"]),
        ):
            row = tk.Frame(sb_inner, bg=PALETTE["bg_card_alt"], pady=4, padx=8)
            row.pack(fill=tk.X, pady=2)
            tk.Label(row, text="●", fg=color, bg=PALETTE["bg_card_alt"], font=("Segoe UI", 9)).pack(side=tk.LEFT, padx=(0, 4))
            tk.Checkbutton(
                row,
                text=title_txt,
                variable=var_obj,
                bg=PALETTE["bg_card_alt"],
                fg=PALETTE["text_primary"],
                selectcolor=PALETTE["bg_input"],
                activebackground=PALETTE["bg_card_alt"],
                activeforeground=PALETTE["text_primary"],
                font=("Segoe UI", 9, "bold"),
                anchor=tk.W,
            ).pack(side=tk.LEFT, fill=tk.X, expand=True)

        sel_row = tk.Frame(sb_inner, bg=PALETTE["bg_card"])
        sel_row.pack(fill=tk.X, pady=(6, 10))
        make_btn(
            sel_row,
            "✓ Chọn tất cả",
            lambda: ([v.set(True) for v in self.scenario_vars.values()], self.ueba_var.set(True), self.lolbin_var.set(True)),
            bg=PALETTE["bg_input"],
            hover_bg="#2D3B52",
            font=("Segoe UI", 8, "bold"),
            padx=8,
            pady=4,
        ).pack(side=tk.LEFT, expand=True, fill=tk.X, padx=(0, 4))
        make_btn(
            sel_row,
            "✕ Bỏ chọn",
            lambda: ([v.set(False) for v in self.scenario_vars.values()], self.ueba_var.set(False), self.lolbin_var.set(False)),
            bg=PALETTE["bg_input"],
            hover_bg="#2D3B52",
            font=("Segoe UI", 8, "bold"),
            padx=8,
            pady=4,
        ).pack(side=tk.LEFT, expand=True, fill=tk.X, padx=(4, 0))

        tk.Frame(sb_inner, bg=PALETTE["border"], height=1).pack(fill=tk.X, pady=4)

        tk.Label(
            sb_inner,
            text="THAM SỐ SINH DỮ LIỆU KIỂM CHUẨN",
            font=("Segoe UI", 9, "bold"),
            bg=PALETTE["bg_card"],
            fg=PALETTE["cyan"],
        ).pack(anchor=tk.W, pady=(6, 6))

        params_grid = tk.Frame(sb_inner, bg=PALETTE["bg_card"])
        params_grid.pack(fill=tk.X)

        param_specs = [
            ("Chiến dịch / mỗi kịch bản:", self.campaigns_var, 1, 500, 5),
            ("Log bình thường (Benign):", self.benign_var, 0, 20000, 100),
            ("Nhiễu Admin (Test FPR):", self.fp_noise_var, 0, 1000, 5),
            ("Random Seed tái lập:", self.seed_var, 1, 99999, 1),
        ]
        for r_idx, (lbl, var_obj, mn, mx, inc) in enumerate(param_specs):
            tk.Label(
                params_grid,
                text=lbl,
                bg=PALETTE["bg_card"],
                fg=PALETTE["text_secondary"],
                font=("Segoe UI", 9),
            ).grid(row=r_idx, column=0, sticky=tk.W, pady=4)
            sb = tk.Spinbox(
                params_grid,
                from_=mn,
                to=mx,
                increment=inc,
                textvariable=var_obj,
                width=10,
                bg=PALETTE["bg_input"],
                fg=PALETTE["text_primary"],
                buttonbackground=PALETTE["bg_card_alt"],
                insertbackground=PALETTE["text_primary"],
                relief=tk.FLAT,
                font=("Consolas", 10, "bold"),
            )
            sb.grid(row=r_idx, column=1, sticky=tk.E, pady=4)
        params_grid.columnconfigure(0, weight=1)

        tk.Frame(sb_inner, bg=PALETTE["border"], height=1).pack(fill=tk.X, pady=(10, 10))

        make_btn(
            sb_inner,
            "▶ 1. SINH LOG XML + JSONL & CHẤM ĐIỂM",
            self.run_generate_and_evaluate,
            bg=PALETTE["crimson"],
            hover_bg=PALETTE["crimson_dark"],
            font=("Segoe UI", 9, "bold"),
            pady=9,
        ).pack(fill=tk.X, pady=(0, 6))

        make_btn(
            sb_inner,
            "⚡ 2. ĐẨY LOG VÀO GLOBALBAN CLI",
            self.run_push_xml_cli,
            bg=PALETTE["cyan_dark"],
            hover_bg=PALETTE["cyan"],
            font=("Segoe UI", 9, "bold"),
            pady=8,
        ).pack(fill=tk.X, pady=(0, 6))

        make_btn(
            sb_inner,
            "🖥 3. MỞ GLOBALBAN DASHBOARD",
            self.open_globalban_dashboard,
            bg=PALETTE["bg_input"],
            hover_bg="#2D3B52",
            fg=PALETTE["cyan"],
            font=("Segoe UI", 9, "bold"),
            pady=8,
        ).pack(fill=tk.X)

        # --- RIGHT CONTENT AREA ---
        right_area = tk.Frame(body, bg=PALETTE["bg_root"])
        right_area.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

        # KPI CARDS ROW
        kpi_row = tk.Frame(right_area, bg=PALETTE["bg_root"])
        kpi_row.pack(fill=tk.X, pady=(0, 10))

        kpi_defs = [
            ("TỔNG SỰ KIỆN XML", "total", PALETTE["cyan"], "total_sub"),
            ("PRECISION", "precision", PALETTE["emerald"], None),
            ("RECALL (ĐỘ PHỦ)", "recall", PALETTE["emerald"], None),
            ("F1-SCORE", "f1", PALETTE["violet"], None),
            ("FALSE POSITIVE RATE", "fpr", PALETTE["amber"], None),
            ("RULE MATCH ACC", "rule_acc", PALETTE["cyan"], None),
        ]
        for idx, (title, key, color, sub_key) in enumerate(kpi_defs):
            card = tk.Frame(
                kpi_row,
                bg=PALETTE["bg_card"],
                highlightbackground=PALETTE["border"],
                highlightthickness=1,
                padx=12,
                pady=8,
            )
            card.grid(row=0, column=idx, sticky="nsew", padx=(0 if idx == 0 else 6, 0))
            kpi_row.columnconfigure(idx, weight=1)

            tk.Label(
                card,
                text=title,
                font=("Segoe UI", 8, "bold"),
                bg=PALETTE["bg_card"],
                fg=PALETTE["text_secondary"],
            ).pack(anchor=tk.W)
            tk.Label(
                card,
                textvariable=self.kpi_vars[key],
                font=("Segoe UI", 15, "bold"),
                bg=PALETTE["bg_card"],
                fg=color,
            ).pack(anchor=tk.W, pady=(2, 0))
            if sub_key:
                tk.Label(
                    card,
                    textvariable=self.kpi_vars[sub_key],
                    font=("Segoe UI", 8),
                    bg=PALETTE["bg_card"],
                    fg=PALETTE["text_muted"],
                ).pack(anchor=tk.W)

        # NOTEBOOK & 6 MODULAR TABS
        self.notebook = ttk.Notebook(right_area)
        self.notebook.pack(fill=tk.BOTH, expand=True)

        build_overview_tab(self.notebook, self)
        build_detections_tab(self.notebook, self)
        build_xml_inspector_tab(self.notebook, self)
        build_ueba_atomic_tab(self.notebook, self)
        build_report_tab(self.notebook, self)
        build_vm_guide_tab(self.notebook, self)

        # --- BOTTOM STATUS BAR ---
        status_bar = tk.Frame(self.root, bg=PALETTE["bg_header"], height=28, highlightbackground=PALETTE["border"], highlightthickness=1)
        status_bar.pack(fill=tk.X, side=tk.BOTTOM)
        status_bar.pack_propagate(False)
        tk.Label(
            status_bar,
            textvariable=self.status_var,
            bg=PALETTE["bg_header"],
            fg=PALETTE["text_secondary"],
            font=("Segoe UI", 8),
        ).pack(side=tk.LEFT, padx=14)
        tk.Label(
            status_bar,
            textvariable=self.output_dir_var,
            bg=PALETTE["bg_header"],
            fg=PALETTE["cyan"],
            font=("Consolas", 8),
        ).pack(side=tk.RIGHT, padx=14)

    def _refresh_engine_badge(self) -> None:
        gb_str = self.globalban_dir_var.get().strip()
        gb_path = Path(gb_str) if gb_str else None
        if gb_path and (gb_path / "src" / "globalban").is_dir():
            self.engine_badge_var.set("● GLOBALBAN LINKED")
            self.badge_label.configure(bg="#132A2E", fg=PALETTE["emerald"])
        else:
            self.engine_badge_var.set("● STANDALONE ENGINE ACTIVE")
            self.badge_label.configure(bg="#1E1B4B", fg=PALETTE["cyan"])

    def _browse_globalban_dir(self) -> None:
        chosen = filedialog.askdirectory(title="Chọn thư mục gốc dự án GlobalBan (chứa thư mục src/)")
        if chosen:
            self.globalban_dir_var.set(chosen)
            self._refresh_engine_badge()
            self.status_var.set(f"Đã cập nhật đường dẫn GlobalBan: {chosen}")

    def _open_output_folder(self) -> None:
        out_dir = Path(self.output_dir_var.get())
        out_dir.mkdir(parents=True, exist_ok=True)
        if sys.platform.startswith("win"):
            os.startfile(str(out_dir))  # type: ignore[attr-defined]
        else:
            webbrowser.open(out_dir.as_uri())

    def run_generate_and_evaluate(self) -> None:
        selected = [k for k, v in self.scenario_vars.items() if v.get()]
        if not selected and self.benign_var.get() <= 0 and not self.ueba_var.get() and not self.lolbin_var.get():
            messagebox.showwarning("Chưa chọn kịch bản", "Vui lòng chọn ít nhất 1 kịch bản.", parent=self.root)
            return

        self.status_var.set("⏳ Đang sinh dữ liệu Windows XML, học hồ sơ UEBA 7 ngày và chấm điểm...")
        self.root.update_idletasks()

        try:
            out_dir = Path(self.output_dir_var.get())
            gb_str = self.globalban_dir_var.get().strip()
            gb_root = Path(gb_str) if gb_str else None

            gen = WindowsAttackLogGenerator(seed=int(self.seed_var.get()))
            records = gen.generate_dataset(
                selected_scenarios=selected,
                campaigns_per_scenario=max(1, int(self.campaigns_var.get())) if selected else 0,
                benign_count=max(0, int(self.benign_var.get())),
                fp_noise_count=max(0, int(self.fp_noise_var.get())),
            )
            self.last_records = records

            jsonl_path = out_dir / "simulated_windows_eval.jsonl"
            xml_path = out_dir / "simulated_windows_events.xml"
            report_json_path = out_dir / "evaluation_report.json"
            export_dataset_files(records, jsonl_path, xml_path)
            self.last_jsonl_path = jsonl_path
            self.last_xml_path = xml_path

            report = run_unified_evaluation(
                jsonl_path=jsonl_path,
                xml_path=xml_path,
                globalban_root=gb_root,
                evaluate_ueba=bool(self.ueba_var.get()),
                evaluate_lolbin=bool(self.lolbin_var.get()),
                output_dir=out_dir,
            )
            self.last_report = report
            report_json_path.write_text(
                json.dumps(report.to_dict(), indent=2, ensure_ascii=False), encoding="utf-8"
            )

            self._update_all_views(report)
            self.status_var.set(
                f"✓ Hoàn tất! Đã sinh {report.total_events:,} sự kiện XML & xuất 7 file vào {out_dir}"
            )
        except Exception as exc:
            self.status_var.set(f"✕ Lỗi: {exc}")
            messagebox.showerror("Lỗi thực thi", str(exc), parent=self.root)

    def _update_all_views(self, report: DetailedEvaluationReport) -> None:
        self.kpi_vars["total"].set(f"{report.total_events:,}")
        self.kpi_vars["total_sub"].set(f"Attack: {report.malicious_events:,} | Clean: {report.benign_events:,}")
        self.kpi_vars["precision"].set(f"{report.precision * 100:.2f}%")
        self.kpi_vars["recall"].set(f"{report.recall * 100:.2f}%")
        self.kpi_vars["f1"].set(f"{report.f1 * 100:.2f}%")
        self.kpi_vars["fpr"].set(f"{report.false_positive_rate * 100:.2f}%")
        self.kpi_vars["rule_acc"].set(f"{report.rule_match_accuracy * 100:.2f}%")

        self._draw_charts()
        self._refresh_alerts_table()
        self._refresh_events_table()
        self._refresh_ueba_view(report)

        self.report_text.delete("1.0", tk.END)
        self.report_text.insert(tk.END, format_report_text(report))

    def _draw_charts(self) -> None:
        if self.last_report is None:
            return
        draw_confusion_matrix(self.cm_canvas, self.last_report)
        draw_mitre_bar_chart(self.mitre_canvas, self.last_report)

    def _refresh_alerts_table(self) -> None:
        for item in self.alerts_tree.get_children():
            self.alerts_tree.delete(item)
        if self.last_report is None:
            return
        q = self.alert_filter_var.get().strip().lower()
        for det in self.last_report.sample_detections:
            blob = f"{det['event_id']} {det['rule_id']} {det['scenario']} {det['target']}".lower()
            if q and q not in blob:
                continue
            self.alerts_tree.insert(
                "",
                tk.END,
                values=(
                    det["event_id"],
                    det["detector"],
                    det["rule_id"],
                    det["target"],
                    det["scenario"],
                    det["explanation"],
                ),
            )

    def _refresh_events_table(self) -> None:
        for item in self.events_tree.get_children():
            self.events_tree.delete(item)
        q = self.xml_search_var.get().strip().lower()
        only_mal = self.only_malicious_var.get()

        shown = 0
        for idx, rec in enumerate(self.last_records):
            if only_mal and not rec.is_malicious:
                continue
            blob = f"{rec.event_id} {rec.scenario} {rec.mitre_technique_id or ''}".lower()
            if q and q not in blob:
                continue
            kind_lbl = "🔴 ATTACK" if rec.is_malicious else "🟢 BENIGN"
            self.events_tree.insert(
                "",
                tk.END,
                iid=str(idx),
                values=(
                    rec.event_id,
                    rec.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                    kind_lbl,
                    rec.mitre_technique_id or "-",
                    rec.scenario,
                    ", ".join(rec.expected_rule_ids) or "(None)",
                ),
            )
            shown += 1
            if shown >= 400:
                break

    def _on_event_selected(self, _event: Any = None) -> None:
        sel = self.events_tree.selection()
        if not sel:
            return
        idx = int(sel[0])
        if 0 <= idx < len(self.last_records):
            rec = self.last_records[idx]
            pretty_xml = rec.xml.replace("><", ">\n  <")
            meta_json = json.dumps(rec.to_jsonl_dict(), indent=2, ensure_ascii=False)
            self.xml_viewer.delete("1.0", tk.END)
            self.xml_viewer.insert(
                tk.END,
                f"=== WINDOWS EVENT XML ({rec.event_id}) ===\n{pretty_xml}\n\n=== GROUND TRUTH METADATA ===\n{meta_json}",
            )

    def _refresh_ueba_view(self, report: DetailedEvaluationReport) -> None:
        self.ueba_text.delete("1.0", tk.END)
        u = report.ueba_evaluation
        if not u:
            self.ueba_text.insert(tk.END, "UEBA Evaluation đang tắt. Hãy tích chọn mục 7 ở thanh bên trái và chạy lại.")
            return

        prof = u.get("profile_summary", {})
        lines = [
            "================================================================================",
            "  HỒ SƠ HÀNH VI 7 NGÀY (BEHAVIORAL PROFILE STORE) & KẾT QUẢ ATOMIC RED TEAM",
            "================================================================================",
            f"Tổng sự kiện học Baseline 7 ngày : {u['baseline_event_count']:,} events",
            f"Số User đã lập hồ sơ             : {u['learned_user_count']} (nguyen.an, tran.binh, admin.it)",
            f"Số Machine đã lập hồ sơ          : {u['learned_machine_count']} (PC-01, PC-02, SRV-FILE01)",
            f"Precision / Recall / F1-Score    : {u['metrics']['precision']*100:.2f}% / {u['metrics']['recall']*100:.2f}% / {u['metrics']['f1_score']*100:.2f}%",
            f"Deviation Tag Match Rate         : {u['metrics']['deviation_tag_match_rate']*100:.2f}%",
            "\n--- CHI TIẾT HỒ SƠ THÓI QUEN TỪNG NGƯỜI DÙNG ---",
        ]
        for uname, udata in prof.get("users", {}).items():
            lines.append(
                f"  • User '{uname}': Giờ làm={udata['hours']} | Máy={udata['machines']} | "
                f"Tiến trình={udata['processes']} | Đích mạng={udata['destinations']}"
            )
        lines.append("\n--- 8 ĐÒN TẤN CÔNG ATOMIC RED TEAM BỊ BẮT TRÚNG (UEBA-BEHAVIOR-DEVIATION) ---")
        for det in u.get("sample_detections", []):
            lines.append(f"  [!] {det['event_id']} | {det['target']:<22} | {det['scenario']:<34} -> {det['explanation']}")
        self.ueba_text.insert(tk.END, "\n".join(lines))

    def _populate_vm_guide(self) -> None:
        guide = """================================================================================
  QUY TRÌNH THU THẬP LOG .EVTX THẬT & QUÉT SIGMA TRÊN MÁY ẢO WINDOWS (VMWARE)
================================================================================
Khi triển khai trên 2 máy ảo VMware (Red Team VM <-> Blue Team GlobalBan VM), chạy
các lệnh PowerShell sau bằng quyền Administrator tại thư mục dự án:

1. Kiểm tra cấu hình máy ảo & trạng thái 4 kênh log (Security, Sysmon, PowerShell, Defender):
   .\\scripts\\preflight.ps1

2. Thu thập dữ liệu hoạt động bình thường Baseline (mỗi ngày 1 case_id):
   .\\scripts\\collect_windows_logs.ps1 -CaseId baseline-day-01 -Kind baseline
   .\\scripts\\collect_windows_logs.ps1 -CaseId baseline-day-02 -Kind baseline
   .\\scripts\\collect_windows_logs.ps1 -CaseId baseline-day-03 -Kind baseline

3. Chạy kỹ thuật Atomic Red Team có phê duyệt (-Approved) & tự động dọn dẹp (Cleanup):
   .\\scripts\\run_approved_atomic.ps1 -CaseId atomic-T1059-001-test-01 -TechniqueId T1059.001 -TestNumbers 1 -Approved
   .\\scripts\\run_approved_atomic.ps1 -CaseId atomic-T1053-005-test-01 -TechniqueId T1053.005 -TestNumbers 1 -Approved

4. Trích xuất trực tiếp Event Viewer thật sang file XML hợp nhất cho GlobalBan:
   .\\scripts\\collect_windows_vm_logs.ps1

5. Quét đối chiếu luật Sigma & đóng gói bàn giao chuẩn Pháp chứng số (SHA256):
   .\\scripts\\run_sigma_on_evtx.ps1
   .\\scripts\\validate_handoff.ps1
================================================================================
"""
        self.vm_text.insert(tk.END, guide)

    def run_push_xml_cli(self) -> None:
        if self.last_xml_path is None or not self.last_xml_path.is_file():
            self.run_generate_and_evaluate()
        if self.last_xml_path is None or self.last_report is None:
            return

        gb_str = self.globalban_dir_var.get().strip()
        gb_root = Path(gb_str) if gb_str else None
        if gb_root and (gb_root / "src" / "globalban").is_dir():
            src_str = str((gb_root / "src").resolve())
            if src_str not in sys.path:
                sys.path.insert(0, src_str)
            try:
                from globalban.main import main as globalban_main

                argv = ["--windows-xml", str(self.last_xml_path.resolve())]
                if self.last_report.ueba_baseline_xml_path:
                    argv.extend(["--learn-baseline", str(self.last_report.ueba_baseline_xml_path.resolve())])
                if self.last_report.ueba_profile_json_path:
                    argv.extend(["--profile-path", str(self.last_report.ueba_profile_json_path.resolve())])
                buf = StringIO()
                with redirect_stdout(buf):
                    globalban_main(argv)
                messagebox.showinfo(
                    "Đã đẩy XML vào GlobalBan CLI",
                    f"Đã gửi thành công {self.last_xml_path.name} vào GlobalBan CLI!\n"
                    f"Kiểm tra chi tiết tại tab 'Báo Cáo Chấm Điểm Chi Tiết'.",
                    parent=self.root,
                )
                return
            except Exception as exc:
                messagebox.showerror("Lỗi GlobalBan CLI", str(exc), parent=self.root)
                return

        total_alerts = sum(self.last_report.triggered_rule_counts.values())
        messagebox.showinfo(
            "Đã kiểm định trên Standalone GlobalBan Engine",
            f"Thư mục GlobalBan ngoài chưa được gắn trên máy này, hệ thống đã chạy kiểm định "
            f"trực tiếp trên Built-in GlobalBan Engine:\n\n"
            f"• File XML: {self.last_xml_path.name}\n"
            f"• Tổng tín hiệu cảnh báo phát hiện: {total_alerts:,}\n"
            f"• Precision: {self.last_report.precision*100:.2f}% | Recall: {self.last_report.recall*100:.2f}% | FPR: {self.last_report.false_positive_rate*100:.2f}%\n\n"
            f"Bạn có thể copy thư mục output/ sang máy ảo GlobalBan hoặc bấm 'Chọn GlobalBan' ở góc trên.",
            parent=self.root,
        )

    def open_globalban_dashboard(self) -> None:
        if self.last_xml_path is None or not self.last_xml_path.is_file():
            self.run_generate_and_evaluate()

        gb_str = self.globalban_dir_var.get().strip()
        gb_root = Path(gb_str) if gb_str else None
        if gb_root and (gb_root / "src" / "globalban").is_dir():
            venv_py = gb_root / ".venv" / "Scripts" / "python.exe"
            py_exe = str(venv_py) if venv_py.is_file() else sys.executable
            cmd = [py_exe, "-m", "globalban.main", "--dashboard"]
            demo_cfg = gb_root / "config" / "demo.config.json"
            if demo_cfg.is_file():
                cmd.extend(["--config", str(demo_cfg)])
            if self.last_report and self.last_report.ueba_baseline_xml_path:
                cmd.extend(["--learn-baseline", str(self.last_report.ueba_baseline_xml_path.resolve())])
            if self.last_report and self.last_report.ueba_profile_json_path:
                cmd.extend(["--profile-path", str(self.last_report.ueba_profile_json_path.resolve())])
            if self.last_xml_path:
                xml_s = str(self.last_xml_path.resolve())
                cmd.extend(["--windows-xml", xml_s, "--watch-windows-xml", xml_s])
            env = os.environ.copy()
            src_p = str((gb_root / "src").resolve())
            env["PYTHONPATH"] = f"{src_p}{os.pathsep}{env['PYTHONPATH']}" if env.get("PYTHONPATH") else src_p
            subprocess.Popen(cmd, cwd=str(gb_root), env=env)
            self.status_var.set("🚀 Đã khởi chạy cửa sổ GlobalBan Security & UEBA Dashboard!")
        else:
            self.notebook.select(3)
            messagebox.showinfo(
                "Chế độ Standalone Dashboard",
                "Không tìm thấy mã nguồn GlobalBan ngoài trên máy cục bộ (ví dụ đang chạy trên máy ảo Red Team riêng).\n\n"
                "Hệ thống đã chuyển sang tab 'Hồ Sơ UEBA 7 Ngày & Atomic' để bạn theo dõi trực tiếp các cảnh báo và hồ sơ hành vi ngay tại đây!",
                parent=self.root,
            )

    def _copy_report_to_clipboard(self) -> None:
        txt = self.report_text.get("1.0", tk.END).strip()
        self.root.clipboard_clear()
        self.root.clipboard_append(txt)
        self.status_var.set("📋 Đã sao chép toàn bộ báo cáo vào Clipboard!")

    def _export_markdown_report(self) -> None:
        if self.last_report is None:
            return
        out_dir = Path(self.output_dir_var.get())
        out_dir.mkdir(parents=True, exist_ok=True)
        md_path = out_dir / "BAO_CAO_CHAM_DIEM_GLOBALBAN.md"
        md_content = "# BÁO CÁO ĐÁNH GIÁ HỆ THỐNG PHÒNG THỦ GLOBALBAN\n\n```text\n" + format_report_text(self.last_report) + "\n```\n"
        md_path.write_text(md_content, encoding="utf-8")
        self.status_var.set(f"💾 Đã xuất báo cáo Markdown tại: {md_path}")
        messagebox.showinfo("Xuất báo cáo thành công", f"Đã lưu file báo cáo tại:\n{md_path}", parent=self.root)
