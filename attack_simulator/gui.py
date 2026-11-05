from __future__ import annotations

import json
import os
import subprocess
import sys
import tkinter as tk
from pathlib import Path
from tkinter import messagebox, ttk

if __package__ in (None, ""):
    _PROJECT_ROOT = str(Path(__file__).resolve().parents[1])
    if _PROJECT_ROOT not in sys.path:
        sys.path.insert(0, _PROJECT_ROOT)

from attack_simulator.evaluator import (
    DEFAULT_GLOBALBAN_ROOT,
    DetailedEvaluationReport,
    format_report_text,
    push_xml_to_globalban_cli,
    run_globalban_evaluation,
)
from attack_simulator.scenarios import (
    SCENARIO_CATALOG,
    WindowsAttackLogGenerator,
    export_dataset_files,
)


class AttackSimulatorGUI:
    """Graphical interface for generating Windows XML attack logs and evaluating GlobalBan."""

    def __init__(
        self,
        root: tk.Tk,
        output_dir: Path | None = None,
        globalban_root: Path = DEFAULT_GLOBALBAN_ROOT,
    ) -> None:
        self.root = root
        self.root.title(
            "GlobalBan Red-Team Simulator & Benchmark Tool (Windows XML Attack Generator)"
        )
        self.root.geometry("1180x780")
        self.output_dir = output_dir or (Path(__file__).resolve().parents[1] / "output")
        self.globalban_root = globalban_root
        self.last_xml_path: Path | None = None
        self.last_jsonl_path: Path | None = None

        self.scenario_vars: dict[str, tk.BooleanVar] = {}
        self.campaigns_var = tk.IntVar(value=20)
        self.benign_var = tk.IntVar(value=600)
        self.fp_noise_var = tk.IntVar(value=0)
        self.seed_var = tk.IntVar(value=42)

        self.metric_vars: dict[str, tk.StringVar] = {
            "total": tk.StringVar(value="0"),
            "precision": tk.StringVar(value="0.00%"),
            "recall": tk.StringVar(value="0.00%"),
            "f1": tk.StringVar(value="0.00%"),
            "fpr": tk.StringVar(value="0.00%"),
            "rule_acc": tk.StringVar(value="0.00%"),
            "cm": tk.StringVar(value="TP: 0 | FP: 0 | FN: 0 | TN: 0"),
        }

        self._build_ui()
        self.root.after(150, self.run_generate_and_evaluate)

    def _build_ui(self) -> None:
        style = ttk.Style(self.root)
        if "vista" in style.theme_names():
            style.theme_use("vista")

        # Top control panel
        top_pane = ttk.Frame(self.root, padding=10)
        top_pane.pack(fill=tk.X)

        scenarios_frame = ttk.LabelFrame(
            top_pane,
            text="Chọn Kịch Bản Chiến Dịch Tấn Công (Attack Scenarios)",
            padding=10,
        )
        scenarios_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 8))

        for idx, spec in enumerate(SCENARIO_CATALOG):
            var = tk.BooleanVar(value=True)
            self.scenario_vars[spec.key] = var
            chk = ttk.Checkbutton(
                scenarios_frame,
                text=f"{spec.title}  [{spec.expected_rules_desc}]",
                variable=var,
            )
            chk.grid(row=idx // 2, column=idx % 2, sticky=tk.W, padx=8, pady=4)

        btn_row = ttk.Frame(scenarios_frame)
        btn_row.grid(row=3, column=0, columnspan=2, sticky=tk.W, padx=8, pady=(6, 0))
        ttk.Button(
            btn_row,
            text="Chọn tất cả",
            command=lambda: [v.set(True) for v in self.scenario_vars.values()],
        ).pack(side=tk.LEFT, padx=(0, 6))
        ttk.Button(
            btn_row,
            text="Bỏ chọn tất cả",
            command=lambda: [v.set(False) for v in self.scenario_vars.values()],
        ).pack(side=tk.LEFT)

        # Parameters panel
        params_frame = ttk.LabelFrame(
            top_pane,
            text="Cấu Hình Số Lượng Log Sinh Ra",
            padding=10,
        )
        params_frame.pack(side=tk.RIGHT, fill=tk.Y)

        ttk.Label(params_frame, text="Số chiến dịch / mỗi kịch bản:").grid(
            row=0, column=0, sticky=tk.W, pady=3
        )
        ttk.Spinbox(
            params_frame, from_=1, to=500, textvariable=self.campaigns_var, width=10
        ).grid(row=0, column=1, sticky=tk.E, padx=(8, 0), pady=3)

        ttk.Label(params_frame, text="Số lượng Log bình thường (Benign):").grid(
            row=1, column=0, sticky=tk.W, pady=3
        )
        ttk.Spinbox(
            params_frame,
            from_=0,
            to=20000,
            increment=100,
            textvariable=self.benign_var,
            width=10,
        ).grid(row=1, column=1, sticky=tk.E, padx=(8, 0), pady=3)

        ttk.Label(params_frame, text="Nhiễu Admin (Test False Positive):").grid(
            row=2, column=0, sticky=tk.W, pady=3
        )
        ttk.Spinbox(
            params_frame,
            from_=0,
            to=1000,
            increment=5,
            textvariable=self.fp_noise_var,
            width=10,
        ).grid(row=2, column=1, sticky=tk.E, padx=(8, 0), pady=3)

        ttk.Label(params_frame, text="Random Seed:").grid(
            row=3, column=0, sticky=tk.W, pady=3
        )
        ttk.Spinbox(
            params_frame, from_=1, to=99999, textvariable=self.seed_var, width=10
        ).grid(row=3, column=1, sticky=tk.E, padx=(8, 0), pady=3)

        # Action toolbar
        actions_frame = ttk.Frame(self.root, padding=(10, 0, 10, 8))
        actions_frame.pack(fill=tk.X)

        ttk.Button(
            actions_frame,
            text="1. Sinh File XML + JSONL & Chấm Điểm Tự Động (evaluate_windows_dataset)",
            command=self.run_generate_and_evaluate,
        ).pack(side=tk.LEFT, padx=(0, 8))

        ttk.Button(
            actions_frame,
            text="2. Bắn Log XML trực tiếp vào GlobalBan CLI (--windows-xml)",
            command=self.run_push_xml_cli,
        ).pack(side=tk.LEFT, padx=(0, 8))

        ttk.Button(
            actions_frame,
            text="3. Mở GlobalBan Dashboard (Tự Động Liên Kết & Nạp XML)",
            command=self.open_globalban_dashboard,
        ).pack(side=tk.LEFT)

        # Metrics scoreboard
        score_frame = ttk.LabelFrame(
            self.root,
            text="Kết Quả Đo Lường GlobalBan (Precision / Recall / F1-Score / False Positive Rate)",
            padding=10,
        )
        score_frame.pack(fill=tk.X, padx=10, pady=(0, 8))

        cards = [
            ("Tổng số Log XML", "total"),
            ("Precision", "precision"),
            ("Recall", "recall"),
            ("F1-Score", "f1"),
            ("False Positive Rate", "fpr"),
            ("Rule Match Accuracy", "rule_acc"),
            ("Confusion Matrix", "cm"),
        ]
        for col, (label_text, key) in enumerate(cards):
            cell = ttk.Frame(score_frame, padding=4)
            cell.grid(row=0, column=col, sticky=tk.NSEW, padx=6)
            score_frame.columnconfigure(col, weight=1)
            ttk.Label(cell, text=label_text, font=("Segoe UI", 9, "bold")).pack(
                anchor=tk.W
            )
            ttk.Label(
                cell,
                textvariable=self.metric_vars[key],
                font=("Segoe UI", 11, "bold"),
                foreground="#0b5394",
            ).pack(anchor=tk.W, pady=(2, 0))

        # Notebook tabs for detailed results
        notebook = ttk.Notebook(self.root)
        notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))

        # Tab 1: Detection Signals & Alerts table
        detections_tab = ttk.Frame(notebook, padding=8)
        notebook.add(detections_tab, text="Cảnh Báo & Tín Hiệu GlobalBan Bắt Được")

        cols = ("event_id", "detector", "rule_id", "target", "scenario", "explanation")
        self.tree = ttk.Treeview(detections_tab, columns=cols, show="headings")
        headings = {
            "event_id": "Event ID",
            "detector": "Bộ Phát Hiện (Detector)",
            "rule_id": "Rule Kích Hoạt",
            "target": "Host / Source IP",
            "scenario": "Kịch Bản Mô Phỏng",
            "explanation": "Giải Thích Của GlobalBan",
        }
        widths = {
            "event_id": 110,
            "detector": 175,
            "rule_id": 220,
            "target": 140,
            "scenario": 220,
            "explanation": 380,
        }
        for c in cols:
            self.tree.heading(c, text=headings[c])
            self.tree.column(c, width=widths[c], anchor=tk.W)
        scroll_y = ttk.Scrollbar(
            detections_tab, orient=tk.VERTICAL, command=self.tree.yview
        )
        self.tree.configure(yscrollcommand=scroll_y.set)
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scroll_y.pack(side=tk.RIGHT, fill=tk.Y)

        # Tab 2: Detailed Text Report & MITRE Breakdown
        report_tab = ttk.Frame(notebook, padding=8)
        notebook.add(report_tab, text="Báo Cáo Chi Tiết & MITRE ATT&CK Recall")
        self.report_text = tk.Text(
            report_tab, font=("Consolas", 10), wrap=tk.NONE, height=20
        )
        rep_scroll = ttk.Scrollbar(
            report_tab, orient=tk.VERTICAL, command=self.report_text.yview
        )
        self.report_text.configure(yscrollcommand=rep_scroll.set)
        self.report_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        rep_scroll.pack(side=tk.RIGHT, fill=tk.Y)

    def run_generate_and_evaluate(self) -> None:
        selected = [k for k, v in self.scenario_vars.items() if v.get()]
        if not selected and self.benign_var.get() <= 0:
            messagebox.showwarning(
                "Chưa chọn kịch bản",
                "Vui lòng chọn ít nhất 1 kịch bản tấn công hoặc cấu hình số lượng log Benign > 0.",
                parent=self.root,
            )
            return

        try:
            gen = WindowsAttackLogGenerator(seed=int(self.seed_var.get()))
            records = gen.generate_dataset(
                selected_scenarios=selected,
                campaigns_per_scenario=max(1, int(self.campaigns_var.get()))
                if selected
                else 0,
                benign_count=max(0, int(self.benign_var.get())),
                fp_noise_count=max(0, int(self.fp_noise_var.get())),
            )

            jsonl_path = self.output_dir / "simulated_windows_eval.jsonl"
            xml_path = self.output_dir / "simulated_windows_events.xml"
            report_json_path = self.output_dir / "evaluation_report.json"
            export_dataset_files(records, jsonl_path, xml_path)
            self.last_jsonl_path = jsonl_path
            self.last_xml_path = xml_path

            report = run_globalban_evaluation(
                jsonl_path=jsonl_path,
                xml_path=xml_path,
                globalban_root=self.globalban_root,
            )
            report_json_path.write_text(
                json.dumps(report.to_dict(), indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
            self._update_ui_with_report(report)
        except Exception as exc:
            messagebox.showerror("Lỗi thực thi", str(exc), parent=self.root)

    def _update_ui_with_report(self, report: DetailedEvaluationReport) -> None:
        self.metric_vars["total"].set(
            f"{report.total_events:,} (Attack: {report.malicious_events:,} | Benign: {report.benign_events:,})"
        )
        self.metric_vars["precision"].set(f"{report.precision * 100:.2f}%")
        self.metric_vars["recall"].set(f"{report.recall * 100:.2f}%")
        self.metric_vars["f1"].set(f"{report.f1 * 100:.2f}%")
        self.metric_vars["fpr"].set(f"{report.false_positive_rate * 100:.2f}%")
        self.metric_vars["rule_acc"].set(f"{report.rule_match_accuracy * 100:.2f}%")
        self.metric_vars["cm"].set(
            f"TP: {report.true_positive} | FP: {report.false_positive} | "
            f"FN: {report.false_negative} | TN: {report.true_negative}"
        )

        for item in self.tree.get_children():
            self.tree.delete(item)
        for det in report.sample_detections:
            self.tree.insert(
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

        self.report_text.delete("1.0", tk.END)
        self.report_text.insert(tk.END, format_report_text(report))

    def run_push_xml_cli(self) -> None:
        if self.last_xml_path is None or not self.last_xml_path.is_file():
            self.run_generate_and_evaluate()
        if self.last_xml_path is None:
            return
        try:
            alerts = push_xml_to_globalban_cli(
                self.last_xml_path, globalban_root=self.globalban_root
            )
            self.report_text.insert(
                tk.END,
                f"\n\n[GLOBALBAN CLI --windows-xml OUTPUT]: Bắt được {len(alerts)} bản ghi cảnh báo JSON.\n",
            )
            for item in alerts[:15]:
                self.report_text.insert(tk.END, f"  {item}\n")
            messagebox.showinfo(
                "Đã bắn Log XML vào GlobalBan",
                f"Đã đẩy file {self.last_xml_path.name} vào GlobalBan CLI.\n"
                f"GlobalBan đã phát hiện và xuất ra {len(alerts)} bản ghi cảnh báo/tín hiệu!",
                parent=self.root,
            )
        except Exception as exc:
            messagebox.showerror("Lỗi khi bắn XML", str(exc), parent=self.root)

    def open_globalban_dashboard(self) -> None:
        if self.last_xml_path is None or not self.last_xml_path.is_file():
            self.run_generate_and_evaluate()
        venv_python = self.globalban_root / ".venv" / "Scripts" / "python.exe"
        py_exe = str(venv_python) if venv_python.is_file() else sys.executable
        cmd = [py_exe, "-m", "globalban.main", "--dashboard"]
        demo_config = self.globalban_root / "config" / "demo.config.json"
        if demo_config.is_file():
            cmd.extend(["--config", str(demo_config)])
        if self.last_xml_path is not None and self.last_xml_path.is_file():
            xml_str = str(self.last_xml_path.resolve())
            cmd.extend(["--windows-xml", xml_str, "--watch-windows-xml", xml_str])
        env = os.environ.copy()
        src_path = str((self.globalban_root / "src").resolve())
        env["PYTHONPATH"] = (
            f"{src_path}{os.pathsep}{env['PYTHONPATH']}"
            if env.get("PYTHONPATH")
            else src_path
        )
        subprocess.Popen(
            cmd,
            cwd=str(self.globalban_root),
            env=env,
        )


def launch_gui(
    output_dir: Path | None = None,
    globalban_root: Path = DEFAULT_GLOBALBAN_ROOT,
) -> None:
    root = tk.Tk()
    AttackSimulatorGUI(root, output_dir=output_dir, globalban_root=globalban_root)
    root.mainloop()


if __name__ == "__main__":
    launch_gui()

