"""Small Windows desktop dashboard for the GlobalBan monitor."""

import queue
import subprocess
import sys
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk


class GlobalBanApp:
    def __init__(self, root: tk.Tk) -> None:
        self._root = root
        self._root.title("GlobalBan | Windows Behavior Monitor")
        self._root.geometry("920x620")
        self._root.minsize(760, 480)
        self._process: subprocess.Popen[str] | None = None
        self._output_queue: queue.Queue[str] = queue.Queue()
        self._alert_count = 0
        self._event_count = 0
        self._config_path = tk.StringVar(value="config/config.yaml")
        self._status = tk.StringVar(value="Stopped")
        self._alerts = tk.StringVar(value="0")
        self._events = tk.StringVar(value="0")
        self._build_ui()
        self._root.after(200, self._drain_output)
        self._root.protocol("WM_DELETE_WINDOW", self._close)

    def _build_ui(self) -> None:
        self._root.configure(bg="#101820")
        header = tk.Frame(self._root, bg="#101820", padx=24, pady=20)
        header.pack(fill="x")
        tk.Label(
            header,
            text="GLOBALBAN",
            fg="#f2f5f7",
            bg="#101820",
            font=("Segoe UI", 22, "bold"),
        ).pack(anchor="w")
        tk.Label(
            header,
            text="Windows behavior monitoring and controlled response",
            fg="#91a4b3",
            bg="#101820",
            font=("Segoe UI", 10),
        ).pack(anchor="w", pady=(4, 0))

        controls = tk.Frame(self._root, bg="#182631", padx=18, pady=14)
        controls.pack(fill="x", padx=18)
        tk.Label(controls, text="Config", fg="#dbe7ee", bg="#182631").pack(side="left")
        tk.Entry(
            controls,
            textvariable=self._config_path,
            width=42,
            bg="#0f171d",
            fg="#e8f0f4",
            insertbackground="#e8f0f4",
            relief="flat",
        ).pack(side="left", padx=10)
        tk.Button(controls, text="Browse", command=self._browse, relief="flat").pack(side="left")
        self._start_button = tk.Button(
            controls,
            text="Start monitor",
            command=self._start,
            bg="#2da66a",
            fg="white",
            relief="flat",
            padx=14,
        )
        self._start_button.pack(side="right", padx=(8, 0))
        self._stop_button = tk.Button(
            controls,
            text="Stop",
            command=self._stop,
            state="disabled",
            bg="#b84a4a",
            fg="white",
            relief="flat",
            padx=14,
        )
        self._stop_button.pack(side="right")

        cards = tk.Frame(self._root, bg="#101820", padx=18, pady=18)
        cards.pack(fill="x")
        self._card(cards, "STATUS", self._status, "#64b5f6", 0)
        self._card(cards, "EVENTS", self._events, "#d8b45a", 1)
        self._card(cards, "ALERTS", self._alerts, "#f07777", 2)

        body = tk.Frame(self._root, bg="#101820", padx=18)
        body.pack(fill="both", expand=True)
        tk.Label(
            body,
            text="Live activity",
            fg="#dbe7ee",
            bg="#101820",
            font=("Segoe UI", 12, "bold"),
        ).pack(anchor="w", pady=(0, 8))
        self._log = tk.Text(
            body,
            bg="#0b1217",
            fg="#c9d7df",
            insertbackground="#ffffff",
            relief="flat",
            wrap="word",
            state="disabled",
            font=("Consolas", 9),
        )
        self._log.pack(fill="both", expand=True)

    def _card(
        self, parent: tk.Frame, title: str, value: tk.StringVar, color: str, column: int
    ) -> None:
        card = tk.Frame(parent, bg="#182631", padx=16, pady=12)
        card.grid(row=0, column=column, sticky="nsew", padx=(0, 10))
        parent.grid_columnconfigure(column, weight=1)
        tk.Label(card, text=title, fg="#91a4b3", bg="#182631", font=("Segoe UI", 9)).pack(anchor="w")
        tk.Label(card, textvariable=value, fg=color, bg="#182631", font=("Segoe UI", 18, "bold")).pack(anchor="w")

    def _browse(self) -> None:
        selected = filedialog.askopenfilename(filetypes=[("YAML files", "*.yaml"), ("All files", "*.*")])
        if selected:
            self._config_path.set(str(Path(selected)))

    def _start(self) -> None:
        if self._process is not None:
            return
        config = Path(self._config_path.get())
        if not config.exists():
            messagebox.showerror("Config not found", f"Cannot find {config}")
            return
        self._process = subprocess.Popen(
            [sys.executable, "-m", "globalban.main", "--config", str(config), "--dry-run"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            cwd=Path.cwd(),
        )
        self._status.set("Running")
        self._start_button.configure(state="disabled")
        self._stop_button.configure(state="normal")
        threading.Thread(target=self._read_output, daemon=True).start()

    def _read_output(self) -> None:
        if self._process is None or self._process.stdout is None:
            return
        for line in self._process.stdout:
            self._output_queue.put(line.rstrip())

    def _drain_output(self) -> None:
        try:
            while True:
                line = self._output_queue.get_nowait()
                self._event_count += int("Windows event observed" in line)
                self._alert_count += int("WARNING" in line or "risk" in line.lower())
                self._events.set(str(self._event_count))
                self._alerts.set(str(self._alert_count))
                self._log.configure(state="normal")
                self._log.insert("end", line + "\n")
                self._log.see("end")
                self._log.configure(state="disabled")
        except queue.Empty:
            pass
        if self._process is not None and self._process.poll() is not None:
            self._status.set(f"Exited ({self._process.returncode})")
            self._process = None
            self._start_button.configure(state="normal")
            self._stop_button.configure(state="disabled")
        self._root.after(200, self._drain_output)

    def _stop(self) -> None:
        if self._process is not None and self._process.poll() is None:
            self._process.terminate()
        self._status.set("Stopped")
        self._start_button.configure(state="normal")
        self._stop_button.configure(state="disabled")
        self._process = None

    def _close(self) -> None:
        self._stop()
        self._root.destroy()


def main() -> None:
    root = tk.Tk()
    GlobalBanApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()