from __future__ import annotations

from pathlib import Path
import tkinter as tk

from attack_simulator.ui.main_window import ModernRedTeamStudioApp


def launch_gui(output_dir: Path | None = None, globalban_root: Path | None = None) -> None:
    root = tk.Tk()
    ModernRedTeamStudioApp(root, output_dir=output_dir, globalban_root=globalban_root)
    root.mainloop()


__all__ = ["ModernRedTeamStudioApp", "launch_gui"]
