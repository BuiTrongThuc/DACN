#!/usr/bin/env python3
"""
attack_tool.py
==============
GlobalBan Red-Team Adversary Emulation & Benchmark CLI / GUI Launcher.
Seamlessly forwards to the modern modular engine in attack_globalban_studio.py.
"""

from __future__ import annotations

import sys
from pathlib import Path

# Ensure workspace root is in sys.path
_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

from attack_globalban_studio import main

if __name__ == "__main__":
    raise SystemExit(main())
