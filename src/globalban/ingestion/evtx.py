"""Offline Windows EVTX reader for the analysis machine."""

from __future__ import annotations

import base64
import subprocess
from pathlib import Path


def read_evtx_events(
    path: Path,
    *,
    timeout_seconds: float = 120.0,
) -> list[str]:
    """Return XML event records from an EVTX file using Windows' native reader."""
    if not path.is_file():
        raise FileNotFoundError(f"EVTX file does not exist: {path}")
    if timeout_seconds <= 0:
        raise ValueError("timeout_seconds must be greater than zero")

    script = (
        "$events = Get-WinEvent -Path $args[0] -ErrorAction Stop; "
        "$events | ForEach-Object { "
        "[Convert]::ToBase64String("
        "[Text.Encoding]::UTF8.GetBytes($_.ToXml())) }"
    )
    try:
        result = subprocess.run(
            [
                "powershell.exe",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                script,
                str(path),
            ],
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"EVTX read timed out: {path}") from exc
    except OSError as exc:
        raise RuntimeError("powershell.exe is required to read EVTX files") from exc
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip()
        raise RuntimeError(f"Could not read EVTX {path}: {detail or 'unknown error'}")

    records: list[str] = []
    for line in result.stdout.splitlines():
        try:
            records.append(base64.b64decode(line.strip(), validate=True).decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            continue
    return records
