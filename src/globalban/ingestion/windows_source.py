"""Windows Event Log source using built-in PowerShell and no extra package."""

import base64
import hashlib
import logging
import subprocess
import time
from collections import deque
from collections.abc import Iterator, Sequence

logger = logging.getLogger(__name__)


def _powershell_script(log_names: Sequence[str], lookback_seconds: int) -> str:
    quoted_names = ",".join("'" + name.replace("'", "''") + "'" for name in log_names)
    return f"""
$start = (Get-Date).AddSeconds(-{lookback_seconds})
$logs = @({quoted_names})
foreach ($log in $logs) {{
    try {{
        Get-WinEvent -LogName $log -MaxEvents 200 -ErrorAction Stop |
            Where-Object {{ $_.TimeCreated -ge $start }} |
            ForEach-Object {{ [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($_.ToXml())) }}
    }} catch {{
        [Console]::Error.WriteLine("GlobalBan channel unavailable: $log - $($_.Exception.Message)")
        continue
    }}
}}
exit 0
"""


def read_windows_events(
    log_names: Sequence[str], *, lookback_seconds: int = 30, timeout_seconds: float = 20.0
) -> list[str]:
    """Return new XML records from configured Windows channels."""
    if lookback_seconds <= 0:
        raise ValueError("lookback_seconds must be greater than zero")
    if timeout_seconds <= 0:
        raise ValueError("timeout_seconds must be greater than zero")
    try:
        result = subprocess.run(
            [
                "powershell.exe",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                _powershell_script(log_names, lookback_seconds),
            ],
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError("Windows Event Log query timed out") from exc
    except OSError as exc:
        raise RuntimeError("powershell.exe is required for Windows Event Log ingestion") from exc
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip()
        logger.warning(
            "PowerShell Event Log query returned exit code %d: %s",
            result.returncode,
            detail or "channel unavailable; continuing with available channels",
        )
    for error_line in result.stderr.splitlines():
        if error_line.strip():
            logger.warning(error_line.strip())
    records: list[str] = []
    for line in result.stdout.splitlines():
        try:
            records.append(base64.b64decode(line.strip()).decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            continue
    return records


def follow_windows_events(
    log_names: Sequence[str], *, poll_interval_seconds: float, lookback_seconds: int = 30
) -> Iterator[str]:
    """Poll Windows Event Log and yield each XML record once per process."""
    if lookback_seconds <= 0:
        raise ValueError("lookback_seconds must be greater than zero")
    seen: set[str] = set()
    seen_order: deque[str] = deque()
    warned_no_events = False
    while True:
        records = read_windows_events(log_names, lookback_seconds=lookback_seconds)
        if not records and not warned_no_events:
            logger.warning(
                "No Windows events received in the last %d seconds; "
                "verify that the attack creates events on this machine",
                lookback_seconds,
            )
            warned_no_events = True
        elif records:
            warned_no_events = False
        logger.debug("Windows Event Log poll completed: %d new record(s)", len(records))
        for record in records:
            fingerprint = hashlib.sha256(record.encode("utf-8")).hexdigest()
            if fingerprint in seen:
                continue
            seen.add(fingerprint)
            seen_order.append(fingerprint)
            while len(seen_order) > 10_000:
                seen.remove(seen_order.popleft())
            yield record
        time.sleep(poll_interval_seconds)