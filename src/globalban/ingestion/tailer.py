"""A lightweight file follower that handles truncation and replacement."""

import os
import time
from collections.abc import Iterator
from pathlib import Path


def follow_file(
    path: str | Path,
    *,
    poll_interval_seconds: float = 1.0,
    start_at_end: bool = True,
) -> Iterator[str]:
    """Yield appended lines, reopening the file when it is rotated or recreated."""
    if poll_interval_seconds <= 0:
        raise ValueError("poll_interval_seconds must be greater than zero")
    log_path = Path(path)
    file = None
    identity: tuple[int, int] | None = None
    try:
        while True:
            try:
                stat = log_path.stat()
                current_identity = (stat.st_dev, stat.st_ino)
                if file is None or identity != current_identity or stat.st_size < file.tell():
                    if file is not None:
                        file.close()
                    file = log_path.open("r", encoding="utf-8", errors="replace")
                    identity = current_identity
                    if start_at_end:
                        file.seek(0, os.SEEK_END)
                line = file.readline()
                if line:
                    yield line
                else:
                    time.sleep(poll_interval_seconds)
            except FileNotFoundError:
                if file is not None:
                    file.close()
                    file = None
                    identity = None
                time.sleep(poll_interval_seconds)
    finally:
        if file is not None:
            file.close()
