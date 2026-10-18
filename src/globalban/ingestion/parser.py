"""Parsers for common OpenSSH authentication log messages."""

import re
from datetime import datetime
from ipaddress import ip_address

from globalban.models.events import AuthEvent

_FAILED = re.compile(
    r"sshd(?:\[\d+\])?: Failed password for (?:invalid user )?(?P<user>\S+) "
    r"from (?P<ip>[0-9a-fA-F:.]+) port \d+"
)
_ACCEPTED = re.compile(
    r"sshd(?:\[\d+\])?: Accepted \S+ for (?P<user>\S+) "
    r"from (?P<ip>[0-9a-fA-F:.]+) port \d+"
)
_SYSLOG_PREFIX = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2}) "
    r"(?P<time>\d{2}:\d{2}:\d{2})\s+"
)


def parse_auth_line(line: str, *, now: datetime | None = None) -> AuthEvent | None:
    """Parse one OpenSSH auth log line; return None for unrelated/malformed lines."""
    match = _FAILED.search(line)
    event_type = "failed"
    if match is None:
        match = _ACCEPTED.search(line)
        event_type = "success"
    if match is None:
        return None

    try:
        source_ip = ip_address(match.group("ip"))
        prefix = _SYSLOG_PREFIX.match(line)
        if prefix:
            reference = now or datetime.now().astimezone()
            timestamp = datetime.strptime(
                f"{reference.year} {prefix.group('month')} {prefix.group('day')} "
                f"{prefix.group('time')}",
                "%Y %b %d %H:%M:%S",
            ).replace(tzinfo=reference.tzinfo)
        else:
            timestamp = now or datetime.now().astimezone()
    except (ValueError, OverflowError):
        return None

    return AuthEvent(
        timestamp=timestamp,
        source_ip=source_ip,
        username=match.group("user"),
        event_type=event_type,
        raw=line.rstrip("\r\n"),
    )
