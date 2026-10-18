"""Parsers for common OpenSSH authentication log messages."""

import re
import xml.etree.ElementTree as ET
from datetime import datetime
from ipaddress import ip_address

from globalban.models.events import AuthEvent, WindowsEvent

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


def _windows_value(root: ET.Element, name: str) -> str | None:
    for element in root.iter():
        local_name = element.tag.rsplit("}", 1)[-1]
        matches_name = local_name == name or (
            local_name == "Data" and element.attrib.get("Name") == name
        )
        if matches_name and element.text:
            return element.text.strip()
    return None


def parse_windows_event(raw: str, *, now: datetime | None = None) -> AuthEvent | None:
    """Parse a Windows Security Event 4625 XML record without forwarding raw data."""
    try:
        root = ET.fromstring(raw)
    except ET.ParseError:
        return None
    if _windows_value(root, "EventID") != "4625":
        return None
    source = _windows_value(root, "IpAddress")
    username = _windows_value(root, "TargetUserName")
    if not source or source == "-" or not username:
        return None
    try:
        source_ip = ip_address(source)
        timestamp = now or datetime.now().astimezone()
        for element in root.iter():
            if element.tag.rsplit("}", 1)[-1] == "TimeCreated":
                value = element.attrib.get("SystemTime")
                if value:
                    timestamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
                break
    except (ValueError, OverflowError):
        return None
    return AuthEvent(
        timestamp=timestamp,
        source_ip=source_ip,
        username=username,
        event_type="failed",
        raw=raw,
    )


def parse_windows_security_event(
    raw: str, *, now: datetime | None = None
) -> WindowsEvent | None:
    """Parse a Windows Event XML record into safe structured fields."""
    try:
        root = ET.fromstring(raw)
        event_id = int(_windows_value(root, "EventID") or "")
    except (ET.ParseError, TypeError, ValueError):
        return None
    provider = "unknown"
    host = ""
    timestamp = now or datetime.now().astimezone()
    fields: dict[str, str] = {}
    for element in root.iter():
        local_name = element.tag.rsplit("}", 1)[-1]
        if local_name == "Provider":
            provider = element.attrib.get("Name", provider)
            host = element.attrib.get("Computer", host)
        elif local_name == "System":
            host = element.attrib.get("Computer", host)
        elif local_name == "TimeCreated":
            value = element.attrib.get("SystemTime")
            if value:
                try:
                    timestamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
                except ValueError:
                    return None
        elif local_name == "Data" and element.attrib.get("Name") and element.text:
            name = element.attrib["Name"]
            if name in {
                "TargetUserName", "SubjectUserName", "IpAddress", "CommandLine",
                "NewProcessName", "ParentImage", "ServiceName", "TaskName",
                "ScriptBlockText", "Image", "DestinationIp", "TargetFilename",
                "ProcessId", "ParentProcessId", "ParentProcessGuid", "ProcessGuid",
            }:
                fields[name] = element.text.strip()
    return WindowsEvent(
        timestamp=timestamp,
        event_id=event_id,
        provider=provider,
        fields=fields,
        host=host,
        raw=raw,
    )


def parse_log_record(line: str, *, now: datetime | None = None) -> AuthEvent | None:
    """Parse either a Windows Event 4625 XML record or an OpenSSH auth line."""
    return parse_windows_event(line, now=now) or parse_auth_line(line, now=now)


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
