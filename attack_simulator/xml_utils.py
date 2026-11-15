"""
attack_simulator.xml_utils
==========================
Windows Event Viewer XML serialization, deserialization, and element parsing utilities.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from xml.sax.saxutils import escape


def build_windows_event_xml(
    *,
    provider: str,
    computer: str,
    event_id: int,
    timestamp: datetime,
    data_fields: dict[str, str],
) -> str:
    """Create a valid Windows Event Viewer XML string."""
    ts_utc = timestamp.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    quot_map = {'"': "&quot;"}
    data_elements = "".join(
        f'<Data Name="{escape(str(k), quot_map)}">{escape(str(v))}</Data>'
        for k, v in data_fields.items()
    )
    provider_attr = escape(provider, {'"': "&quot;"})
    return (
        '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
        "<System>"
        f'<Provider Name="{provider_attr}"/>'
        f"<Computer>{escape(computer)}</Computer>"
        f"<EventID>{event_id}</EventID>"
        f'<TimeCreated SystemTime="{ts_utc}"/>'
        "</System>"
        f"<EventData>{data_elements}</EventData>"
        "</Event>"
    )


@dataclass(slots=True)
class ParsedWinEvent:
    provider: str
    computer: str
    event_id: int
    timestamp: datetime
    data: dict[str, str]

    @property
    def username(self) -> str | None:
        raw = (
            self.data.get("TargetUserName")
            or self.data.get("SubjectUserName")
            or self.data.get("User")
        )
        if not raw:
            return None
        return raw.split("\\")[-1].strip().lower()

    @property
    def source_ip(self) -> str | None:
        return self.data.get("IpAddress") or self.data.get("ClientAddress")


def parse_xml_event_element(elem: ET.Element) -> ParsedWinEvent | None:
    ns_strip = lambda tag: tag.split("}", 1)[-1]
    provider = ""
    computer = ""
    event_id = 0
    ts = datetime.now(timezone.utc)
    data_map: dict[str, str] = {}

    for child in elem:
        cname = ns_strip(child.tag)
        if cname == "System":
            for s in child:
                sname = ns_strip(s.tag)
                if sname == "Provider":
                    provider = s.attrib.get("Name", "")
                elif sname == "Computer":
                    computer = (s.text or "").strip()
                elif sname == "EventID":
                    try:
                        event_id = int((s.text or "0").strip())
                    except ValueError:
                        event_id = 0
                elif sname == "TimeCreated":
                    raw_ts = s.attrib.get("SystemTime", "")
                    if raw_ts:
                        try:
                            ts = datetime.fromisoformat(raw_ts.replace("Z", "+00:00"))
                        except ValueError:
                            pass
        elif cname == "EventData":
            for d in child:
                if ns_strip(d.tag) == "Data":
                    key = d.attrib.get("Name", "")
                    if key:
                        data_map[key] = d.text or ""

    if event_id <= 0:
        return None
    return ParsedWinEvent(
        provider=provider,
        computer=computer,
        event_id=event_id,
        timestamp=ts,
        data=data_map,
    )


def parse_xml_event_string(xml_str: str) -> ParsedWinEvent | None:
    try:
        root = ET.fromstring(xml_str)
        return parse_xml_event_element(root)
    except ET.ParseError:
        return None


def parse_xml_events_file(xml_path: str | Path) -> list[ParsedWinEvent]:
    root = ET.parse(str(xml_path)).getroot()
    events: list[ParsedWinEvent] = []
    for elem in root:
        if elem.tag.split("}", 1)[-1] == "Event":
            parsed = parse_xml_event_element(elem)
            if parsed is not None:
                events.append(parsed)
    return events
