"""Authentication event models."""

from dataclasses import dataclass
from datetime import datetime
from ipaddress import IPv4Address, IPv6Address, ip_address
from typing import Mapping, TypeAlias

IPAddress: TypeAlias = IPv4Address | IPv6Address


@dataclass(frozen=True, slots=True)
class AuthEvent:
    timestamp: datetime
    source_ip: IPAddress
    username: str
    event_type: str
    raw: str = ""

    @property
    def failed(self) -> bool:
        return self.event_type == "failed"


@dataclass(frozen=True, slots=True)
class WindowsEvent:
    timestamp: datetime
    event_id: int
    provider: str
    fields: Mapping[str, str]
    host: str = ""
    raw: str = ""

    @property
    def priority(self) -> str:
        if self.event_id in {4624, 4625, 4648, 4672, 4688, 4698, 4702, 4719, 1102,
                             4720, 4724, 4728, 4732, 4740, 4104, 1, 13, 7045, 1116, 1117}:
            return "P0"
        if self.event_id in {4697, 4700, 4616, 4907, 4722, 4723, 4725, 4726, 4729,
                             4733, 4735, 4738, 4768, 4769, 4771, 4776, 4946, 4947,
                             4948, 4950, 4956, 5025, 5157, 4103, 3, 6, 8, 10, 11,
                             12, 16, 19, 20, 21, 22, 25, 7040, 1149, 21}:
            return "P1"
        return "P2"

    @property
    def event_type(self) -> str:
        return f"windows_event_{self.event_id}"

    @property
    def username(self) -> str:
        return self.fields.get("TargetUserName") or self.fields.get("SubjectUserName", "")

    @property
    def source_ip(self) -> IPAddress | None:
        value = self.fields.get("IpAddress") or self.fields.get("SourceIp")
        if not value or value == "-":
            return None
        try:
            return ip_address(value)
        except ValueError:
            return None

    @property
    def process_id(self) -> str | None:
        return self.fields.get("ProcessId")

    @property
    def parent_process_id(self) -> str | None:
        return self.fields.get("ParentProcessId")

    @property
    def executable(self) -> str | None:
        return self.fields.get("NewProcessName") or self.fields.get("Image")

    @property
    def command_line(self) -> str | None:
        return self.fields.get("CommandLine") or self.fields.get("ScriptBlockText")
