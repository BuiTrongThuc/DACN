"""Authentication event models."""

from dataclasses import dataclass
from datetime import datetime
from ipaddress import IPv4Address, IPv6Address
from typing import TypeAlias

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
