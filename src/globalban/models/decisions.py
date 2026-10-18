"""Detection and policy decision models."""

from dataclasses import dataclass
from datetime import datetime
from ipaddress import IPv4Address, IPv6Address
from typing import TypeAlias

IPAddress: TypeAlias = IPv4Address | IPv6Address


@dataclass(frozen=True, slots=True)
class BanCandidate:
    source_ip: IPAddress
    failed_attempts: int
    window_started_at: datetime
    window_ended_at: datetime


@dataclass(frozen=True, slots=True)
class PolicyDecision:
    allowed: bool
    reason: str
