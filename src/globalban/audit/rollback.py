"""TTL-backed action records for controlled rollback."""

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from ipaddress import IPv4Address, IPv6Address

from globalban.actions.block_ip import BlockResult, IPBlocker

IPAddress = IPv4Address | IPv6Address


@dataclass(frozen=True, slots=True)
class ActionRecord:
    address: IPAddress
    created_at: datetime
    expires_at: datetime
    block_result: BlockResult


class RollbackManager:
    def __init__(self, *, blocker: IPBlocker, ttl_seconds: int = 3600) -> None:
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be greater than zero")
        self._blocker = blocker
        self._ttl = timedelta(seconds=ttl_seconds)
        self._records: dict[str, ActionRecord] = {}

    def record(self, address: IPAddress, result: BlockResult) -> ActionRecord:
        created = datetime.now(timezone.utc)
        record = ActionRecord(address, created, created + self._ttl, result)
        self._records[str(address)] = record
        return record

    def rollback(self, address: IPAddress, *, approved: bool = False) -> BlockResult:
        if not approved:
            raise PermissionError("explicit approval is required for rollback")
        if str(address) not in self._records:
            raise KeyError(f"no action record for {address}")
        return self._blocker.rollback(address)

    def expired(self, *, now: datetime | None = None) -> tuple[ActionRecord, ...]:
        current = now or datetime.now(timezone.utc)
        return tuple(record for record in self._records.values() if record.expires_at <= current)