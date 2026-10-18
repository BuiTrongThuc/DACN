"""Approval and rate gates for defensive actions."""

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from ipaddress import IPv4Address, IPv6Address

from globalban.policy.guard import PolicyGuard

IPAddress = IPv4Address | IPv6Address


@dataclass(frozen=True, slots=True)
class GateDecision:
    status: str
    reasons: tuple[str, ...]

    @property
    def allowed(self) -> bool:
        return self.status == "allow"


class PolicyGate:
    def __init__(
        self,
        *,
        policy: PolicyGuard,
        minimum_risk_score: int = 80,
        max_actions_per_hour: int = 5,
    ) -> None:
        if not 0 <= minimum_risk_score <= 100:
            raise ValueError("minimum_risk_score must be from 0 to 100")
        if max_actions_per_hour <= 0:
            raise ValueError("max_actions_per_hour must be greater than zero")
        self._policy = policy
        self._minimum_risk_score = minimum_risk_score
        self._max_actions = max_actions_per_hour
        self._actions: list[datetime] = []

    def evaluate(
        self,
        address: IPAddress,
        *,
        risk_score: int,
        approved: bool = False,
        now: datetime | None = None,
    ) -> GateDecision:
        current = now or datetime.now(timezone.utc)
        self._actions = [stamp for stamp in self._actions if stamp > current - timedelta(hours=1)]
        reasons: list[str] = []
        if not self._policy.evaluate_address(address).allowed:
            return GateDecision("deny", ("address rejected by local policy",))
        if risk_score < self._minimum_risk_score:
            reasons.append("risk score is below action threshold")
        if len(self._actions) >= self._max_actions:
            reasons.append("hourly action limit reached")
        if not approved:
            reasons.append("explicit human approval is required")
        if reasons:
            return GateDecision("approval_required" if reasons == ["explicit human approval is required"] else "deny", tuple(reasons))
        self._actions.append(current)
        return GateDecision("allow", ())