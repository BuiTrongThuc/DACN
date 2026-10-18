"""Policy-gated action execution; AI cannot bypass this boundary."""

from dataclasses import dataclass
from ipaddress import IPv4Address, IPv6Address

from globalban.actions.block_ip import BlockResult, IPBlocker
from globalban.policy.gate import GateDecision, PolicyGate

IPAddress = IPv4Address | IPv6Address


@dataclass(frozen=True, slots=True)
class EnforcementResult:
    decision: GateDecision
    result: BlockResult | None


class ActionEnforcer:
    def __init__(self, *, blocker: IPBlocker, gate: PolicyGate) -> None:
        self._blocker = blocker
        self._gate = gate

    def block_ip(
        self,
        address: IPAddress,
        *,
        risk_score: int,
        approved: bool = False,
    ) -> EnforcementResult:
        decision = self._gate.evaluate(address, risk_score=risk_score, approved=approved)
        if not decision.allowed:
            return EnforcementResult(decision, None)
        return EnforcementResult(decision, self._blocker.block(address))