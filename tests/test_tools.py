from ipaddress import ip_address

from globalban.actions.block_ip import IPBlocker
from globalban.agent.tools import empty_registry
from globalban.evaluation.metrics import evaluate_binary
from globalban.policy.gate import PolicyGate
from globalban.policy.guard import PolicyGuard


def test_registry_exposes_twelve_tools_and_gates_actions():
    registry = empty_registry()

    assert len(registry.specs()) == 12
    result = registry.invoke("action_enforcer", {})

    assert result.ok is False
    assert result.error == "explicit approval is required"


def test_binary_metrics_are_reproducible():
    metrics = evaluate_binary(
        [True, True, False, False],
        [True, False, True, False],
    )

    assert metrics.true_positive == 1
    assert metrics.false_positive == 1
    assert metrics.false_negative == 1
    assert metrics.precision == 0.5
    assert metrics.recall == 0.5
    assert metrics.f1 == 0.5


def test_policy_gate_requires_approval_before_dry_run_action():
    gate = PolicyGate(
        policy=PolicyGuard(allowlist=("127.0.0.1",)),
        minimum_risk_score=80,
    )

    decision = gate.evaluate(ip_address("8.8.8.8"), risk_score=90)

    assert decision.status == "approval_required"
    assert not decision.allowed


def test_policy_gate_allows_approved_action_without_executing_it():
    gate = PolicyGate(policy=PolicyGuard(), minimum_risk_score=80)
    blocker = IPBlocker(command_template=("firewall", "block", "{ip}"), dry_run=True)

    decision = gate.evaluate(ip_address("8.8.8.8"), risk_score=90, approved=True)
    result = blocker.block(ip_address("8.8.8.8"))

    assert decision.allowed
    assert result.blocked is False