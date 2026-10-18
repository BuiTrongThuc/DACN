from datetime import datetime, timezone
from ipaddress import ip_address

from globalban.models.decisions import BanCandidate
from globalban.policy.guard import PolicyGuard


def candidate(address: str) -> BanCandidate:
    now = datetime.now(timezone.utc)
    return BanCandidate(ip_address(address), 5, now, now)


def test_rejects_allowlisted_address_and_network():
    guard = PolicyGuard(allowlist=("8.8.8.8", "2001:4860::/32"))

    assert not guard.evaluate(candidate("8.8.8.8")).allowed
    assert not guard.evaluate(candidate("2001:4860::8888")).allowed


def test_rejects_loopback_and_private_addresses():
    guard = PolicyGuard()

    assert not guard.evaluate(candidate("127.0.0.1")).allowed
    assert not guard.evaluate(candidate("192.168.1.20")).allowed


def test_accepts_public_non_allowlisted_address():
    decision = PolicyGuard().evaluate(candidate("8.8.8.8"))

    assert decision.allowed


def test_invalid_allowlist_is_reported():
    try:
        PolicyGuard(allowlist=("not-an-ip",))
    except ValueError as exc:
        assert "Invalid policy allowlist entry" in str(exc)
    else:
        raise AssertionError("invalid allowlist entry should fail")
