from datetime import datetime, timezone
from ipaddress import ip_address

from globalban.ingestion.parser import parse_auth_line


def test_parse_failed_password_for_invalid_user():
    event = parse_auth_line(
        "Jan  1 10:00:00 host sshd[123]: Failed password for invalid user admin "
        "from 8.8.8.8 port 51234 ssh2",
        now=datetime(2025, 1, 1, tzinfo=timezone.utc),
    )

    assert event is not None
    assert event.source_ip == ip_address("8.8.8.8")
    assert event.username == "admin"
    assert event.event_type == "failed"
    assert event.timestamp == datetime(2025, 1, 1, 10, 0, tzinfo=timezone.utc)


def test_parse_successful_login():
    event = parse_auth_line(
        "Jan  1 10:00:00 host sshd[123]: Accepted publickey for admin "
        "from 2001:4860:4860::8888 port 51234 ssh2",
        now=datetime(2025, 1, 1, tzinfo=timezone.utc),
    )

    assert event is not None
    assert event.source_ip == ip_address("2001:4860:4860::8888")
    assert event.event_type == "success"
    assert not event.failed


def test_ignore_unrelated_and_malformed_log_lines():
    assert parse_auth_line("systemd[10]: Started something") is None
    assert parse_auth_line(
        "Jan  1 10:00:00 host sshd[123]: Failed password for root "
        "from not-an-ip port 22 ssh2"
    ) is None
