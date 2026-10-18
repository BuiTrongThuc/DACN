from datetime import datetime, timezone
from ipaddress import ip_address

from globalban.ingestion.parser import (
    parse_auth_line,
    parse_windows_event,
    parse_windows_security_event,
)


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


def test_parse_windows_security_event_4625():
        event = parse_windows_event(
                """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
                    <System><EventID>4625</EventID><TimeCreated SystemTime="2025-01-01T10:00:00Z" /></System>
                    <EventData><Data Name="TargetUserName">admin</Data><Data Name="IpAddress">8.8.8.8</Data></EventData>
                </Event>"""
        )

        assert event is not None
        assert event.source_ip == ip_address("8.8.8.8")
        assert event.username == "admin"
        assert event.event_type == "failed"


def test_parse_windows_event_keeps_host_and_process_fields():
        event = parse_windows_security_event(
                """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
                    <System><Provider Name="Microsoft-Windows-Security-Auditing" Computer="WS-01" />
                        <EventID>4688</EventID><TimeCreated SystemTime="2025-01-01T10:00:00Z" /></System>
                    <EventData><Data Name="SubjectUserName">alice</Data>
                        <Data Name="ProcessId">1234</Data><Data Name="ParentProcessId">1000</Data>
                        <Data Name="NewProcessName">C:\\Windows\\System32\\cmd.exe</Data></EventData>
                </Event>"""
        )

        assert event is not None
        assert event.host == "WS-01"
        assert event.process_id == "1234"
        assert event.parent_process_id == "1000"
        assert event.executable.endswith("cmd.exe")
