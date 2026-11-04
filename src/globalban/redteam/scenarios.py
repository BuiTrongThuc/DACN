"""Synthetic attack scenarios expressed as Windows Event XML lines.

All IPs are RFC 5737 documentation addresses. Nothing here executes anything:
command lines are inert strings inside XML data fields.
"""

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

NS = "http://schemas.microsoft.com/win/2004/08/events/event"
START = datetime(2025, 6, 1, 9, 0, 0, tzinfo=timezone.utc)
ATTACKER = "198.51.100.7"


def make_event(
    event_id: int,
    ts: datetime,
    *,
    provider: str = "Microsoft-Windows-Security-Auditing",
    host: str = "WS-01",
    **data: str,
) -> str:
    body = "".join(f'<Data Name="{k}">{v}</Data>' for k, v in data.items())
    return (
        f'<Event xmlns="{NS}"><System><Provider Name="{provider}"/>'
        f"<EventID>{event_id}</EventID>"
        f'<TimeCreated SystemTime="{ts.strftime("%Y-%m-%dT%H:%M:%SZ")}"/>'
        f"<Computer>{host}</Computer></System>"
        f"<EventData>{body}</EventData></Event>"
    )


def _fail(ts: datetime, user: str, ip: str, substatus: str = "0xc000006a") -> str:
    return make_event(4625, ts, TargetUserName=user, IpAddress=ip, SubStatus=substatus)


def _ok(ts: datetime, user: str, ip: str) -> str:
    return make_event(4624, ts, TargetUserName=user, IpAddress=ip)


def brute_force_fast() -> list[str]:
    return [_fail(START + timedelta(seconds=3 * i), "admin", ATTACKER) for i in range(8)]


def slow_and_low() -> list[str]:
    return [_fail(START + timedelta(minutes=10 * i), "admin", ATTACKER) for i in range(6)]


def password_spray() -> list[str]:
    users = ["admin", "alice", "bob", "carol", "dave", "erin"]
    return [_fail(START + timedelta(seconds=40 * i), u, ATTACKER) for i, u in enumerate(users)]


def user_enumeration() -> list[str]:
    return [
        _fail(START + timedelta(seconds=90 * i), f"ghost{i}", ATTACKER, "0xc0000064")
        for i in range(4)
    ]


def distributed_attack() -> list[str]:
    return [
        _fail(START + timedelta(seconds=20 * i), "admin", f"203.0.113.{10 + i}")
        for i in range(6)
    ]


def compromise_after_failures() -> list[str]:
    events = [_fail(START + timedelta(seconds=30 * i), "alice", ATTACKER) for i in range(5)]
    events.append(_ok(START + timedelta(seconds=200), "alice", ATTACKER))
    return events


def encoded_powershell() -> list[str]:
    return [
        _ok(START, "alice", ATTACKER),
        make_event(
            4688, START + timedelta(seconds=5), SubjectUserName="alice",
            ProcessId="4100", ParentProcessId="1000",
            NewProcessName="C:\\Users\\alice\\AppData\\Local\\Temp\\powershell.exe",
            CommandLine="powershell.exe -enc SIMULATEDBASE64PAYLOAD",
        ),
    ]


def persistence_chain() -> list[str]:
    return [
        _ok(START, "alice", ATTACKER),
        make_event(
            4688, START + timedelta(seconds=5), SubjectUserName="alice",
            ProcessId="4200", ParentProcessId="1000",
            NewProcessName="C:\\Windows\\System32\\cmd.exe",
            CommandLine="cmd.exe /c schtasks /create /tn Updater",
        ),
        make_event(
            4698, START + timedelta(seconds=10),
            provider="Microsoft-Windows-TaskScheduler",
            SubjectUserName="alice", TaskName="\\Updater",
        ),
    ]


def audit_log_cleared() -> list[str]:
    return [make_event(1102, START, SubjectUserName="alice")]


def evasion_slow_below_threshold() -> list[str]:
    """Attacker stays under every threshold: 4 failures spread over 3 hours."""
    return [_fail(START + timedelta(minutes=45 * i), "admin", ATTACKER) for i in range(4)]


def benign_normal_day() -> list[str]:
    """Control: ordinary logins and a plain process. Must NOT alert."""
    return [
        _ok(START, "alice", "192.0.2.10"),
        _fail(START + timedelta(minutes=5), "alice", "192.0.2.10"),
        _ok(START + timedelta(minutes=6), "alice", "192.0.2.10"),
        make_event(
            4688, START + timedelta(minutes=7), SubjectUserName="alice",
            ProcessId="5000", ParentProcessId="1000",
            NewProcessName="C:\\Windows\\explorer.exe", CommandLine="explorer.exe",
        ),
    ]


@dataclass(frozen=True, slots=True)
class Scenario:
    name: str
    technique: str
    expect_detect: bool
    build: Callable[[], list[str]]


SCENARIOS: tuple[Scenario, ...] = (
    Scenario("brute_force_fast", "T1110.001 Password Guessing", True, brute_force_fast),
    Scenario("slow_and_low", "T1110.001 (low rate)", True, slow_and_low),
    Scenario("password_spray", "T1110.003 Password Spraying", True, password_spray),
    Scenario("user_enumeration", "T1087 Account Discovery", True, user_enumeration),
    Scenario("distributed_attack", "T1110 distributed", True, distributed_attack),
    Scenario("compromise_after_failures", "T1078 Valid Accounts", True, compromise_after_failures),
    Scenario("encoded_powershell", "T1059.001 PowerShell", True, encoded_powershell),
    Scenario("persistence_chain", "T1053.005 Scheduled Task", True, persistence_chain),
    Scenario("audit_log_cleared", "T1070.001 Clear Logs", True, audit_log_cleared),
    Scenario("evasion_slow_below_threshold", "Evasion: under thresholds", False,
             evasion_slow_below_threshold),
    Scenario("benign_normal_day", "Control (false-positive check)", False, benign_normal_day),
)
