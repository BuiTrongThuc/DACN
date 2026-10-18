from datetime import datetime, timezone

from globalban.agent.router import choose_tools
from globalban.models.events import WindowsEvent


def test_router_selects_tools_for_persistence_and_encoded_powershell():
    events = (
        WindowsEvent(
            datetime(2025, 1, 1, tzinfo=timezone.utc),
            4688,
            "Security",
            {
                "SubjectUserName": "alice",
                "ProcessId": "10",
                "CommandLine": "powershell.exe -EncodedCommand abc",
            },
            host="WS-01",
        ),
        WindowsEvent(
            datetime(2025, 1, 1, 0, 0, 1, tzinfo=timezone.utc),
            4698,
            "TaskScheduler",
            {"SubjectUserName": "alice", "TaskName": "\\Update"},
            host="WS-01",
        ),
    )

    plan = choose_tools(events, risk_score=92)

    assert "process_monitor" in plan.tools
    assert "threat_intelligence_lookup" in plan.tools
    assert "policy_gate" in plan.tools
    assert "T1053.005" in plan.mitre_attack
    assert plan.requires_approval is True
    assert "encoded or obfuscated script execution" in plan.behavioral_indicators