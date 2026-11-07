from datetime import datetime, timezone

from globalban.agent.runtime import AgentRuntime
from globalban.models.events import WindowsEvent


def test_runtime_plans_without_executing_by_default():
    event = WindowsEvent(
        timestamp=datetime.now(timezone.utc),
        event_id=4688,
        provider="fixture",
        fields={"TargetUserName": "alice", "NewProcessName": "powershell.exe"},
    )

    run = AgentRuntime().run((event,), risk_score=90)

    assert run.plan.tools
    assert run.results == ()


def test_runtime_keeps_unwired_tools_explicitly_failed():
    event = WindowsEvent(
        timestamp=datetime.now(timezone.utc),
        event_id=1102,
        provider="fixture",
        fields={"TargetUserName": "alice"},
    )

    run = AgentRuntime().run((event,), risk_score=90, execute=True)

    assert run.results
    assert all(not result.ok for result in run.results)
    assert {result.error for result in run.results} <= {
        "tool handler is not wired",
        "explicit approval is required",
    }
