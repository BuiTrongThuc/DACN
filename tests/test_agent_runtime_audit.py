import json
from datetime import datetime, timezone

from globalban.agent.runtime import AgentRuntime
from globalban.agent.tools import ToolRegistry, ToolSpec
from globalban.audit.logger import AuditLogger
from globalban.models.events import WindowsEvent


def test_runtime_audits_plan_and_allowlisted_function_call(tmp_path):
    audit_path = tmp_path / "audit.jsonl"
    registry = ToolRegistry()
    registry.register(ToolSpec("safe_lookup", "Read-only lookup", False), lambda: "ok")
    runtime = AgentRuntime(registry, AuditLogger(audit_path))
    event = WindowsEvent(
        timestamp=datetime.now(timezone.utc),
        event_id=4688,
        provider="fixture",
        fields={"TargetUserName": "alice"},
    )

    runtime.run((event,), risk_score=10)
    results = runtime.run_function_calls(
        (
            {"name": "safe_lookup", "arguments": {}},
            {"name": "not_registered", "arguments": {}},
            {"name": "bad_call", "arguments": "not-an-object"},
        )
    )

    assert results[0].ok
    assert results[1].error == "tool is not allowlisted"
    assert results[2].error == "invalid tool call"
    records = [json.loads(line) for line in audit_path.read_text(encoding="utf-8").splitlines()]
    assert [record["event"] for record in records] == [
        "agent.plan",
        "agent.tool_call",
        "agent.tool_call",
        "agent.tool_call",
    ]
