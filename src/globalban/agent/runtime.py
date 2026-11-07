"""Controlled runtime for executing an allowlisted investigation plan."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from globalban.agent.router import ToolPlan, choose_tools
from globalban.agent.tools import ToolRegistry, ToolResult, empty_registry
from globalban.audit.logger import AuditLogger
from globalban.models.events import WindowsEvent


@dataclass(frozen=True, slots=True)
class AgentRun:
    plan: ToolPlan
    results: tuple[ToolResult, ...]


class AgentRuntime:
    """Plan first, then optionally invoke only registered tools."""

    def __init__(
        self,
        registry: ToolRegistry | None = None,
        audit_logger: AuditLogger | None = None,
    ) -> None:
        self._registry = registry or empty_registry()
        self._audit_logger = audit_logger

    def run(
        self,
        events: tuple[WindowsEvent, ...],
        *,
        risk_score: int = 0,
        approved: bool = False,
        execute: bool = False,
        arguments: Mapping[str, Mapping[str, Any]] | None = None,
    ) -> AgentRun:
        plan = choose_tools(events, risk_score=risk_score)
        self._record(
            "agent.plan",
            tools=plan.tools,
            risk_score=risk_score,
            execute=execute,
        )
        if not execute:
            return AgentRun(plan, ())
        supplied = arguments or {}
        results = tuple(self._invoke(tool, supplied.get(tool, {}), approved) for tool in plan.tools)
        return AgentRun(plan, results)

    def run_function_calls(
        self,
        calls: tuple[Mapping[str, Any], ...],
        *,
        approved: bool = False,
    ) -> tuple[ToolResult, ...]:
        """Execute model-proposed calls only when their names are allowlisted."""
        results: list[ToolResult] = []
        for call in calls:
            name = call.get("name")
            arguments = call.get("arguments", {})
            if not isinstance(name, str) or not isinstance(arguments, Mapping):
                result = ToolResult(str(name), False, None, "invalid tool call")
            else:
                result = self._invoke(name, arguments, approved)
            results.append(result)
        return tuple(results)

    def _invoke(
        self,
        name: str,
        arguments: Mapping[str, Any],
        approved: bool,
    ) -> ToolResult:
        result = self._registry.invoke(name, arguments, approved=approved)
        self._record(
            "agent.tool_call",
            tool=name,
            approved=approved,
            ok=result.ok,
            error=result.error,
        )
        return result

    def _record(self, event: str, **details: Any) -> None:
        if self._audit_logger is not None:
            self._audit_logger.record(event, **details)
