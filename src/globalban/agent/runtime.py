"""Controlled runtime for executing an allowlisted investigation plan."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from globalban.agent.router import ToolPlan, choose_tools
from globalban.agent.tools import ToolRegistry, ToolResult, empty_registry
from globalban.models.events import WindowsEvent


@dataclass(frozen=True, slots=True)
class AgentRun:
    plan: ToolPlan
    results: tuple[ToolResult, ...]


class AgentRuntime:
    """Plan first, then optionally invoke only registered tools."""

    def __init__(self, registry: ToolRegistry | None = None) -> None:
        self._registry = registry or empty_registry()

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
        if not execute:
            return AgentRun(plan, ())
        supplied = arguments or {}
        results = tuple(
            self._registry.invoke(
                tool,
                supplied.get(tool, {}),
                approved=approved,
            )
            for tool in plan.tools
        )
        return AgentRun(plan, results)
