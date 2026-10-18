"""Deterministic tool selection for the AI agent.

The router chooses investigation tools from observed evidence. It does not
execute tools and it never lets model text invent a command or module name.
"""

from dataclasses import dataclass
from typing import Iterable

from globalban.models.events import WindowsEvent


@dataclass(frozen=True, slots=True)
class ToolPlan:
    attack_hypotheses: tuple[str, ...]
    tools: tuple[str, ...]
    mitre_attack: tuple[str, ...]
    requires_approval: bool
    reasons: tuple[str, ...]
    behavioral_indicators: tuple[str, ...]


def choose_tools(
    events: Iterable[WindowsEvent],
    *,
    risk_score: int = 0,
) -> ToolPlan:
    """Select an allowlisted investigation plan from normalized evidence."""
    observed = tuple(events)
    event_ids = {event.event_id for event in observed}
    text = " ".join(
        (event.command_line or "") + " " + (event.executable or "")
        for event in observed
    ).lower()
    tools = ["behavioral_context_builder", "anomaly_detection_engine"]
    hypotheses: list[str] = []
    techniques: list[str] = []
    reasons: list[str] = []
    indicators: list[str] = []

    for event in observed:
        event_text = " ".join(
            value for value in (
                event.command_line,
                event.executable,
                event.fields.get("TaskName"),
                event.fields.get("ServiceName"),
                event.fields.get("TargetFilename"),
            ) if value
        ).lower()
        if any(token in event_text for token in ("-enc", "encodedcommand", "invoke-expression")):
            indicators.append("encoded or obfuscated script execution")
        if any(token in event_text for token in ("downloadstring", "invoke-webrequest", "curl", "bitsadmin")):
            indicators.append("script or utility initiated download")
        if any(token in event_text for token in ("\\temp\\", "\\appdata\\", "\\public\\", "\\downloads\\")):
            indicators.append("execution from user-writable or staging path")
        if any(token in event_text for token in ("schtasks", "scheduled task", "service")):
            indicators.append("persistence artifact observed")
        if any(token in event_text for token in ("lsass", "sam", "ntds.dit", "credential", "password")):
            indicators.append("credential-access indicator observed")
        if any(token in event_text for token in ("wevtutil", "clear-eventlog", "auditpol")):
            indicators.append("audit or log manipulation indicator observed")
    if len(observed) >= 2 and any(event.username for event in observed):
        process_users = {event.username for event in observed if event.executable or event.command_line}
        if len(process_users) == 1:
            indicators.append("same user linked across multiple event types")
    if any(event.parent_process_id and event.process_id for event in observed):
        indicators.append("parent-child process relationship available")

    if event_ids & {4624, 4625, 4648, 4672, 4740}:
        tools.append("security_event_collector")
        hypotheses.append("authentication or account activity")
        reasons.append("authentication-related event observed")
    if event_ids & {1, 4688}:
        tools.append("process_monitor")
        hypotheses.append("process execution")
        reasons.append("process creation event observed")
    if event_ids & {4698, 4702, 7045} or "persistence artifact observed" in indicators:
        tools.extend(("process_monitor", "security_event_collector"))
        hypotheses.append("persistence through task or service")
        techniques.append("T1053.005" if event_ids & {4698, 4702} else "T1543.003")
        reasons.append("persistence-related event observed")
    if event_ids & {1102, 4719} or "audit or log manipulation indicator observed" in indicators:
        tools.append("security_event_collector")
        hypotheses.append("defense evasion through audit manipulation")
        techniques.append("T1070.001" if 1102 in event_ids else "T1562.002")
        reasons.append("audit integrity event observed")
    if event_ids & {4720, 4728, 4732, 4740} or "credential-access indicator observed" in indicators:
        tools.append("security_event_collector")
        hypotheses.append("account or privilege manipulation")
        techniques.append("T1136" if 4720 in event_ids else "T1098")
        reasons.append("account or group change observed")
    if event_ids & {4104} or "encoded or obfuscated script execution" in indicators or any(
        token in text
        for token in ("-enc", "encodedcommand", "invoke-expression", "downloadstring")
    ):
        tools.extend(("process_monitor", "threat_intelligence_lookup"))
        hypotheses.append("suspicious PowerShell or script execution")
        techniques.append("T1059.001")
        reasons.append("script execution indicator observed")
    if event_ids & {3, 5156, 5157} or "script or utility initiated download" in indicators or any(
        token in text for token in ("curl", "invoke-webrequest", "bitsadmin", "nslookup")
    ):
        tools.extend(("behavioral_context_builder", "threat_intelligence_lookup"))
        hypotheses.append("network discovery or transfer")
        techniques.append("T1046" if event_ids & {3, 5156, 5157} else "T1105")
        reasons.append("network activity indicator observed")
    if risk_score >= 80:
        tools.append("ai_decision_engine")
        reasons.append("risk score requires structured AI assessment")
    if risk_score >= 90:
        tools.extend(("policy_gate", "audit_rollback_manager"))
        reasons.append("high risk requires controlled response review")

    deduplicated_tools = tuple(dict.fromkeys(tools))
    return ToolPlan(
        attack_hypotheses=tuple(dict.fromkeys(hypotheses)),
        tools=deduplicated_tools,
        mitre_attack=tuple(dict.fromkeys(techniques)),
        requires_approval=bool({"action_enforcer", "policy_gate"} & set(deduplicated_tools)),
        reasons=tuple(dict.fromkeys(reasons)),
        behavioral_indicators=tuple(dict.fromkeys(indicators)),
    )