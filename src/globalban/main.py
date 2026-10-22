"""Command-line entry point for the GlobalBan log monitor."""

import argparse
import logging
from pathlib import Path

from globalban.ai.client import AIClient
from globalban.agent.router import choose_tools
from globalban.actions.block_ip import IPBlocker
from globalban.audit.logger import AuditLogger
from globalban.config import AppConfig, load_config
from globalban.detection.aggregator import FailedAttemptAggregator
from globalban.detection.baseline import BehaviorBaseline
from globalban.detection.behavior import WindowsBehaviorDetector
from globalban.detection.sequence import SequenceCorrelator
from globalban.ingestion.parser import (
    parse_auth_line,
    parse_windows_event,
    parse_windows_security_event,
)
from globalban.ingestion.windows_source import follow_windows_events
from globalban.models.events import WindowsEvent
from globalban.ingestion.tailer import follow_file
from globalban.notifications.whatsapp import WhatsAppNotifier
from globalban.policy.guard import PolicyGuard
from globalban.privacy.masking import mask_ip

logger = logging.getLogger("globalban")
_HIGH_SIGNAL_EVENT_IDS = frozenset({1102, 4104, 4698, 4702, 4719, 4720, 4724, 4728, 4732, 4740, 7045, 1116, 1117})


def _handle_windows_event(
    event: WindowsEvent,
    *,
    correlator: SequenceCorrelator,
    audit: AuditLogger,
    ai_client: AIClient | None,
    blocker: IPBlocker,
    policy: PolicyGuard,
    risk_candidate=None,
) -> None:
    candidate = risk_candidate or correlator.add(event)
    if candidate is None:
        return
    tool_plan = choose_tools((event,), risk_score=candidate.score)
    audit.record(
        "windows_risk_detected",
        event_ids=list(candidate.event_ids),
        score=candidate.score,
        reasons=list(candidate.reasons),
        provider=event.provider,
        selected_tools=list(tool_plan.tools),
        attack_hypotheses=list(tool_plan.attack_hypotheses),
        mitre_attack=list(tool_plan.mitre_attack),
        tool_plan_reasons=list(tool_plan.reasons),
        behavioral_indicators=list(tool_plan.behavioral_indicators),
        requires_approval=tool_plan.requires_approval,
    )
    logger.warning(
        "Threat recorded: Windows risk score=%d event_ids=%s reasons=%s",
        candidate.score,
        ",".join(str(event_id) for event_id in candidate.event_ids),
        "; ".join(candidate.reasons),
    )
    if ai_client is None:
        logger.info("AI agent: advisory disabled; threat recorded for audit only")
        audit.record(
            "ai_agent_action",
            action="disabled",
            result="threat recorded for audit only",
            event_ids=list(candidate.event_ids),
        )
    else:
        try:
            explanation = ai_client.explain_risk(candidate)
        except (RuntimeError, ValueError) as exc:
            logger.warning("Windows AI assessment unavailable: %s", exc)
        else:
            logger.warning(
                "Windows behavior score %d assessed as %s: %s",
                candidate.score,
                explanation.severity,
                explanation.summary,
            )
            logger.info(
                "AI agent processed Windows risk: severity=%s confidence=%.2f recommendations=%s",
                explanation.severity,
                explanation.confidence,
                "; ".join(explanation.recommended_actions) or "none",
            )
            audit.record(
                "windows_ai_assessment",
                event_ids=list(candidate.event_ids),
                score=candidate.score,
                reasons=list(candidate.reasons),
                severity=explanation.severity,
                summary=explanation.summary,
                confidence=explanation.confidence,
                evidence=list(explanation.evidence),
                hypotheses=list(explanation.hypotheses),
                mitre_attack=list(explanation.mitre_attack),
                missing_data=list(explanation.missing_data),
                recommended_actions=list(explanation.recommended_actions),
            )
    if candidate.source_ip is not None:
        decision = policy.evaluate_address(candidate.source_ip)
        if decision.allowed and candidate.score >= 100:
            result = blocker.block(candidate.source_ip)
            audit.record(
                "windows_behavior_action",
                source_network=mask_ip(candidate.source_ip),
                score=candidate.score,
                allowed=decision.allowed,
                command=result.command,
                result=result.message,
            )


def _handle_candidate(
    candidate,
    *,
    policy: PolicyGuard,
    blocker: IPBlocker,
    audit: AuditLogger,
    notifier: WhatsAppNotifier | None,
    ai_client: AIClient | None,
) -> None:
    decision = policy.evaluate(candidate)
    if not decision.allowed:
        logger.info("Skipped %s: %s", mask_ip(candidate.source_ip), decision.reason)
        logger.info("Policy handled candidate: rejected before firewall action")
        audit.record(
            "candidate_rejected",
            source_network=mask_ip(candidate.source_ip),
            failed_attempts=candidate.failed_attempts,
            reason=decision.reason,
        )
        return

    result = blocker.block(candidate.source_ip)
    explanation = None
    if ai_client is not None:
        try:
            explanation = ai_client.explain(candidate)
            logger.info("AI assessment (%s): %s", explanation.severity, explanation.summary)
        except (RuntimeError, ValueError) as exc:
            logger.warning("AI assessment unavailable: %s", exc)
    else:
        logger.info("AI agent: advisory disabled; action handled by policy and dry-run enforcer")
    logger.warning(
        "%s %s after %d failed attempts (%s)",
        "Would block" if not result.blocked else "Blocked",
        mask_ip(candidate.source_ip),
        candidate.failed_attempts,
        result.message,
    )
    audit.record(
        "block_dry_run" if not result.blocked else "ip_blocked",
        source_network=mask_ip(candidate.source_ip),
        failed_attempts=candidate.failed_attempts,
        command=result.command,
        message=result.message,
    )
    if explanation is not None:
        audit.record(
            "ai_assessment",
            severity=explanation.severity,
            summary=explanation.summary,
            confidence=explanation.confidence,
            evidence=list(explanation.evidence),
            hypotheses=list(explanation.hypotheses),
            mitre_attack=list(explanation.mitre_attack),
            missing_data=list(explanation.missing_data),
            recommended_actions=list(explanation.recommended_actions),
        )
    if notifier is not None:
        notifier.send(
            f"GlobalBan alert: {mask_ip(candidate.source_ip)} had "
            f"{candidate.failed_attempts} failed SSH attempts. "
            f"Action: {'dry-run' if not result.blocked else 'blocked'}."
        )


def run(
    config: AppConfig,
    *,
    dry_run_override: bool = False,
    live_override: bool = False,
) -> None:
    blocker = IPBlocker(
        command_template=config.actions.firewall_command,
        rollback_command_template=config.actions.rollback_command,
        dry_run=False if live_override else (config.actions.dry_run or dry_run_override),
    )
    policy = PolicyGuard(
        allowlist=config.policy.allowlist,
        block_private_addresses=config.policy.block_private_addresses,
    )
    aggregator = FailedAttemptAggregator(
        window_seconds=config.detection.window_seconds,
        threshold=config.detection.failed_attempt_threshold,
    )
    baseline = BehaviorBaseline(
        path=config.detection.baseline_path,
        warmup_events=config.detection.baseline_warmup_events,
    )
    correlator = SequenceCorrelator(
        window_seconds=config.detection.window_seconds,
        baseline=baseline,
    )
    behavior = WindowsBehaviorDetector(state_path=config.detection.behavior_state_path)
    audit = AuditLogger(config.audit.path)
    notifier = (
        WhatsAppNotifier()
        if config.notifications.whatsapp_enabled
        else None
    )
    ai_client = (
        AIClient(base_url=config.ai.base_url, model=config.ai.model)
        if config.ai.enabled
        else None
    )
    if config.ingestion.source == "windows_event_log":
        logger.info("Polling Windows Event Log channels: %s", config.ingestion.log_names)
        records = follow_windows_events(
            config.ingestion.log_names,
            poll_interval_seconds=config.ingestion.poll_interval_seconds,
        )
    else:
        log_path = Path(config.ingestion.log_path)
        if not log_path.exists():
            raise FileNotFoundError(f"Authentication log does not exist: {log_path}")
        logger.info("Following authentication log: %s", log_path)
        records = follow_file(
            log_path,
            poll_interval_seconds=config.ingestion.poll_interval_seconds,
        )

    for line in records:
        windows_event = parse_windows_security_event(line)
        if windows_event is not None:
            logger.info(
                "Windows event observed: id=%d provider=%s host=%s",
                windows_event.event_id,
                windows_event.provider,
                windows_event.host or "-",
            )
            tool_plan = choose_tools((windows_event,))
            if (
                windows_event.event_id in _HIGH_SIGNAL_EVENT_IDS
                or tool_plan.behavioral_indicators
            ):
                source = mask_ip(windows_event.source_ip) if windows_event.source_ip else "-"
                logger.warning(
                    "Suspicious Windows event: id=%d provider=%s host=%s user=%s source=%s tools=%s hypotheses=%s mitre=%s indicators=%s",
                    windows_event.event_id,
                    windows_event.provider,
                    windows_event.host or "-",
                    windows_event.username or "-",
                    source,
                    ",".join(tool_plan.tools),
                    "; ".join(tool_plan.attack_hypotheses) or "-",
                    ",".join(tool_plan.mitre_attack) or "-",
                    "; ".join(tool_plan.behavioral_indicators),
                )
                audit.record(
                    "tool_plan_selected",
                    event_id=windows_event.event_id,
                    provider=windows_event.provider,
                    selected_tools=list(tool_plan.tools),
                    attack_hypotheses=list(tool_plan.attack_hypotheses),
                    mitre_attack=list(tool_plan.mitre_attack),
                    behavioral_indicators=list(tool_plan.behavioral_indicators),
                    requires_approval=tool_plan.requires_approval,
                )
            if windows_event.event_id != 4625:
                behavior_candidate = behavior.add(windows_event)
                if behavior_candidate is not None:
                    _handle_windows_event(
                        windows_event,
                        correlator=correlator,
                        audit=audit,
                        ai_client=ai_client,
                        blocker=blocker,
                        policy=policy,
                        risk_candidate=behavior_candidate,
                    )
                else:
                    _handle_windows_event(
                        windows_event,
                        correlator=correlator,
                        audit=audit,
                        ai_client=ai_client,
                        blocker=blocker,
                        policy=policy,
                    )
                continue
            event = parse_windows_event(line)
        else:
            event = parse_auth_line(line)
        if event is None:
            continue
        if windows_event is not None:
            behavior_candidate = behavior.add(windows_event)
            if behavior_candidate is not None:
                _handle_windows_event(
                    windows_event,
                    correlator=correlator,
                    audit=audit,
                    ai_client=ai_client,
                    blocker=blocker,
                    policy=policy,
                    risk_candidate=behavior_candidate,
                )
        if windows_event is not None and event.failed:
            source_network = mask_ip(event.source_ip)
            logger.warning(
                "Windows failed logon observed: source=%s user=%s event_id=4625 tools=%s hypotheses=%s mitre=%s",
                source_network,
                event.username,
                ",".join(tool_plan.tools),
                "; ".join(tool_plan.attack_hypotheses) or "-",
                ",".join(tool_plan.mitre_attack) or "-",
            )
            audit.record(
                "windows_failed_logon_observed",
                source_network=source_network,
                username=event.username,
                event_id=4625,
            )
        candidate = aggregator.add(event)
        if candidate is not None:
            _handle_candidate(
                candidate,
                policy=policy,
                blocker=blocker,
                audit=audit,
                notifier=notifier,
                ai_client=ai_client,
            )


def main() -> None:
    parser = argparse.ArgumentParser(description="Monitor SSH authentication logs.")
    parser.add_argument(
        "--config",
        default="config/config.yaml",
        help="Path to YAML config (default: config/config.yaml)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Do not execute firewall commands, regardless of config",
    )
    parser.add_argument(
        "--live",
        action="store_true",
        help="Allow configured firewall actions (requires Administrator)",
    )
    args = parser.parse_args()
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    config = load_config(args.config)
    run(config, dry_run_override=args.dry_run, live_override=args.live)


if __name__ == "__main__":
    main()
