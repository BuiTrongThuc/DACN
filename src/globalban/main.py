"""Command-line entry point for the GlobalBan log monitor."""

import argparse
import logging
from pathlib import Path

from globalban.actions.block_ip import IPBlocker
from globalban.audit.logger import AuditLogger
from globalban.config import AppConfig, load_config
from globalban.detection.aggregator import FailedAttemptAggregator
from globalban.ingestion.parser import parse_auth_line
from globalban.ingestion.tailer import follow_file
from globalban.notifications.whatsapp import WhatsAppNotifier
from globalban.policy.guard import PolicyGuard
from globalban.privacy.masking import mask_ip

logger = logging.getLogger("globalban")


def _handle_candidate(
    candidate,
    *,
    policy: PolicyGuard,
    blocker: IPBlocker,
    audit: AuditLogger,
    notifier: WhatsAppNotifier | None,
) -> None:
    decision = policy.evaluate(candidate)
    if not decision.allowed:
        logger.info("Skipped %s: %s", mask_ip(candidate.source_ip), decision.reason)
        audit.record(
            "candidate_rejected",
            source_network=mask_ip(candidate.source_ip),
            failed_attempts=candidate.failed_attempts,
            reason=decision.reason,
        )
        return

    result = blocker.block(candidate.source_ip)
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
    if notifier is not None:
        notifier.send(
            f"GlobalBan alert: {mask_ip(candidate.source_ip)} had "
            f"{candidate.failed_attempts} failed SSH attempts. "
            f"Action: {'dry-run' if not result.blocked else 'blocked'}."
        )


def run(config: AppConfig, *, dry_run_override: bool = False) -> None:
    blocker = IPBlocker(
        command_template=config.actions.firewall_command,
        dry_run=config.actions.dry_run or dry_run_override,
    )
    policy = PolicyGuard(
        allowlist=config.policy.allowlist,
        block_private_addresses=config.policy.block_private_addresses,
    )
    aggregator = FailedAttemptAggregator(
        window_seconds=config.detection.window_seconds,
        threshold=config.detection.failed_attempt_threshold,
    )
    audit = AuditLogger(config.audit.path)
    notifier = (
        WhatsAppNotifier()
        if config.notifications.whatsapp_enabled
        else None
    )
    log_path = Path(config.ingestion.log_path)
    if not log_path.exists():
        raise FileNotFoundError(f"SSH authentication log does not exist: {log_path}")

    logger.info("Following SSH authentication log: %s", log_path)
    for line in follow_file(
        log_path,
        poll_interval_seconds=config.ingestion.poll_interval_seconds,
    ):
        event = parse_auth_line(line)
        if event is None:
            continue
        candidate = aggregator.add(event)
        if candidate is not None:
            _handle_candidate(
                candidate,
                policy=policy,
                blocker=blocker,
                audit=audit,
                notifier=notifier,
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
    args = parser.parse_args()
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    config = load_config(args.config)
    run(config, dry_run_override=args.dry_run)


if __name__ == "__main__":
    main()
