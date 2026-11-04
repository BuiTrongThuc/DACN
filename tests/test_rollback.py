from datetime import datetime, timedelta, timezone
from ipaddress import ip_address

import pytest

from globalban.actions.block_ip import BlockResult, IPBlocker
from globalban.audit.rollback import ActionRecord, RollbackManager


def test_rollback_rejects_expired_record():
    address = ip_address("8.8.8.8")
    blocker = IPBlocker(command_template=("firewall", "block", "{ip}"), dry_run=True)
    manager = RollbackManager(blocker=blocker)
    manager._records[str(address)] = ActionRecord(
        address=address,
        created_at=datetime.now(timezone.utc) - timedelta(hours=2),
        expires_at=datetime.now(timezone.utc) - timedelta(hours=1),
        block_result=BlockResult(False, (), "test"),
    )

    with pytest.raises(PermissionError, match="rollback TTL expired"):
        manager.rollback(address, approved=True)