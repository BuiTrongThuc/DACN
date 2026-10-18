from ipaddress import ip_address
from subprocess import CompletedProcess

import pytest

from globalban.actions.block_ip import IPBlocker


def test_dry_run_does_not_execute_firewall_command(monkeypatch):
    def fail_if_called(*args, **kwargs):
        raise AssertionError("subprocess must not run in dry-run mode")

    monkeypatch.setattr("globalban.actions.block_ip.subprocess.run", fail_if_called)
    blocker = IPBlocker(command_template=("firewall", "block", "{ip}"), dry_run=True)

    result = blocker.block(ip_address("8.8.8.8"))

    assert result.blocked is False
    assert result.command == ("firewall", "block", "8.8.8.8")


def test_live_mode_executes_argument_list_without_a_shell(monkeypatch):
    observed = {}

    def fake_run(command, **kwargs):
        observed["command"] = command
        observed.update(kwargs)
        return CompletedProcess(command, 0, stdout="ok", stderr="")

    monkeypatch.setattr("globalban.actions.block_ip.subprocess.run", fake_run)
    blocker = IPBlocker(command_template=("firewall", "block", "{ip}"), dry_run=False)

    result = blocker.block(ip_address("8.8.8.8"))

    assert result.blocked is True
    assert observed["command"] == ["firewall", "block", "8.8.8.8"]
    assert observed["check"] is True
    assert "shell" not in observed


def test_firewall_errors_are_not_hidden(monkeypatch):
    def fail(*args, **kwargs):
        raise OSError("firewall unavailable")

    monkeypatch.setattr("globalban.actions.block_ip.subprocess.run", fail)
    blocker = IPBlocker(command_template=("firewall", "{ip}"), dry_run=False)

    with pytest.raises(OSError, match="firewall unavailable"):
        blocker.block(ip_address("8.8.8.8"))
