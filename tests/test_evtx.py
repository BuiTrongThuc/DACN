from pathlib import Path

import pytest

from globalban.ingestion import evtx


def test_read_evtx_events_uses_native_powershell_reader(monkeypatch, tmp_path):
    path = tmp_path / "Security.evtx"
    path.write_bytes(b"EVTX")

    xml = "<Event><System><EventID>4688</EventID></System></Event>"
    encoded = evtx.base64.b64encode(xml.encode("utf-8")).decode("ascii")

    class Result:
        returncode = 0
        stdout = encoded + "\n"
        stderr = ""

    def fake_run(command, **kwargs):
        assert command[0] == "powershell.exe"
        assert str(path) in command
        return Result()

    monkeypatch.setattr(evtx.subprocess, "run", fake_run)

    assert evtx.read_evtx_events(path) == [xml]


def test_read_evtx_events_reports_missing_file(tmp_path):
    with pytest.raises(FileNotFoundError):
        evtx.read_evtx_events(tmp_path / "missing.evtx")
