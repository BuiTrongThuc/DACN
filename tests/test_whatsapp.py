import base64
from urllib.parse import parse_qs

import pytest

from globalban.notifications.whatsapp import WhatsAppNotifier


class FakeResponse:
    status = 201

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        return False


def test_sends_whatsapp_message_with_twilio_auth(monkeypatch):
    observed = {}

    def fake_urlopen(request, timeout):
        observed["request"] = request
        observed["timeout"] = timeout
        return FakeResponse()

    monkeypatch.setattr("globalban.notifications.whatsapp.urlopen", fake_urlopen)
    notifier = WhatsAppNotifier(
        account_sid="AC123",
        auth_token="secret",
        sender="whatsapp:+10000000000",
        recipient="whatsapp:+20000000000",
    )

    notifier.send("SSH alert")

    request = observed["request"]
    assert request.full_url.endswith("/Accounts/AC123/Messages.json")
    assert request.get_header("Authorization") == (
        "Basic " + base64.b64encode(b"AC123:secret").decode("ascii")
    )
    assert parse_qs(request.data.decode("ascii"))["Body"] == ["SSH alert"]
    assert observed["timeout"] == 10.0


def test_missing_credentials_are_reported():
    with pytest.raises(ValueError, match="GLOBALBAN_TWILIO_ACCOUNT_SID"):
        WhatsAppNotifier(account_sid="", auth_token="", recipient="")


def test_empty_message_is_rejected():
    notifier = WhatsAppNotifier(
        account_sid="AC123",
        auth_token="secret",
        recipient="whatsapp:+20000000000",
    )

    with pytest.raises(ValueError, match="cannot be empty"):
        notifier.send("   ")
