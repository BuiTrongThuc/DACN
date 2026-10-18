"""WhatsApp messaging through the Twilio Messages API."""

import base64
import os
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen


class WhatsAppNotifier:
    def __init__(
        self,
        *,
        account_sid: str | None = None,
        auth_token: str | None = None,
        sender: str | None = None,
        recipient: str | None = None,
        timeout_seconds: float = 10.0,
    ) -> None:
        self._account_sid = account_sid or os.getenv("GLOBALBAN_TWILIO_ACCOUNT_SID")
        self._auth_token = auth_token or os.getenv("GLOBALBAN_TWILIO_AUTH_TOKEN")
        self._sender = sender or os.getenv(
            "GLOBALBAN_WHATSAPP_FROM", "whatsapp:+14155238886"
        )
        self._recipient = recipient or os.getenv("GLOBALBAN_WHATSAPP_TO")
        self._timeout_seconds = timeout_seconds
        missing = [
            name
            for name, value in (
                ("GLOBALBAN_TWILIO_ACCOUNT_SID", self._account_sid),
                ("GLOBALBAN_TWILIO_AUTH_TOKEN", self._auth_token),
                ("GLOBALBAN_WHATSAPP_TO", self._recipient),
            )
            if not value
        ]
        if missing:
            raise ValueError(f"Missing WhatsApp configuration: {', '.join(missing)}")
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be greater than zero")

    def send(self, message: str) -> None:
        if not message.strip():
            raise ValueError("WhatsApp message cannot be empty")
        credentials = base64.b64encode(
            f"{self._account_sid}:{self._auth_token}".encode("utf-8")
        ).decode("ascii")
        data = urlencode(
            {"From": self._sender, "To": self._recipient, "Body": message}
        ).encode("utf-8")
        request = Request(
            f"https://api.twilio.com/2010-04-01/Accounts/{self._account_sid}/Messages.json",
            data=data,
            headers={
                "Authorization": f"Basic {credentials}",
                "Content-Type": "application/x-www-form-urlencoded",
            },
            method="POST",
        )
        try:
            with urlopen(request, timeout=self._timeout_seconds) as response:
                if response.status >= 300:
                    raise RuntimeError(f"Twilio returned HTTP {response.status}")
        except HTTPError as exc:
            raise RuntimeError(f"Twilio returned HTTP {exc.code}") from exc
        except URLError as exc:
            raise RuntimeError(f"Could not reach Twilio: {exc.reason}") from exc
