"""Optional, explicit threat-intelligence lookup adapter."""

import json
import os
from dataclasses import dataclass
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen


@dataclass(frozen=True, slots=True)
class ThreatIntelResult:
    indicator: str
    source: str
    malicious: bool | None
    confidence: float
    details: str


class ThreatIntelClient:
    def __init__(
        self,
        *,
        endpoint_template: str | None = None,
        api_key: str | None = None,
        enabled: bool = False,
        timeout_seconds: float = 5.0,
    ) -> None:
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be greater than zero")
        self._endpoint_template = endpoint_template or os.getenv("GLOBALBAN_TI_ENDPOINT")
        self._api_key = api_key or os.getenv("GLOBALBAN_TI_API_KEY")
        self._enabled = enabled
        self._timeout_seconds = timeout_seconds

    def lookup_ip(self, indicator: str) -> ThreatIntelResult:
        if not self._enabled or not self._endpoint_template:
            return ThreatIntelResult(indicator, "disabled", None, 0.0, "lookup disabled")
        endpoint = self._endpoint_template.format(indicator=quote(indicator, safe=""))
        headers = {"Accept": "application/json"}
        if self._api_key:
            headers["Authorization"] = f"Bearer {self._api_key}"
        request = Request(endpoint, headers=headers, method="GET")
        try:
            with urlopen(request, timeout=self._timeout_seconds) as response:
                data = json.loads(response.read(128 * 1024).decode("utf-8"))
        except (HTTPError, URLError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            return ThreatIntelResult(indicator, "error", None, 0.0, str(exc))
        malicious = data.get("malicious") if isinstance(data, dict) else None
        confidence = data.get("confidence", 0.0) if isinstance(data, dict) else 0.0
        if not isinstance(malicious, bool) or not isinstance(confidence, (int, float)):
            return ThreatIntelResult(indicator, "invalid", None, 0.0, "invalid provider response")
        return ThreatIntelResult(indicator, "configured", malicious, float(confidence), "provider result")