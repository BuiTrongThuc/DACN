"""Small OpenAI-compatible chat completion client using the Python standard library."""

import json
import os
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from globalban.ai.schemas import AIExplanation, parse_explanation
from globalban.models.decisions import BanCandidate
from globalban.privacy.egress_check import validate_ai_payload
from globalban.privacy.payload_builder import build_ai_payload


class AIClient:
    def __init__(
        self,
        *,
        api_key: str | None = None,
        base_url: str | None = None,
        model: str = "gpt-4o-mini",
        timeout_seconds: float = 15.0,
    ) -> None:
        self._api_key = api_key or os.getenv("GLOBALBAN_AI_API_KEY")
        self._base_url = (
            base_url or os.getenv("GLOBALBAN_AI_BASE_URL") or "https://api.openai.com/v1"
        ).rstrip("/")
        self._model = model or os.getenv("GLOBALBAN_AI_MODEL", "gpt-4o-mini")
        self._timeout_seconds = timeout_seconds
        if not self._api_key:
            raise ValueError("GLOBALBAN_AI_API_KEY is required when AI is enabled")
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be greater than zero")

    def explain(self, candidate: BanCandidate) -> AIExplanation:
        payload = build_ai_payload(candidate)
        validate_ai_payload(payload)
        prompt = Path(__file__).with_name("prompt.txt").read_text(encoding="utf-8")
        body = json.dumps(
            {
                "model": self._model,
                "temperature": 0,
                "messages": [
                    {"role": "system", "content": prompt},
                    {"role": "user", "content": json.dumps(payload)},
                ],
                "response_format": {"type": "json_object"},
            }
        ).encode("utf-8")
        request = Request(
            f"{self._base_url}/chat/completions",
            data=body,
            headers={
                "Authorization": f"Bearer {self._api_key}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        try:
            with urlopen(request, timeout=self._timeout_seconds) as response:
                result = json.loads(response.read().decode("utf-8"))
        except HTTPError as exc:
            raise RuntimeError(f"AI service returned HTTP {exc.code}") from exc
        except URLError as exc:
            raise RuntimeError(f"Could not reach AI service: {exc.reason}") from exc
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise RuntimeError("AI service returned an invalid response") from exc

        try:
            content = result["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError) as exc:
            raise RuntimeError("AI service response is missing completion content") from exc
        if not isinstance(content, str):
            raise RuntimeError("AI service completion content must be text")
        return parse_explanation(content)
