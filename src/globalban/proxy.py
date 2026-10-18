"""Allowlisted API egress proxy for the Ubuntu host."""

import json
import os
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from globalban.privacy.egress_check import (
    validate_ai_payload,
    validate_risk_payload,
    validate_windows_payload,
)

MAX_BODY_BYTES = 64 * 1024


@dataclass(frozen=True, slots=True)
class ProxyConfig:
    bind_host: str = "127.0.0.1"
    port: int = 8080
    upstream_base_url: str = "https://api.openai.com/v1"


def validate_api_request(body: bytes) -> None:
    if len(body) > MAX_BODY_BYTES:
        raise ValueError("request body is too large")
    try:
        request = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("request body must be valid JSON") from exc
    if not isinstance(request, dict):
        raise ValueError("request body must be a JSON object")
    if set(request) != {"model", "temperature", "messages", "response_format"}:
        raise ValueError("request contains disallowed fields")
    if not isinstance(request["model"], str) or not request["model"]:
        raise ValueError("model must be a non-empty string")
    if request["temperature"] != 0:
        raise ValueError("temperature must be zero")
    if request["response_format"] != {"type": "json_object"}:
        raise ValueError("response_format must request a JSON object")
    messages = request["messages"]
    if not isinstance(messages, list) or len(messages) != 2:
        raise ValueError("exactly two messages are required")
    if any(
        not isinstance(message, dict)
        or set(message) != {"role", "content"}
        or message["role"] not in {"system", "user"}
        or not isinstance(message["content"], str)
        for message in messages
    ):
        raise ValueError("messages contain disallowed fields")
    if messages[0]["role"] != "system" or messages[1]["role"] != "user":
        raise ValueError("messages must contain system then user content")
    try:
        user_payload = json.loads(messages[1]["content"])
    except json.JSONDecodeError as exc:
        raise ValueError("user content must be JSON") from exc
    if not isinstance(user_payload, dict):
        raise ValueError("user content must be a JSON object")
    if "risk_score" in user_payload:
        validate_risk_payload(user_payload)
    elif "event_id" in user_payload:
        validate_windows_payload(user_payload)
    else:
        validate_ai_payload(user_payload)


class EgressProxyHandler(BaseHTTPRequestHandler):
    server_version = "GlobalBanEgressProxy/1.0"

    def do_POST(self) -> None:
        if self.path != "/v1/chat/completions":
            self.send_error(404, "endpoint is not allowlisted")
            return
        try:
            content_length = int(self.headers.get("Content-Length", "-1"))
            if content_length < 0 or content_length > MAX_BODY_BYTES:
                raise ValueError("invalid or oversized Content-Length")
            body = self.rfile.read(content_length)
            validate_api_request(body)
        except (ValueError, TypeError) as exc:
            self.send_error(400, str(exc))
            return

        config: ProxyConfig = self.server.proxy_config  # type: ignore[attr-defined]
        request = Request(
            f"{config.upstream_base_url.rstrip('/')}/chat/completions",
            data=body,
            headers={
                "Authorization": self.headers.get("Authorization", ""),
                "Content-Type": "application/json",
            },
            method="POST",
        )
        try:
            with urlopen(request, timeout=30) as response:
                response_body = response.read(MAX_BODY_BYTES)
                self.send_response(response.status)
                self.send_header(
                    "Content-Type", response.headers.get("Content-Type", "application/json")
                )
                self.send_header("Content-Length", str(len(response_body)))
                self.end_headers()
                self.wfile.write(response_body)
        except HTTPError as exc:
            self.send_error(exc.code, "upstream API rejected the request")
        except URLError:
            self.send_error(502, "could not reach upstream API")

    def log_message(self, format: str, *args: object) -> None:
        super().log_message(format, *args)


def serve(config: ProxyConfig) -> None:
    server = ThreadingHTTPServer((config.bind_host, config.port), EgressProxyHandler)
    server.proxy_config = config  # type: ignore[attr-defined]
    print(f"GlobalBan egress proxy listening on {config.bind_host}:{config.port}")
    server.serve_forever()


def main() -> None:
    config = ProxyConfig(
        bind_host=os.getenv("GLOBALBAN_PROXY_BIND", "127.0.0.1"),
        port=int(os.getenv("GLOBALBAN_PROXY_PORT", "8080")),
        upstream_base_url=os.getenv(
            "GLOBALBAN_PROXY_UPSTREAM",
            "https://generativelanguage.googleapis.com/v1beta/openai",
        ),
    )
    if not 1 <= config.port <= 65535:
        raise ValueError("GLOBALBAN_PROXY_PORT must be between 1 and 65535")
    serve(config)


if __name__ == "__main__":
    main()