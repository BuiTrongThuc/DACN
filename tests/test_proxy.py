import json

import pytest

from globalban.proxy import validate_api_request


def _body(user_payload: dict[str, object]) -> bytes:
    return json.dumps(
        {
            "model": "gpt-4o-mini",
            "temperature": 0,
            "messages": [
                {"role": "system", "content": "return JSON"},
                {"role": "user", "content": json.dumps(user_payload)},
            ],
            "response_format": {"type": "json_object"},
        }
    ).encode()


def test_proxy_accepts_only_masked_allowlisted_payload():
    validate_api_request(
        _body(
            {
                "source_network": "192.0.2.0/24",
                "failed_attempts": 5,
                "window_seconds": 300,
                "event_type": "ssh_authentication_failures",
            }
        )
    )


def test_proxy_rejects_raw_ip_and_extra_data():
    with pytest.raises(ValueError):
        validate_api_request(
            _body(
                {
                    "source_network": "192.0.2.42",
                    "failed_attempts": 5,
                    "window_seconds": 300,
                    "event_type": "ssh_authentication_failures",
                    "password": "secret",
                }
            )
        )