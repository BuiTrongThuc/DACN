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


def test_proxy_rejects_noncanonical_or_host_cidr():
    with pytest.raises(ValueError):
        validate_api_request(
            _body(
                {
                    "source_network": "8.8.8.8/32",
                    "failed_attempts": 5,
                    "window_seconds": 300,
                    "event_type": "ssh_authentication_failures",
                }
            )
        )


def test_proxy_rejects_unallowlisted_windows_metadata():
    with pytest.raises(ValueError):
        validate_api_request(
            _body(
                {
                    "event_id": 4688,
                    "event_type": "windows_event_4688",
                    "priority": "P0",
                    "provider": "Security",
                    "fields": {"CommandLine": "secret command"},
                }
            )
        )


def test_proxy_accepts_allowlisted_windows_metadata():
    validate_api_request(
        _body(
            {
                "event_id": 4625,
                "event_type": "windows_event_4625",
                "priority": "P0",
                "provider": "Security",
                "fields": {"TargetUserName": "admin"},
            }
        )
    )