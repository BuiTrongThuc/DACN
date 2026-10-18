"""Helpers for masking IP addresses in logs and external payloads."""

from ipaddress import IPv4Address, IPv6Address, ip_address, ip_network


def mask_ip(value: str | IPv4Address | IPv6Address) -> str:
    address = ip_address(value)
    prefix = 24 if address.version == 4 else 64
    return str(ip_network(f"{address}/{prefix}", strict=False).network_address) + (
        f"/{prefix}"
    )
