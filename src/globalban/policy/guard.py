"""Safety checks that must pass before a firewall action is considered."""

from ipaddress import IPv4Address, IPv6Address, ip_address, ip_network

from globalban.models.decisions import BanCandidate, PolicyDecision


class PolicyGuard:
    def __init__(
        self,
        *,
        allowlist: tuple[str, ...] | list[str] = ("127.0.0.1", "::1"),
        block_private_addresses: bool = True,
    ) -> None:
        self._allowlist_addresses = set()
        self._allowlist_networks = set()
        for entry in allowlist:
            try:
                if "/" in entry:
                    self._allowlist_networks.add(ip_network(entry, strict=False))
                else:
                    self._allowlist_addresses.add(ip_address(entry))
            except ValueError as exc:
                raise ValueError(f"Invalid policy allowlist entry: {entry}") from exc
        self._block_private_addresses = block_private_addresses

    def evaluate(self, candidate: BanCandidate) -> PolicyDecision:
        return self.evaluate_address(candidate.source_ip)

    def evaluate_address(self, address: IPv4Address | IPv6Address) -> PolicyDecision:
        if address in self._allowlist_addresses or any(
            address.version == network.version and address in network
            for network in self._allowlist_networks
        ):
            return PolicyDecision(False, "source address is allowlisted")
        if address.is_loopback:
            return PolicyDecision(False, "loopback addresses are never blocked")
        if self._block_private_addresses and (
            address.is_private or address.is_link_local or address.is_reserved
        ):
            return PolicyDecision(False, "non-public source addresses are not blocked")
        return PolicyDecision(True, "candidate passed policy checks")
