"""Egress controller for outbound destination validation.

Validates all outbound destinations against whitelist and deny-list rules,
preventing SSRF attacks, metadata endpoint access, and data exfiltration
to unauthorized servers.
"""

from __future__ import annotations

import socket
from dataclasses import dataclass
from ipaddress import AddressValueError, ip_address, ip_network
from urllib.parse import urlparse


# Link-local network range used by cloud metadata services
_LINK_LOCAL_NETWORK = ip_network("169.254.0.0/16")


@dataclass(frozen=True)
class EgressResult:
    """Result of an egress validation check."""

    allowed: bool
    reason: str


class EgressController:
    """Validates outbound destinations against whitelist and deny-list.

    Evaluation order (Requirement 4.8 - deny before whitelist):
      1. Parse URL → extract hostname
      2. Deny if URL cannot be parsed or hostname cannot be extracted
      3. Check hardcoded deny list (link-local range, metadata endpoints)
      4. Check policy deny_destinations (case-insensitive)
      5. Check DNS resolution for link-local range
      6. Check destination_whitelist (must be configured for ALLOW)
    """

    # Always denied regardless of whitelist configuration
    HARDCODED_DENY: list[str] = [
        "169.254.169.254",
        "metadata.google.internal",
        "169.254.0.0/16",
    ]

    def __init__(self, tool_config: dict) -> None:
        """Initialize with tool configuration from PolicyResult.

        Args:
            tool_config: Dict containing destination_whitelist and deny_destinations.
        """
        self._whitelist: list[str] = tool_config.get("destination_whitelist", [])
        self._deny_list: list[str] = tool_config.get("deny_destinations", [])

    def check(self, destination: str) -> EgressResult:
        """Validate destination against deny-list and whitelist.

        Evaluation order:
          1. Parse URL → extract host
          2. Check hardcoded deny (metadata, link-local range)
          3. Check policy deny_destinations
          4. Check DNS resolution for link-local range
          5. Check destination_whitelist (must be present for ALLOW)

        Args:
            destination: The full URL string to validate.

        Returns:
            EgressResult indicating whether the destination is allowed.
        """
        # Step 1: Parse URL and extract hostname (Requirement 4.7)
        host = self._extract_host(destination)
        if not host:
            return EgressResult(
                allowed=False,
                reason="URL cannot be parsed or hostname cannot be extracted",
            )

        # Step 2: Check hardcoded deny - link-local IP range (Requirement 4.1)
        if self._is_link_local_ip(host):
            return EgressResult(
                allowed=False,
                reason="Destination is a link-local IP address (169.254.0.0/16)",
            )

        # Step 3: Check hardcoded deny - metadata hostname (Requirement 4.2)
        if host.lower() == "metadata.google.internal":
            return EgressResult(
                allowed=False,
                reason="Destination matches hardcoded deny: metadata.google.internal",
            )

        # Step 4: Check policy deny_destinations (Requirement 4.3, case-insensitive)
        for denied in self._deny_list:
            if host.lower() == denied.lower():
                return EgressResult(
                    allowed=False,
                    reason=f"Destination matches deny_destinations: {denied}",
                )

        # Step 5: Check DNS resolution for link-local range (Requirement 4.1)
        if self._dns_resolves_to_link_local(host):
            return EgressResult(
                allowed=False,
                reason="Destination DNS-resolves to link-local range (169.254.0.0/16)",
            )

        # Step 6: Check whitelist (Requirement 4.6 - no whitelist means deny all)
        if not self._whitelist:
            return EgressResult(
                allowed=False,
                reason="No destination_whitelist configured (default deny)",
            )

        # Step 7: Match whitelist via prefix comparison (Requirement 4.4, 4.5)
        for allowed_dest in self._whitelist:
            if self._matches_whitelist(host, allowed_dest):
                return EgressResult(
                    allowed=True,
                    reason=f"Destination matches whitelist: {allowed_dest}",
                )

        # Default deny - hostname not in whitelist (Requirement 4.4)
        return EgressResult(
            allowed=False,
            reason="Destination not in whitelist (default deny)",
        )

    def _extract_host(self, destination: str) -> str | None:
        """Parse URL and extract hostname.

        Args:
            destination: The URL string to parse.

        Returns:
            The hostname string, or None if parsing fails.
        """
        try:
            parsed = urlparse(destination)
            hostname = parsed.hostname
            if hostname:
                return hostname
        except Exception:
            pass
        return None

    def _is_link_local_ip(self, host: str) -> bool:
        """Check if host is a literal IP in the 169.254.0.0/16 range.

        Args:
            host: The hostname or IP address string.

        Returns:
            True if the host is an IP in the link-local range.
        """
        try:
            addr = ip_address(host)
            return addr in _LINK_LOCAL_NETWORK
        except (AddressValueError, ValueError):
            return False

    def _dns_resolves_to_link_local(self, host: str) -> bool:
        """Check if hostname DNS-resolves to an IP in the link-local range.

        Uses socket.getaddrinfo for resolution. Wrapped in try/except since
        DNS resolution may not work in all environments.

        Args:
            host: The hostname to resolve.

        Returns:
            True if any resolved IP is in the link-local range.
        """
        # Skip if already an IP address (already checked in _is_link_local_ip)
        try:
            ip_address(host)
            return False  # Already handled as literal IP
        except (AddressValueError, ValueError):
            pass

        try:
            results = socket.getaddrinfo(host, None)
            for _family, _type, _proto, _canonname, sockaddr in results:
                resolved_ip = sockaddr[0]
                try:
                    addr = ip_address(resolved_ip)
                    if addr in _LINK_LOCAL_NETWORK:
                        return True
                except (AddressValueError, ValueError):
                    continue
        except (socket.gaierror, OSError):
            # DNS resolution failed - not necessarily an error in dev environments
            pass

        return False

    def _matches_whitelist(self, host: str, whitelist_entry: str) -> bool:
        """Check if hostname matches a whitelist entry.

        Whitelist entries may be full URLs ("https://api.example.com"),
        bare hostnames ("api.example.com"), or wildcard patterns
        ("*.example.com" — matches subdomains, not the apex domain).
        In every form, only the hostname component is compared.

        Args:
            host: The parsed hostname from the URL.
            whitelist_entry: An entry from the destination_whitelist.

        Returns:
            True if the hostname matches the whitelist entry.
        """
        host = host.lower()
        entry = whitelist_entry.strip().lower()

        if "://" in entry:
            entry_host = urlparse(entry).hostname
            if not entry_host:
                return False
            entry = entry_host
        else:
            # Bare entry — drop any path component
            entry = entry.split("/", 1)[0]

        if entry.startswith("*."):
            return host.endswith(entry[1:])

        return host == entry
