"""Stdlib-only DNS fallback that patches socket.getaddrinfo.

When the system DNS can't resolve external hostnames (common on managed/university
networks), this module retries via DNS-over-HTTPS — connecting directly to
8.8.8.8:443 by IP so no DNS is needed to reach the resolver itself.
Call apply() once at startup; all subsequent socket connections benefit.
"""
from __future__ import annotations

import json
import logging
import socket
import ssl
import urllib.parse
import urllib.request

LOGGER = logging.getLogger(__name__)

_DOH_IP = "8.8.8.8"   # Google public DNS — reachable by IP, no DNS lookup needed
_DOH_TIMEOUT = 5.0

_original_getaddrinfo = socket.getaddrinfo
_patched = False


def _resolve_via_doh(hostname: str) -> str | None:
    """Return an IPv4 address for hostname via Google DNS-over-HTTPS, or None."""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False   # connecting to IP, not hostname
        ctx.verify_mode = ssl.CERT_NONE

        query = urllib.parse.urlencode({"name": hostname, "type": "A"})
        req = urllib.request.Request(
            f"https://{_DOH_IP}/resolve?{query}",
            headers={"Accept": "application/dns-json"},
        )
        with urllib.request.urlopen(req, context=ctx, timeout=_DOH_TIMEOUT) as resp:
            data = json.loads(resp.read())

        for record in data.get("Answer", []):
            if record.get("type") == 1:  # A record
                return record["data"]
        return None
    except Exception:
        return None


def _is_ip(host: str) -> bool:
    try:
        socket.inet_aton(host)
        return True
    except OSError:
        return False


def _patched_getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
    try:
        return _original_getaddrinfo(host, port, family, type, proto, flags)
    except socket.gaierror:
        if isinstance(host, str) and not _is_ip(host):
            ip = _resolve_via_doh(host)
            if ip:
                LOGGER.debug("dns_patch: %s → %s (via DoH/8.8.8.8)", host, ip)
                return _original_getaddrinfo(ip, port, family, type, proto, flags)
        raise


def apply() -> None:
    """Patch socket.getaddrinfo to fall back to Google DoH on system DNS failure."""
    global _patched
    if _patched:
        return
    socket.getaddrinfo = _patched_getaddrinfo
    _patched = True
    LOGGER.info("dns_patch: active — failures will retry via DoH at 8.8.8.8")
