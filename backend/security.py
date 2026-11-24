"""Enterprise security guardrails: Anti-SSRF, PII redaction, URL defanging, and hashing."""

from __future__ import annotations

import hashlib
import ipaddress
import re
import socket
from typing import Any
from urllib.parse import urlparse

ALLOWED_SCHEMES = {"http", "https"}
DEMO_HOSTS = {"127.0.0.1", "localhost"}
DEMO_PATH_PREFIXES = ("/mock-",)

# PII patterns (India-focused DPDP Act data minimization)
_AADHAAR_PATTERN = re.compile(r"\b\d{4}[\s-]?\d{4}[\s-]?\d{4}\b")
_PHONE_PATTERN = re.compile(r"(?:\+91[\s-]?)?\b[6-9]\d{9}\b")
_CARD_OR_ACCOUNT_PATTERN = re.compile(r"\b\d{13,16}\b")


def is_safe_local_demo_url(url: str) -> bool:
    """Allow only our built-in local /mock-* routes on port 8000."""
    parsed = urlparse(url.strip())
    host = (parsed.hostname or "").lower()
    port = parsed.port
    path = parsed.path or ""
    return (
        parsed.scheme in ALLOWED_SCHEMES
        and host in DEMO_HOSTS
        and port in (8000, None)
        and any(path.startswith(prefix) for prefix in DEMO_PATH_PREFIXES)
    )


def _is_blocked_ip(ip_str: str) -> bool:
    """Return True for private, loopback, link-local, multicast, or reserved IPs."""
    try:
        ip_obj = ipaddress.ip_address(ip_str)
    except ValueError:
        return True
    return (
        ip_obj.is_private
        or ip_obj.is_loopback
        or ip_obj.is_link_local
        or ip_obj.is_multicast
        or ip_obj.is_reserved
        or ip_obj.is_unspecified
    )


def validate_url_ssrf(url: str) -> dict[str, Any]:
    """Validate URL scheme and resolved IP against SSRF attacks.

    Blocks non-HTTP(S) schemes (file://, gopher://, javascript:, data:, ftp://)
    and RFC-1918 / loopback / cloud metadata IPs (169.254.169.254), while
    cleanly exempting local /mock-* demo routes.
    """
    cleaned = url.strip()
    parsed = urlparse(cleaned)

    scheme = (parsed.scheme or "").lower()
    if scheme not in ALLOWED_SCHEMES:
        return {
            "allowed": False,
            "is_demo_route": False,
            "resolved_ip": None,
            "reason": f"Blocked unsafe URI scheme '{scheme or 'unknown'}://'. Only http:// and https:// are permitted.",
        }

    hostname = (parsed.hostname or "").lower()
    if not hostname:
        return {
            "allowed": False,
            "is_demo_route": False,
            "resolved_ip": None,
            "reason": "Blocked malformed URL with missing hostname.",
        }

    if is_safe_local_demo_url(cleaned):
        return {
            "allowed": True,
            "is_demo_route": True,
            "resolved_ip": "127.0.0.1",
            "reason": "Allowed local sandbox demo route.",
        }

    # Direct IP literal check
    try:
        ipaddress.ip_address(hostname)
        if _is_blocked_ip(hostname):
            return {
                "allowed": False,
                "is_demo_route": False,
                "resolved_ip": hostname,
                "reason": f"SSRF Guard blocked private/internal IP target ({hostname}).",
            }
        return {
            "allowed": True,
            "is_demo_route": False,
            "resolved_ip": hostname,
            "reason": "Public IP validated.",
        }
    except ValueError:
        pass

    # Resolve DNS and verify every returned IP is public
    try:
        addr_info = socket.getaddrinfo(hostname, parsed.port or (443 if scheme == "https" else 80))
        resolved_ips = sorted({entry[4][0] for entry in addr_info if entry and entry[4]})
    except socket.gaierror:
        # Unresolvable domain: let Playwright report clean network error rather than SSRF block
        return {
            "allowed": True,
            "is_demo_route": False,
            "resolved_ip": None,
            "reason": "DNS could not be resolved; proceeding to sandbox for clean error reporting.",
        }

    for ip_str in resolved_ips:
        if _is_blocked_ip(ip_str):
            return {
                "allowed": False,
                "is_demo_route": False,
                "resolved_ip": ip_str,
                "reason": f"SSRF Guard blocked internal/private network address ({ip_str}) resolved for {hostname}.",
            }

    return {
        "allowed": True,
        "is_demo_route": False,
        "resolved_ip": resolved_ips[0] if resolved_ips else None,
        "reason": "Public host validated.",
    }


def redact_pii(text: str) -> tuple[str, dict[str, int]]:
    """Scrub Indian phone numbers, Aadhaar numbers, and bank/card numbers."""
    counts = {"phone": 0, "aadhaar": 0, "account": 0}

    def _sub_account(match: re.Match[str]) -> str:
        counts["account"] += 1
        return "[REDACTED_ACCOUNT]"

    def _sub_aadhaar(match: re.Match[str]) -> str:
        counts["aadhaar"] += 1
        return "[REDACTED_AADHAAR]"

    def _sub_phone(match: re.Match[str]) -> str:
        counts["phone"] += 1
        return "[REDACTED_PHONE]"

    # Order matters: longer sequences first so 12-16 digit numbers aren't partially matched as 10-digit phones
    scrubbed = _CARD_OR_ACCOUNT_PATTERN.sub(_sub_account, text)
    scrubbed = _AADHAAR_PATTERN.sub(_sub_aadhaar, scrubbed)
    scrubbed = _PHONE_PATTERN.sub(_sub_phone, scrubbed)
    return scrubbed, counts


def defang_url(url: str) -> str:
    """Defang URLs (http -> hxxp, . -> [.]) so reports are never accidentally clickable."""
    if not url:
        return ""
    defanged = re.sub(r"^https://", "hxxps[://]", url.strip(), flags=re.IGNORECASE)
    defanged = re.sub(r"^http://", "hxxp[://]", defanged, flags=re.IGNORECASE)
    return defanged.replace(".", "[.]")


def compute_sha256(data: bytes | None) -> str | None:
    """Compute SHA-256 forensic hash for captured screenshots or payloads."""
    if not data:
        return None
    return hashlib.sha256(data).hexdigest()
