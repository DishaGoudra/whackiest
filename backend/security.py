"""Enterprise security guardrails: Anti-SSRF, URL heuristics, PII redaction, URL defanging, and hashing."""

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

BLOCKED_METADATA_HOSTS = {
    "metadata.google.internal",
    "metadata.goog",
    "169.254.169.254",
    "100.100.100.200",
    "fd00:ec2::254",
}

URL_SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "rb.gy",
    "cutt.ly",
    "is.gd",
    "ow.ly",
    "shorturl.at",
    "s.id",
    "tiny.cc",
}

RISKY_TLDS = {
    ".xyz",
    ".top",
    ".tk",
    ".ml",
    ".ga",
    ".cf",
    ".gq",
    ".click",
    ".icu",
    ".buzz",
    ".work",
    ".support",
    ".cam",
    ".rest",
}

KNOWN_BRAND_KEYWORDS = (
    "bescom",
    "kseb",
    "msedcl",
    "sbi",
    "hdfc",
    "icici",
    "axis",
    "paytm",
    "phonepe",
    "gpay",
    "uidai",
    "aadhaar",
    "trai",
    "indiapost",
    "incometax",
    "npci",
    "bhim",
)

# PII patterns (India-focused DPDP Act data minimization)
_URL_MASK_PATTERN = re.compile(
    r"(?:https?|file|ftp|gopher|javascript|data):[^\s<>\"'\]\)]+|www\.[^\s<>\"'\]\)]+",
    re.IGNORECASE,
)
_CARD_OR_ACCOUNT_PATTERN = re.compile(r"\b\d{13,16}\b")
_AADHAAR_PATTERN = re.compile(r"\b\d{4}[\s-]?\d{4}[\s-]?\d{4}\b")
_PAN_PATTERN = re.compile(r"\b[A-Z]{5}\d{4}[A-Z]\b")
_PHONE_PATTERN = re.compile(r"(?:\+91[\s-]?)?\b[6-9]\d{9}\b")
_BANK_ACCOUNT_SHORT_PATTERN = re.compile(r"\b\d{9,12}\b")
_UPI_ID_PATTERN = re.compile(
    r"\b[a-zA-Z0-9._-]{2,}@(?:okicici|oksbi|okaxis|okhdfcbank|ybl|ibl|axl|paytm|upi|apl|icici|sbi|hdfcbank|axisbank|kotak|bob|pnb|cnrb|unionbank|indus|federal|rbl|yesbank|bandhan|idbi|jupiteraxis|slice|cred|fam|airtel|jio|postbank)\b",
    re.IGNORECASE,
)
_EMAIL_PATTERN = re.compile(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b")


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
    """Return True for private, loopback, link-local, multicast, reserved, or IPv4-mapped internal IPs."""
    try:
        ip_obj = ipaddress.ip_address(ip_str)
    except ValueError:
        return True

    # Check IPv4-mapped IPv6 addresses (e.g. ::ffff:127.0.0.1)
    if isinstance(ip_obj, ipaddress.IPv6Address) and ip_obj.ipv4_mapped is not None:
        if _is_blocked_ip(str(ip_obj.ipv4_mapped)):
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
    """Validate URL scheme, hostname, and resolved IPs against SSRF attacks.

    Blocks non-HTTP(S) schemes (file://, gopher://, javascript:, data:, ftp://),
    cloud metadata hostnames, and RFC-1918 / loopback / link-local IPs (including
    IPv4-mapped IPv6), while cleanly exempting local /mock-* demo routes.
    """
    cleaned = url.strip()
    parsed = urlparse(cleaned)

    scheme = (parsed.scheme or "").lower()
    if scheme not in ALLOWED_SCHEMES:
        return {
            "allowed": False,
            "is_demo_route": False,
            "resolved_ip": None,
            "resolved_ips": [],
            "reason": f"Blocked unsafe URI scheme '{scheme or 'unknown'}://'. Only http:// and https:// are permitted.",
        }

    hostname = (parsed.hostname or "").lower().strip(".")
    if not hostname:
        return {
            "allowed": False,
            "is_demo_route": False,
            "resolved_ip": None,
            "resolved_ips": [],
            "reason": "Blocked malformed URL with missing hostname.",
        }

    if is_safe_local_demo_url(cleaned):
        return {
            "allowed": True,
            "is_demo_route": True,
            "resolved_ip": "127.0.0.1",
            "resolved_ips": ["127.0.0.1"],
            "reason": "Allowed local sandbox demo route.",
        }

    if hostname in BLOCKED_METADATA_HOSTS or hostname.endswith((".internal", ".local", ".localhost")):
        return {
            "allowed": False,
            "is_demo_route": False,
            "resolved_ip": None,
            "resolved_ips": [],
            "reason": f"SSRF Guard blocked internal/metadata hostname ({hostname}).",
        }

    # Direct IP literal check
    try:
        ipaddress.ip_address(hostname)
        if _is_blocked_ip(hostname):
            return {
                "allowed": False,
                "is_demo_route": False,
                "resolved_ip": hostname,
                "resolved_ips": [hostname],
                "reason": f"SSRF Guard blocked private/internal IP target ({hostname}).",
            }
        return {
            "allowed": True,
            "is_demo_route": False,
            "resolved_ip": hostname,
            "resolved_ips": [hostname],
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
            "resolved_ips": [],
            "reason": "DNS could not be resolved; proceeding to sandbox for clean error reporting.",
        }

    for ip_str in resolved_ips:
        if _is_blocked_ip(ip_str):
            return {
                "allowed": False,
                "is_demo_route": False,
                "resolved_ip": ip_str,
                "resolved_ips": resolved_ips,
                "reason": f"SSRF Guard blocked internal/private network address ({ip_str}) resolved for {hostname}.",
            }

    return {
        "allowed": True,
        "is_demo_route": False,
        "resolved_ip": resolved_ips[0] if resolved_ips else None,
        "resolved_ips": resolved_ips,
        "reason": "Public host validated.",
    }


def analyze_url_heuristics(url: str) -> dict[str, Any]:
    """Detect lexical phishing indicators: punycode, @ userinfo, IP literals, shorteners, risky TLDs."""
    parsed = urlparse(url.strip())
    hostname = (parsed.hostname or "").lower().strip(".")
    flags: list[str] = []
    risk_points = 0

    is_demo = is_safe_local_demo_url(url)
    has_userinfo = bool(parsed.username or parsed.password)
    if has_userinfo:
        flags.append("URL contains '@' userinfo obfuscation to disguise the real destination host")
        risk_points += 25

    is_punycode = "xn--" in hostname or any(ord(ch) > 127 for ch in hostname)
    if is_punycode:
        flags.append("Internationalized / Punycode domain (potential homograph spoofing)")
        risk_points += 20

    is_ip_literal = False
    if hostname and not is_demo:
        try:
            ipaddress.ip_address(hostname)
            is_ip_literal = True
            flags.append(f"Uses raw IP address ({hostname}) instead of a registered domain")
            risk_points += 20
        except ValueError:
            pass

    is_shortener = hostname in URL_SHORTENERS
    if is_shortener:
        flags.append(f"Uses URL shortener ({hostname}) that hides the true destination")
        risk_points += 10

    risky_tld = next((tld for tld in RISKY_TLDS if hostname.endswith(tld)), None)
    if risky_tld:
        flags.append(f"Uses high-abuse top-level domain ({risky_tld})")
        risk_points += 15

    labels = [lbl for lbl in hostname.split(".") if lbl and lbl != "www"]
    if len(labels) >= 4 and not is_ip_literal:
        flags.append("Excessive subdomain nesting used to mimic legitimate portals")
        risk_points += 10

    if len(labels) >= 3 and not is_demo:
        subdomain_part = ".".join(labels[:-2])
        if any(brand in subdomain_part for brand in KNOWN_BRAND_KEYWORDS):
            flags.append("Known brand keyword placed in subdomain rather than root domain")
            risk_points += 15

    return {
        "flags": flags,
        "risk_points": min(35, risk_points),
        "is_shortener": is_shortener,
        "is_punycode": is_punycode,
        "has_userinfo": has_userinfo,
        "is_ip_literal": is_ip_literal,
        "risky_tld": risky_tld,
    }


def redact_pii(text: str) -> tuple[str, dict[str, int]]:
    """Scrub Indian phone numbers, Aadhaar, PAN, UPI IDs, emails, and bank/card numbers.

    Preserves URLs intact before scrubbing so numeric IDs inside URLs are not corrupted.
    """
    counts = {"phone": 0, "aadhaar": 0, "pan": 0, "upi": 0, "email": 0, "account": 0}
    masked_urls: list[str] = []

    def _mask_url(match: re.Match[str]) -> str:
        idx = len(masked_urls)
        masked_urls.append(match.group(0))
        return f"__URL_PLACEHOLDER_{idx}__"

    def _sub_account(match: re.Match[str]) -> str:
        counts["account"] += 1
        return "[REDACTED_ACCOUNT]"

    def _sub_aadhaar(match: re.Match[str]) -> str:
        counts["aadhaar"] += 1
        return "[REDACTED_AADHAAR]"

    def _sub_pan(match: re.Match[str]) -> str:
        counts["pan"] += 1
        return "[REDACTED_PAN]"

    def _sub_phone(match: re.Match[str]) -> str:
        counts["phone"] += 1
        return "[REDACTED_PHONE]"

    def _sub_upi(match: re.Match[str]) -> str:
        counts["upi"] += 1
        return "[REDACTED_UPI]"

    def _sub_email(match: re.Match[str]) -> str:
        counts["email"] += 1
        return "[REDACTED_EMAIL]"

    scrubbed = _URL_MASK_PATTERN.sub(_mask_url, text)
    scrubbed = _CARD_OR_ACCOUNT_PATTERN.sub(_sub_account, scrubbed)
    scrubbed = _AADHAAR_PATTERN.sub(_sub_aadhaar, scrubbed)
    scrubbed = _PAN_PATTERN.sub(_sub_pan, scrubbed)
    scrubbed = _UPI_ID_PATTERN.sub(_sub_upi, scrubbed)
    scrubbed = _EMAIL_PATTERN.sub(_sub_email, scrubbed)
    scrubbed = _PHONE_PATTERN.sub(_sub_phone, scrubbed)
    scrubbed = _BANK_ACCOUNT_SHORT_PATTERN.sub(_sub_account, scrubbed)

    for idx, original_url in enumerate(masked_urls):
        scrubbed = scrubbed.replace(f"__URL_PLACEHOLDER_{idx}__", original_url)

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
