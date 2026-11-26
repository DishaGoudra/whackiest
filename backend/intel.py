"""Threat intelligence lookup module (WHOIS, HTTPS IP/ASN, TLS inspection, URL heuristics, VirusTotal v3)."""

from __future__ import annotations

import asyncio
import base64
import logging
import os
import socket
import ssl
import time
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

import httpx

try:
    import whois
except ImportError:  # pragma: no cover
    whois = None  # type: ignore[assignment]

from backend.security import analyze_url_heuristics

logger = logging.getLogger("scam_soc.intel")

LOCALHOST_HOSTS = {"localhost", "127.0.0.1", "::1", "0.0.0.0"}
VT_TIMEOUT_SECONDS = 8.0
IP_GEO_TIMEOUT_SECONDS = 3.0
TLS_TIMEOUT_SECONDS = 3.0
INTEL_CACHE_TTL_SECONDS = 600.0

_INTEL_CACHE: dict[str, tuple[float, dict[str, Any]]] = {}


def _normalize_url(url: str) -> str:
    cleaned = url.strip()
    parsed = urlparse(cleaned)
    if not parsed.scheme:
        return f"https://{cleaned}"
    return cleaned


def _extract_domain(url: str) -> str:
    parsed = urlparse(_normalize_url(url))
    return (parsed.hostname or "").lower().strip(".")


def _coerce_datetime(value: Any) -> datetime | None:
    if isinstance(value, list):
        candidates = [_coerce_datetime(item) for item in value]
        valid = [dt for dt in candidates if dt is not None]
        return min(valid) if valid else None
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)
    if isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
        except ValueError:
            return None
    return None


def _lookup_whois_age(domain: str) -> tuple[int | None, str]:
    if whois is None:
        return None, "Domain age unavailable (python-whois not installed)"
    try:
        record = whois.whois(domain)
        created_at = _coerce_datetime(getattr(record, "creation_date", None))
        if created_at is None:
            return None, "Domain age unavailable (registration date hidden or missing)"
        age_days = max(0, (datetime.now(timezone.utc) - created_at).days)
        return age_days, f"{age_days} days old (registered {created_at.strftime('%Y-%m-%d')})"
    except Exception as exc:  # noqa: BLE001
        return None, f"Domain age unavailable (WHOIS lookup failed: {exc})"


def _inspect_tls_cert(url: str, domain: str) -> dict[str, Any]:
    """Inspect TLS certificate validity, issuer, and age for HTTPS targets."""
    parsed = urlparse(url)
    if parsed.scheme.lower() != "https":
        return {
            "checked": False,
            "valid": False,
            "issuer": None,
            "cert_age_days": None,
            "note": "Unencrypted HTTP (no TLS certificate)",
        }

    port = parsed.port or 443
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((domain, port), timeout=TLS_TIMEOUT_SECONDS) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert() or {}
        issuer_tuples = cert.get("issuer", ())
        issuer_dict = {k: v for part in issuer_tuples for k, v in part}
        issuer = issuer_dict.get("organizationName") or issuer_dict.get("commonName") or "Unknown CA"

        not_before_raw = cert.get("notBefore")
        cert_age_days: int | None = None
        if not_before_raw:
            try:
                nb_dt = datetime.strptime(not_before_raw, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                cert_age_days = max(0, (datetime.now(timezone.utc) - nb_dt).days)
            except ValueError:
                pass

        return {
            "checked": True,
            "valid": True,
            "issuer": issuer,
            "cert_age_days": cert_age_days,
            "note": f"Valid TLS ({issuer})" + (f" · {cert_age_days}d old" if cert_age_days is not None else ""),
        }
    except ssl.SSLCertVerificationError as exc:
        return {
            "checked": True,
            "valid": False,
            "issuer": None,
            "cert_age_days": None,
            "note": f"Untrusted/Invalid TLS certificate: {exc.reason}",
        }
    except Exception as exc:  # noqa: BLE001
        return {
            "checked": True,
            "valid": False,
            "issuer": None,
            "cert_age_days": None,
            "note": f"TLS handshake failed ({type(exc).__name__})",
        }


async def _lookup_ip_and_asn_async(domain: str, client: httpx.AsyncClient) -> dict[str, Any]:
    """Resolve IP address and fetch HTTPS ASN/geolocation metadata for SOC Analyst mode."""
    info: dict[str, Any] = {
        "ip": None,
        "asn": "Unavailable",
        "org": "Unavailable",
        "country": "Unavailable",
    }
    try:
        ip_addr = await asyncio.to_thread(socket.gethostbyname, domain)
        info["ip"] = ip_addr
    except OSError:
        return info

    try:
        resp = await client.get(
            f"https://ipwho.is/{ip_addr}",
            timeout=IP_GEO_TIMEOUT_SECONDS,
        )
        if resp.status_code == 200:
            data = resp.json()
            if data.get("success"):
                conn = data.get("connection") or {}
                asn_val = conn.get("asn")
                info["asn"] = f"AS{asn_val}" if asn_val else "Unavailable"
                info["org"] = conn.get("org") or conn.get("isp") or "Unavailable"
                info["country"] = data.get("country") or "Unavailable"
    except httpx.HTTPError as exc:
        logger.debug("HTTPS IP geolocation failed for %s: %s", ip_addr, exc)
    return info


def _vt_url_id(url: str) -> str:
    return base64.urlsafe_b64encode(url.encode("utf-8")).decode("ascii").rstrip("=")


def _parse_vt_stats(payload: dict[str, Any], source_label: str) -> dict[str, Any]:
    stats = (
        payload.get("data", {})
        .get("attributes", {})
        .get("last_analysis_stats", {})
    )
    malicious = int(stats.get("malicious", 0) or 0)
    suspicious = int(stats.get("suspicious", 0) or 0)
    harmless = int(stats.get("harmless", 0) or 0)
    undetected = int(stats.get("undetected", 0) or 0)
    return {
        "checked": True,
        "malicious": malicious,
        "suspicious": suspicious,
        "harmless": harmless,
        "undetected": undetected,
        "note": f"VirusTotal ({source_label}): {malicious} malicious, {suspicious} suspicious",
    }


async def _query_virustotal_async(url: str, domain: str, client: httpx.AsyncClient) -> dict[str, Any]:
    default_result: dict[str, Any] = {
        "checked": False,
        "malicious": 0,
        "suspicious": 0,
        "harmless": 0,
        "undetected": 0,
        "note": "",
    }

    api_key = os.getenv("VIRUSTOTAL_API_KEY", "").strip()
    if not api_key:
        default_result["note"] = "VirusTotal check skipped (VIRUSTOTAL_API_KEY not set)"
        return default_result

    headers = {"x-apikey": api_key, "Accept": "application/json"}
    endpoints = (
        ("URL", f"https://www.virustotal.com/api/v3/urls/{_vt_url_id(url)}"),
        ("domain", f"https://www.virustotal.com/api/v3/domains/{domain}"),
    )

    try:
        for label, endpoint in endpoints:
            resp = await client.get(endpoint, headers=headers, timeout=VT_TIMEOUT_SECONDS)
            if resp.status_code == 200:
                return _parse_vt_stats(resp.json(), label)
            if resp.status_code == 429:
                default_result["note"] = "VirusTotal rate limit reached; using local & sandbox signals"
                return default_result
            if resp.status_code in (401, 403):
                default_result["note"] = "VirusTotal API key rejected or unauthorized"
                return default_result
            if resp.status_code == 404:
                continue
            default_result["note"] = f"VirusTotal unavailable (HTTP {resp.status_code})"
            return default_result

        default_result["note"] = "VirusTotal has no prior scan record for this URL or domain"
        return default_result
    except httpx.HTTPError as exc:
        default_result["note"] = f"VirusTotal lookup failed ({type(exc).__name__})"
        return default_result


async def check_threat_intel_async(url: str) -> dict[str, Any]:
    """Gather WHOIS domain age, HTTPS IP/ASN, TLS cert, URL heuristics, and VirusTotal reputation."""
    normalized_url = _normalize_url(url)
    domain = _extract_domain(normalized_url)
    url_heuristics = analyze_url_heuristics(normalized_url)

    if not domain:
        return {
            "domain": "",
            "is_localhost": False,
            "domain_age_days": None,
            "domain_age_summary": "Could not extract domain from URL",
            "network": {"ip": None, "asn": "Unavailable", "org": "Unavailable", "country": "Unavailable"},
            "tls": {"checked": False, "valid": False, "issuer": None, "cert_age_days": None, "note": "Invalid domain"},
            "url_heuristics": url_heuristics,
            "virustotal": {
                "checked": False,
                "malicious": 0,
                "suspicious": 0,
                "harmless": 0,
                "undetected": 0,
                "note": "VirusTotal check skipped (invalid domain)",
            },
        }

    if domain in LOCALHOST_HOSTS or domain.endswith(".localhost"):
        return {
            "domain": domain,
            "is_localhost": True,
            "domain_age_days": 0,
            "domain_age_summary": "Demo Localhost (0 days - newly created)",
            "network": {
                "ip": "127.0.0.1",
                "asn": "LOCAL-SANDBOX-DEMO",
                "org": "Local Phishing Simulation Host",
                "country": "India (Local Demo)",
            },
            "tls": {
                "checked": False,
                "valid": False,
                "issuer": None,
                "cert_age_days": None,
                "note": "Local demo HTTP route",
            },
            "url_heuristics": url_heuristics,
            "virustotal": {
                "checked": False,
                "malicious": 0,
                "suspicious": 0,
                "harmless": 0,
                "undetected": 0,
                "note": "VirusTotal check skipped for local demo host",
            },
        }

    now = time.monotonic()
    cached = _INTEL_CACHE.get(normalized_url)
    if cached and cached[0] > now:
        return cached[1]

    async with httpx.AsyncClient() as client:
        whois_task = asyncio.to_thread(_lookup_whois_age, domain)
        tls_task = asyncio.to_thread(_inspect_tls_cert, normalized_url, domain)
        net_task = _lookup_ip_and_asn_async(domain, client)
        vt_task = _query_virustotal_async(normalized_url, domain, client)
        (domain_age_days, domain_age_summary), tls_info, network_info, vt_result = await asyncio.gather(
            whois_task, tls_task, net_task, vt_task
        )

    result = {
        "domain": domain,
        "is_localhost": False,
        "domain_age_days": domain_age_days,
        "domain_age_summary": domain_age_summary,
        "network": network_info,
        "tls": tls_info,
        "url_heuristics": url_heuristics,
        "virustotal": vt_result,
    }
    _INTEL_CACHE[normalized_url] = (now + INTEL_CACHE_TTL_SECONDS, result)
    return result


def check_threat_intel(url: str) -> dict[str, Any]:
    """Synchronous wrapper for check_threat_intel_async."""
    return asyncio.run(check_threat_intel_async(url))
