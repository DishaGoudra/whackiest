"""Threat intelligence lookup module (WHOIS domain age, IP/ASN enrichment, and VirusTotal v3)."""

from __future__ import annotations

import base64
import os
import socket
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

import requests
import whois

LOCALHOST_HOSTS = {"localhost", "127.0.0.1", "::1", "0.0.0.0"}
VT_TIMEOUT_SECONDS = 8
IP_GEO_TIMEOUT_SECONDS = 3


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


def _lookup_ip_and_asn(domain: str) -> dict[str, Any]:
    """Resolve IP address and fetch lightweight ASN/geolocation metadata for SOC Analyst mode."""
    info: dict[str, Any] = {
        "ip": None,
        "asn": "Unavailable",
        "org": "Unavailable",
        "country": "Unavailable",
    }
    try:
        ip_addr = socket.gethostbyname(domain)
        info["ip"] = ip_addr
    except OSError:
        return info

    try:
        resp = requests.get(
            f"http://ip-api.com/json/{ip_addr}?fields=status,country,isp,org,as",
            timeout=IP_GEO_TIMEOUT_SECONDS,
        )
        if resp.status_code == 200:
            data = resp.json()
            if data.get("status") == "success":
                info["asn"] = data.get("as") or "Unavailable"
                info["org"] = data.get("org") or data.get("isp") or "Unavailable"
                info["country"] = data.get("country") or "Unavailable"
    except requests.RequestException:
        pass
    return info


def _lookup_whois_age(domain: str) -> tuple[int | None, str]:
    try:
        record = whois.whois(domain)
        created_at = _coerce_datetime(getattr(record, "creation_date", None))
        if created_at is None:
            return None, "Domain age unavailable (registration date hidden or missing)"
        age_days = max(0, (datetime.now(timezone.utc) - created_at).days)
        return age_days, f"{age_days} days old (registered {created_at.strftime('%Y-%m-%d')})"
    except Exception as exc:  # noqa: BLE001
        return None, f"Domain age unavailable (WHOIS lookup failed: {exc})"


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


def _query_virustotal(url: str, domain: str) -> dict[str, Any]:
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
            resp = requests.get(endpoint, headers=headers, timeout=VT_TIMEOUT_SECONDS)
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
    except requests.RequestException as exc:
        default_result["note"] = f"VirusTotal lookup failed ({exc})"
        return default_result


def check_threat_intel(url: str) -> dict[str, Any]:
    """Gather WHOIS domain age, IP/ASN info, and VirusTotal reputation for a URL."""
    normalized_url = _normalize_url(url)
    domain = _extract_domain(normalized_url)

    if not domain:
        return {
            "domain": "",
            "is_localhost": False,
            "domain_age_days": None,
            "domain_age_summary": "Could not extract domain from URL",
            "network": {"ip": None, "asn": "Unavailable", "org": "Unavailable", "country": "Unavailable"},
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
            "virustotal": {
                "checked": False,
                "malicious": 0,
                "suspicious": 0,
                "harmless": 0,
                "undetected": 0,
                "note": "VirusTotal check skipped for local demo host",
            },
        }

    domain_age_days, domain_age_summary = _lookup_whois_age(domain)
    network_info = _lookup_ip_and_asn(domain)
    vt_result = _query_virustotal(normalized_url, domain)

    return {
        "domain": domain,
        "is_localhost": False,
        "domain_age_days": domain_age_days,
        "domain_age_summary": domain_age_summary,
        "network": network_info,
        "virustotal": vt_result,
    }
