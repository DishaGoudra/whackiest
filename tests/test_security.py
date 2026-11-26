"""Unit tests for SSRF guardrails, URL heuristics, PII scrubbing, and verdict scoring."""

from __future__ import annotations

from backend.security import (
    analyze_url_heuristics,
    defang_url,
    redact_pii,
    validate_url_ssrf,
)
from backend.verdict import build_verdict


def test_ssrf_blocks_dangerous_schemes_and_internal_ips() -> None:
    for bad_url in (
        "file:///etc/passwd",
        "gopher://127.0.0.1:6379/_INFO",
        "javascript:alert(1)",
        "http://169.254.169.254/latest/meta-data/",
        "http://10.0.0.5/internal",
        "http://127.0.0.1:8000/api/analyze",
        "http://[::ffff:127.0.0.1]/secret",
        "http://metadata.google.internal/computeMetadata/v1/",
    ):
        res = validate_url_ssrf(bad_url)
        assert res["allowed"] is False, f"Expected block for {bad_url}"


def test_ssrf_allows_local_mock_demo_routes() -> None:
    for demo_url in (
        "http://127.0.0.1:8000/mock-scam-redirect",
        "http://localhost:8000/mock-apk-trap",
        "http://127.0.0.1:8000/mock-bescom-kyc",
    ):
        res = validate_url_ssrf(demo_url)
        assert res["allowed"] is True
        assert res["is_demo_route"] is True


def test_url_heuristics_detects_phishing_patterns() -> None:
    h1 = analyze_url_heuristics("https://sbi.co.in@evil-kyc.xyz/login")
    assert h1["has_userinfo"] is True
    assert h1["risky_tld"] == ".xyz"
    assert h1["risk_points"] >= 30

    h2 = analyze_url_heuristics("https://xn--pytm-0na.top/verify")
    assert h2["is_punycode"] is True
    assert h2["risky_tld"] == ".top"

    h3 = analyze_url_heuristics("https://bit.ly/3xFakeKyc")
    assert h3["is_shortener"] is True


def test_redact_pii_scrubs_indian_identifiers_and_preserves_urls() -> None:
    raw = (
        "Call 9876543210, Aadhaar 1234 5678 9012, PAN ABCDE1234F, "
        "UPI user@oksbi, email test.user@example.com, "
        "link https://example.com/path?id=9876543210"
    )
    scrubbed, counts = redact_pii(raw)
    assert "[REDACTED_PHONE]" in scrubbed
    assert "[REDACTED_AADHAAR]" in scrubbed
    assert "[REDACTED_PAN]" in scrubbed
    assert "[REDACTED_UPI]" in scrubbed
    assert "[REDACTED_EMAIL]" in scrubbed
    assert "https://example.com/path?id=9876543210" in scrubbed
    assert counts["phone"] == 1
    assert counts["aadhaar"] == 1
    assert counts["pan"] == 1
    assert counts["upi"] == 1
    assert counts["email"] == 1


def test_defang_url() -> None:
    assert defang_url("https://evil.example.com/login") == "hxxps[://]evil[.]example[.]com/login"


def test_build_verdict_scoring_tiers() -> None:
    ssrf_verdict = build_verdict(
        "gopher://127.0.0.1",
        {"ssrf_blocked": True, "error": "Blocked unsafe URI scheme"},
        {},
    )
    assert ssrf_verdict["status"] == "DANGEROUS"
    assert ssrf_verdict["risk_score"] == 95

    safe_verdict = build_verdict(
        "https://www.wikipedia.org",
        {"ssrf_blocked": False, "redirect_chain": ["https://www.wikipedia.org"], "detected_forms": [], "urgency_flags": []},
        {"domain_age_days": 8000, "virustotal": {"malicious": 0, "suspicious": 0}, "tls": {"checked": True, "valid": True}, "url_heuristics": {"risk_points": 0, "flags": []}},
    )
    assert safe_verdict["status"] == "SAFE"
    assert safe_verdict["risk_score"] < 30
