"""API integration tests for FastAPI routes, security headers, and analysis pipeline."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

from fastapi.testclient import TestClient

from backend.main import app


def test_health_and_security_headers() -> None:
    client = TestClient(app)
    resp = client.get("/healthz")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"
    assert resp.headers["X-Content-Type-Options"] == "nosniff"
    assert resp.headers["X-Frame-Options"] == "DENY"
    assert resp.headers["Referrer-Policy"] == "no-referrer"


def test_frontend_and_demo_routes() -> None:
    client = TestClient(app)
    assert client.get("/").status_code == 200
    assert client.get("/app.js").status_code == 200
    assert client.get("/mock-bescom-kyc").status_code == 200
    redir = client.get("/mock-scam-redirect", follow_redirects=False)
    assert redir.status_code == 302
    apk = client.get("/mock-apk-trap")
    assert apk.status_code == 200
    assert "BESCOM_KYC_Update.apk" in apk.headers["content-disposition"]


def test_analyze_missing_url_returns_400() -> None:
    client = TestClient(app)
    resp = client.post("/api/analyze", json={"message": "Hello, no link here", "language": "en"})
    assert resp.status_code == 400
    assert resp.json()["extracted_url"] is None


def test_analyze_pipeline_with_mocked_sandbox() -> None:
    fake_sandbox = {
        "final_url": "https://fake-bescom-kyc.xyz/pay",
        "redirect_chain": ["https://bit.ly/demo", "https://fake-bescom-kyc.xyz/pay"],
        "page_title": "BESCOM KYC Update",
        "detected_forms": ["upi", "otp"],
        "dom_inputs": [{"tag": "input", "type": "password", "name": "upi_pin", "id": "upi_pin", "placeholder": "", "label": "UPI PIN"}],
        "urgency_flags": ["suspended", "kyc"],
        "visible_text_excerpt": "Your meter is suspended",
        "screenshot_base64": None,
        "screenshot_sha256": None,
        "http_status": 200,
        "response_headers": {"content-type": "text/html"},
        "security_headers_audit": {"hsts": False, "csp": False, "x_frame_options": False, "x_content_type_options": False},
        "ssrf_check": {"allowed": True, "resolved_ip": "93.184.216.34"},
        "ssrf_blocked": False,
        "apk_trap": {"detected": False},
        "security_profile": {"ssrf_guard": "ACTIVE"},
        "error": None,
    }
    fake_intel = {
        "domain": "fake-bescom-kyc.xyz",
        "is_localhost": False,
        "domain_age_days": 2,
        "domain_age_summary": "2 days old",
        "network": {"ip": "93.184.216.34", "asn": "AS15133", "org": "Edgecast", "country": "US"},
        "tls": {"checked": True, "valid": True, "issuer": "Let's Encrypt", "cert_age_days": 1, "note": "Valid TLS"},
        "url_heuristics": {"flags": ["Uses high-abuse top-level domain (.xyz)"], "risk_points": 15},
        "virustotal": {"checked": False, "malicious": 0, "suspicious": 0, "harmless": 0, "undetected": 0, "note": "Skipped"},
    }

    with (
        patch("backend.main.detonate_url", new=AsyncMock(return_value=fake_sandbox)),
        patch("backend.main.check_threat_intel_async", new=AsyncMock(return_value=fake_intel)),
    ):
        client = TestClient(app)
        resp = client.post(
            "/api/analyze",
            json={"message": "URGENT call 9876543210 https://bit.ly/demo", "language": "en"},
        )

    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "DANGEROUS"
    assert body["risk_score"] >= 60
    assert "[REDACTED_PHONE]" in body["redacted_message"]
    assert body["defanged_url"] == "hxxps[://]fake-bescom-kyc[.]xyz/pay"
