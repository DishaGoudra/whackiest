"""FastAPI entrypoint for the hardened Scam SOC Crew suspicious link analyzer."""

from __future__ import annotations

import asyncio
import re
from pathlib import Path
from typing import Any, Literal

from dotenv import load_dotenv
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse, Response
from pydantic import BaseModel, Field

from backend.intel import check_threat_intel
from backend.sandbox import detonate_url
from backend.security import defang_url, redact_pii
from backend.verdict import (
    build_cybercrime_report,
    build_verdict,
    generate_voice_audio,
    get_emergency_script,
)
from backend.vision import analyze_screenshot_with_vision

load_dotenv()

BASE_DIR = Path(__file__).resolve().parent.parent
FRONTEND_INDEX = BASE_DIR / "frontend" / "index.html"

URL_PATTERN = re.compile(
    r"((?:https?|file|ftp|gopher|javascript|data):[^\s<>\"'\]\)]+|www\.[^\s<>\"'\]\)]+)",
    re.IGNORECASE,
)

app = FastAPI(
    title="scam-soc-crew",
    description="Hardened Playwright URL detonation sandbox, Gemini Vision & vernacular voice triage API",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class AnalyzeRequest(BaseModel):
    message: str = Field(..., min_length=1, description="Raw SMS/WhatsApp/email text")
    language: Literal["en", "kn", "hi"] = Field(default="en", description="Preferred response language code")


class EmergencyAudioRequest(BaseModel):
    language: Literal["en", "kn", "hi"] = Field(default="en")
    entered_credentials: bool = Field(default=True)


def extract_first_url(message: str) -> str | None:
    match = URL_PATTERN.search(message)
    if not match:
        return None
    return match.group(1).rstrip(".,!?;:")


@app.get("/", response_class=FileResponse)
async def serve_frontend() -> FileResponse:
    return FileResponse(FRONTEND_INDEX)


@app.get("/app.js", response_class=FileResponse)
async def serve_frontend_js() -> FileResponse:
    return FileResponse(BASE_DIR / "frontend" / "app.js", media_type="application/javascript")


@app.get("/mock-scam-redirect")
async def mock_scam_redirect() -> RedirectResponse:
    """Safe local demo route simulating a URL shortener 302 redirect."""
    return RedirectResponse(url="/mock-bescom-kyc", status_code=302)


@app.get("/mock-apk-trap")
async def mock_apk_trap() -> Response:
    """Safe local demo route simulating a drive-by BESCOM_KYC_Update.apk Trojan download."""
    return Response(
        content=b"SAFE_DEMO_NON_EXECUTABLE_PLACEHOLDER",
        media_type="application/vnd.android.package-archive",
        headers={
            "Content-Disposition": 'attachment; filename="BESCOM_KYC_Update.apk"',
        },
    )


@app.get("/mock-bescom-kyc", response_class=HTMLResponse)
async def mock_bescom_kyc() -> HTMLResponse:
    """Safe local demo page simulating a fake BESCOM disconnection scam."""
    html_content = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>[DEMO ONLY] BESCOM Electricity Bill & KYC Update</title>
  <style>
    body { margin: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #f3f5f9; color: #1e293b; }
    .demo-banner { background: #1d4ed8; color: #ffffff; text-align: center; padding: 10px 16px; font-weight: 700; font-size: 12px; letter-spacing: 0.03em; }
    .container { max-width: 400px; margin: 18px auto; background: #ffffff; border-radius: 12px; box-shadow: 0 10px 25px rgba(15, 23, 42, 0.08); overflow: hidden; border: 1px solid #e2e8f0; }
    .header { background: #0f172a; color: #ffffff; padding: 18px 20px; }
    .header h1 { margin: 0; font-size: 17px; }
    .header p { margin: 5px 0 0; font-size: 12px; color: #cbd5e1; }
    .alert { background: #fef2f2; border-left: 4px solid #dc2626; color: #991b1b; padding: 12px 16px; margin: 16px 20px 0; font-size: 13px; line-height: 1.45; }
    form { padding: 18px 20px 24px; display: flex; flex-direction: column; gap: 12px; }
    label { display: block; font-size: 13px; font-weight: 600; margin-bottom: 5px; }
    input { width: 100%; box-sizing: border-box; padding: 10px 12px; border: 1px solid #cbd5e1; border-radius: 8px; font-size: 14px; }
    button { margin-top: 4px; background: #dc2626; color: #ffffff; border: none; border-radius: 8px; padding: 12px; font-size: 14px; font-weight: 700; cursor: pointer; }
    .disclaimer { font-size: 11px; color: #64748b; text-align: center; margin-top: 4px; }
  </style>
</head>
<body>
  <div class="demo-banner">[DEMO ONLY] SAFE LOCAL PHISHING SIMULATION — NOT REAL BESCOM</div>
  <div class="container">
    <div class="header">
      <h1>[DEMO ONLY] BESCOM Consumer KYC Portal</h1>
      <p>Bangalore Electricity Supply Company — Verification Desk</p>
    </div>
    <div class="alert">
      <strong>URGENT NOTICE:</strong> Your electricity meter account has been <strong>suspended</strong> and will be
      <strong>disconnected</strong> tonight at 9:30 PM because your <strong>KYC</strong> is incomplete.
      Your consumer ID is currently <strong>blocked</strong>. Please <strong>pay now</strong> (₹12 verification fee)
      to avoid immediate power cut.
    </div>
    <form onsubmit="event.preventDefault(); document.getElementById('demo-msg').style.display='block';">
      <div>
        <label for="mobile_number">Mobile Number</label>
        <input id="mobile_number" name="mobile_number" type="tel" placeholder="Enter 10-digit mobile number" required />
      </div>
      <div>
        <label for="upi_pin">UPI PIN</label>
        <input id="upi_pin" name="upi_pin" type="password" placeholder="Enter 4 or 6 digit UPI PIN" required />
      </div>
      <div>
        <label for="otp">OTP Verification Code</label>
        <input id="otp" name="otp" type="text" placeholder="Enter 6-digit OTP" required />
      </div>
      <button type="submit">Pay Now &amp; Unblock Connection [DEMO ONLY]</button>
      <div id="demo-msg" class="disclaimer" style="display:none; color:#1d4ed8; font-weight:600;">
        [DEMO ONLY] Form submission intercepted safely — no data was sent.
      </div>
      <div class="disclaimer">[DEMO ONLY] For cybersecurity sandbox testing in scam-soc-crew.</div>
    </form>
  </div>
</body>
</html>
"""
    return HTMLResponse(content=html_content)


@app.post("/api/emergency-audio")
async def emergency_audio(payload: EmergencyAudioRequest) -> Any:
    """Return soothing emergency damage-control guidance + ElevenLabs audio."""
    script = get_emergency_script(payload.language, payload.entered_credentials)
    audio_b64 = await asyncio.to_thread(generate_voice_audio, script, payload.language)
    return {
        "language": payload.language,
        "entered_credentials": payload.entered_credentials,
        "script": script,
        "voice_audio_base64": audio_b64,
    }


@app.post("/api/analyze")
async def analyze_message(payload: AnalyzeRequest) -> Any:
    """Redacts PII, validates SSRF, detonates in stealth sandbox, runs Vision + Intel, and returns verdict."""
    extracted_url = extract_first_url(payload.message)
    if not extracted_url:
        return JSONResponse(
            status_code=400,
            content={
                "extracted_url": None,
                "language": payload.language,
                "error": "No URL found in the provided message.",
            },
        )

    redacted_message, pii_counts = redact_pii(payload.message)
    sandbox_data = await detonate_url(extracted_url)

    intel_target_url = sandbox_data.get("final_url") or extracted_url
    if sandbox_data.get("ssrf_blocked"):
        intel_data: dict[str, Any] = {
            "domain": extracted_url,
            "is_localhost": False,
            "domain_age_days": None,
            "domain_age_summary": "Blocked by SSRF Guard",
            "network": {
                "ip": (sandbox_data.get("ssrf_check") or {}).get("resolved_ip"),
                "asn": "BLOCKED-INTERNAL",
                "org": "Internal / Restricted Target",
                "country": "Restricted",
            },
            "virustotal": {
                "checked": False,
                "malicious": 0,
                "suspicious": 0,
                "harmless": 0,
                "undetected": 0,
                "note": "Skipped external lookup (SSRF Guard blocked target)",
            },
        }
        vision_data: dict[str, Any] = {
            "source": "ssrf_guard",
            "impersonated_brand": None,
            "official_domain": None,
            "visual_verdict": sandbox_data.get("error") or "Blocked internal/unsafe URI before rendering.",
            "manipulation_tactics": [],
        }
    else:
        intel_task = asyncio.to_thread(check_threat_intel, intel_target_url)
        vision_task = asyncio.to_thread(analyze_screenshot_with_vision, redacted_message, sandbox_data)
        intel_data, vision_data = await asyncio.gather(intel_task, vision_task)

    verdict_data = build_verdict(
        redacted_message,
        sandbox_data,
        intel_data,
        vision_data,
        payload.language,
    )
    action_kit = build_cybercrime_report(
        redacted_message,
        extracted_url,
        sandbox_data,
        intel_data,
        vision_data,
        verdict_data,
    )
    voice_audio_base64 = await asyncio.to_thread(
        generate_voice_audio,
        verdict_data["voice_script"],
        verdict_data["language"],
    )

    defanged_chain = [defang_url(hop) for hop in (sandbox_data.get("redirect_chain") or [extracted_url])]

    return {
        "extracted_url": extracted_url,
        "defanged_url": defang_url(sandbox_data.get("final_url") or extracted_url),
        "defanged_redirect_chain": defanged_chain,
        "redacted_message": redacted_message,
        "pii_redacted": pii_counts,
        "language": payload.language,
        **sandbox_data,
        "intel": intel_data,
        "vision": vision_data,
        "verdict": verdict_data,
        "action_kit": action_kit,
        "risk_score": verdict_data["risk_score"],
        "status": verdict_data["status"],
        "evidence": verdict_data["evidence"],
        "voice_script": verdict_data["voice_script"],
        "voice_audio_base64": voice_audio_base64,
    }
