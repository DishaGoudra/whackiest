"""FastAPI entrypoint for the hardened Scam SOC Crew suspicious link analyzer."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import time
from collections import defaultdict, deque
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, AsyncIterator, Awaitable, Callable, Literal

from dotenv import load_dotenv
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import (
    FileResponse,
    HTMLResponse,
    JSONResponse,
    RedirectResponse,
    Response,
    StreamingResponse,
)
from pydantic import BaseModel, Field
from starlette.middleware.base import BaseHTTPMiddleware

from backend.intel import check_threat_intel_async
from backend.sandbox import PLAYWRIGHT_AVAILABLE, browser_pool, detonate_url
from backend.security import defang_url, redact_pii
from backend.verdict import (
    build_cybercrime_report,
    build_official_pdf_bytes,
    build_verdict,
    generate_voice_audio_async,
    get_emergency_script,
    localize_analysis_with_gemini_async,
)
from backend.vision import analyze_screenshot_with_vision_async

load_dotenv()

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
)
logger = logging.getLogger("scam_soc.api")

BASE_DIR = Path(__file__).resolve().parent.parent
FRONTEND_INDEX = BASE_DIR / "frontend" / "index.html"

URL_PATTERN = re.compile(
    r"((?:https?|file|ftp|gopher|javascript|data):[^\s<>\"'\]\)]+|www\.[^\s<>\"'\]\)]+)",
    re.IGNORECASE,
)
BARE_DOMAIN_PATTERN = re.compile(
    r"(?<![@\w.-])((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|org|net|in|co\.in|gov\.in|edu|io|xyz|info|biz|me|ly|app|dev|ai|online|site|top|club|live|tech|shop|link|click)(?:/[^\s<>\"'\]\)]*)?)",
    re.IGNORECASE,
)

RATE_LIMIT_PER_MIN = int(os.getenv("RATE_LIMIT_PER_MIN", "30"))
_RATE_BUCKETS: dict[str, deque[float]] = defaultdict(deque)


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    await browser_pool.startup()
    try:
        yield
    finally:
        await browser_pool.shutdown()


app = FastAPI(
    title="scam-soc-crew",
    description="Hardened Playwright URL detonation sandbox, Gemini Vision & vernacular voice triage API",
    version="2.0.0",
    lifespan=lifespan,
)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Attach defensive HTTP security headers to every response."""

    async def dispatch(self, request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        return response


app.add_middleware(SecurityHeadersMiddleware)

_cors_origins = [
    origin.strip()
    for origin in os.getenv("CORS_ORIGINS", "http://127.0.0.1:8000,http://localhost:8000").split(",")
    if origin.strip()
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)


def _check_rate_limit(client_ip: str) -> bool:
    """Return True if within sliding-window rate limit, False if exceeded."""
    if RATE_LIMIT_PER_MIN <= 0:
        return True
    now = time.monotonic()
    bucket = _RATE_BUCKETS[client_ip]
    cutoff = now - 60.0
    while bucket and bucket[0] < cutoff:
        bucket.popleft()
    if len(bucket) >= RATE_LIMIT_PER_MIN:
        return False
    bucket.append(now)
    return True


SUPPORTED_LANGUAGES = (
    "en", "hi", "kn", "ta", "te", "ml", "mr", "bn", "gu", "pa",
    "ur", "ar", "es", "fr", "de", "ja", "ko", "pt", "id", "vi",
    "tr", "ru", "it", "nl", "pl",
)


class AnalyzeRequest(BaseModel):
    message: str = Field(default="", max_length=4000, description="Raw SMS/WhatsApp/email text")
    language: str = Field(default="en", min_length=2, max_length=5, description="Preferred response language code")
    image_base64: str | None = Field(default=None, max_length=8_000_000, description="Optional uploaded screenshot base64")


class EmergencyAudioRequest(BaseModel):
    language: str = Field(default="en", min_length=2, max_length=5)
    entered_credentials: bool = Field(default=True)


def extract_first_url(message: str) -> str | None:
    match = URL_PATTERN.search(message)
    if match:
        return match.group(1).rstrip(".,!?;:")
    bare = BARE_DOMAIN_PATTERN.search(message)
    if bare:
        candidate = bare.group(1).rstrip(".,!?;:")
        return f"https://{candidate}"
    return None


@app.get("/healthz")
async def healthz() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/readyz")
async def readyz() -> JSONResponse:
    ready = browser_pool.is_ready or not PLAYWRIGHT_AVAILABLE
    return JSONResponse(
        status_code=200 if ready else 503,
        content={
            "status": "ready" if ready else "degraded",
            "playwright_installed": PLAYWRIGHT_AVAILABLE,
            "browser_pool_warm": browser_pool.is_ready,
        },
    )


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


@app.post("/api/report/pdf")
async def export_official_pdf(payload: dict[str, Any]) -> Response:
    """Generate and return a downloadable official PDF dossier."""
    pdf_bytes = build_official_pdf_bytes(payload)
    raw_case = str(payload.get("case_id") or "CASE-0001").replace(" ", "-")
    safe_name = re.sub(r"[^A-Za-z0-9_-]", "", raw_case) or "CASE-0001"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="scam-soc-dossier-{safe_name}.pdf"'},
    )


@app.post("/api/emergency-audio")
async def emergency_audio(payload: EmergencyAudioRequest, request: Request) -> Any:
    """Return soothing emergency damage-control guidance + ElevenLabs audio."""
    client_ip = request.client.host if request.client else "unknown"
    if not _check_rate_limit(client_ip):
        return JSONResponse(status_code=429, content={"error": "Rate limit exceeded. Please wait a minute."})

    script = get_emergency_script(payload.language, payload.entered_credentials)
    audio_b64 = await generate_voice_audio_async(script, payload.language)
    return {
        "language": payload.language,
        "entered_credentials": payload.entered_credentials,
        "script": script,
        "voice_audio_base64": audio_b64,
    }


async def _run_analysis_pipeline(
    message: str,
    language: str,
    extracted_url: str,
    on_progress: Callable[[int, str], Awaitable[None]] | None = None,
) -> dict[str, Any]:
    """Execute the full SSRF -> Sandbox -> Intel/Vision -> Verdict -> Voice pipeline."""
    if on_progress:
        await on_progress(0, "Validating SSRF & scrubbing DPDP PII...")
    redacted_message, pii_counts = redact_pii(message)

    if on_progress:
        await on_progress(1, "Opening in stealth Android mobile sandbox...")
    sandbox_data = await detonate_url(extracted_url)

    if on_progress:
        await on_progress(2, "Running Gemini Vision, TLS & Threat Intel...")
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
            "tls": {"checked": False, "valid": False, "issuer": None, "cert_age_days": None, "note": "Blocked by SSRF Guard"},
            "url_heuristics": {"flags": [], "risk_points": 0},
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
        intel_task = check_threat_intel_async(intel_target_url)
        vision_task = analyze_screenshot_with_vision_async(redacted_message, sandbox_data)
        intel_data, vision_data = await asyncio.gather(intel_task, vision_task)

    if on_progress:
        await on_progress(3, "Generating verdict & multilingual voice...")
    verdict_data = build_verdict(
        redacted_message,
        sandbox_data,
        intel_data,
        vision_data,
        language,
    )
    await localize_analysis_with_gemini_async(verdict_data, vision_data, language)
    action_kit = build_cybercrime_report(
        redacted_message,
        extracted_url,
        sandbox_data,
        intel_data,
        vision_data,
        verdict_data,
    )
    voice_audio_base64 = await generate_voice_audio_async(
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
        "language": language,
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


async def _run_image_only_pipeline(
    message: str,
    language: str,
    image_base64: str,
    on_progress: Callable[[int, str], Awaitable[None]] | None = None,
) -> dict[str, Any]:
    """Analyze an uploaded screenshot directly when no URL was typed."""
    if on_progress:
        await on_progress(0, "Scrubbing personal numbers from text...")
    redacted_message, pii_counts = redact_pii(message or "[Uploaded screenshot]")

    if on_progress:
        await on_progress(1, "Preparing uploaded image in safe viewer...")
    raw_b64 = image_base64.split(",", 1)[-1]
    import hashlib
    sha256_hash = hashlib.sha256(raw_b64.encode("utf-8")).hexdigest()
    sandbox_data: dict[str, Any] = {
        "final_url": "uploaded-image://local-specimen",
        "redirect_chain": [],
        "page_title": "Uploaded image specimen",
        "visible_text_excerpt": redacted_message,
        "detected_forms": [],
        "urgency_flags": [],
        "screenshot_base64": raw_b64,
        "screenshot_sha256": sha256_hash,
        "http_status": None,
        "response_headers": {},
        "security_headers_audit": {},
        "dom_inputs": [],
        "ssrf_blocked": False,
        "apk_trap": {"detected": False},
        "security_profile": {"ssrf_guard": "N/A (Image)", "stealth_mobile": "Uploaded Specimen", "permissions": "Denied"},
    }
    intel_data: dict[str, Any] = {
        "domain": "uploaded-image",
        "domain_age_days": None,
        "domain_age_summary": "Uploaded image",
        "network": {"ip": "Local upload", "asn": "N/A", "org": "User uploaded screenshot", "country": "N/A"},
        "tls": {"checked": False, "valid": True, "note": "Image upload"},
        "url_heuristics": {"flags": [], "risk_points": 0},
        "virustotal": {"checked": False, "malicious": 0, "suspicious": 0, "note": "Image upload — no external URL"},
    }

    if on_progress:
        await on_progress(2, "Running visual inspection...")
    vision_data = await analyze_screenshot_with_vision_async(redacted_message, sandbox_data)

    if on_progress:
        await on_progress(3, "Generating verdict and voice summary...")
    verdict_data = build_verdict(redacted_message, sandbox_data, intel_data, vision_data, language)
    await localize_analysis_with_gemini_async(verdict_data, vision_data, language)
    action_kit = build_cybercrime_report(redacted_message, "uploaded-image", sandbox_data, intel_data, vision_data, verdict_data)
    voice_audio_base64 = await generate_voice_audio_async(verdict_data["voice_script"], verdict_data["language"])

    return {
        "extracted_url": None,
        "defanged_url": "uploaded-image",
        "defanged_redirect_chain": [],
        "redacted_message": redacted_message,
        "pii_redacted": pii_counts,
        "language": language,
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


@app.post("/api/analyze")
async def analyze_message(payload: AnalyzeRequest, request: Request) -> Any:
    """Redacts PII, validates SSRF, detonates in stealth sandbox, runs Vision + Intel, and returns verdict."""
    client_ip = request.client.host if request.client else "unknown"
    if not _check_rate_limit(client_ip):
        return JSONResponse(status_code=429, content={"error": "Rate limit exceeded. Please wait a minute."})

    extracted_url = extract_first_url(payload.message)
    if not extracted_url:
        if payload.image_base64:
            return await _run_image_only_pipeline(payload.message, payload.language, payload.image_base64)
        return JSONResponse(
            status_code=400,
            content={
                "extracted_url": None,
                "language": payload.language,
                "error": "No URL found in the provided message.",
            },
        )

    return await _run_analysis_pipeline(payload.message, payload.language, extracted_url)


@app.post("/api/analyze/stream")
async def analyze_message_stream(payload: AnalyzeRequest, request: Request) -> Any:
    """Stream real-time pipeline progress events (SSE) followed by the final analysis result."""
    client_ip = request.client.host if request.client else "unknown"
    if not _check_rate_limit(client_ip):
        return JSONResponse(status_code=429, content={"error": "Rate limit exceeded. Please wait a minute."})

    extracted_url = extract_first_url(payload.message)
    if not extracted_url and not payload.image_base64:
        return JSONResponse(
            status_code=400,
            content={
                "extracted_url": None,
                "language": payload.language,
                "error": "No URL found in the provided message.",
            },
        )

    queue: asyncio.Queue[str | None] = asyncio.Queue()

    async def _emit_progress(step: int, message: str) -> None:
        event = json.dumps({"type": "progress", "step": step, "message": message})
        await queue.put(f"data: {event}\n\n")

    async def _worker() -> None:
        try:
            if extracted_url:
                result = await _run_analysis_pipeline(
                    payload.message,
                    payload.language,
                    extracted_url,
                    on_progress=_emit_progress,
                )
            else:
                result = await _run_image_only_pipeline(
                    payload.message,
                    payload.language,
                    payload.image_base64 or "",
                    on_progress=_emit_progress,
                )
            await queue.put(f"data: {json.dumps({'type': 'result', 'data': result})}\n\n")
        except Exception as exc:  # noqa: BLE001
            logger.exception("Streaming analysis failed")
            await queue.put(f"data: {json.dumps({'type': 'error', 'error': str(exc)})}\n\n")
        finally:
            await queue.put(None)

    asyncio.create_task(_worker())

    async def _event_stream() -> AsyncIterator[str]:
        while True:
            chunk = await queue.get()
            if chunk is None:
                break
            yield chunk

    return StreamingResponse(
        _event_stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )
