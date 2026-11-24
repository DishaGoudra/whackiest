"""Multimodal AI Vision & Psychological Manipulation Breakdown (Gemini Vision + fallback)."""

from __future__ import annotations

import json
import os
import re
from typing import Any

import requests

GEMINI_VISION_MODEL = "gemini-2.5-flash"
GEMINI_TIMEOUT_SECONDS = 15

_KNOWN_INDIAN_BRANDS: list[tuple[str, str, str]] = [
    ("bescom", "BESCOM Karnataka", "bescom.karnataka.gov.in"),
    ("kseb", "KSEB Kerala", "kseb.in"),
    ("msedcl", "MSEDCL Mahavitaran", "mahadiscom.in"),
    ("sbi", "State Bank of India (SBI)", "sbi.co.in"),
    ("hdfc", "HDFC Bank", "hdfcbank.com"),
    ("icici", "ICICI Bank", "icicibank.com"),
    ("axis", "Axis Bank", "axisbank.com"),
    ("paytm", "Paytm", "paytm.com"),
    ("phonepe", "PhonePe", "phonepe.com"),
    ("gpay", "Google Pay", "pay.google.com"),
    ("uidai", "UIDAI / Aadhaar", "uidai.gov.in"),
    ("aadhaar", "UIDAI / Aadhaar", "uidai.gov.in"),
    ("trai", "TRAI", "trai.gov.in"),
    ("india post", "India Post", "indiapost.gov.in"),
    ("income tax", "Income Tax India", "incometax.gov.in"),
]


def _heuristic_vision_fallback(
    redacted_message: str,
    sandbox_data: dict[str, Any],
) -> dict[str, Any]:
    """Provide deterministic brand & psychological-tactic analysis when Gemini API is unavailable."""
    combined = " ".join(
        [
            redacted_message or "",
            sandbox_data.get("page_title") or "",
            sandbox_data.get("visible_text_excerpt") or "",
        ]
    ).lower()
    final_url = (sandbox_data.get("final_url") or "").lower()
    detected_forms = sandbox_data.get("detected_forms") or []
    urgency_flags = sandbox_data.get("urgency_flags") or []
    apk_trap = sandbox_data.get("apk_trap") or {}

    impersonated_brand = None
    official_domain = None
    for keyword, brand_name, domain in _KNOWN_INDIAN_BRANDS:
        if keyword in combined and domain not in final_url:
            impersonated_brand = brand_name
            official_domain = domain
            break

    tactics: list[dict[str, str]] = []
    if urgency_flags or any(w in combined for w in ("tonight", "9:30", "immediately", "24 hours", "disconnected")):
        tactics.append(
            {
                "tactic": "False Urgency",
                "detail": "Threatens sudden disconnection or account suspension to trigger panic and bypass careful thinking.",
            }
        )
    if impersonated_brand or any(w in combined for w in ("verification desk", "officer", "kyc", "official", "department")):
        tactics.append(
            {
                "tactic": "Authority Exploitation",
                "detail": (
                    f"Poses as {impersonated_brand} to borrow institutional trust."
                    if impersonated_brand
                    else "Impersonates an official utility, bank, or government authority."
                ),
            }
        )
    if re.search(r"(?:₹|rs\.?|inr)\s*\d{1,3}\b", combined) or "fee" in combined:
        tactics.append(
            {
                "tactic": "Micro-Fee Trap",
                "detail": "Asks for a tiny token fee (e.g., ₹10–₹12) solely to lure the victim into entering their UPI PIN or OTP.",
            }
        )
    if detected_forms:
        tactics.append(
            {
                "tactic": "Credential Harvesting",
                "detail": f"Requests sensitive inputs ({', '.join(detected_forms).upper()}) directly on an unverified page.",
            }
        )
    if apk_trap.get("detected"):
        tactics.append(
            {
                "tactic": "Trojan App Lure",
                "detail": f"Attempts to force-download '{apk_trap.get('filename', 'malicious.apk')}' to hijack SMS OTPs on Android.",
            }
        )

    if apk_trap.get("detected"):
        visual_verdict = (
            f"Drive-by malware trap detected: link attempts to download '{apk_trap.get('filename')}' "
            "instead of opening a legitimate portal."
        )
    elif impersonated_brand:
        visual_verdict = (
            f"This page mimics {impersonated_brand} branding/wording, but is hosted on an unofficial address "
            f"instead of the real domain ({official_domain})."
        )
    elif tactics:
        visual_verdict = (
            "Visual and text cues match common Indian social-engineering patterns designed to rush users into sharing credentials."
        )
    else:
        visual_verdict = "No obvious brand impersonation or coercive visual manipulation tactics were spotted."

    return {
        "source": "heuristic_fallback",
        "impersonated_brand": impersonated_brand,
        "official_domain": official_domain,
        "visual_verdict": visual_verdict,
        "manipulation_tactics": tactics[:4],
    }


def analyze_screenshot_with_vision(
    redacted_message: str,
    sandbox_data: dict[str, Any],
) -> dict[str, Any]:
    """Analyze the Playwright screenshot with Gemini Vision for brand spoofing & scam psychology."""
    api_key = os.getenv("GEMINI_API_KEY", "").strip()
    screenshot_b64 = sandbox_data.get("screenshot_base64")

    if not api_key or not screenshot_b64:
        return _heuristic_vision_fallback(redacted_message, sandbox_data)

    prompt = (
        "You are a cybersecurity visual analyst protecting everyday Indian smartphone users from phishing.\n"
        f"Redacted SMS/Message: {redacted_message}\n"
        f"Final Landing URL: {sandbox_data.get('final_url', '')}\n"
        f"Page Title: {sandbox_data.get('page_title', '')}\n\n"
        "Inspect the attached webpage screenshot and respond ONLY with valid JSON (no markdown fences) "
        "matching this exact schema:\n"
        "{\n"
        '  "impersonated_brand": "Brand name or null if none",\n'
        '  "official_domain": "Official domain (e.g. bescom.karnataka.gov.in) or null",\n'
        '  "visual_verdict": "1-2 plain sentences explaining any logo/color/domain mismatch or visual cues",\n'
        '  "manipulation_tactics": [\n'
        '    {"tactic": "False Urgency | Authority Exploitation | Micro-Fee Trap | Credential Harvesting", "detail": "Short plain explanation"}\n'
        "  ]\n"
        "}"
    )

    endpoint = (
        f"https://generativelanguage.googleapis.com/v1beta/models/"
        f"{GEMINI_VISION_MODEL}:generateContent?key={api_key}"
    )
    payload = {
        "contents": [
            {
                "parts": [
                    {"text": prompt},
                    {
                        "inline_data": {
                            "mime_type": "image/png",
                            "data": screenshot_b64,
                        }
                    },
                ]
            }
        ],
        "generationConfig": {
            "temperature": 0.2,
            "responseMimeType": "application/json",
        },
    }

    try:
        resp = requests.post(endpoint, json=payload, timeout=GEMINI_TIMEOUT_SECONDS)
        if resp.status_code != 200:
            print(f"[Gemini Vision] HTTP {resp.status_code}: {resp.text[:200]}")
            return _heuristic_vision_fallback(redacted_message, sandbox_data)

        body = resp.json()
        raw_text = (
            body.get("candidates", [{}])[0]
            .get("content", {})
            .get("parts", [{}])[0]
            .get("text", "")
            .strip()
        )
        raw_text = re.sub(r"^```json\s*|\s*```$", "", raw_text, flags=re.IGNORECASE)
        parsed = json.loads(raw_text)

        return {
            "source": "gemini_vision",
            "impersonated_brand": parsed.get("impersonated_brand"),
            "official_domain": parsed.get("official_domain"),
            "visual_verdict": parsed.get("visual_verdict") or "Visual inspection completed.",
            "manipulation_tactics": (parsed.get("manipulation_tactics") or [])[:4],
        }
    except Exception as exc:  # noqa: BLE001
        print(f"[Gemini Vision] Fallback triggered: {exc}")
        return _heuristic_vision_fallback(redacted_message, sandbox_data)
