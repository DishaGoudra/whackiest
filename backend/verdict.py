"""Rule-based risk scoring, plain-language verdict, cybercrime report generator, and ElevenLabs v3 TTS."""

from __future__ import annotations

import base64
import os
from datetime import datetime, timezone
from typing import Any

import requests

from backend.security import defang_url

ELEVENLABS_DEFAULT_VOICE_ID = "21m00Tcm4TlvDq8ikWAM"
ELEVENLABS_TIMEOUT_SECONDS = 15

_FIELD_PLAIN_LABELS: dict[str, str] = {
    "password": "password",
    "otp": "OTP",
    "pin": "PIN",
    "card": "card number",
    "cvv": "CVV",
    "aadhaar": "Aadhaar number",
    "upi": "UPI details",
}

_SPOKEN_SCRIPTS: dict[str, dict[str, str]] = {
    "en": {
        "DANGEROUS": (
            "This link looks dangerous and shows clear signs of a scam trying to steal your money or personal details. "
            "Please delete this message right away, never share your OTP or UPI PIN, and report it by calling 1930 or using the Chakshu portal."
        ),
        "SUSPICIOUS": (
            "This link looks suspicious and has warning signs that do not match a trusted official service. "
            "Do not enter any OTP, PIN, or payment details here; delete the message and report it to 1930 or the Chakshu portal if you are unsure."
        ),
        "SAFE": (
            "We did not find obvious scam traps or risky payment requests on this link. "
            "Even so, never share your OTP or PIN, and always double-check important bills or alerts directly inside the official app."
        ),
        "APK_TRAP": (
            "Warning! This link is a dangerous phone virus trap that tries to download a fake app to steal your bank OTPs. "
            "Do not install anything, delete this message immediately, and report the sender on 1930 or the Chakshu portal."
        ),
    },
    "kn": {
        "DANGEROUS": (
            "ಈ ಲಿಂಕ್ ಅಪಾಯಕಾರಿಯಾಗಿದ್ದು ನಿಮ್ಮ ಹಣ ಅಥವಾ ವೈಯಕ್ತಿಕ ಮಾಹಿತಿಯನ್ನು ಕದಿಯುವ ವಂಚನೆಯ ಲಕ್ಷಣಗಳನ್ನು ತೋರಿಸುತ್ತಿದೆ. "
            "ದಯವಿಟ್ಟು ಈ ಸಂದೇಶವನ್ನು ತಕ್ಷಣ ಅಳಿಸಿ, ನಿಮ್ಮ ಒಟಿಪಿ ಅಥವಾ ಯುಪಿಐ ಪಿನ್ ಅನ್ನು ಎಂದಿಗೂ ಹಂಚಿಕೊಳ್ಳಬೇಡಿ, ಮತ್ತು 1930 ಗೆ ಕರೆ ಮಾಡಿ ಅಥವಾ ಚಕ್ಷು ಪೋರ್ಟಲ್‌ನಲ್ಲಿ ದೂರು ನೀಡಿ."
        ),
        "SUSPICIOUS": (
            "ಈ ಲಿಂಕ್ ಅನುಮಾನಾಸ್ಪದವಾಗಿದ್ದು ಅಧಿಕೃತ ಸೇವೆಯಂತೆ ಕಾಣದ ಎಚ್ಚರಿಕೆಯ ಚಿಹ್ನೆಗಳನ್ನು ಹೊಂದಿದೆ. "
            "ದಯವಿಟ್ಟು ಇಲ್ಲಿ ನಿಮ್ಮ ಒಟಿಪಿ, ಪಿನ್ ಅಥವಾ ಬ್ಯಾಂಕ್ ವಿವರಗಳನ್ನು ನಮೂದಿಸಬೇಡಿ, ಸಂದೇಶವನ್ನು ಅಳಿಸಿ ಮತ್ತು ಅಗತ್ಯವಿದ್ದರೆ 1930 ಅಥವಾ ಚಕ್ಷು ಪೋರ್ಟಲ್‌ಗೆ ವರದಿ ಮಾಡಿ."
        ),
        "SAFE": (
            "ಈ ಲಿಂಕ್‌ನಲ್ಲಿ ತಕ್ಷಣದ ವಂಚನೆಯ ಲಕ್ಷಣಗಳು ಅಥವಾ ಅಪಾಯಕಾರಿ ಪಾವತಿ ಫಾರ್ಮ್‌ಗಳು ಕಂಡುಬಂದಿಲ್ಲ. "
            "ಆದರೂ, ನಿಮ್ಮ ಒಟಿಪಿ ಅಥವಾ ಪಿನ್ ಅನ್ನು ಯಾರಿಗೂ ನೀಡಬೇಡಿ ಮತ್ತು ಯಾವುದೇ ಬಿಲ್ ಅಥವಾ ಖಾತೆಯ ಮಾಹಿತಿಯನ್ನು ಅಧಿಕೃತ ಆ್ಯಪ್‌ನಲ್ಲಿಯೇ ಪರಿಶೀಲಿಸಿ."
        ),
        "APK_TRAP": (
            "ಎಚ್ಚರಿಕೆ! ಈ ಲಿಂಕ್ ಅಪಾಯಕಾರಿ ನಕಲಿ ಆ್ಯಪ್ ಅನ್ನು ಡೌನ್‌ಲೋಡ್ ಮಾಡಿ ನಿಮ್ಮ ಬ್ಯಾಂಕ್ ಒಟಿಪಿ ಕದಿಯಲು ಪ್ರಯತ್ನಿಸುತ್ತಿದೆ. "
            "ಯಾವುದೇ ಫೈಲ್ ಇನ್‌ಸ್ಟಾಲ್ ಮಾಡಬೇಡಿ, ಈ ಸಂದೇಶವನ್ನು ತಕ್ಷಣ ಅಳಿಸಿ, ಮತ್ತು 1930 ಅಥವಾ ಚಕ್ಷು ಪೋರ್ಟಲ್‌ನಲ್ಲಿ ದೂರು ನೀಡಿ."
        ),
    },
    "hi": {
        "DANGEROUS": (
            "यह लिंक खतरनाक लग रहा है और इसमें आपके पैसे या निजी जानकारी चुराने वाले धोखाधड़ी के साफ संकेत हैं। "
            "कृपया इस संदेश को तुरंत हटा दें, अपना ओटीपी या यूपीआई पिन कभी साझा न करें, और 1930 पर कॉल करके या चक्षु पोर्टल पर इसकी शिकायत करें।"
        ),
        "SUSPICIOUS": (
            "यह लिंक संदिग्ध लग रहा है और इसमें ऐसे चेतावनी संकेत हैं जो किसी असली सरकारी या बैंक सेवा से मेल नहीं खाते। "
            "कृपया यहाँ कोई ओटीपी, पिन या भुगतान विवरण न डालें, संदेश को हटा दें, और संदेह होने पर 1930 या चक्षु पोर्टल पर रिपोर्ट करें।"
        ),
        "SAFE": (
            "इस लिंक पर धोखाधड़ी के कोई स्पष्ट संकेत या संदिग्ध भुगतान फॉर्म नहीं मिले हैं। "
            "फिर भी, अपना ओटीपी या पिन कभी साझा न करें और किसी भी बिल या अलर्ट की जांच हमेशा आधिकारिक ऐप से ही करें।"
        ),
        "APK_TRAP": (
            "चेतावनी! यह लिंक एक खतरनाक नकली ऐप डाउनलोड करने की कोशिश कर रहा है जो आपके बैंक ओटीपी चुरा सकता है। "
            "कृपया कोई भी फाइल इंस्टॉल न करें, इस संदेश को तुरंत हटा दें, और 1930 या चक्षु पोर्टल पर शिकायत करें।"
        ),
    },
}

_EMERGENCY_SCRIPTS: dict[str, dict[str, str]] = {
    "en": {
        "credentials_entered": (
            "Stay calm, you can still protect your money if you act right now. "
            "First, call 1930 immediately to freeze any fraudulent transfer. "
            "Second, call your bank's official helpline to block your UPI, debit card, and net banking. "
            "Finally, turn off mobile data if you installed any unknown app."
        ),
        "clicked_only": (
            "Take a deep breath. If you only opened the link and did not enter your OTP, PIN, or install an app, your bank account is usually safe. "
            "Close the browser tab right away, delete the message, and block the sender."
        ),
    },
    "kn": {
        "credentials_entered": (
            "ಗಾಬರಿಯಾಗಬೇಡಿ, ಈಗಲೇ ಕ್ರಮ ಕೈಗೊಂಡರೆ ನಿಮ್ಮ ಹಣವನ್ನು ಉಳಿಸಬಹುದು. "
            "ಮೊದಲು ತಕ್ಷಣ 1930 ಗೆ ಕರೆ ಮಾಡಿ ವಹಿವಾಟನ್ನು ತಡೆಹಿಡಿಯಿರಿ. "
            "ನಂತರ ನಿಮ್ಮ ಬ್ಯಾಂಕ್ ಸಹಾಯವಾಣಿಗೆ ಕರೆ ಮಾಡಿ ಯುಪಿಐ, ಕಾರ್ಡ್ ಮತ್ತು ನೆಟ್ ಬ್ಯಾಂಕಿಂಗ್ ಬ್ಲಾಕ್ ಮಾಡಿಸಿ. "
            "ಯಾವುದೇ ಅಪರಿಚಿತ ಆ್ಯಪ್ ಡೌನ್‌ಲೋಡ್ ಆಗಿದ್ದರೆ ತಕ್ಷಣ ಮೊಬೈಲ್ ಡೇಟಾ ಆಫ್ ಮಾಡಿ."
        ),
        "clicked_only": (
            "ಗಾಬರಿಯಾಗಬೇಡಿ. ನೀವು ಕೇವಲ ಲಿಂಕ್ ತೆರೆದಿದ್ದು, ಯಾವುದೇ ಒಟಿಪಿ, ಪಿನ್ ನಮೂದಿಸದಿದ್ದರೆ ಅಥವಾ ಆ್ಯಪ್ ಇನ್‌ಸ್ಟಾಲ್ ಮಾಡದಿದ್ದರೆ ನಿಮ್ಮ ಖಾತೆ ಸುರಕ್ಷಿತವಾಗಿರುತ್ತದೆ. "
            "ತಕ್ಷಣ ಬ್ರೌಸರ್ ಟ್ಯಾಬ್ ಮುಚ್ಚಿ, ಸಂದೇಶವನ್ನು ಅಳಿಸಿ ಮತ್ತು ಆ ನಂಬರ್ ಬ್ಲಾಕ್ ಮಾಡಿ."
        ),
    },
    "hi": {
        "credentials_entered": (
            "घबराएं नहीं, अभी तुरंत कदम उठाने से आपका पैसा बचाया जा सकता है। "
            "सबसे पहले तुरंत 1930 पर कॉल करें ताकि धोखाधड़ी वाला लेनदेन रोका जा सके। "
            "इसके बाद अपने बैंक की आधिकारिक हेल्पलाइन पर कॉल करके यूपीआई, कार्ड और नेट बैंकिंग ब्लॉक करवाएं। "
            "अगर कोई अनजान ऐप डाउनलोड हुआ है तो तुरंत मोबाइल डेटा बंद कर दें।"
        ),
        "clicked_only": (
            "चिंता न करें। अगर आपने सिर्फ लिंक खोला है और कोई ओटीपी, पिन नहीं डाला या ऐप इंस्टॉल नहीं किया, तो आपका खाता सुरक्षित है। "
            "तुरंत ब्राउज़र बंद करें, संदेश हटा दें और उस नंबर को ब्लॉक कर दें।"
        ),
    },
}


def get_emergency_script(language: str, entered_credentials: bool) -> str:
    lang_code = language if language in _EMERGENCY_SCRIPTS else "en"
    key = "credentials_entered" if entered_credentials else "clicked_only"
    return _EMERGENCY_SCRIPTS[lang_code][key]


def _format_plain_fields(detected_forms: list[str]) -> str:
    labels = [_FIELD_PLAIN_LABELS.get(field, field) for field in detected_forms]
    if len(labels) == 1:
        return labels[0]
    if len(labels) == 2:
        return f"{labels[0]} and {labels[1]}"
    return ", ".join(labels[:-1]) + f", and {labels[-1]}"


def _assign_status(risk_score: int) -> str:
    if risk_score >= 60:
        return "DANGEROUS"
    if risk_score >= 30:
        return "SUSPICIOUS"
    return "SAFE"


def build_verdict(
    message: str,
    sandbox_data: dict[str, Any],
    intel_data: dict[str, Any],
    vision_data: dict[str, Any] | None = None,
    language: str = "en",
) -> dict[str, Any]:
    """Compute transparent risk score, status, plain-language evidence, and spoken script."""
    redirect_chain: list[str] = sandbox_data.get("redirect_chain") or []
    detected_forms: list[str] = sandbox_data.get("detected_forms") or []
    urgency_flags: list[str] = sandbox_data.get("urgency_flags") or []
    sandbox_error: str | None = sandbox_data.get("error")
    ssrf_blocked: bool = bool(sandbox_data.get("ssrf_blocked"))
    apk_trap: dict[str, Any] = sandbox_data.get("apk_trap") or {}

    domain_age_days: int | None = intel_data.get("domain_age_days")
    vt_data: dict[str, Any] = intel_data.get("virustotal") or {}
    vt_malicious = int(vt_data.get("malicious", 0) or 0)
    vt_suspicious = int(vt_data.get("suspicious", 0) or 0)

    score = 0
    breakdown: list[dict[str, Any]] = []

    if ssrf_blocked:
        score = 95
        breakdown.append({"rule": "SSRF Guard blocked internal/unsafe URI target", "points": 95})
    else:
        if apk_trap.get("detected"):
            score += 75
            breakdown.append(
                {"rule": f"CRITICAL: Drive-by malware/APK trap ({apk_trap.get('filename', 'file')})", "points": 75}
            )

        if len(redirect_chain) > 1:
            score += 20
            breakdown.append({"rule": "Multiple redirects detected (> 1 hop)", "points": 20})

        if detected_forms:
            score += 35
            breakdown.append({"rule": "Sensitive credential/payment inputs requested", "points": 35})

        if len(urgency_flags) >= 2:
            score += 20
            breakdown.append({"rule": "Multiple urgency/fear keywords on landing page", "points": 20})
        elif len(urgency_flags) == 1:
            score += 15
            breakdown.append({"rule": "Urgency keyword detected on landing page", "points": 15})
        elif sandbox_error and any(
            kw in message.lower()
            for kw in ("blocked", "suspended", "kyc", "disconnected", "urgent", "pay now")
        ):
            score += 15
            breakdown.append({"rule": "Urgency wording in message (page unreachable)", "points": 15})

        if domain_age_days is not None and domain_age_days < 30:
            score += 20
            breakdown.append({"rule": "Newly created domain (< 30 days old)", "points": 20})

        if vt_malicious > 0:
            score += 30
            breakdown.append({"rule": f"VirusTotal malicious detections ({vt_malicious})", "points": 30})
        elif vt_suspicious > 0:
            score += 15
            breakdown.append({"rule": f"VirusTotal suspicious detections ({vt_suspicious})", "points": 15})

        if vision_data and vision_data.get("impersonated_brand"):
            score += 15
            breakdown.append(
                {"rule": f"Visual brand impersonation ({vision_data['impersonated_brand']})", "points": 15}
            )

    risk_score = min(100, score)
    status = _assign_status(risk_score)

    evidence: list[str] = []

    if ssrf_blocked:
        evidence.append(sandbox_error or "Blocked by SSRF Guard: unsafe or private network address.")
    elif apk_trap.get("detected"):
        evidence.append(apk_trap.get("warning", "Attempted drive-by APK/malware download was blocked safely."))
    else:
        if len(redirect_chain) > 1:
            evidence.append(
                "This link bounced through another hidden web address before opening, a common trick used to disguise scam sites."
            )
        elif not sandbox_error:
            evidence.append(
                "This link went straight to its destination without bouncing through hidden redirects."
            )

        if detected_forms:
            fields_text = _format_plain_fields(detected_forms)
            evidence.append(
                f"The page asks for sensitive details ({fields_text}). Trusted banks, utility boards, and government offices do not ask for these through message links."
            )
        elif not sandbox_error:
            evidence.append(
                "The page did not ask you to type any passwords, OTPs, PINs, or payment card details."
            )

        if urgency_flags:
            evidence.append(
                "The page uses urgent warnings and threats (such as blocking or disconnecting your service) to rush you into acting quickly."
            )
        elif sandbox_error:
            evidence.append(
                "The website could not be reached right now, which often happens when short-lived scam pages are taken down or broken."
            )
        else:
            evidence.append(
                "No scare tactics or urgent payment threats were found on the page."
            )

        if vt_malicious > 0 or vt_suspicious > 0:
            evidence.append("Independent security scanners have already flagged this web address as unsafe.")
        elif domain_age_days is not None and domain_age_days < 30:
            evidence.append(
                f"This website address appears brand new ({domain_age_days} days old), which is a classic warning sign of a temporary scam page."
            )
        elif domain_age_days is not None:
            evidence.append(
                f"This website address has existed for {domain_age_days} days and had no security scanner warnings."
            )

    lang_code = language if language in _SPOKEN_SCRIPTS else "en"
    script_key = "APK_TRAP" if apk_trap.get("detected") else status
    voice_script = _SPOKEN_SCRIPTS[lang_code][script_key]

    return {
        "risk_score": risk_score,
        "status": status,
        "evidence": evidence[:4],
        "score_breakdown": breakdown,
        "voice_script": voice_script,
        "language": lang_code,
    }


def build_cybercrime_report(
    redacted_message: str,
    extracted_url: str,
    sandbox_data: dict[str, Any],
    intel_data: dict[str, Any],
    vision_data: dict[str, Any],
    verdict_data: dict[str, Any],
) -> dict[str, str]:
    """Generate a ready-to-file 1930 / Chakshu complaint and a WhatsApp Family Safety Alert."""
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    defanged_initial = defang_url(extracted_url)
    defanged_final = defang_url(sandbox_data.get("final_url") or extracted_url)
    network = intel_data.get("network") or {}
    resolved_ip = network.get("ip") or (sandbox_data.get("ssrf_check") or {}).get("resolved_ip") or "Unresolved"
    asn = network.get("asn") or "N/A"
    spoofed = vision_data.get("impersonated_brand") or "Unverified / Unknown Sender"
    sha256_hash = sandbox_data.get("screenshot_sha256") or "N/A (No screenshot captured)"
    apk_trap = sandbox_data.get("apk_trap") or {}

    threat_type = (
        f"Malicious APK / Drive-By Malware ({apk_trap.get('filename')})"
        if apk_trap.get("detected")
        else f"Phishing / Social Engineering ({verdict_data['status']}, Score {verdict_data['risk_score']}/100)"
    )

    complaint_text = (
        "OFFICIAL CYBERCRIME INCIDENT REPORT (1930 / CHAKSHU - SANCHAR SAATHI)\n"
        f"Timestamp: {timestamp}\n"
        f"Threat Classification: {threat_type}\n"
        f"Suspect URL (Defanged): {defanged_initial}\n"
        f"Final Landing URL (Defanged): {defanged_final}\n"
        f"Resolved Host / ASN: {resolved_ip} ({asn})\n"
        f"Spoofed Identity: {spoofed}\n"
        f"Victim Message (PII Redacted): \"{redacted_message}\"\n"
        f"Forensic Screenshot SHA-256: {sha256_hash}\n"
        "Generated by: Scam SOC Crew (Sandboxed Browser Triage)"
    )

    brand_label = vision_data.get("impersonated_brand") or "suspicious"
    whatsapp_alert = (
        f"⚠️ Family Safety Alert: Fake {brand_label} scam link detected! "
        f"Verified as {verdict_data['status']} ({verdict_data['risk_score']}/100) by Scam SOC Crew. "
        "Do NOT click this link, do NOT install any APK, and NEVER share your OTP or UPI PIN. "
        "If targeted, report on Chakshu (sancharsaathi.gov.in) or call 1930."
    )

    return {
        "complaint_text": complaint_text,
        "whatsapp_alert": whatsapp_alert,
        "defanged_url": defanged_final,
    }


def generate_voice_audio(script_text: str, language: str = "en") -> str | None:
    """Synthesize spoken audio via ElevenLabs (eleven_v3) as base64 MP3."""
    api_key = os.getenv("ELEVENLABS_API_KEY", "").strip()
    if not api_key or not script_text.strip():
        return None

    voice_id = os.getenv("ELEVENLABS_VOICE_ID", ELEVENLABS_DEFAULT_VOICE_ID).strip() or ELEVENLABS_DEFAULT_VOICE_ID
    endpoint = f"https://api.elevenlabs.io/v1/text-to-speech/{voice_id}"
    headers = {
        "xi-api-key": api_key,
        "Content-Type": "application/json",
        "Accept": "audio/mpeg",
    }
    payload = {
        "text": script_text,
        "model_id": "eleven_v3",
        "language_code": language if language in ("en", "hi", "kn") else "en",
        "voice_settings": {
            "stability": 0.5,
            "similarity_boost": 0.75,
        },
    }

    try:
        resp = requests.post(
            endpoint,
            headers=headers,
            json=payload,
            timeout=ELEVENLABS_TIMEOUT_SECONDS,
        )
        if resp.status_code != 200 or not resp.content:
            print(f"[ElevenLabs] HTTP {resp.status_code}: {resp.text[:200]}")
            return None
        return base64.b64encode(resp.content).decode("utf-8")
    except requests.RequestException as exc:
        print(f"[ElevenLabs] Request failed: {exc}")
        return None
