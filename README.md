# Scam SOC Crew — Your Personal Link Scout

**Scam SOC Crew** helps everyday users safely inspect suspicious SMS, WhatsApp, and email links before clicking them. Instead of trusting a URL blindly, it detonates the link inside an isolated headless Chromium sandbox, enriches the destination with domain-age and threat-intelligence checks, scores the risk transparently, and delivers a calm, plain-language spoken verdict in **English**, **ಕನ್ನಡ (Kannada)**, or **हिन्दी (Hindi)**.

---

## Architecture Summary (For Judges)

```text
User Message + Language (en | kn | hi)
   │
   ▼
POST /api/analyze  (backend/main.py)
   ├── 1. Regex URL Extraction
   ├── 2. Safe Detonation Sandbox  (backend/sandbox.py)
   │      • Headless Chromium via Playwright (downloads disabled, 12s timeout)
   │      • Captures full HTTP + client-side redirect_chain & PNG screenshot
   │      • Inspects DOM for sensitive inputs (OTP, PIN, UPI, password, card, CVV, Aadhaar)
   │      • Scans visible text for social-engineering urgency keywords
   ├── 3. Threat Intelligence  (backend/intel.py)
   │      • WHOIS domain age calculation (with safe local demo host handling)
   │      • Optional VirusTotal v3 URL/domain reputation lookup
   ├── 4. Transparent Verdict & Multilingual Voice  (backend/verdict.py)
   │      • Rule-based 0–100 risk score → SAFE (<30) / SUSPICIOUS (30–59) / DANGEROUS (>=60)
   │      • 3–4 plain-language evidence bullets + 1930 / Chakshu next steps
   │      • ElevenLabs eleven_multilingual_v2 MP3 synthesis (or browser Web Speech fallback)
   ▼
Tailwind + Vanilla JS UI  (frontend/index.html)
```

### Safe Local Demo Routes
To demonstrate a full phishing redirect chain offline without touching real malware:
- `GET /mock-scam-redirect` → HTTP `302` redirect to `/mock-bescom-kyc`
- `GET /mock-bescom-kyc` → Clearly labeled `[DEMO ONLY]` fake BESCOM disconnection page requesting Mobile Number, UPI PIN, and OTP.

---

## Project Structure

```text
scam-soc-crew/
├── backend/
│   ├── main.py         # FastAPI app, CORS, demo routes, POST /api/analyze pipeline
│   ├── sandbox.py      # Playwright headless Chromium detonation & DOM/text inspection
│   ├── intel.py        # WHOIS domain age & VirusTotal v3 threat intelligence
│   └── verdict.py      # Rule-based risk scoring, multilingual scripts & ElevenLabs TTS
├── frontend/
│   └── index.html      # Tailwind CDN + Vanilla JS UI with Audio/Web Speech playback
├── requirements.txt
├── .env.example
└── README.md
```

---

## Local Setup & Run Instructions

### 1. Create and activate a virtual environment
```bash
cd scam-soc-crew
python3 -m venv .venv
source .venv/bin/activate   # On Windows: .venv\Scripts\activate
```

### 2. Install Python dependencies
```bash
pip install -r requirements.txt
```

### 3. Install Playwright's Chromium browser
```bash
playwright install chromium
```

### 4. Configure environment variables (optional keys)
```bash
cp .env.example .env
```
Edit `.env` if you have API keys:
- `VIRUSTOTAL_API_KEY` — Enables VirusTotal v3 reputation lookups (optional; skips cleanly if blank).
- `ELEVENLABS_API_KEY` — Enables neural multilingual MP3 voice verdicts via `eleven_multilingual_v2` (optional; the UI automatically falls back to `window.speechSynthesis` when omitted).
- `ELEVENLABS_VOICE_ID` — Optional ElevenLabs voice ID override.

### 5. Start the FastAPI server
```bash
uvicorn backend.main:app --reload
```
Open **[http://127.0.0.1:8000](http://127.0.0.1:8000)** in your browser and try the three one-click demo presets:
1. **Test Fake BESCOM KYC Scam** (`http://127.0.0.1:8000/mock-scam-redirect`)
2. **Test Safe Official Site** (`https://www.wikipedia.org`)
3. **Test Broken Link** (`https://nonexistent-demo-link.xyz`)
