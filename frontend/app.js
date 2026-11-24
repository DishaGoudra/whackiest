let selectedLanguage = "en";
let currentViewMode = "family";
let lastAnalysisData = null;
let currentVoiceScript = "";
let currentAudioBase64 = null;
let emergencyScript = "";
let emergencyAudioBase64 = null;
let loadingTimer = null;
let isSpeakingFallback = false;
let demoPresets = {};

const LOADING_STEPS = [
  "Validating SSRF & scrubbing PII...",
  "Opening in stealth Android mobile sandbox...",
  "Running Gemini Vision & Threat Intel...",
  "Synthesizing ElevenLabs voice verdict...",
];

const SPEECH_LANG_MAP = { en: "en-IN", kn: "kn-IN", hi: "hi-IN" };

function loadDemoPresets() {
  const origin = window.location.origin;
  demoPresets = {
    bescom: `[DEMO] Electricity KYC notice: ${origin}/mock-scam-redirect`,
    apk: `[DEMO] Verification app update link: ${origin}/mock-apk-trap`,
    ssrf: "[DEMO] Restricted scheme check: gopher://example.com/test",
    safe: "[DEMO] Official reference site: https://www.wikipedia.org",
  };
}

loadDemoPresets();

function setViewMode(mode) {
  currentViewMode = mode;
  const body = document.getElementById("appBody");
  const familyBtn = document.getElementById("modeFamilyBtn");
  const socBtn = document.getElementById("modeSocBtn");
  const familyView = document.getElementById("familyView");
  const socView = document.getElementById("socView");

  if (mode === "soc") {
    body.classList.add("soc-mode");
    socBtn.className = "rounded-lg bg-emerald-400 px-3.5 py-2 font-mono text-xs font-extrabold text-slate-950 transition";
    familyBtn.className = "rounded-lg px-3.5 py-2 text-xs font-bold text-slate-300 transition hover:text-white";
    familyView.classList.add("hidden");
    socView.classList.remove("hidden");
  } else {
    body.classList.remove("soc-mode");
    familyBtn.className = "rounded-lg bg-sky-400 px-3.5 py-2 text-xs font-extrabold text-slate-950 transition";
    socBtn.className = "rounded-lg px-3.5 py-2 font-mono text-xs font-bold text-slate-300 transition hover:text-emerald-300";
    socView.classList.add("hidden");
    familyView.classList.remove("hidden");
  }
}

async function applyPreset(key) {
  if (!demoPresets[key]) await loadDemoPresets();
  document.getElementById("messageInput").value = demoPresets[key] || "";
  hideError();
}

function selectLanguage(lang) {
  selectedLanguage = lang;
  document.querySelectorAll(".lang-pill").forEach((btn) => {
    const active = btn.dataset.lang === lang;
    btn.className = active
      ? "lang-pill rounded-full border border-sky-400 bg-sky-500 px-4 py-1.5 text-sm font-bold text-slate-950 transition"
      : "lang-pill rounded-full border border-slate-700 bg-slate-800 px-4 py-1.5 text-sm font-semibold text-slate-200 transition hover:border-slate-500";
  });
}

function showError(msg) {
  const el = document.getElementById("errorBanner");
  el.textContent = msg;
  el.classList.remove("hidden");
}

function hideError() {
  const el = document.getElementById("errorBanner");
  el.classList.add("hidden");
  el.textContent = "";
}

function setLoadingStep(activeIdx) {
  document.getElementById("loadingHeadline").textContent = LOADING_STEPS[activeIdx];
  LOADING_STEPS.forEach((_, idx) => {
    const stepEl = document.getElementById(`step-${idx}`);
    if (idx < activeIdx) {
      stepEl.className = "rounded-lg border border-emerald-500/40 bg-emerald-500/15 px-3 py-2 text-xs font-semibold text-emerald-200";
    } else if (idx === activeIdx) {
      stepEl.className = "rounded-lg border border-sky-500/50 bg-sky-500/15 px-3 py-2 text-xs font-semibold text-sky-200";
    } else {
      stepEl.className = "rounded-lg border border-slate-800 bg-slate-900 px-3 py-2 text-xs font-semibold text-slate-400";
    }
  });
}

function startLoading() {
  document.getElementById("inspectBtn").disabled = true;
  document.getElementById("inspectBtnLabel").textContent = "Inspecting...";
  document.getElementById("loadingBox").classList.remove("hidden");
  let stepIdx = 0;
  setLoadingStep(stepIdx);
  clearInterval(loadingTimer);
  loadingTimer = setInterval(() => {
    if (stepIdx < LOADING_STEPS.length - 1) {
      stepIdx += 1;
      setLoadingStep(stepIdx);
    }
  }, 1300);
}

function stopLoading() {
  clearInterval(loadingTimer);
  loadingTimer = null;
  document.getElementById("inspectBtn").disabled = false;
  document.getElementById("inspectBtnLabel").textContent = "Inspect Safely";
  document.getElementById("loadingBox").classList.add("hidden");
}

function stopAllAudio() {
  const audioEl = document.getElementById("elevenLabsAudio");
  audioEl.pause();
  audioEl.currentTime = 0;
  if ("speechSynthesis" in window) window.speechSynthesis.cancel();
  isSpeakingFallback = false;
  document.getElementById("playAudioLabel").textContent = "Play Voice Verdict";
}

function toggleVoicePlayback() {
  const audioEl = document.getElementById("elevenLabsAudio");
  if (currentAudioBase64) {
    if (audioEl.paused) {
      audioEl.play().catch(() => {});
      document.getElementById("playAudioLabel").textContent = "Pause Voice Verdict";
    } else {
      audioEl.pause();
      document.getElementById("playAudioLabel").textContent = "Play Voice Verdict";
    }
    return;
  }
  if (!("speechSynthesis" in window)) return;
  if (isSpeakingFallback) {
    stopAllAudio();
    return;
  }
  window.speechSynthesis.cancel();
  const utterance = new SpeechSynthesisUtterance(currentVoiceScript);
  utterance.lang = SPEECH_LANG_MAP[selectedLanguage] || "en-IN";
  utterance.rate = 0.95;
  utterance.onend = utterance.onerror = () => {
    isSpeakingFallback = false;
    document.getElementById("playAudioLabel").textContent = "Play Voice Verdict";
  };
  isSpeakingFallback = true;
  document.getElementById("playAudioLabel").textContent = "Stop Voice Verdict";
  window.speechSynthesis.speak(utterance);
}

function copyText(elementId, buttonId, originalLabel) {
  const text = document.getElementById(elementId).textContent || "";
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(text).then(() => {
      const btn = document.getElementById(buttonId);
      btn.textContent = "Copied!";
      setTimeout(() => { btn.textContent = originalLabel; }, 1800);
    });
  }
}

function downloadFamilySafetyCard() {
  if (!lastAnalysisData) return;
  const canvas = document.getElementById("safetyCardCanvas");
  const ctx = canvas.getContext("2d");
  const status = lastAnalysisData.status || "DANGEROUS";
  const score = lastAnalysisData.risk_score ?? 0;
  const brand = (lastAnalysisData.vision && lastAnalysisData.vision.impersonated_brand) || "Suspicious Link";
  const defanged = lastAnalysisData.defanged_url || "";

  ctx.fillStyle = "#0f172a";
  ctx.fillRect(0, 0, 900, 520);

  ctx.fillStyle = status === "SAFE" ? "#10b981" : status === "SUSPICIOUS" ? "#f59e0b" : "#e11d48";
  ctx.fillRect(0, 0, 900, 110);

  ctx.fillStyle = "#ffffff";
  ctx.font = "bold 34px sans-serif";
  ctx.fillText(`FAMILY SAFETY ALERT · ${status} (${score}/100)`, 40, 68);

  ctx.fillStyle = "#e2e8f0";
  ctx.font = "bold 26px sans-serif";
  ctx.fillText(`Detected Target: ${brand}`, 40, 170);

  ctx.fillStyle = "#94a3b8";
  ctx.font = "18px monospace";
  ctx.fillText(`Defanged URL: ${defanged.slice(0, 68)}`, 40, 215);

  ctx.fillStyle = "#f8fafc";
  ctx.font = "22px sans-serif";
  const lines = [
    "1. Do NOT click this link or install any .apk file.",
    "2. NEVER enter your OTP, UPI PIN, or Aadhaar on message links.",
    "3. Report scams at sancharsaathi.gov.in (Chakshu) or dial 1930.",
  ];
  lines.forEach((line, idx) => ctx.fillText(line, 40, 285 + idx * 48));

  ctx.fillStyle = "#38bdf8";
  ctx.font = "bold 18px sans-serif";
  ctx.fillText("Verified safely inside an isolated sandbox by Scam SOC Crew", 40, 475);

  canvas.classList.remove("hidden");
  canvas.classList.add("mt-4", "w-full", "rounded-xl", "border", "border-slate-700");
  canvas.scrollIntoView({ behavior: "smooth", block: "center" });
}

function openDamageControl() {
  const modal = document.getElementById("damageControlModal");
  modal.classList.remove("hidden");
  modal.classList.add("flex");
}

function closeDamageControl() {
  const modal = document.getElementById("damageControlModal");
  modal.classList.add("hidden");
  modal.classList.remove("flex");
  const audioEl = document.getElementById("emergencyAudioEl");
  audioEl.pause();
  if ("speechSynthesis" in window) window.speechSynthesis.cancel();
}

async function loadEmergencyPlan(enteredCredentials) {
  const box = document.getElementById("emergencyPlanBox");
  const title = document.getElementById("emergencyPlanTitle");
  const stepsList = document.getElementById("emergencyStepsList");
  const scriptEl = document.getElementById("emergencyScriptText");
  const audioEl = document.getElementById("emergencyAudioEl");

  box.classList.remove("hidden");
  title.textContent = enteredCredentials
    ? "Golden-Hour Emergency Checklist (Act Now)"
    : "Safe Cleanup Checklist (Low Risk)";
  scriptEl.textContent = "Preparing calm voice instructions...";
  audioEl.classList.add("hidden");

  const steps = enteredCredentials
    ? [
        "1. Dial 1930 immediately (National Cyber Crime Helpline) to freeze fraudulent UPI/bank transfers.",
        "2. Call your bank's official toll-free number to block UPI, debit/credit cards, and net banking.",
        "3. If an unknown .apk app was downloaded, turn OFF mobile data/Wi-Fi immediately and uninstall it in Safe Mode.",
        "4. File the pre-filled complaint from Scam SOC Crew on cybercrime.gov.in and Chakshu (sancharsaathi.gov.in).",
      ]
    : [
        "1. Close the browser tab immediately — do NOT interact with any buttons on the page.",
        "2. Delete the SMS/WhatsApp message and block the sender number.",
        "3. Check your Downloads folder to make sure no .apk file was saved.",
        "4. Report the sender on TRAI DND / Chakshu to protect others.",
      ];

  stepsList.replaceChildren();
  steps.forEach((stepText) => {
    const li = document.createElement("li");
    li.className = "rounded-lg border border-slate-800 bg-slate-900/80 px-3 py-2";
    li.textContent = stepText;
    stepsList.appendChild(li);
  });

  try {
    const res = await fetch("/api/emergency-audio", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ language: selectedLanguage, entered_credentials: enteredCredentials }),
    });
    const data = await res.json();
    emergencyScript = data.script || "";
    emergencyAudioBase64 = data.voice_audio_base64 || null;
    scriptEl.textContent = emergencyScript;
    if (emergencyAudioBase64) {
      audioEl.src = `data:audio/mpeg;base64,${emergencyAudioBase64}`;
      audioEl.classList.remove("hidden");
    }
  } catch (e) {
    scriptEl.textContent = "Call 1930 immediately and contact your bank's official helpline.";
  }
}

function playEmergencyAudio() {
  const audioEl = document.getElementById("emergencyAudioEl");
  if (emergencyAudioBase64) {
    audioEl.play().catch(() => {});
    return;
  }
  if ("speechSynthesis" in window && emergencyScript) {
    window.speechSynthesis.cancel();
    const u = new SpeechSynthesisUtterance(emergencyScript);
    u.lang = SPEECH_LANG_MAP[selectedLanguage] || "en-IN";
    window.speechSynthesis.speak(u);
  }
}

function renderSocMode(data) {
  const sec = data.security_profile || {};
  const pii = data.pii_redacted || {};
  const totalPii = (pii.phone || 0) + (pii.aadhaar || 0) + (pii.account || 0);

  const secGrid = document.getElementById("socSecurityGrid");
  secGrid.replaceChildren();
  const telemetryItems = [
    ["SSRF_GUARD", data.ssrf_blocked ? "BLOCKED_ATTACK" : sec.ssrf_guard || "ACTIVE"],
    ["STEALTH_PROFILE", sec.stealth_mobile || "Android 14 Mobile"],
    ["PERMISSIONS", sec.permissions || "ZERO_TRUST_DENIED"],
    ["DOWNLOAD_GUARD", data.apk_trap && data.apk_trap.detected ? `INTERCEPTED: ${data.apk_trap.filename}` : "INTERCEPT & ABORT"],
    ["DPDP_PII_SCRUBBER", totalPii > 0 ? `REDACTED ${totalPii} ITEM(S)` : "CLEAN (0 PII FOUND)"],
    ["URL_DEFANGING", "ACTIVE (hxxp / [.])"],
  ];
  telemetryItems.forEach(([k, v]) => {
    const card = document.createElement("div");
    card.className = "rounded-lg border border-emerald-500/25 bg-slate-950 p-3";
    const keyP = document.createElement("p");
    keyP.className = "text-[10px] text-slate-500";
    keyP.textContent = k;
    const valP = document.createElement("p");
    valP.className = "mt-1 font-bold text-emerald-300";
    valP.textContent = v;
    card.append(keyP, valP);
    secGrid.appendChild(card);
  });

  const net = (data.intel && data.intel.network) || {};
  const vt = (data.intel && data.intel.virustotal) || {};
  const netDump = document.getElementById("socNetworkDump");
  netDump.replaceChildren();
  const netRows = [
    ["HTTP_STATUS:", String(data.http_status ?? "N/A")],
    ["RESOLVED_IP:", net.ip || "Unresolved"],
    ["ASN / ORG:", `${net.asn || "N/A"} · ${net.org || "N/A"}`],
    ["GEO_COUNTRY:", net.country || "N/A"],
    ["WHOIS_AGE:", (data.intel && data.intel.domain_age_summary) || "N/A"],
    ["VIRUSTOTAL:", vt.note || "N/A"],
  ];
  netRows.forEach(([label, value]) => {
    const p = document.createElement("p");
    const s1 = document.createElement("span");
    s1.className = "text-slate-500 mr-2";
    s1.textContent = label;
    const s2 = document.createElement("span");
    s2.className = "text-cyan-300";
    s2.textContent = value;
    p.append(s1, s2);
    netDump.appendChild(p);
  });

  const headers = data.response_headers || {};
  document.getElementById("socHeadersDump").textContent =
    Object.keys(headers).length > 0 ? JSON.stringify(headers, null, 2) : "// No HTTP response headers captured";

  const hops = data.defanged_redirect_chain || [data.defanged_url || ""];
  const graphEl = document.getElementById("socRedirectGraph");
  graphEl.replaceChildren();
  hops.forEach((h, i) => {
    const div = document.createElement("div");
    div.className = "rounded-lg border border-slate-800 bg-slate-950 px-3 py-2 text-emerald-300 break-all";
    div.textContent = `[HOP_${i + 1}] ${h}`;
    graphEl.appendChild(div);
  });

  const rules = (data.verdict && data.verdict.score_breakdown) || [];
  const rulesEl = document.getElementById("socScoreRules");
  rulesEl.replaceChildren();
  if (rules.length > 0) {
    rules.forEach((r) => {
      const row = document.createElement("div");
      row.className = "flex justify-between rounded-lg border border-slate-800 bg-slate-950 px-3 py-2";
      const left = document.createElement("span");
      left.className = "text-slate-200";
      left.textContent = r.rule;
      const right = document.createElement("span");
      right.className = "font-bold text-rose-400";
      right.textContent = `+${r.points}`;
      row.append(left, right);
      rulesEl.appendChild(row);
    });
  } else {
    const empty = document.createElement("div");
    empty.className = "rounded-lg border border-slate-800 bg-slate-950 px-3 py-2 text-emerald-300";
    empty.textContent = "No risk rules triggered (0 pts)";
    rulesEl.appendChild(empty);
  }

  const domInputs = data.dom_inputs || [];
  document.getElementById("socDomDump").textContent =
    domInputs.length > 0 ? JSON.stringify(domInputs, null, 2) : "// No DOM form inputs extracted";

  document.getElementById("socSha256").textContent = data.screenshot_sha256 || "N/A (No screenshot)";
  document.getElementById("socRedactedMsg").textContent = data.redacted_message || "";
}

function renderResults(data) {
  stopAllAudio();
  lastAnalysisData = data;

  const status = data.status || "SUSPICIOUS";
  const riskScore = data.risk_score ?? 0;
  const evidence = data.evidence || [];
  const intel = data.intel || {};
  const vision = data.vision || {};
  const actionKit = data.action_kit || {};

  const critBanner = document.getElementById("criticalAlertBanner");
  if (data.apk_trap && data.apk_trap.detected) {
    critBanner.classList.remove("hidden");
    document.getElementById("criticalAlertTag").textContent = "CRITICAL · MALICIOUS APK / MALWARE INTERCEPTED";
    document.getElementById("criticalAlertTitle").textContent = `Blocked Drive-By Download: ${data.apk_trap.filename}`;
    document.getElementById("criticalAlertDetail").textContent = data.apk_trap.warning;
  } else if (data.ssrf_blocked) {
    critBanner.classList.remove("hidden");
    document.getElementById("criticalAlertTag").textContent = "ENTERPRISE SSRF GUARD · REQUEST BLOCKED";
    document.getElementById("criticalAlertTitle").textContent = "Internal / Unsafe URI Target Blocked Safely";
    document.getElementById("criticalAlertDetail").textContent = data.error || "Unsafe URI rejected before browser launch.";
  } else {
    critBanner.classList.add("hidden");
  }

  const pii = data.pii_redacted || {};
  const totalPii = (pii.phone || 0) + (pii.aadhaar || 0) + (pii.account || 0);
  const piiBanner = document.getElementById("piiNoticeBanner");
  if (totalPii > 0) {
    piiBanner.classList.remove("hidden");
    piiBanner.textContent = `Privacy Shield (DPDP Act): Automatically redacted ${totalPii} personal identifier(s) (phone/Aadhaar/account) before external analysis or reporting.`;
  } else {
    piiBanner.classList.add("hidden");
  }

  const styles = {
    DANGEROUS: {
      card: "rounded-2xl border border-rose-500/50 bg-gradient-to-br from-rose-950 via-rose-900/60 to-slate-900 p-6 shadow-xl",
      badge: "inline-flex items-center rounded-xl bg-rose-500 px-4 py-1.5 text-xl font-black tracking-wide text-white",
    },
    SUSPICIOUS: {
      card: "rounded-2xl border border-amber-500/50 bg-gradient-to-br from-amber-950 via-amber-900/50 to-slate-900 p-6 shadow-xl",
      badge: "inline-flex items-center rounded-xl bg-amber-400 px-4 py-1.5 text-xl font-black tracking-wide text-slate-950",
    },
    SAFE: {
      card: "rounded-2xl border border-emerald-500/50 bg-gradient-to-br from-emerald-950 via-emerald-900/50 to-slate-900 p-6 shadow-xl",
      badge: "inline-flex items-center rounded-xl bg-emerald-400 px-4 py-1.5 text-xl font-black tracking-wide text-slate-950",
    },
  };
  const st = styles[status] || styles.SUSPICIOUS;
  document.getElementById("verdictCard").className = st.card;
  const badge = document.getElementById("verdictBadge");
  badge.className = st.badge;
  badge.textContent = status;
  document.getElementById("riskScoreValue").textContent = String(riskScore);
  document.getElementById("domainSummaryBadge").textContent = intel.domain_age_summary || "Domain checked";

  currentVoiceScript = data.voice_script || "";
  currentAudioBase64 = data.voice_audio_base64 || null;
  document.getElementById("voiceScriptText").textContent = currentVoiceScript;
  const audioEl = document.getElementById("elevenLabsAudio");
  if (currentAudioBase64) {
    audioEl.src = `data:audio/mpeg;base64,${currentAudioBase64}`;
    audioEl.classList.remove("hidden");
    audioEl.onplay = () => { document.getElementById("playAudioLabel").textContent = "Pause Voice Verdict"; };
    audioEl.onpause = audioEl.onended = () => { document.getElementById("playAudioLabel").textContent = "Play Voice Verdict"; };
    document.getElementById("audioSourceLabel").textContent = "ElevenLabs v3 multilingual neural audio ready";
  } else {
    audioEl.removeAttribute("src");
    audioEl.classList.add("hidden");
    document.getElementById("audioSourceLabel").textContent = "Using browser speech synthesis fallback";
  }

  document.getElementById("visionSourceLabel").textContent =
    vision.source === "gemini_vision"
      ? "Analyzed live by Gemini Vision Multimodal AI"
      : "Analyzed via visual & behavioral scam heuristics";
  document.getElementById("visionVerdictText").textContent = vision.visual_verdict || "Visual analysis complete.";
  const brandPill = document.getElementById("brandSpoofPill");
  if (vision.impersonated_brand) {
    brandPill.classList.remove("hidden");
    brandPill.textContent = `Impersonates: ${vision.impersonated_brand} (Real: ${vision.official_domain || "official portal"})`;
  } else {
    brandPill.classList.add("hidden");
  }

  const tactics = vision.manipulation_tactics || [];
  const tacticsGrid = document.getElementById("tacticsGrid");
  tacticsGrid.replaceChildren();
  if (tactics.length > 0) {
    tactics.forEach((t) => {
      const card = document.createElement("div");
      card.className = "rounded-xl border border-indigo-500/30 bg-indigo-950/30 p-3.5";
      const titleP = document.createElement("p");
      titleP.className = "text-xs font-extrabold uppercase tracking-wider text-indigo-300";
      titleP.textContent = t.tactic;
      const detailP = document.createElement("p");
      detailP.className = "mt-1 text-xs leading-relaxed text-slate-200";
      detailP.textContent = t.detail;
      card.append(titleP, detailP);
      tacticsGrid.appendChild(card);
    });
  } else {
    const emptyP = document.createElement("p");
    emptyP.className = "text-xs text-slate-400";
    emptyP.textContent = "No coercive psychological manipulation tactics detected.";
    tacticsGrid.appendChild(emptyP);
  }

  const evidenceList = document.getElementById("evidenceList");
  evidenceList.replaceChildren();
  evidence.forEach((item) => {
    const li = document.createElement("li");
    li.className = "flex items-start gap-2.5 rounded-xl border border-slate-800 bg-slate-950 p-3";
    const bullet = document.createElement("span");
    bullet.className = status === "SAFE" ? "mt-0.5 font-bold text-emerald-400" : status === "SUSPICIOUS" ? "mt-0.5 font-bold text-amber-400" : "mt-0.5 font-bold text-rose-400";
    bullet.textContent = "•";
    const textSpan = document.createElement("span");
    textSpan.textContent = item;
    li.append(bullet, textSpan);
    evidenceList.appendChild(li);
  });

  const nextBox = document.getElementById("nextStepsBody");
  nextBox.replaceChildren();
  const alertDiv = document.createElement("div");
  const ul = document.createElement("ul");
  ul.className = "space-y-2 text-slate-200";
  if (status === "DANGEROUS" || status === "SUSPICIOUS") {
    alertDiv.className = "rounded-xl border border-rose-500/30 bg-rose-950/40 p-3.5 text-rose-100 font-semibold";
    alertDiv.textContent = "Do NOT enter your OTP, UPI PIN, Aadhaar, or install any app from this link.";
    [
      "1. Delete this message immediately and block the sender.",
      "2. Verify bills or bank alerts only inside the official app.",
      "3. Copy the pre-filled complaint below to report on Chakshu or call 1930.",
    ].forEach((step) => {
      const li = document.createElement("li");
      li.textContent = step;
      ul.appendChild(li);
    });
  } else {
    alertDiv.className = "rounded-xl border border-emerald-500/30 bg-emerald-950/40 p-3.5 text-emerald-100 font-semibold";
    alertDiv.textContent = "No obvious scam traps or malicious downloads were detected.";
    const li = document.createElement("li");
    li.textContent = "Always double-check the domain spelling and never share an OTP or UPI PIN with anyone.";
    ul.appendChild(li);
  }
  nextBox.append(alertDiv, ul);

  document.getElementById("complaintPreview").textContent = actionKit.complaint_text || "";
  document.getElementById("whatsappPreview").textContent = actionKit.whatsapp_alert || "";

  document.getElementById("pageTitleLine").textContent = data.page_title ? `Page title: ${data.page_title}` : "Page title unavailable";
  document.getElementById("finalUrlPill").textContent = data.defanged_url || "";

  const hops = data.defanged_redirect_chain || [];
  const redirectList = document.getElementById("redirectChainList");
  redirectList.replaceChildren();
  hops.forEach((hopUrl, idx) => {
    const li = document.createElement("li");
    li.className = "flex items-start gap-2.5 rounded-lg border border-slate-800 bg-slate-950 p-2.5 text-xs";
    const numSpan = document.createElement("span");
    numSpan.className = "inline-flex h-5 w-5 shrink-0 items-center justify-center rounded-full bg-slate-800 font-bold text-sky-300";
    numSpan.textContent = String(idx + 1);
    const urlSpan = document.createElement("span");
    urlSpan.className = "break-all font-mono text-slate-200";
    urlSpan.textContent = hopUrl;
    li.append(numSpan, urlSpan);
    redirectList.appendChild(li);
  });

  document.getElementById("intelNote").textContent = (intel.virustotal && intel.virustotal.note) || "Threat intel check completed.";

  const img = document.getElementById("sandboxScreenshot");
  const fallback = document.getElementById("screenshotFallback");
  if (data.screenshot_base64) {
    img.src = `data:image/png;base64,${data.screenshot_base64}`;
    img.classList.remove("hidden");
    fallback.classList.add("hidden");
  } else {
    img.classList.add("hidden");
    fallback.classList.remove("hidden");
    fallback.textContent = data.apk_trap && data.apk_trap.detected
      ? `Screenshot skipped — drive-by download (${data.apk_trap.filename}) was intercepted safely before rendering.`
      : data.error || "No screenshot captured.";
  }

  renderSocMode(data);

  const panel = document.getElementById("resultsPanel");
  panel.classList.remove("hidden");
  panel.scrollIntoView({ behavior: "smooth", block: "start" });
}

async function inspectMessage() {
  hideError();
  stopAllAudio();
  const message = document.getElementById("messageInput").value.trim();
  if (!message) {
    showError("Please paste a suspicious message or URL first (or click a Demo Preset above).");
    return;
  }

  startLoading();
  try {
    const response = await fetch("/api/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ message, language: selectedLanguage }),
    });
    const data = await response.json();
    if (!response.ok) {
      showError(data.error || data.detail || "Could not analyze that message.");
      return;
    }
    renderResults(data);
  } catch (err) {
    showError("Unable to reach the backend server. Ensure uvicorn is running.");
  } finally {
    stopLoading();
  }
}
