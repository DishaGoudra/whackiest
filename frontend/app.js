let selectedLanguage = "en";
let currentViewMode = "family";
let lastAnalysisData = null;
let currentVoiceScript = "";
let currentAudioBase64 = null;
let emergencyScript = "";
let emergencyAudioBase64 = null;
let isSpeakingFallback = false;
let speechRate = 1.0;
let isScreenshotBlurred = true;
let demoPresets = {};
let activePresetKey = null;
let spotGuess = null;
let lastFocusedElement = null;
let lastClearedHistory = null;
let uploadedImageBase64 = null;

const HISTORY_STORAGE_KEY = "scam_soc_recent_scans_v1";
const SCOUT_STORAGE_KEY = "scam_soc_scout_v1";
const WRONG_VERDICT_KEY = "scam_soc_wrong_verdicts_v1";
const THEME_STORAGE_KEY = "scam_soc_theme_v1";

const LANGUAGES_25 = [
  { code: "en", label: "English", native: "English" },
  { code: "hi", label: "Hindi", native: "हिन्दी" },
  { code: "kn", label: "Kannada", native: "ಕನ್ನಡ" },
  { code: "ta", label: "Tamil", native: "தமிழ்" },
  { code: "te", label: "Telugu", native: "తెలుగు" },
  { code: "ml", label: "Malayalam", native: "മലയാളം" },
  { code: "mr", label: "Marathi", native: "मराठी" },
  { code: "bn", label: "Bengali", native: "বাংলা" },
  { code: "gu", label: "Gujarati", native: "ગુજરાતી" },
  { code: "pa", label: "Punjabi", native: "ਪੰਜਾਬੀ" },
  { code: "ur", label: "Urdu", native: "اردو" },
  { code: "ar", label: "Arabic", native: "العربية" },
  { code: "es", label: "Spanish", native: "Español" },
  { code: "fr", label: "French", native: "Français" },
  { code: "de", label: "German", native: "Deutsch" },
  { code: "ja", label: "Japanese", native: "日本語" },
  { code: "ko", label: "Korean", native: "한국어" },
  { code: "pt", label: "Portuguese", native: "Português" },
  { code: "id", label: "Indonesian", native: "Bahasa Indonesia" },
  { code: "vi", label: "Vietnamese", native: "Tiếng Việt" },
  { code: "tr", label: "Turkish", native: "Türkçe" },
  { code: "ru", label: "Russian", native: "Русский" },
  { code: "it", label: "Italian", native: "Italiano" },
  { code: "nl", label: "Dutch", native: "Nederlands" },
  { code: "pl", label: "Polish", native: "Polski" },
];

const LOADING_STEPS = [
  "Validating SSRF guard and scrubbing personal numbers...",
  "Opening inside isolated mobile browser...",
  "Running visual, TLS, and threat intel checks...",
  "Preparing verdict and voice summary...",
];

const SPEECH_LANG_MAP = {
  en: "en-IN", hi: "hi-IN", kn: "kn-IN", ta: "ta-IN", te: "te-IN",
  ml: "ml-IN", mr: "mr-IN", bn: "bn-IN", gu: "gu-IN", pa: "pa-IN",
  ur: "ur-PK", ar: "ar-SA", es: "es-ES", fr: "fr-FR", de: "de-DE",
  ja: "ja-JP", ko: "ko-KR", pt: "pt-PT", id: "id-ID", vi: "vi-VN",
  tr: "tr-TR", ru: "ru-RU", it: "it-IT", nl: "nl-NL", pl: "pl-PL",
};

const UI_STRINGS = {
  en: {
    nav_history: "History",
    nav_help: "Help",
    nav_sos: "Already clicked or shared OTP",
    hero_title: "Check a suspicious link before anyone in your family opens it",
    hero_sub: "Paste an SMS, WhatsApp forward, or web address. We open it inside an isolated browser, mask personal numbers automatically, and explain what it does in 25 languages.",
    input_label: "Message or link to inspect",
    privacy_line: "Aadhaar, PAN, UPI IDs, phone numbers, and bank numbers are redacted before external checks. Scan history stays in your browser only.",
    presets_label: "Sample cases",
    lang_label: "Verdict and voice language (25 supported)",
    inspect_btn: "Inspect safely",
    verdict_kicker: "Scout security verdict",
    voice_title: "Calm voice verdict",
    vision_title: "Visual and manipulation analysis",
    evidence_title: "Why this was flagged",
    next_title: "What to do next",
    action_title: "Action kit",
  },
  kn: {
    nav_history: "ಇತಿಹಾಸ",
    nav_help: "ಸಹಾಯ",
    nav_sos: "ಲಿಂಕ್ ಒತ್ತಿದ್ದೀರಾ / OTP ಹಂಚಿದ್ದೀರಾ",
    hero_title: "ನಿಮ್ಮ ಕುಟುಂಬದವರು ತೆರೆಯುವ ಮೊದಲು ಅನುಮಾನಾಸ್ಪದ ಲಿಂಕ್ ಪರಿಶೀಲಿಸಿ",
    hero_sub: "SMS, WhatsApp ಸಂದೇಶ ಅಥವಾ ಲಿಂಕ್ ಅನ್ನು ಇಲ್ಲಿ ಅಂಟಿಸಿ. ನಾವು ಅದನ್ನು ಸುರಕ್ಷಿತ ಬ್ರೌಸರ್‌ನಲ್ಲಿ ತೆರೆದು, ವೈಯಕ್ತಿಕ ಸಂಖ್ಯೆಗಳನ್ನು ಮರೆಮಾಡಿ, 25 ಭಾಷೆಗಳಲ್ಲಿ ವಿವರಿಸುತ್ತೇವೆ.",
    input_label: "ಪರಿಶೀಲಿಸಬೇಕಾದ ಸಂದೇಶ ಅಥವಾ ಲಿಂಕ್",
    privacy_line: "ಆಧಾರ್, ಪ್ಯಾನ್, ಯುಪಿಐ, ಫೋನ್ ಮತ್ತು ಬ್ಯಾಂಕ್ ಸಂಖ್ಯೆಗಳನ್ನು ಸ್ವಯಂಚಾಲಿತವಾಗಿ ಮರೆಮಾಡಲಾಗುತ್ತದೆ. ಇತಿಹಾಸ ನಿಮ್ಮ ಬ್ರೌಸರ್‌ನಲ್ಲಿ ಮಾತ್ರ ಉಳಿಯುತ್ತದೆ.",
    presets_label: "ಮಾದರಿ ಪ್ರಕರಣಗಳು",
    lang_label: "ತೀರ್ಪು ಮತ್ತು ಧ್ವನಿ ಭಾಷೆ (25 ಭಾಷೆಗಳು)",
    inspect_btn: "ಸುರಕ್ಷಿತವಾಗಿ ಪರಿಶೀಲಿಸಿ",
    verdict_kicker: "ಸ್ಕೌಟ್ ಭದ್ರತಾ ತೀರ್ಪು",
    voice_title: "ಶಾಂತ ಧ್ವನಿ ವಿವರಣೆ",
    vision_title: "ದೃಶ್ಯ ಮತ್ತು ವಂಚನೆ ವಿಶ್ಲೇಷಣೆ",
    evidence_title: "ಇದನ್ನು ಏಕೆ ಗುರುತಿಸಲಾಗಿದೆ",
    next_title: "ಮುಂದೆ ಏನು ಮಾಡಬೇಕು",
    action_title: "ತಕ್ಷಣದ ಕ್ರಮ ಕಿಟ್",
  },
  hi: {
    nav_history: "इतिहास",
    nav_help: "सहायता",
    nav_sos: "लिंक खोला या OTP साझा किया",
    hero_title: "परिवार के किसी सदस्य के खोलने से पहले संदिग्ध लिंक की जांच करें",
    hero_sub: "SMS, WhatsApp संदेश या वेब पता यहाँ पेस्ट करें। हम इसे अलग ब्राउज़र में खोलते हैं, निजी नंबर छिपाते हैं और 25 भाषाओं में परिणाम समझाते हैं।",
    input_label: "जांच के लिए संदेश या लिंक",
    privacy_line: "आधार, पैन, यूपीआई, फ़ोन और बैंक नंबर स्वचालित रूप से छिपा दिए जाते हैं। जांच इतिहास केवल आपके ब्राउज़र में रहता है।",
    presets_label: "नमूना मामले",
    lang_label: "निर्णय और आवाज़ की भाषा (25 भाषाएं)",
    inspect_btn: "सुरक्षित जांच करें",
    verdict_kicker: "स्काउट सुरक्षा निर्णय",
    voice_title: "शांत आवाज़ में सारांश",
    vision_title: "दृश्य और हेरफेर विश्लेषण",
    evidence_title: "चेतावनी के कारण",
    next_title: "आगे क्या करें",
    action_title: "त्वरित कार्रवाई किट",
  },
};

const FAQ_ITEMS = [
  {
    q: "What personal details are redacted?",
    a: "Phone numbers, Aadhaar numbers, PAN numbers, UPI IDs, email addresses, and bank account numbers are masked before external intel or AI checks run.",
  },
  {
    q: "What does the safe preview room do?",
    a: "It opens the URL inside an isolated preview browser away from your device, blocks private-network targets, stops file downloads, and captures a static screenshot.",
  },
  {
    q: "How should I read the 0 to 100 risk score?",
    a: "0 to 29 is Safe, 30 to 59 is Suspicious, and 60 to 100 is Dangerous. Every rule that added points is listed in SOC Analyst mode.",
  },
  {
    q: "What if I already clicked a link or entered an OTP?",
    a: "Use the SOS button in the top bar. Dial 1930 immediately for financial fraud, call your bank helpline to freeze UPI/cards, and report on sancharsaathi.gov.in.",
  },
  {
    q: "What is stored on my device?",
    a: "Only defanged URLs, risk scores, timestamps, and your local Scout progress are saved on this device. Nothing is shared with other users.",
  },
];

const BADGE_DEFS = [
  { id: "first_scan", label: "First scan", icon: '<path d="M12 20s7-3.5 7-8.75V6l-7-2.5L5 6v5.25C5 16.5 12 20 12 20z"/>' },
  { id: "caught_apk", label: "APK trap", icon: '<rect x="5" y="2" width="14" height="20" rx="2"/><line x1="12" y1="18" x2="12.01" y2="18"/>' },
  { id: "blocked_ssrf", label: "SSRF block", icon: '<rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>' },
  { id: "three_langs", label: "3+ langs", icon: '<circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/>' },
  { id: "opened_soc", label: "SOC mode", icon: '<polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/>' },
  { id: "exported_card", label: "Card saved", icon: '<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/>' },
];

/* --- THEME WITH SKIPEr MORPHING SVG & VIEW TRANSITIONS --- */
function applyTheme(theme) {
  document.documentElement.setAttribute("data-theme", theme);
  try { localStorage.setItem(THEME_STORAGE_KEY, theme); } catch {}
  const clipPath = document.getElementById("skiperClipPath");
  const core = document.getElementById("skiperSunCore");
  const rays = document.getElementById("skiperSunRays");
  const isDark = theme === "dark";
  if (clipPath && core && rays) {
    clipPath.style.transform = isDark ? "translate(-12px, 10px)" : "translate(0px, 0px)";
    core.setAttribute("r", isDark ? "10" : "8");
    rays.style.transform = isDark ? "rotate(-100deg) scale(0.5)" : "rotate(0deg) scale(1)";
    rays.style.opacity = isDark ? "0" : "1";
  }
}

function toggleTheme(event) {
  const current = document.documentElement.getAttribute("data-theme") || "dark";
  const next = current === "dark" ? "light" : "dark";
  if (event && event.currentTarget) {
    const rect = event.currentTarget.getBoundingClientRect();
    document.documentElement.style.setProperty("--tx", `${rect.left + rect.width / 2}px`);
    document.documentElement.style.setProperty("--ty", `${rect.top + rect.height / 2}px`);
  }
  if (!document.startViewTransition || window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
    applyTheme(next);
    return;
  }
  document.startViewTransition(() => applyTheme(next));
}

/* --- SLIDING MODE THUMB --- */
function updateModeThumb() {
  const thumb = document.getElementById("modeThumb");
  const activeBtn = currentViewMode === "soc" ? document.getElementById("modeSocBtn") : document.getElementById("modeFamilyBtn");
  if (!thumb || !activeBtn) return;
  thumb.style.width = `${activeBtn.offsetWidth}px`;
  thumb.style.transform = `translateX(${activeBtn.offsetLeft - 4}px)`;
}

/* --- THREE-LINE NAV MENU --- */
function toggleNavMenu(forceClose) {
  const menu = document.getElementById("navMenuDropdown");
  const btn = document.getElementById("navMenuBtn");
  if (!menu || !btn) return;
  const shouldOpen = forceClose === true ? false : menu.classList.contains("hidden");
  if (shouldOpen) {
    menu.classList.remove("hidden");
    btn.setAttribute("aria-expanded", "true");
  } else {
    menu.classList.add("hidden");
    btn.setAttribute("aria-expanded", "false");
  }
}

/* --- SMOOTH ANIMATED CARET ON MESSAGE INPUT --- */
function updateSmoothCaret() {
  const input = document.getElementById("messageInput");
  const mirror = document.getElementById("caretMirror");
  const caret = document.getElementById("smoothCaret");
  if (!input || !mirror || !caret) return;

  if (document.activeElement !== input) {
    caret.style.opacity = "0";
    return;
  }

  const cs = window.getComputedStyle(input);
  mirror.style.boxSizing = "border-box";
  mirror.style.width = `${input.clientWidth}px`;
  mirror.style.font = `${cs.fontStyle} ${cs.fontWeight} ${cs.fontSize} ${cs.fontFamily}`;
  mirror.style.letterSpacing = cs.letterSpacing;
  mirror.style.wordSpacing = cs.wordSpacing;
  mirror.style.lineHeight = cs.lineHeight;
  mirror.style.padding = cs.padding;

  const pos = input.selectionDirection === "backward" ? (input.selectionStart ?? 0) : (input.selectionEnd ?? 0);
  const before = input.value.slice(0, pos);
  mirror.textContent = before;

  const marker = document.createElement("span");
  marker.textContent = "\u200b";
  mirror.appendChild(marker);

  const x = marker.offsetLeft + 4;
  const y = marker.offsetTop - input.scrollTop + 4;

  if (y < 6 || y > input.clientHeight - 10) {
    caret.style.opacity = "0";
    return;
  }
  caret.style.transform = `translate3d(${x}px, ${y}px, 0)`;
  caret.style.opacity = "1";
}

/* --- 25-LANGUAGE DROPDOWN --- */
function toggleLangDropdown(forceClose) {
  const menu = document.getElementById("langDropdownMenu");
  const btn = document.getElementById("langDropdownBtn");
  if (!menu || !btn) return;
  const shouldOpen = forceClose === true ? false : menu.classList.contains("hidden");
  if (shouldOpen) {
    menu.classList.remove("hidden");
    btn.setAttribute("aria-expanded", "true");
    renderLangDropdown("");
    const search = document.getElementById("langSearchInput");
    if (search) {
      search.value = "";
      search.focus();
    }
  } else {
    menu.classList.add("hidden");
    btn.setAttribute("aria-expanded", "false");
  }
}

function renderLangDropdown(query) {
  const list = document.getElementById("langDropdownList");
  if (!list) return;
  const q = (query || "").trim().toLowerCase();
  list.replaceChildren();
  const matches = LANGUAGES_25.filter((l) => !q || l.label.toLowerCase().includes(q) || l.native.toLowerCase().includes(q) || l.code.includes(q));
  if (matches.length === 0) {
    const empty = document.createElement("p");
    empty.className = "px-3 py-2 text-xs text-muted";
    empty.textContent = "No matching language";
    list.appendChild(empty);
    return;
  }
  matches.forEach((l) => {
    const active = l.code === selectedLanguage;
    const btn = document.createElement("button");
    btn.type = "button";
    btn.role = "option";
    btn.setAttribute("aria-selected", active ? "true" : "false");
    btn.className = active
      ? "focus-ring surface-raised flex w-full items-center justify-between rounded-lg px-3 py-2 text-left text-xs font-medium text-primary"
      : "focus-ring flex w-full items-center justify-between rounded-lg px-3 py-2 text-left text-xs text-secondary hover:bg-white/5 hover:text-primary";
    btn.onclick = () => {
      selectLanguage(l.code);
      toggleLangDropdown(true);
    };
    const left = document.createElement("span");
    left.textContent = `${l.native} · ${l.label}`;
    const right = document.createElement("span");
    right.className = "font-mono text-[11px] text-muted";
    right.textContent = active ? "Active" : l.code;
    btn.append(left, right);
    list.appendChild(btn);
  });
}

function filterLangDropdown(query) {
  renderLangDropdown(query);
}

const LEGAL_PAGES = {
  inspector: {
    title: "Link inspector",
    subtitle: "Check any SMS, WhatsApp forward, or URL safely",
    paragraphs: [
      "Paste any suspicious message into the main box. Scam SOC Crew extracts the web link, masks your personal numbers, and opens the page inside a separate mobile browser so your own phone is never exposed.",
      "You get a clear Safe, Suspicious, or Dangerous verdict along with a blurred preview screenshot and step-by-step advice.",
    ],
  },
  family: {
    title: "Family safe view",
    subtitle: "Plain-language explanations without technical jargon",
    paragraphs: [
      "Family safe view translates security checks into simple everyday guidance. It tells you why a link was flagged, whether it is asking for an OTP or UPI PIN, and lets you listen to the verdict aloud.",
      "You can also download a Family Safety Card image to warn relatives on WhatsApp.",
    ],
  },
  soc: {
    title: "SOC analyst view",
    subtitle: "Technical evidence for security reviewers",
    paragraphs: [
      "Switch to SOC Analyst mode in the top bar to inspect resolved IP addresses, ASN details, TLS certificate status, HTTP security headers, redirect hops, DOM form inputs, and the screenshot SHA-256 hash.",
      "Use Copy IOC bundle (JSON) to export the full technical record.",
    ],
  },
  cases: {
    title: "Reference cases",
    subtitle: "Safe local simulations built into the app",
    paragraphs: [
      "Four sample cases are included so you can test how the sandbox behaves without visiting real scam websites: a fake electricity KYC page, a drive-by APK download trap, a blocked internal-network scheme, and a safe reference site.",
    ],
  },
  how: {
    title: "How it works",
    subtitle: "Four steps from raw message to spoken verdict",
    paragraphs: [
      "1. Personal numbers (Aadhaar, PAN, UPI, phone) are hidden and unsafe local targets are blocked.",
      "2. An isolated preview room opens the link away from your phone and stops file downloads.",
      "3. Visual spoofing, site certificates, domain age, and threat databases are checked.",
      "4. A transparent 0–100 risk score, spoken audio summary, and 1930 report draft are generated.",
    ],
  },
  languages: {
    title: "25 voice languages",
    subtitle: "Multilingual verdicts for families",
    paragraphs: [
      "Choose from 25 Indian and global languages using the language dropdown in the inspector box. Voice playback uses our cloud voice service when active, with automatic device speech as fallback.",
    ],
  },
  sos: {
    title: "Emergency SOS guide",
    subtitle: "What to do if you already clicked or shared an OTP",
    paragraphs: [
      "If you entered an OTP, UPI PIN, or installed an unknown app, act immediately: call 1930 to freeze fraudulent bank transfers, call your bank helpline to block cards and UPI, switch off mobile data, and uninstall any unknown .apk app.",
    ],
  },
  reporting: {
    title: "1930 and Chakshu reporting",
    subtitle: "Official Indian cybercrime channels",
    paragraphs: [
      "For financial fraud or unauthorized money transfers, dial 1930 immediately or file a complaint at cybercrime.gov.in.",
      "To report scam SMS, WhatsApp messages, or fake calls before losing money, submit the details on the Chakshu portal at sancharsaathi.gov.in.",
    ],
  },
  terms: {
    title: "Terms and conditions",
    subtitle: "Usage boundaries and automated analysis notice",
    paragraphs: [
      "Scam SOC Crew provides automated link inspection, sandboxed rendering, and plain-language risk summaries for educational and protective triage.",
      "Automated scores and AI visual explanations are advisory only. A Safe verdict does not guarantee a website is free from future changes or fraud.",
      "Never share your OTP, UPI PIN, or bank password with anyone, even if a page appears normal.",
    ],
  },
  privacy: {
    title: "Privacy policy",
    subtitle: "Zero server-side user accounts or tracking cookies",
    paragraphs: [
      "Scam SOC Crew does not require registration, login, or tracking cookies. Your recent scan history, scout rank, and theme choice are stored locally on your device only.",
      "Submitted messages are processed in memory to extract URLs and mask personal identifiers before any external check is made.",
    ],
  },
  dpdp: {
    title: "DPDP redaction",
    subtitle: "Automatic masking of Indian personal identifiers",
    paragraphs: [
      "Before sending text to external threat-intel or AI vision services, the backend redacts phone numbers, Aadhaar numbers, PAN numbers, UPI IDs, email addresses, and bank account numbers.",
      "All URLs saved in local history and incident drafts are defanged (hxxp / [.]) so they cannot be clicked accidentally.",
    ],
  },
  accessibility: {
    title: "Accessibility",
    subtitle: "Keyboard navigation, contrast, and motion preferences",
    paragraphs: [
      "All interactive controls support keyboard navigation, visible focus rings, 4.5:1 text contrast, and 44px touch targets on primary actions.",
      "Modals and drawers trap focus and close on Escape. Animations respect your system prefers-reduced-motion setting.",
    ],
  },
  choices: {
    title: "Manage local data",
    subtitle: "Control what is saved in this browser",
    paragraphs: [
      "This browser stores only your recent defanged scan history (up to 10 items), Scout XP/badges, wrong-verdict notes, and dark/light theme preference.",
      "You can delete all locally stored data at any time using the button below.",
    ],
    showClear: true,
  },
};

function openLegalModal(pageKey) {
  const page = LEGAL_PAGES[pageKey] || LEGAL_PAGES.terms;
  const modal = document.getElementById("legalModal");
  if (!modal) return;
  document.getElementById("legalModalTitle").textContent = page.title;
  document.getElementById("legalModalSubtitle").textContent = page.subtitle;
  const body = document.getElementById("legalModalBody");
  body.replaceChildren();
  page.paragraphs.forEach((txt) => {
    const p = document.createElement("p");
    p.textContent = txt;
    body.appendChild(p);
  });
  const actions = document.getElementById("legalModalActions");
  if (page.showClear) actions.classList.remove("hidden");
  else actions.classList.add("hidden");
  modal.classList.remove("hidden");
  modal.classList.add("flex");
  trapFocusIn(modal);
}

function closeLegalModal() {
  const modal = document.getElementById("legalModal");
  if (!modal || modal.classList.contains("hidden")) return;
  modal.classList.add("hidden");
  modal.classList.remove("flex");
  restoreFocus();
}

function clearAllLocalData() {
  localStorage.removeItem(HISTORY_STORAGE_KEY);
  localStorage.removeItem(SCOUT_STORAGE_KEY);
  localStorage.removeItem(WRONG_VERDICT_KEY);
  renderHistory();
  renderScoutUI();
  closeLegalModal();
  showToast("All local browser data cleared");
}

/* --- COMMAND MENU (⌘K) --- */
function openCommandMenu() {
  const modal = document.getElementById("commandMenuModal");
  if (!modal) return;
  modal.classList.remove("hidden");
  modal.classList.add("flex");
  const input = document.getElementById("commandSearchInput");
  input.value = "";
  renderCommandItems("");
  trapFocusIn(modal);
}

function closeCommandMenu() {
  const modal = document.getElementById("commandMenuModal");
  if (!modal || modal.classList.contains("hidden")) return;
  modal.classList.add("hidden");
  modal.classList.remove("flex");
  restoreFocus();
}

function renderCommandItems(query) {
  const q = (query || "").trim().toLowerCase();
  const list = document.getElementById("commandList");
  if (!list) return;
  list.replaceChildren();
  const commands = [
    { label: "Inspect current message", hint: "⌘Enter", action: () => { closeCommandMenu(); inspectMessage(); } },
    { label: "Switch to Family Safe mode", hint: "Mode", action: () => { closeCommandMenu(); setViewMode("family"); } },
    { label: "Switch to SOC Analyst mode", hint: "Mode", action: () => { closeCommandMenu(); setViewMode("soc"); } },
    { label: "Load BESCOM KYC sample", hint: "Sample", action: () => { closeCommandMenu(); applyPreset("bescom"); } },
    { label: "Load APK trap sample", hint: "Sample", action: () => { closeCommandMenu(); applyPreset("apk"); } },
    { label: "Open Emergency SOS guide", hint: "SOS", action: () => { closeCommandMenu(); openDamageControl(); } },
    { label: "Toggle dark / light theme", hint: "Theme", action: () => { closeCommandMenu(); toggleTheme(); } },
    { label: "Open Help and FAQ", hint: "Help", action: () => { closeCommandMenu(); toggleHelpDrawer(); } },
  ];
  const filtered = commands.filter((c) => !q || c.label.toLowerCase().includes(q));
  filtered.forEach((c) => {
    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "focus-ring flex w-full items-center justify-between rounded-lg px-3 py-2.5 text-left text-xs text-primary hover:bg-white/5";
    btn.onclick = c.action;
    const left = document.createElement("span");
    left.textContent = c.label;
    const right = document.createElement("kbd");
    right.className = "surface-raised rounded px-2 py-0.5 font-mono text-[11px] text-muted";
    right.textContent = c.hint;
    btn.append(left, right);
    list.appendChild(btn);
  });
}

/* --- SCOUT GAMIFICATION --- */
function getScoutState() {
  try {
    const raw = JSON.parse(localStorage.getItem(SCOUT_STORAGE_KEY) || "null");
    if (raw && typeof raw === "object") {
      return {
        xp: Number(raw.xp) || 0,
        scans: Number(raw.scans) || 0,
        streak: Number(raw.streak) || 0,
        lastScanDate: raw.lastScanDate || null,
        languages: Array.isArray(raw.languages) ? raw.languages : [],
        badges: Array.isArray(raw.badges) ? raw.badges : [],
      };
    }
  } catch {}
  return { xp: 0, scans: 0, streak: 0, lastScanDate: null, languages: [], badges: [] };
}

function saveScoutState(state) {
  try { localStorage.setItem(SCOUT_STORAGE_KEY, JSON.stringify(state)); } catch {}
}

function getRankInfo(xp) {
  if (xp >= 300) return { name: "Lead", pct: 100 };
  if (xp >= 100) return { name: "Analyst", pct: Math.min(100, Math.round(((xp - 100) / 200) * 100)) };
  return { name: "Trainee", pct: Math.min(100, Math.round((xp / 100) * 100)) };
}

function formatCaseNumber(num) {
  return `CASE ${String(Math.max(1, num)).padStart(4, "0")}`;
}

function showToast(msg, undoCallback) {
  const el = document.getElementById("scoutToast");
  const msgEl = document.getElementById("scoutToastMsg");
  const undoBtn = document.getElementById("scoutToastUndo");
  if (!el || !msgEl) return;
  msgEl.textContent = msg;
  if (undoBtn) {
    if (undoCallback) {
      undoBtn.classList.remove("hidden");
      undoBtn.onclick = () => {
        undoCallback();
        el.classList.add("hidden");
        el.classList.remove("flex");
      };
    } else {
      undoBtn.classList.add("hidden");
    }
  }
  el.classList.remove("hidden");
  el.classList.add("flex");
  clearTimeout(el._timer);
  el._timer = setTimeout(() => {
    el.classList.add("hidden");
    el.classList.remove("flex");
  }, 4000);
}

function tweenNumber(el, from, to, duration = 450) {
  if (!el) return;
  const start = performance.now();
  function tick(now) {
    const t = Math.min(1, (now - start) / duration);
    const eased = 1 - Math.pow(1 - t, 3);
    el.textContent = String(Math.round(from + (to - from) * eased));
    if (t < 1) requestAnimationFrame(tick);
  }
  requestAnimationFrame(tick);
}

function renderScoutUI() {
  const state = getScoutState();
  const rank = getRankInfo(state.xp);
  document.getElementById("navRankLabel").textContent = `${rank.name} · ${state.xp} XP`;
  document.getElementById("navRankBar").style.width = `${rank.pct}%`;
  document.getElementById("navStreakLabel").textContent = `${state.streak}d`;
  document.getElementById("statTotalScans").textContent = String(state.scans);
  document.getElementById("statRankName").textContent = rank.name;
  document.getElementById("statStreakDays").textContent = `${state.streak}d`;
  document.getElementById("benchCaseCounter").textContent = `CASE ${String(state.scans).padStart(4, "0")}`;
  document.getElementById("badgeCountText").textContent = `${state.badges.length} / ${BADGE_DEFS.length}`;

  const grid = document.getElementById("badgesGrid");
  grid.replaceChildren();
  BADGE_DEFS.forEach((b) => {
    const unlocked = state.badges.includes(b.id);
    const card = document.createElement("div");
    card.className = unlocked
      ? "surface-raised flex items-center justify-center rounded-lg px-2 py-2.5 text-center"
      : "surface-deep flex items-center justify-center rounded-lg px-2 py-2.5 text-center opacity-50";
    card.title = unlocked ? `${b.label} (Unlocked)` : `${b.label} (Locked)`;
    const label = document.createElement("span");
    label.className = `text-[11px] font-medium leading-tight ${unlocked ? "text-primary" : "text-muted"}`;
    label.textContent = b.label;
    card.appendChild(label);
    grid.appendChild(card);
  });
}

function recordScanProgress(data, lang, matchedGuess) {
  const state = getScoutState();
  const today = new Date().toISOString().slice(0, 10);
  if (state.lastScanDate !== today) {
    const yesterday = new Date(Date.now() - 86400000).toISOString().slice(0, 10);
    state.streak = state.lastScanDate === yesterday ? state.streak + 1 : 1;
    state.lastScanDate = today;
  }
  state.scans += 1;
  const gained = 25 + (matchedGuess ? 15 : 0);
  state.xp += gained;
  if (!state.languages.includes(lang)) state.languages.push(lang);

  const newlyUnlocked = [];
  const unlock = (id, label) => {
    if (!state.badges.includes(id)) {
      state.badges.push(id);
      newlyUnlocked.push(label);
    }
  };
  unlock("first_scan", "First scan");
  if (data.apk_trap && data.apk_trap.detected) unlock("caught_apk", "APK trap");
  if (data.ssrf_blocked) unlock("blocked_ssrf", "SSRF block");
  if (state.languages.length >= 3) unlock("three_langs", "3+ langs");

  saveScoutState(state);
  renderScoutUI();
  showToast(newlyUnlocked.length > 0 ? `+${gained} XP · Badge unlocked: ${newlyUnlocked[0]}` : `+${gained} XP · ${formatCaseNumber(state.scans)} recorded`);
  return state.scans;
}

function unlockScoutBadge(id, label) {
  const state = getScoutState();
  if (!state.badges.includes(id)) {
    state.badges.push(id);
    saveScoutState(state);
    renderScoutUI();
    showToast(`Badge unlocked: ${label}`);
  }
}

function loadDemoPresets() {
  const origin = window.location.origin;
  demoPresets = {
    bescom: `[DEMO] Dear Consumer, your BESCOM electricity meter will be disconnected tonight at 9:30 PM due to incomplete KYC. Pay ₹12 verification fee immediately: ${origin}/mock-scam-redirect`,
    apk: `[DEMO] Urgent bank security update required. Download BESCOM_KYC_Update.apk to keep your account active: ${origin}/mock-apk-trap`,
    ssrf: "[DEMO] Restricted scheme check targeting internal network: gopher://example.com/test",
    safe: "[DEMO] Official public encyclopedia reference link: https://www.wikipedia.org",
    upi: `[DEMO] Congratulations! You received ₹4,999 UPI cashback. Enter your UPI PIN to claim before midnight: ${origin}/mock-scam-redirect`,
    courier: `[DEMO] India Post: Your parcel IN-847291 is held at customs. Update address and pay ₹25 duty: ${origin}/mock-scam-redirect`,
    bank: `[DEMO] SBI Alert: Your YONO KYC is suspended (Aadhaar 4123 5678 9012, Mob +91 9876543210, UPI rahul@okicici). Verify now: ${origin}/mock-scam-redirect`,
    gov: "[DEMO] Official National Cyber Crime Reporting Portal: https://cybercrime.gov.in",
  };
}

const FLOW_STEP_DETAILS = [
  {
    title: "Step 1: You share the suspicious message or screenshot",
    desc: "Nothing is opened on your phone or laptop. We only read the text or image you submit to find links and warning signs.",
    example: 'Example: "Your electricity meter will be disconnected tonight. Verify at hxxp://example[.]com"',
  },
  {
    title: "Step 2: Privacy shield hides your personal numbers",
    desc: "Before any external check runs, Aadhaar, PAN, UPI IDs, phone numbers, and bank numbers are automatically masked.",
    example: "Before: +91 9876543210, rahul@okicici  →  After: [PHONE_REDACTED], [UPI_REDACTED]",
  },
  {
    title: "Step 3: Safe preview room opens the link away from you",
    desc: "An isolated mobile viewer visits the link, records hidden redirects, stops file downloads, and captures a blurred preview.",
    example: "Blocked: BESCOM_KYC_Update.apk download stopped before reaching your device",
  },
  {
    title: "Step 4: Clear verdict, voice summary, and official report",
    desc: "You receive a 0–100 risk score, spoken advice in 25 languages, and a ready-to-file 1930 / Chakshu incident dossier.",
    example: "Verdict: DANGEROUS (85/100) · Ready for 1930 & sancharsaathi.gov.in",
  },
];

function selectFlowStep(idx) {
  const step = FLOW_STEP_DETAILS[idx] || FLOW_STEP_DETAILS[0];
  FLOW_STEP_DETAILS.forEach((_, i) => {
    const btn = document.getElementById(`flowStepBtn-${i}`);
    if (btn) btn.style.borderLeft = i === idx ? "2px solid var(--accent)" : "2px solid transparent";
  });
  document.getElementById("flowDetailTitle").textContent = step.title;
  document.getElementById("flowDetailDesc").textContent = step.desc;
  document.getElementById("flowDetailExample").textContent = step.example;
}

function handleImageUpload(event) {
  const file = event.target && event.target.files && event.target.files[0];
  if (!file) return;
  loadUploadedImageFile(file);
}

function loadUploadedImageFile(file) {
  if (!file.type.startsWith("image/")) {
    showError("Please upload a PNG, JPG, or WebP image.");
    return;
  }
  const reader = new FileReader();
  reader.onload = () => {
    uploadedImageBase64 = String(reader.result || "");
    document.getElementById("imagePreviewThumb").src = uploadedImageBase64;
    document.getElementById("imagePreviewName").textContent = file.name || "Pasted image";
    const wrap = document.getElementById("imagePreviewWrap");
    wrap.classList.remove("hidden");
    wrap.classList.add("flex");
    hideError();
  };
  reader.readAsDataURL(file);
}

function clearUploadedImage() {
  uploadedImageBase64 = null;
  const inp = document.getElementById("imageUploadInput");
  if (inp) inp.value = "";
  const wrap = document.getElementById("imagePreviewWrap");
  if (wrap) {
    wrap.classList.add("hidden");
    wrap.classList.remove("flex");
  }
}

async function downloadOfficialPdf() {
  const data = lastAnalysisData || {
    status: "DANGEROUS",
    risk_score: 85,
    defanged_url: "hxxp[://]127[.]0[.]0[.]1:8000/mock-bescom-kyc",
    redacted_message: "[DEMO] Dear Consumer, your BESCOM electricity meter will be disconnected tonight. ([REDACTED_PHONE])",
    screenshot_sha256: "sample-preview-run-inspection-for-live-hash",
    evidence: ["Sample preview — run any inspection to populate live evidence."],
    vision: { impersonated_brand: "BESCOM Karnataka" },
    intel: { network: { ip: "127.0.0.1", asn: "LOCAL-DEMO", country: "IN" } },
  };
  const caseTag = lastAnalysisData ? (document.getElementById("caseNumberTag").textContent || "CASE-0001") : "SAMPLE-PREVIEW";
  const net = (data.intel && data.intel.network) || {};
  const payload = {
    case_id: caseTag,
    timestamp: new Date().toISOString().replace("T", " ").slice(0, 19) + " UTC",
    status: data.status || "SUSPICIOUS",
    risk_score: data.risk_score ?? 0,
    defanged_url: data.defanged_url || "N/A",
    impersonated_brand: (data.vision && data.vision.impersonated_brand) || "Unverified / Unknown",
    network: `${net.ip || "Unresolved"} · ${net.asn || "N/A"} (${net.country || "N/A"})`,
    redacted_message: data.redacted_message || "N/A",
    screenshot_sha256: data.screenshot_sha256 || "N/A",
    evidence: data.evidence || [],
  };
  try {
    const resp = await fetch("/api/report/pdf", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    if (!resp.ok) throw new Error("PDF generation failed");
    const blob = await resp.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `scam-soc-dossier-${caseTag.toLowerCase().replace(/\s+/g, "-")}.pdf`;
    a.click();
    setTimeout(() => URL.revokeObjectURL(url), 4000);
    showToast("Official PDF dossier downloaded");
  } catch {
    showToast("Could not generate PDF");
  }
}

function openOfficialReport() {
  const data = lastAnalysisData || {
    status: "DANGEROUS",
    risk_score: 85,
    defanged_url: "hxxp[://]127[.]0[.]0[.]1:8000/mock-bescom-kyc",
    redacted_message: "[DEMO] Dear Consumer, your BESCOM electricity meter will be disconnected tonight. ([REDACTED_PHONE])",
    screenshot_sha256: "sample-preview-run-inspection-for-live-hash",
    vision: { impersonated_brand: "BESCOM Karnataka" },
    intel: { network: { ip: "127.0.0.1", asn: "LOCAL-DEMO", country: "IN" } },
  };
  const modal = document.getElementById("officialReportModal");
  const body = document.getElementById("officialReportBody");
  if (!modal || !body) return;

  const caseTag = lastAnalysisData ? (document.getElementById("caseNumberTag").textContent || "CASE 0001") : "SAMPLE PREVIEW";
  const net = (data.intel && data.intel.network) || {};
  const vision = data.vision || {};
  const nowUtc = new Date().toISOString().replace("T", " ").slice(0, 19) + " UTC";

  body.replaceChildren();
  const rows = [
    ["Reference ID", caseTag],
    ["Date & Time (UTC)", nowUtc],
    ["Assessment Verdict", `${data.status || "SUSPICIOUS"} (Risk Score: ${data.risk_score ?? 0} / 100)`],
    ["Suspect Address (Defanged)", data.defanged_url || "N/A"],
    ["Impersonated Entity", vision.impersonated_brand || "Unverified / Unknown"],
    ["Resolved Host / Network", `${net.ip || "Unresolved"} · ${net.asn || "N/A"} (${net.country || "N/A"})`],
    ["Message Excerpt (Redacted)", data.redacted_message || "N/A"],
    ["Visual Evidence Hash", data.screenshot_sha256 || "Not applicable"],
    ["Recommended Channels", "Dial 1930 (Financial Fraud) · cybercrime.gov.in · sancharsaathi.gov.in (Chakshu)"],
  ];

  const table = document.createElement("table");
  table.className = "w-full border-collapse text-left text-xs";
  rows.forEach(([k, v]) => {
    const tr = document.createElement("tr");
    tr.style.borderBottom = "1px solid var(--line)";
    const th = document.createElement("th");
    th.className = "w-48 py-2.5 pr-4 font-medium text-secondary align-top";
    th.textContent = k;
    const td = document.createElement("td");
    td.className = "py-2.5 font-mono text-primary break-all";
    td.textContent = v;
    tr.append(th, td);
    table.appendChild(tr);
  });
  body.appendChild(table);

  const note = document.createElement("p");
  note.className = "surface-deep rounded-lg p-3 text-xs text-secondary";
  note.textContent = "Declaration: Personal identifiers (phone, Aadhaar, PAN, UPI) have been masked and web addresses defanged for safe submission to cybercrime authorities.";
  body.appendChild(note);

  modal.classList.remove("hidden");
  modal.classList.add("flex");
  trapFocusIn(modal);
}

function closeOfficialReport() {
  const modal = document.getElementById("officialReportModal");
  if (!modal || modal.classList.contains("hidden")) return;
  modal.classList.add("hidden");
  modal.classList.remove("flex");
  restoreFocus();
}

function applyUiLanguage(lang) {
  const dict = UI_STRINGS[lang] || UI_STRINGS.en;
  document.querySelectorAll("[data-i18n]").forEach((el) => {
    const key = el.dataset.i18n;
    if (dict[key]) el.textContent = dict[key];
  });
  document.documentElement.lang = lang;
  document.documentElement.dir = lang === "ar" || lang === "ur" ? "rtl" : "ltr";
}

function filterFaq(query) {
  const q = (query || "").trim().toLowerCase();
  const wrap = document.getElementById("faqList");
  if (!wrap) return;
  wrap.replaceChildren();
  const matches = FAQ_ITEMS.filter((item) => !q || item.q.toLowerCase().includes(q) || item.a.toLowerCase().includes(q));
  if (matches.length === 0) {
    const p = document.createElement("p");
    p.className = "surface-card rounded-lg p-3 text-xs text-muted";
    p.textContent = "No matching help entries.";
    wrap.appendChild(p);
    return;
  }
  matches.forEach((item) => {
    const card = document.createElement("div");
    card.className = "surface-card rounded-xl p-3.5";
    const h = document.createElement("p");
    h.className = "text-xs font-medium text-primary";
    h.textContent = item.q;
    const body = document.createElement("p");
    body.className = "mt-1 text-xs leading-relaxed text-secondary";
    body.textContent = item.a;
    card.append(h, body);
    wrap.appendChild(card);
  });
}

function submitWrongVerdict(e) {
  e.preventDefault();
  const urlVal = document.getElementById("reportUrlInput").value.trim();
  const reasonVal = document.getElementById("reportReasonInput").value.trim();
  if (!urlVal || !reasonVal) return;
  try {
    const existing = JSON.parse(localStorage.getItem(WRONG_VERDICT_KEY) || "[]");
    existing.unshift({ target: urlVal, reason: reasonVal, timestamp: new Date().toISOString() });
    localStorage.setItem(WRONG_VERDICT_KEY, JSON.stringify(existing.slice(0, 20)));
  } catch {}
  showToast("Feedback saved locally");
  const subject = encodeURIComponent(`Scam SOC Crew Verdict Feedback: ${urlVal}`);
  const body = encodeURIComponent(`Target / Case: ${urlVal}\nObserved issue: ${reasonVal}\n`);
  window.location.href = `mailto:security-feedback@example.com?subject=${subject}&body=${body}`;
}

function updateOfflineBanner() {
  const banner = document.getElementById("offlineBanner");
  if (!banner) return;
  if (navigator.onLine === false) banner.classList.remove("hidden");
  else banner.classList.add("hidden");
}

function trapFocusIn(container) {
  lastFocusedElement = document.activeElement;
  const focusable = container.querySelectorAll('button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])');
  if (focusable.length > 0) focusable[0].focus();
}

function restoreFocus() {
  if (lastFocusedElement && typeof lastFocusedElement.focus === "function") {
    lastFocusedElement.focus();
    lastFocusedElement = null;
  }
}

/* --- SWIPE TO DISMISS FOR DRAWERS --- */
function attachSwipeToDismiss(sheetId, closeFn) {
  const sheet = document.getElementById(sheetId);
  if (!sheet) return;
  let startX = 0;
  let deltaX = 0;
  sheet.addEventListener("touchstart", (e) => {
    startX = e.touches[0].clientX;
    deltaX = 0;
  }, { passive: true });
  sheet.addEventListener("touchmove", (e) => {
    deltaX = Math.max(0, e.touches[0].clientX - startX);
    if (deltaX > 12) sheet.style.transform = `translateX(${deltaX}px)`;
  }, { passive: true });
  sheet.addEventListener("touchend", () => {
    sheet.style.transform = "";
    if (deltaX > 90) closeFn();
    deltaX = 0;
  });
}

/* --- INIT --- */
try {
  const savedTheme = localStorage.getItem(THEME_STORAGE_KEY);
  if (savedTheme === "light" || savedTheme === "dark") applyTheme(savedTheme);
} catch {}

loadDemoPresets();
renderHistory();
renderScoutUI();
filterFaq("");
updateOfflineBanner();
updateModeThumb();
attachSwipeToDismiss("historyDrawerSheet", toggleHistoryDrawer);
attachSwipeToDismiss("helpDrawerSheet", toggleHelpDrawer);
window.addEventListener("online", updateOfflineBanner);
window.addEventListener("offline", updateOfflineBanner);
window.addEventListener("resize", () => { updateModeThumb(); updateSmoothCaret(); });

const heroSpecEl = document.getElementById("heroSpecimenPhone");
if (heroSpecEl && !window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
  let masked = true;
  setInterval(() => {
    masked = !masked;
    heroSpecEl.style.opacity = "0";
    setTimeout(() => {
      heroSpecEl.textContent = masked ? "[PHONE_REDACTED]" : "+91 9876543210";
      heroSpecEl.style.opacity = "1";
    }, 180);
  }, 3200);
}

const msgInput = document.getElementById("messageInput");
if (msgInput) {
  ["input", "click", "keyup", "scroll", "focus"].forEach((evt) => msgInput.addEventListener(evt, updateSmoothCaret));
  msgInput.addEventListener("blur", updateSmoothCaret);
  msgInput.addEventListener("paste", (e) => {
    const items = e.clipboardData && e.clipboardData.items;
    if (!items) return;
    for (const item of items) {
      if (item.type.startsWith("image/")) {
        const file = item.getAsFile();
        if (file) loadUploadedImageFile(file);
        break;
      }
    }
  });
  msgInput.addEventListener("input", () => {
    document.getElementById("charCountLabel").textContent = `${msgInput.value.length} / 4000`;
    activePresetKey = null;
    spotGuess = null;
    document.getElementById("spotGuessBar").classList.add("hidden");
    document.getElementById("spotGuessBar").classList.remove("flex");
    document.getElementById("spotPromptTag").classList.add("hidden");
  });
}

document.addEventListener("click", (e) => {
  const menu = document.getElementById("langDropdownMenu");
  const btn = document.getElementById("langDropdownBtn");
  if (menu && btn && !menu.classList.contains("hidden") && !menu.contains(e.target) && !btn.contains(e.target)) {
    toggleLangDropdown(true);
  }
  const navMenu = document.getElementById("navMenuDropdown");
  const navBtn = document.getElementById("navMenuBtn");
  if (navMenu && navBtn && !navMenu.classList.contains("hidden") && !navMenu.contains(e.target) && !navBtn.contains(e.target)) {
    toggleNavMenu(true);
  }
});

document.addEventListener("keydown", (e) => {
  if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
    e.preventDefault();
    const modal = document.getElementById("commandMenuModal");
    if (modal.classList.contains("hidden")) openCommandMenu();
    else closeCommandMenu();
    return;
  }
  if ((e.metaKey || e.ctrlKey) && e.key === "Enter" && document.activeElement === msgInput) {
    e.preventDefault();
    inspectMessage();
    return;
  }
  if (e.key === "Escape") {
    closeCommandMenu();
    closeLegalModal();
    closeOfficialReport();
    toggleLangDropdown(true);
    toggleNavMenu(true);
    closeDamageControl();
    closeScreenshotModal();
    const hDrawer = document.getElementById("historyDrawer");
    if (!hDrawer.classList.contains("hidden")) toggleHistoryDrawer();
    const helpD = document.getElementById("helpDrawer");
    if (helpD && !helpD.classList.contains("hidden")) toggleHelpDrawer();
  }
});

function renderSocStandby() {
  renderSocMode({
    status: "STANDBY",
    risk_score: 0,
    ssrf_blocked: false,
    security_profile: {
      ssrf_guard: "Active (awaiting target)",
      stealth_mobile: "Isolated mobile profile",
      permissions: "Denied",
    },
    pii_redacted: {},
    http_status: "—",
    intel: {
      network: { ip: "Pending inspection", asn: "—", org: "—", country: "—" },
      tls: { note: "Pending inspection" },
      domain_age_summary: "Pending inspection",
      virustotal: { note: "Pending inspection" },
      url_heuristics: { flags: [] },
    },
    security_headers_audit: {},
    response_headers: {},
    defanged_redirect_chain: ["Awaiting link submission"],
    verdict: { score_breakdown: [] },
    dom_inputs: [],
    screenshot_sha256: "Pending inspection",
    redacted_message: "Paste a message or load a sample case to populate live telemetry.",
  });
}

function setViewMode(mode) {
  currentViewMode = mode;
  const body = document.getElementById("appBody");
  const familyBtn = document.getElementById("modeFamilyBtn");
  const socBtn = document.getElementById("modeSocBtn");
  const familyView = document.getElementById("familyView");
  const socView = document.getElementById("socView");
  const familyNote = document.getElementById("familyBenchNote");
  const socNote = document.getElementById("socBenchNote");
  const heroTitle = document.querySelector('[data-i18n="hero_title"]');
  const resultsPanel = document.getElementById("resultsPanel");
  const verdictCard = document.getElementById("verdictCard");

  if (mode === "soc") {
    body.classList.add("soc-mode");
    socBtn.style.color = "var(--bg)";
    familyBtn.style.color = "var(--text-2)";
    familyView.classList.add("hidden");
    socView.classList.remove("hidden");
    if (familyNote) familyNote.classList.add("hidden");
    if (socNote) socNote.classList.remove("hidden");
    if (heroTitle) heroTitle.textContent = "Triage suspicious links and extract technical indicators";
    if (!lastAnalysisData && resultsPanel) {
      renderSocStandby();
      if (verdictCard) verdictCard.classList.add("hidden");
      resultsPanel.classList.remove("hidden");
    } else if (verdictCard) {
      verdictCard.classList.remove("hidden");
    }
    unlockScoutBadge("opened_soc", "SOC mode");
  } else {
    body.classList.remove("soc-mode");
    familyBtn.style.color = "var(--bg)";
    socBtn.style.color = "var(--text-2)";
    socView.classList.add("hidden");
    familyView.classList.remove("hidden");
    if (socNote) socNote.classList.add("hidden");
    if (familyNote) familyNote.classList.remove("hidden");
    if (!lastAnalysisData && resultsPanel) {
      resultsPanel.classList.add("hidden");
    } else if (verdictCard) {
      verdictCard.classList.remove("hidden");
    }
    applyUiLanguage(selectedLanguage);
  }
  updateModeThumb();
}

function setSpotGuess(guess) {
  spotGuess = guess;
  const safeBtn = document.getElementById("guessSafeBtn");
  const dangerBtn = document.getElementById("guessDangerBtn");
  safeBtn.style.backgroundColor = guess === "SAFE" ? "var(--text)" : "var(--raised)";
  safeBtn.style.color = guess === "SAFE" ? "var(--bg)" : "var(--text)";
  dangerBtn.style.backgroundColor = guess === "DANGEROUS" ? "var(--text)" : "var(--raised)";
  dangerBtn.style.color = guess === "DANGEROUS" ? "var(--bg)" : "var(--text)";
}

async function applyPreset(key) {
  if (!demoPresets[key]) loadDemoPresets();
  const input = document.getElementById("messageInput");
  input.value = demoPresets[key] || "";
  document.getElementById("charCountLabel").textContent = `${input.value.length} / 4000`;
  activePresetKey = key;
  spotGuess = null;
  setSpotGuess(null);
  const bar = document.getElementById("spotGuessBar");
  bar.classList.remove("hidden");
  bar.classList.add("flex");
  document.getElementById("spotPromptTag").classList.remove("hidden");
  hideError();
  updateSmoothCaret();
}

function selectLanguage(lang) {
  if (!lang) return;
  selectedLanguage = lang;
  const langObj = LANGUAGES_25.find((l) => l.code === lang);
  const ddLabel = document.getElementById("langDropdownLabel");
  if (ddLabel && langObj) ddLabel.textContent = `${langObj.native} (${langObj.code}) · 25 languages`;
  applyUiLanguage(lang);
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

function setLoadingStep(activeIdx, customText) {
  document.getElementById("loadingHeadline").textContent = customText || LOADING_STEPS[activeIdx] || "Processing...";
  LOADING_STEPS.forEach((_, idx) => {
    const stepEl = document.getElementById(`step-${idx}`);
    stepEl.style.backgroundColor = "var(--surface)";
    if (idx < activeIdx) {
      stepEl.style.borderLeft = "2px solid var(--ok)";
      stepEl.style.color = "var(--text)";
    } else if (idx === activeIdx) {
      stepEl.style.borderLeft = "2px solid var(--accent)";
      stepEl.style.color = "var(--text)";
    } else {
      stepEl.style.borderLeft = "2px solid transparent";
      stepEl.style.color = "var(--muted)";
    }
  });
}

function startLoading() {
  const nextCase = getScoutState().scans + 1;
  document.getElementById("loadingCaseTag").textContent = formatCaseNumber(nextCase);
  document.getElementById("inspectBtn").disabled = true;
  document.getElementById("inspectBtnLabel").textContent = "Inspecting...";
  document.getElementById("inspectSpinner").classList.remove("hidden");
  document.getElementById("inspectIcon").classList.add("hidden");
  document.getElementById("loadingBox").classList.remove("hidden");
  setLoadingStep(0);
}

function stopLoading() {
  document.getElementById("inspectBtn").disabled = false;
  document.getElementById("inspectBtnLabel").textContent = (UI_STRINGS[selectedLanguage] || UI_STRINGS.en).inspect_btn;
  document.getElementById("inspectSpinner").classList.add("hidden");
  document.getElementById("inspectIcon").classList.remove("hidden");
  document.getElementById("loadingBox").classList.add("hidden");
}

function setWaveformPlaying(playing) {
  const wf = document.getElementById("voiceWaveform");
  if (playing) wf.classList.add("wave-playing");
  else wf.classList.remove("wave-playing");
}

function toggleSpeechSpeed() {
  speechRate = speechRate === 1.0 ? 0.85 : 1.0;
  document.getElementById("speedToggleBtn").textContent = `${speechRate.toFixed(1)}x`;
  document.getElementById("elevenLabsAudio").playbackRate = speechRate;
}

function stopAllAudio() {
  const audioEl = document.getElementById("elevenLabsAudio");
  audioEl.pause();
  audioEl.currentTime = 0;
  if ("speechSynthesis" in window) window.speechSynthesis.cancel();
  isSpeakingFallback = false;
  setWaveformPlaying(false);
  document.getElementById("playAudioLabel").textContent = "Play voice verdict";
}

function toggleVoicePlayback() {
  const audioEl = document.getElementById("elevenLabsAudio");
  if (currentAudioBase64) {
    audioEl.playbackRate = speechRate;
    if (audioEl.paused) {
      audioEl.play().catch(() => {});
      setWaveformPlaying(true);
      document.getElementById("playAudioLabel").textContent = "Pause voice verdict";
    } else {
      audioEl.pause();
      setWaveformPlaying(false);
      document.getElementById("playAudioLabel").textContent = "Play voice verdict";
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
  utterance.rate = speechRate;
  utterance.onend = utterance.onerror = () => {
    isSpeakingFallback = false;
    setWaveformPlaying(false);
    document.getElementById("playAudioLabel").textContent = "Play voice verdict";
  };
  isSpeakingFallback = true;
  setWaveformPlaying(true);
  document.getElementById("playAudioLabel").textContent = "Stop voice verdict";
  window.speechSynthesis.speak(utterance);
}

function copyText(elementId, buttonId, originalLabel) {
  const text = document.getElementById(elementId).textContent || "";
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(text).then(() => {
      const btn = document.getElementById(buttonId);
      btn.textContent = "Copied";
      setTimeout(() => { btn.textContent = originalLabel; }, 1800);
    });
  }
}

function copyIocBundle() {
  if (!lastAnalysisData) return;
  const bundle = {
    case_id: document.getElementById("caseNumberTag").textContent,
    timestamp: new Date().toISOString(),
    status: lastAnalysisData.status,
    risk_score: lastAnalysisData.risk_score,
    defanged_url: lastAnalysisData.defanged_url,
    defanged_redirect_chain: lastAnalysisData.defanged_redirect_chain,
    network: lastAnalysisData.intel && lastAnalysisData.intel.network,
    tls: lastAnalysisData.intel && lastAnalysisData.intel.tls,
    screenshot_sha256: lastAnalysisData.screenshot_sha256,
    impersonated_brand: lastAnalysisData.vision && lastAnalysisData.vision.impersonated_brand,
  };
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(JSON.stringify(bundle, null, 2)).then(() => {
      const btn = document.getElementById("copyIocJsonBtn");
      btn.textContent = "IOC JSON copied";
      setTimeout(() => { btn.textContent = "Copy IOC bundle (JSON)"; }, 1800);
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
  const caseTag = document.getElementById("caseNumberTag").textContent || "CASE 0001";
  const scout = getScoutState();
  const rank = getRankInfo(scout.xp);

  ctx.fillStyle = "#121214";
  ctx.fillRect(0, 0, 900, 540);
  ctx.fillStyle = status === "SAFE" ? "#74d1a0" : status === "SUSPICIOUS" ? "#e3b862" : "#f2939a";
  ctx.fillRect(0, 0, 900, 108);
  ctx.fillStyle = "#121214";
  ctx.font = "bold 30px sans-serif";
  ctx.fillText(`FAMILY SAFETY CARD · ${status} (${score}/100)`, 40, 65);
  ctx.fillStyle = "#a6a6ad";
  ctx.font = "16px monospace";
  ctx.fillText(`${caseTag} · Scout Rank: ${rank.name} (${scout.badges.length}/6 badges)`, 40, 148);
  ctx.fillStyle = "#ececee";
  ctx.font = "bold 24px sans-serif";
  ctx.fillText(`Target: ${brand}`, 40, 192);
  ctx.fillStyle = "#a6a6ad";
  ctx.font = "18px monospace";
  ctx.fillText(`Defanged URL: ${defanged.slice(0, 64)}`, 40, 232);
  ctx.fillStyle = "#ececee";
  ctx.font = "21px sans-serif";
  [
    "1. Do not click this link or install any .apk file.",
    "2. Never enter your OTP, UPI PIN, or Aadhaar on message links.",
    "3. Report scams at sancharsaathi.gov.in (Chakshu) or dial 1930.",
  ].forEach((line, idx) => ctx.fillText(line, 40, 300 + idx * 46));
  ctx.fillStyle = "#79aef0";
  ctx.font = "bold 17px sans-serif";
  ctx.fillText("Inspected in isolated browser sandbox · Scam SOC Crew", 40, 492);

  const link = document.createElement("a");
  link.download = `scam-soc-safety-card-${status.toLowerCase()}.png`;
  link.href = canvas.toDataURL("image/png");
  link.click();
  unlockScoutBadge("exported_card", "Card saved");
}

function toggleScreenshotBlur() {
  isScreenshotBlurred = !isScreenshotBlurred;
  const img = document.getElementById("sandboxScreenshot");
  const overlay = document.getElementById("screenshotBlurOverlay");
  const btn = document.getElementById("toggleBlurBtn");
  if (isScreenshotBlurred) {
    img.classList.add("blur-md");
    overlay.classList.remove("hidden");
    overlay.classList.add("flex");
    btn.textContent = "Reveal preview";
  } else {
    img.classList.remove("blur-md");
    overlay.classList.add("hidden");
    overlay.classList.remove("flex");
    btn.textContent = "Blur preview";
  }
}

function openScreenshotModal() {
  const src = document.getElementById("sandboxScreenshot").src;
  if (!src) return;
  document.getElementById("screenshotModalImg").src = src;
  const modal = document.getElementById("screenshotModal");
  modal.classList.remove("hidden");
  modal.classList.add("flex");
  trapFocusIn(modal);
}

function closeScreenshotModal() {
  const modal = document.getElementById("screenshotModal");
  if (modal.classList.contains("hidden")) return;
  modal.classList.add("hidden");
  modal.classList.remove("flex");
  restoreFocus();
}

function openDamageControl() {
  const modal = document.getElementById("damageControlModal");
  modal.classList.remove("hidden");
  modal.classList.add("flex");
  trapFocusIn(modal);
}

function closeDamageControl() {
  const modal = document.getElementById("damageControlModal");
  if (modal.classList.contains("hidden")) return;
  modal.classList.add("hidden");
  modal.classList.remove("flex");
  const audioEl = document.getElementById("emergencyAudioEl");
  audioEl.pause();
  if ("speechSynthesis" in window) window.speechSynthesis.cancel();
  restoreFocus();
}

async function loadEmergencyPlan(enteredCredentials) {
  const box = document.getElementById("emergencyPlanBox");
  const title = document.getElementById("emergencyPlanTitle");
  const stepsList = document.getElementById("emergencyStepsList");
  const scriptEl = document.getElementById("emergencyScriptText");
  const audioEl = document.getElementById("emergencyAudioEl");

  box.classList.remove("hidden");
  title.textContent = enteredCredentials ? "Golden-hour emergency checklist" : "Safe cleanup checklist";
  scriptEl.textContent = "Preparing calm voice instructions...";
  audioEl.classList.add("hidden");

  const steps = enteredCredentials
    ? [
        "1. Dial 1930 immediately (National Cyber Crime Helpline) to freeze fraudulent transfers.",
        "2. Call your bank toll-free helpline to block UPI, cards, and net banking.",
        "3. If an unknown .apk file was installed, switch off mobile data and uninstall it.",
        "4. File the pre-filled report on cybercrime.gov.in and sancharsaathi.gov.in.",
      ]
    : [
        "1. Close the browser tab immediately without interacting with the page.",
        "2. Delete the message and block the sender.",
        "3. Check your Downloads folder to ensure no .apk file was saved.",
        "4. Report the sender on Chakshu (sancharsaathi.gov.in).",
      ];

  stepsList.replaceChildren();
  steps.forEach((stepText) => {
    const li = document.createElement("li");
    li.className = "surface-card rounded-lg px-3 py-2";
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
      const isWav = emergencyAudioBase64.startsWith("UklGR");
      audioEl.src = `data:${isWav ? "audio/wav" : "audio/mpeg"};base64,${emergencyAudioBase64}`;
      audioEl.classList.remove("hidden");
    }
  } catch {
    scriptEl.textContent = "Call 1930 immediately and contact your bank official helpline.";
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

function getHistory() {
  try { return JSON.parse(localStorage.getItem(HISTORY_STORAGE_KEY) || "[]"); } catch { return []; }
}

function saveToHistory(data, caseNum) {
  const list = getHistory();
  const compactSnapshot = {
    ...data,
    voice_audio_base64: null,
    screenshot_base64: data.screenshot_base64 && data.screenshot_base64.length < 300000 ? data.screenshot_base64 : null,
  };
  const entry = {
    case_id: formatCaseNumber(caseNum),
    defanged_url: data.defanged_url || "",
    status: data.status || "SUSPICIOUS",
    risk_score: data.risk_score ?? 0,
    timestamp: new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
    snapshot: compactSnapshot,
  };
  const updated = [entry, ...list.filter((i) => i.defanged_url !== entry.defanged_url)].slice(0, 10);
  try { localStorage.setItem(HISTORY_STORAGE_KEY, JSON.stringify(updated)); } catch {}
  renderHistory();
}

function restoreHistoryItem(item) {
  if (!item || !item.snapshot) {
    showToast("Run a new scan to inspect full details");
    return;
  }
  const drawer = document.getElementById("historyDrawer");
  if (drawer && !drawer.classList.contains("hidden")) toggleHistoryDrawer();
  renderResults(item.snapshot, { skipRecord: true, overrideCaseId: item.case_id });
}

function clearHistory() {
  lastClearedHistory = getHistory();
  if (lastClearedHistory.length === 0) return;
  localStorage.removeItem(HISTORY_STORAGE_KEY);
  renderHistory();
  showToast("Scan history cleared", () => {
    try { localStorage.setItem(HISTORY_STORAGE_KEY, JSON.stringify(lastClearedHistory)); } catch {}
    renderHistory();
  });
}

function renderHistory() {
  const list = getHistory();
  document.getElementById("historyCountBadge").textContent = String(list.length);
  const container = document.getElementById("historyList");
  container.replaceChildren();
  if (list.length === 0) {
    const empty = document.createElement("p");
    empty.className = "surface-card rounded-xl p-4 text-center text-xs text-muted";
    empty.textContent = "No recent scans yet. Inspect a link to build your local history.";
    container.appendChild(empty);
    return;
  }
  list.forEach((item) => {
    const card = document.createElement("button");
    card.type = "button";
    card.onclick = () => restoreHistoryItem(item);
    card.className = "focus-ring surface-card w-full rounded-xl p-3 text-left transition-opacity hover:opacity-90";
    card.style.borderLeft = `2px solid ${item.status === "SAFE" ? "var(--ok)" : item.status === "SUSPICIOUS" ? "var(--warn)" : "var(--bad)"}`;
    const top = document.createElement("div");
    top.className = "flex items-center justify-between gap-2";
    const badge = document.createElement("span");
    badge.className = "surface-raised rounded px-2 py-0.5 font-mono text-xs text-primary";
    badge.textContent = `${item.case_id ? item.case_id + " · " : ""}${item.status} · ${item.risk_score}/100`;
    const timeSpan = document.createElement("span");
    timeSpan.className = "font-mono text-xs text-muted";
    timeSpan.textContent = item.timestamp;
    top.append(badge, timeSpan);
    const urlP = document.createElement("p");
    urlP.className = "mt-1.5 break-all font-mono text-xs text-secondary";
    urlP.textContent = item.defanged_url;
    card.append(top, urlP);
    container.appendChild(card);
  });

  renderBenchRecent(list);
}

function renderBenchRecent(list) {
  const wrap = document.getElementById("benchRecentList");
  if (!wrap) return;
  wrap.replaceChildren();
  const top3 = (list || []).slice(0, 3);
  if (top3.length === 0) {
    const p = document.createElement("p");
    p.className = "surface-deep rounded-lg px-3 py-2.5 text-xs text-muted";
    p.textContent = "No checks yet. Your recent scans will appear here.";
    wrap.appendChild(p);
    return;
  }
  top3.forEach((item) => {
    const row = document.createElement("button");
    row.type = "button";
    row.onclick = () => restoreHistoryItem(item);
    row.className = "focus-ring surface-deep flex w-full items-center justify-between gap-2 rounded-lg px-3 py-2 text-left text-xs transition-opacity hover:opacity-90";
    const left = document.createElement("span");
    left.className = "truncate font-mono text-primary";
    left.textContent = item.defanged_url || "Uploaded image";
    const right = document.createElement("span");
    right.className = "shrink-0 font-mono text-muted tabular-nums";
    right.textContent = `${item.status} ${item.risk_score}`;
    row.append(left, right);
    wrap.appendChild(row);
  });
}

function toggleHistoryDrawer() {
  const drawer = document.getElementById("historyDrawer");
  if (drawer.classList.contains("hidden")) {
    drawer.classList.remove("hidden");
    drawer.classList.add("flex");
    trapFocusIn(drawer);
  } else {
    drawer.classList.add("hidden");
    drawer.classList.remove("flex");
    restoreFocus();
  }
}

function toggleHelpDrawer() {
  const drawer = document.getElementById("helpDrawer");
  if (!drawer) return;
  if (drawer.classList.contains("hidden")) {
    drawer.classList.remove("hidden");
    drawer.classList.add("flex");
    trapFocusIn(drawer);
  } else {
    drawer.classList.add("hidden");
    drawer.classList.remove("flex");
    restoreFocus();
  }
}

function renderSocMode(data) {
  const sec = data.security_profile || {};
  const pii = data.pii_redacted || {};
  const totalPii = (pii.phone || 0) + (pii.aadhaar || 0) + (pii.pan || 0) + (pii.upi || 0) + (pii.email || 0) + (pii.account || 0);

  const secGrid = document.getElementById("socSecurityGrid");
  secGrid.replaceChildren();
  [
    ["SSRF guard", data.ssrf_blocked ? "Blocked target" : sec.ssrf_guard || "Active"],
    ["Browser profile", sec.stealth_mobile || "Android 14 Mobile"],
    ["Permissions", sec.permissions || "Denied"],
    ["Download guard", data.apk_trap && data.apk_trap.detected ? `Intercepted: ${data.apk_trap.filename}` : "Intercept and abort"],
    ["PII scrubber", totalPii > 0 ? `Redacted ${totalPii} item(s)` : "Clean (0 found)"],
    ["URL defanging", "Active (hxxp / [.])"],
  ].forEach(([k, v]) => {
    const card = document.createElement("div");
    card.className = "surface-card rounded-xl p-3.5";
    const keyP = document.createElement("p");
    keyP.className = "text-xs text-muted";
    keyP.textContent = k;
    const valP = document.createElement("p");
    valP.className = "mt-1 font-medium text-primary";
    valP.textContent = v;
    card.append(keyP, valP);
    secGrid.appendChild(card);
  });

  const net = (data.intel && data.intel.network) || {};
  const vt = (data.intel && data.intel.virustotal) || {};
  const tls = (data.intel && data.intel.tls) || {};
  const netDump = document.getElementById("socNetworkDump");
  netDump.replaceChildren();
  [
    ["HTTP status:", String(data.http_status ?? "N/A")],
    ["Resolved IP:", net.ip || "Unresolved"],
    ["ASN / Org:", `${net.asn || "N/A"} · ${net.org || "N/A"}`],
    ["Country:", net.country || "N/A"],
    ["TLS cert:", tls.note || "N/A"],
    ["Domain age:", (data.intel && data.intel.domain_age_summary) || "N/A"],
    ["VirusTotal:", vt.note || "N/A"],
  ].forEach(([label, value]) => {
    const p = document.createElement("p");
    const s1 = document.createElement("span");
    s1.className = "mr-2 text-muted";
    s1.textContent = label;
    const s2 = document.createElement("span");
    s2.className = "text-primary";
    s2.textContent = value;
    p.append(s1, s2);
    netDump.appendChild(p);
  });

  const heuristics = (data.intel && data.intel.url_heuristics && data.intel.url_heuristics.flags) || [];
  const heurBox = document.getElementById("socHeuristicsBox");
  heurBox.replaceChildren();
  heuristics.forEach((flag) => {
    const pill = document.createElement("div");
    pill.className = "surface-deep rounded px-2.5 py-1 text-primary";
    pill.style.borderLeft = "2px solid var(--warn)";
    pill.textContent = `URL heuristic: ${flag}`;
    heurBox.appendChild(pill);
  });

  const audit = data.security_headers_audit || {};
  const badgeWrap = document.getElementById("socHeaderBadges");
  badgeWrap.replaceChildren();
  [
    ["HSTS", audit.hsts],
    ["CSP", audit.csp],
    ["X-Frame-Options", audit.x_frame_options],
    ["X-Content-Type", audit.x_content_type_options],
  ].forEach(([name, present]) => {
    const b = document.createElement("span");
    b.className = "surface-deep rounded px-2.5 py-1 text-xs text-primary";
    b.style.borderLeft = `2px solid ${present ? "var(--ok)" : "var(--bad)"}`;
    b.textContent = `${name}: ${present ? "Present" : "Missing"}`;
    badgeWrap.appendChild(b);
  });

  const headers = data.response_headers || {};
  document.getElementById("socHeadersDump").textContent =
    Object.keys(headers).length > 0 ? JSON.stringify(headers, null, 2) : "// No HTTP response headers captured";

  const hops = data.defanged_redirect_chain || [data.defanged_url || ""];
  const graphEl = document.getElementById("socRedirectGraph");
  graphEl.replaceChildren();
  hops.forEach((h, i) => {
    const div = document.createElement("div");
    div.className = "surface-deep break-all rounded-lg px-3 py-2";
    div.style.color = "var(--ok)";
    div.textContent = `Hop ${i + 1}: ${h}`;
    graphEl.appendChild(div);
  });

  const rules = (data.verdict && data.verdict.score_breakdown) || [];
  const rulesEl = document.getElementById("socScoreRules");
  rulesEl.replaceChildren();
  if (rules.length > 0) {
    rules.forEach((r) => {
      const row = document.createElement("div");
      row.className = "surface-deep flex justify-between gap-2 rounded-lg px-3 py-2";
      const left = document.createElement("span");
      left.className = "text-primary";
      left.textContent = r.rule;
      const right = document.createElement("span");
      right.className = "font-medium tabular-nums";
      right.style.color = "var(--bad)";
      right.textContent = `+${r.points}`;
      row.append(left, right);
      rulesEl.appendChild(row);
    });
  } else {
    const empty = document.createElement("div");
    empty.className = "surface-deep rounded-lg px-3 py-2";
    empty.style.color = "var(--ok)";
    empty.textContent = "No risk rules triggered (0 pts)";
    rulesEl.appendChild(empty);
  }

  const domInputs = data.dom_inputs || [];
  const domWrap = document.getElementById("socDomTableWrap");
  domWrap.replaceChildren();
  if (domInputs.length === 0) {
    const p = document.createElement("p");
    p.className = "text-xs text-muted";
    p.textContent = "// No DOM form inputs extracted";
    domWrap.appendChild(p);
  } else {
    const table = document.createElement("table");
    table.className = "w-full min-w-[480px] text-left text-xs text-secondary";
    const thead = document.createElement("thead");
    thead.className = "text-primary";
    thead.style.borderBottom = "1px solid var(--line)";
    const hRow = document.createElement("tr");
    ["Tag", "Type", "Name", "ID", "Label / Placeholder"].forEach((col) => {
      const th = document.createElement("th");
      th.className = "py-2 pr-3 font-medium";
      th.textContent = col;
      hRow.appendChild(th);
    });
    thead.appendChild(hRow);
    const tbody = document.createElement("tbody");
    domInputs.forEach((inp) => {
      const tr = document.createElement("tr");
      tr.style.borderBottom = "1px solid var(--line)";
      [inp.tag, inp.type, inp.name || "-", inp.id || "-", inp.label || inp.placeholder || "-"].forEach((val) => {
        const td = document.createElement("td");
        td.className = "py-2 pr-3";
        td.textContent = val;
        tr.appendChild(td);
      });
      tbody.appendChild(tr);
    });
    table.append(thead, tbody);
    domWrap.appendChild(table);
  }

  document.getElementById("socSha256").textContent = data.screenshot_sha256 || "N/A (No screenshot)";
  document.getElementById("socRedactedMsg").textContent = data.redacted_message || "";
}

function updateRiskGauge(score, status) {
  const circumference = 201.06;
  const clamped = Math.max(0, Math.min(100, Number(score) || 0));
  const offset = circumference - (clamped / 100) * circumference;
  const arc = document.getElementById("riskGaugeArc");
  arc.style.strokeDashoffset = String(offset);
  arc.style.stroke = status === "SAFE" ? "var(--ok)" : status === "SUSPICIOUS" ? "var(--warn)" : "var(--bad)";
}

function renderResults(data, options = {}) {
  stopAllAudio();
  lastAnalysisData = data;
  const verdictCardEl = document.getElementById("verdictCard");
  if (verdictCardEl) verdictCardEl.classList.remove("hidden");

  const status = data.status || "SUSPICIOUS";
  let matchedGuess = false;
  const spotBanner = document.getElementById("spotOutcomeBanner");
  if (!options.skipRecord && activePresetKey && spotGuess) {
    const actualGroup = status === "SAFE" ? "SAFE" : "DANGEROUS";
    matchedGuess = spotGuess === actualGroup;
    spotBanner.classList.remove("hidden");
    spotBanner.style.backgroundColor = "var(--surface)";
    spotBanner.style.color = "var(--text)";
    spotBanner.style.borderLeft = `2px solid ${matchedGuess ? "var(--ok)" : "var(--warn)"}`;
    spotBanner.textContent = matchedGuess
      ? `Spot the scam: You guessed ${spotGuess} and the real verdict is ${status}. (+15 XP bonus)`
      : `Spot the scam: You guessed ${spotGuess}, but the real verdict is ${status}.`;
  } else {
    spotBanner.classList.add("hidden");
  }

  let caseTag = options.overrideCaseId || "CASE 0001";
  if (!options.skipRecord) {
    const caseNum = recordScanProgress(data, selectedLanguage, matchedGuess);
    caseTag = formatCaseNumber(caseNum);
    saveToHistory(data, caseNum);
  }
  document.getElementById("caseNumberTag").textContent = caseTag;
  document.getElementById("specimenTagLabel").textContent = `${caseTag} · SPECIMEN`;

  const riskScore = data.risk_score ?? 0;
  const evidence = data.evidence || [];
  const intel = data.intel || {};
  const vision = data.vision || {};
  const actionKit = data.action_kit || {};

  const critBanner = document.getElementById("criticalAlertBanner");
  if (data.apk_trap && data.apk_trap.detected) {
    critBanner.classList.remove("hidden");
    document.getElementById("criticalAlertTag").textContent = "Critical · Malware APK intercepted";
    document.getElementById("criticalAlertTitle").textContent = `Blocked drive-by download: ${data.apk_trap.filename}`;
    document.getElementById("criticalAlertDetail").textContent = data.apk_trap.warning;
  } else if (data.ssrf_blocked) {
    critBanner.classList.remove("hidden");
    document.getElementById("criticalAlertTag").textContent = "SSRF guard · Request blocked";
    document.getElementById("criticalAlertTitle").textContent = "Internal or unsafe URI target blocked safely";
    document.getElementById("criticalAlertDetail").textContent = data.error || "Unsafe URI rejected before browser launch.";
  } else {
    critBanner.classList.add("hidden");
  }

  const pii = data.pii_redacted || {};
  const totalPii = (pii.phone || 0) + (pii.aadhaar || 0) + (pii.pan || 0) + (pii.upi || 0) + (pii.email || 0) + (pii.account || 0);
  const piiBanner = document.getElementById("piiNoticeBanner");
  if (totalPii > 0) {
    piiBanner.classList.remove("hidden");
    piiBanner.textContent = `Privacy scrubber: automatically redacted ${totalPii} personal identifier(s) before external analysis or reporting.`;
  } else {
    piiBanner.classList.add("hidden");
  }

  const statusColor = status === "SAFE" ? "var(--ok)" : status === "SUSPICIOUS" ? "var(--warn)" : "var(--bad)";
  const verdictCard = document.getElementById("verdictCard");
  verdictCard.style.backgroundColor = "var(--surface)";
  verdictCard.style.borderLeft = `2px solid ${statusColor}`;
  const badge = document.getElementById("verdictBadge");
  badge.style.backgroundColor = "var(--raised)";
  badge.style.color = "var(--text)";
  badge.style.borderLeft = `2px solid ${statusColor}`;
  badge.textContent = status;
  tweenNumber(document.getElementById("riskScoreValue"), 0, riskScore);
  updateRiskGauge(riskScore, status);

  document.getElementById("domainSummaryBadge").textContent = intel.domain_age_summary || "Domain checked";
  document.getElementById("tlsSummaryBadge").textContent = (intel.tls && intel.tls.note) || "TLS checked";
  const sumTarget = document.getElementById("summaryTargetVal");
  if (sumTarget) sumTarget.textContent = data.defanged_url || "Uploaded image";
  const sumBrand = document.getElementById("summaryBrandVal");
  if (sumBrand) sumBrand.textContent = vision.impersonated_brand || "None detected";
  const sumPii = document.getElementById("summaryPiiVal");
  if (sumPii) sumPii.textContent = `${totalPii} item(s)`;

  currentVoiceScript = data.voice_script || "";
  currentAudioBase64 = data.voice_audio_base64 || null;
  document.getElementById("voiceScriptText").textContent = currentVoiceScript;
  const audioEl = document.getElementById("elevenLabsAudio");
  if (currentAudioBase64) {
    const isWav = currentAudioBase64.startsWith("UklGR");
    audioEl.src = `data:${isWav ? "audio/wav" : "audio/mpeg"};base64,${currentAudioBase64}`;
    audioEl.classList.remove("hidden");
    audioEl.onplay = () => {
      setWaveformPlaying(true);
      document.getElementById("playAudioLabel").textContent = "Pause voice verdict";
    };
    audioEl.onpause = audioEl.onended = () => {
      setWaveformPlaying(false);
      document.getElementById("playAudioLabel").textContent = "Play voice verdict";
    };
    document.getElementById("audioSourceLabel").textContent = `Voice audio ready (${selectedLanguage})`;
  } else {
    audioEl.removeAttribute("src");
    audioEl.classList.add("hidden");
    document.getElementById("audioSourceLabel").textContent = "Device speech synthesis ready";
  }

  document.getElementById("visionSourceLabel").textContent =
    vision.source === "gemini_vision"
      ? "Visual inspection completed"
      : "Behavioral and visual check completed";
  document.getElementById("visionVerdictText").textContent = vision.visual_verdict || "Visual analysis complete.";
  const brandPill = document.getElementById("brandSpoofPill");
  if (vision.impersonated_brand) {
    brandPill.classList.remove("hidden");
    brandPill.textContent = `Impersonates: ${vision.impersonated_brand} (Official: ${vision.official_domain || "official portal"})`;
  } else {
    brandPill.classList.add("hidden");
  }

  const tactics = vision.manipulation_tactics || [];
  const tacticsGrid = document.getElementById("tacticsGrid");
  tacticsGrid.replaceChildren();
  if (tactics.length > 0) {
    tactics.forEach((t) => {
      const card = document.createElement("div");
      card.className = "surface-deep rounded-xl p-3.5";
      const titleP = document.createElement("p");
      titleP.className = "text-xs font-medium text-accent";
      titleP.textContent = t.tactic;
      const detailP = document.createElement("p");
      detailP.className = "mt-1 text-xs leading-relaxed text-secondary";
      detailP.textContent = t.detail;
      card.append(titleP, detailP);
      tacticsGrid.appendChild(card);
    });
  } else {
    const emptyP = document.createElement("p");
    emptyP.className = "text-xs text-muted";
    emptyP.textContent = "No coercive psychological manipulation tactics detected.";
    tacticsGrid.appendChild(emptyP);
  }

  const evidenceList = document.getElementById("evidenceList");
  evidenceList.replaceChildren();
  evidence.forEach((item) => {
    const li = document.createElement("li");
    li.className = "surface-deep flex items-start gap-2.5 rounded-xl p-3";
    const bullet = document.createElement("span");
    bullet.className = "mt-0.5";
    bullet.style.color = status === "SAFE" ? "var(--ok)" : status === "SUSPICIOUS" ? "var(--warn)" : "var(--bad)";
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
  ul.className = "space-y-2 text-secondary";
  if (status === "DANGEROUS" || status === "SUSPICIOUS") {
    alertDiv.className = "surface-deep rounded-xl p-3.5 font-medium text-primary";
    alertDiv.style.borderLeft = "2px solid var(--bad)";
    alertDiv.textContent = "Do not enter your OTP, UPI PIN, Aadhaar, or install any app from this link.";
    [
      "1. Delete this message and block the sender.",
      "2. Verify bills or bank alerts inside the official app only.",
      "3. Copy the pre-filled complaint below to report on Chakshu or call 1930.",
    ].forEach((step) => {
      const li = document.createElement("li");
      li.textContent = step;
      ul.appendChild(li);
    });
  } else {
    alertDiv.className = "surface-deep rounded-xl p-3.5 font-medium text-primary";
    alertDiv.style.borderLeft = "2px solid var(--ok)";
    alertDiv.textContent = "No obvious scam traps or malicious downloads were detected.";
    const li = document.createElement("li");
    li.textContent = "Double-check the domain spelling and never share an OTP or UPI PIN.";
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
    li.className = "surface-deep relative rounded-lg p-2.5 text-xs";
    const dot = document.createElement("span");
    dot.className = "absolute -left-[22px] top-3 h-2.5 w-2.5 rounded-full";
    dot.style.backgroundColor = idx === hops.length - 1 ? "var(--accent)" : "var(--warn)";
    const label = document.createElement("span");
    label.className = "mb-1 block font-mono text-xs text-muted";
    label.textContent = idx === 0 ? "Initial link" : idx === hops.length - 1 ? "Final destination" : `Redirect hop ${idx}`;
    const urlSpan = document.createElement("span");
    urlSpan.className = "break-all font-mono text-primary";
    urlSpan.textContent = hopUrl;
    li.append(dot, label, urlSpan);
    redirectList.appendChild(li);
  });

  document.getElementById("intelNote").textContent = (intel.virustotal && intel.virustotal.note) || "Threat intel check completed.";

  const img = document.getElementById("sandboxScreenshot");
  const fallback = document.getElementById("screenshotFallback");
  const blurBtn = document.getElementById("toggleBlurBtn");
  const zoomBtn = document.getElementById("zoomScreenshotBtn");
  const overlay = document.getElementById("screenshotBlurOverlay");

  if (data.screenshot_base64) {
    img.src = `data:image/png;base64,${data.screenshot_base64}`;
    img.classList.remove("hidden");
    fallback.classList.add("hidden");
    blurBtn.classList.remove("hidden");
    zoomBtn.classList.remove("hidden");
    isScreenshotBlurred = status !== "SAFE";
    if (isScreenshotBlurred) {
      img.classList.add("blur-md");
      overlay.classList.remove("hidden");
      overlay.classList.add("flex");
      blurBtn.textContent = "Reveal preview";
    } else {
      img.classList.remove("blur-md");
      overlay.classList.add("hidden");
      overlay.classList.remove("flex");
      blurBtn.textContent = "Blur preview";
    }
  } else {
    img.classList.add("hidden");
    overlay.classList.add("hidden");
    blurBtn.classList.add("hidden");
    zoomBtn.classList.add("hidden");
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
  if (!message && !uploadedImageBase64) {
    showError("Paste a suspicious message, attach a screenshot, or load a sample case.");
    return;
  }

  startLoading();
  try {
    const response = await fetch("/api/analyze/stream", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        message: message || "[Uploaded screenshot]",
        language: selectedLanguage,
        image_base64: uploadedImageBase64,
      }),
    });

    if (!response.ok) {
      const errData = await response.json().catch(() => ({}));
      showError(errData.error || errData.detail || "Could not analyze that message.");
      return;
    }

    const contentType = response.headers.get("content-type") || "";
    if (!contentType.includes("text/event-stream") || !response.body) {
      const data = await response.json();
      renderResults(data);
      return;
    }

    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    let buffer = "";

    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });
      const parts = buffer.split("\n\n");
      buffer = parts.pop() || "";

      for (const chunk of parts) {
        const line = chunk.split("\n").find((l) => l.startsWith("data: "));
        if (!line) continue;
        const evt = JSON.parse(line.slice(6));
        if (evt.type === "progress") {
          setLoadingStep(evt.step, evt.message);
        } else if (evt.type === "result") {
          renderResults(evt.data);
        } else if (evt.type === "error") {
          showError(evt.error || "Analysis failed.");
        }
      }
    }
  } catch {
    showError("Unable to reach the inspection service right now. Please try again.");
  } finally {
    stopLoading();
  }
}
