"""Hardened Playwright URL detonation sandbox with Browser Pool, per-hop Route SSRF Guard, and APK trap interception."""

from __future__ import annotations

import asyncio
import base64
import logging
import re
from typing import Any
from urllib.parse import urlparse

try:
    from playwright.async_api import (
        Browser,
        Page,
        Playwright,
        Response,
        Route,
        TimeoutError as PlaywrightTimeoutError,
        async_playwright,
    )
    PLAYWRIGHT_AVAILABLE = True
except ImportError:  # pragma: no cover - graceful fallback if playwright isn't installed
    Browser = Any  # type: ignore[misc, assignment]
    Page = Any  # type: ignore[misc, assignment]
    Playwright = Any  # type: ignore[misc, assignment]
    Response = Any  # type: ignore[misc, assignment]
    Route = Any  # type: ignore[misc, assignment]
    PlaywrightTimeoutError = TimeoutError  # type: ignore[misc, assignment]
    async_playwright = None  # type: ignore[assignment]
    PLAYWRIGHT_AVAILABLE = False

from backend.security import compute_sha256, validate_url_ssrf

logger = logging.getLogger("scam_soc.sandbox")

TIMEOUT_MS = 12_000
MAX_REDIRECT_HOPS = 5
MAX_CONCURRENT_SANDBOXES = 4

MOBILE_USER_AGENT = (
    "Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/126.0.6478.122 Mobile Safari/537.36"
)

CHROMIUM_HARDENED_ARGS = [
    "--no-sandbox",
    "--disable-dev-shm-usage",
    "--disable-gpu",
    "--disable-background-networking",
    "--disable-default-apps",
    "--disable-extensions",
    "--disable-sync",
    "--metrics-recording-only",
    "--no-first-run",
]

BLOCKED_RESOURCE_TYPES = {"media", "font"}

DANGEROUS_EXTENSIONS = (".apk", ".exe", ".msi", ".bat", ".scr", ".dmg", ".sh")
DANGEROUS_MIME_KEYWORDS = (
    "android.package-archive",
    "x-msdownload",
    "x-msdos-program",
    "octet-stream",
)

SENSITIVE_FIELD_KEYWORDS = (
    "password",
    "otp",
    "pin",
    "card",
    "cvv",
    "aadhaar",
    "upi",
)

URGENCY_KEYWORDS = (
    "blocked",
    "suspended",
    "kyc",
    "disconnected",
    "urgent",
    "pay now",
)

_SENSITIVE_FIELD_PATTERNS: dict[str, re.Pattern[str]] = {
    kw: re.compile(rf"(?<![a-z0-9]){re.escape(kw)}(?![a-z0-9])", re.IGNORECASE)
    for kw in SENSITIVE_FIELD_KEYWORDS
}

_URGENCY_PATTERNS: dict[str, re.Pattern[str]] = {
    kw: re.compile(rf"(?<![a-z0-9]){re.escape(kw)}(?![a-z0-9])", re.IGNORECASE)
    for kw in URGENCY_KEYWORDS
}


class SandboxBrowserPool:
    """Manages a warm headless Chromium instance and concurrency semaphore."""

    def __init__(self, max_concurrent: int = MAX_CONCURRENT_SANDBOXES) -> None:
        self._playwright: Playwright | None = None
        self._browser: Browser | None = None
        self._lock = asyncio.Lock()
        self._semaphore = asyncio.Semaphore(max_concurrent)

    @property
    def is_ready(self) -> bool:
        return self._browser is not None and self._browser.is_connected()

    async def startup(self) -> None:
        if not PLAYWRIGHT_AVAILABLE:
            logger.warning("Playwright is not installed; sandbox detonation will be unavailable.")
            return
        async with self._lock:
            if self._browser is None or not self._browser.is_connected():
                self._playwright = await async_playwright().start()
                self._browser = await self._playwright.chromium.launch(
                    headless=True,
                    args=CHROMIUM_HARDENED_ARGS,
                )
                logger.info("Warm Chromium sandbox pool initialized.")

    async def shutdown(self) -> None:
        async with self._lock:
            if self._browser is not None:
                try:
                    await self._browser.close()
                except Exception:  # noqa: BLE001
                    pass
                self._browser = None
            if self._playwright is not None:
                try:
                    await self._playwright.stop()
                except Exception:  # noqa: BLE001
                    pass
                self._playwright = None
            logger.info("Warm Chromium sandbox pool shut down.")

    async def acquire_browser(self) -> tuple[Browser, bool]:
        """Return (browser, owns_temporary_instance)."""
        if self._browser is not None and self._browser.is_connected():
            return self._browser, False
        if not PLAYWRIGHT_AVAILABLE:
            raise RuntimeError("Playwright is not installed in this environment.")
        pw = await async_playwright().start()
        browser = await pw.chromium.launch(headless=True, args=CHROMIUM_HARDENED_ARGS)
        browser._temp_pw = pw  # type: ignore[attr-defined]
        return browser, True

    @property
    def semaphore(self) -> asyncio.Semaphore:
        return self._semaphore


browser_pool = SandboxBrowserPool()


def _normalize_url(url: str) -> str:
    """Ensure bare domains get https:// while preserving explicit schemes for SSRF validation."""
    cleaned = url.strip()
    if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*:", cleaned):
        return cleaned
    return f"https://{cleaned}"


def _split_camel_and_separators(text: str) -> str:
    spaced = re.sub(r"([a-z])([A-Z])", r"\1 \2", text)
    return re.sub(r"[_\-./:]+", " ", spaced)


def _extract_http_redirect_chain(response: Response | None) -> list[str]:
    if response is None:
        return []
    chain: list[str] = []
    req = response.request
    while req is not None:
        chain.append(req.url)
        req = req.redirected_from
    chain.reverse()
    return chain


def _merge_redirect_chains(http_chain: list[str], frame_navigations: list[str], final_url: str) -> list[str]:
    merged: list[str] = []
    for candidate in [*http_chain, *frame_navigations, final_url]:
        if candidate and (not merged or merged[-1] != candidate):
            merged.append(candidate)
    return merged[: MAX_REDIRECT_HOPS + 1]


def _extract_filename_from_disposition(content_disposition: str, url: str) -> str:
    match = re.search(r'filename\*?=(?:UTF-8\'\')?"?([^";\r\n]+)"?', content_disposition, re.IGNORECASE)
    if match:
        return match.group(1).strip()
    path = urlparse(url).path
    return path.rsplit("/", 1)[-1] if "/" in path else "unknown_payload"


def _detect_download_trap_from_headers(headers: dict[str, str], url: str) -> dict[str, Any] | None:
    lower_headers = {k.lower(): v for k, v in headers.items()}
    content_disp = lower_headers.get("content-disposition", "")
    content_type = lower_headers.get("content-type", "").lower()
    filename = _extract_filename_from_disposition(content_disp, url)
    lower_file = filename.lower()
    lower_url = url.lower()

    is_attachment = "attachment" in content_disp.lower()
    has_bad_ext = any(lower_file.endswith(ext) or lower_url.endswith(ext) for ext in DANGEROUS_EXTENSIONS)
    has_bad_mime = any(m in content_type for m in DANGEROUS_MIME_KEYWORDS)

    if is_attachment or has_bad_ext or has_bad_mime:
        is_apk = lower_file.endswith(".apk") or "android.package-archive" in content_type or lower_url.endswith(".apk")
        warning = (
            f"Dangerous Trojan APK Detected ({filename}): This link attempts to force-install an Android app "
            "that can silently read your bank OTPs and SMS messages."
            if is_apk
            else f"Drive-By Malware Payload Detected ({filename}): This link attempted to force-download an executable installer."
        )
        return {
            "detected": True,
            "filename": filename,
            "mime_type": content_type or "application/octet-stream",
            "severity": "CRITICAL",
            "warning": warning,
        }
    return None


def _audit_security_headers(headers: dict[str, str]) -> dict[str, bool]:
    lower_keys = {k.lower() for k in headers}
    return {
        "hsts": "strict-transport-security" in lower_keys,
        "csp": "content-security-policy" in lower_keys,
        "x_frame_options": "x-frame-options" in lower_keys,
        "x_content_type_options": "x-content-type-options" in lower_keys,
    }


async def _inspect_dom_fields(page: Page) -> tuple[list[str], list[dict[str, str]]]:
    """Inspect form inputs, labels, and attributes in the DOM; return keywords + raw SOC dump."""
    field_descriptors: list[dict[str, str]] = await page.evaluate(
        """() => {
            const elements = Array.from(document.querySelectorAll('input, textarea, select'));
            return elements.map((el) => {
                const tag = el.tagName.toLowerCase();
                const type = (el.getAttribute('type') || 'text').toLowerCase();
                const name = el.getAttribute('name') || '';
                const id = el.getAttribute('id') || '';
                const placeholder = el.getAttribute('placeholder') || '';
                const ariaLabel = el.getAttribute('aria-label') || '';
                const autocomplete = el.getAttribute('autocomplete') || '';

                let labelText = '';
                if (id) {
                    const explicitLabel = document.querySelector(`label[for="${CSS.escape(id)}"]`);
                    if (explicitLabel) labelText += ' ' + (explicitLabel.innerText || '');
                }
                const parentLabel = el.closest('label');
                if (parentLabel) {
                    labelText += ' ' + (parentLabel.innerText || '');
                }
                const container = el.closest('div, section, form, td, li');
                if (!labelText && container) {
                    const siblingLabel = container.querySelector('label');
                    if (siblingLabel) labelText += ' ' + (siblingLabel.innerText || '');
                }

                return {
                    tag,
                    type,
                    name,
                    id,
                    placeholder,
                    label: labelText.trim(),
                    combined: [type, name, id, placeholder, ariaLabel, autocomplete, labelText].join(' ')
                };
            });
        }"""
    )

    found: list[str] = []
    seen: set[str] = set()
    dom_dump: list[dict[str, str]] = []

    for field in field_descriptors:
        field_type = field.get("type", "")
        raw_text = field.get("combined", "")
        normalized_text = _split_camel_and_separators(raw_text)

        dom_dump.append(
            {
                "tag": field.get("tag", "input"),
                "type": field_type,
                "name": field.get("name", ""),
                "id": field.get("id", ""),
                "placeholder": field.get("placeholder", ""),
                "label": field.get("label", ""),
            }
        )

        if field_type == "password" and "password" not in seen:
            seen.add("password")
            found.append("password")

        for kw, pattern in _SENSITIVE_FIELD_PATTERNS.items():
            if kw in seen:
                continue
            if pattern.search(normalized_text) or (
                kw in ("password", "aadhaar") and kw in raw_text.lower()
            ):
                seen.add(kw)
                found.append(kw)

    return found, dom_dump[:20]


async def _inspect_page_text(page: Page) -> tuple[list[str], str]:
    """Scan visible page text for urgency keywords and return a concise excerpt."""
    visible_text: str = await page.evaluate(
        "() => (document.body ? document.body.innerText : '') || ''"
    )
    matched: list[str] = []
    for kw, pattern in _URGENCY_PATTERNS.items():
        if pattern.search(visible_text):
            matched.append(kw)
    excerpt = re.sub(r"\s+", " ", visible_text).strip()[:600]
    return matched, excerpt


async def detonate_url(url: str) -> dict[str, Any]:
    """Open a URL inside a hardened stealth mobile Chromium sandbox."""
    target_url = _normalize_url(url)
    ssrf_check = validate_url_ssrf(target_url)

    result: dict[str, Any] = {
        "final_url": target_url,
        "redirect_chain": [],
        "page_title": "",
        "detected_forms": [],
        "dom_inputs": [],
        "urgency_flags": [],
        "visible_text_excerpt": "",
        "screenshot_base64": None,
        "screenshot_sha256": None,
        "http_status": None,
        "response_headers": {},
        "security_headers_audit": {},
        "ssrf_check": ssrf_check,
        "ssrf_blocked": not ssrf_check["allowed"],
        "apk_trap": {"detected": False},
        "security_profile": {
            "ssrf_guard": "ACTIVE (per-hop route guard)",
            "stealth_mobile": "Android 14 · 412x915 · webdriver hidden",
            "permissions": "DENIED (zero-trust)",
            "popup_blocker": "ACTIVE + Dialog Auto-Dismiss",
            "download_guard": "INTERCEPT & ABORT",
        },
        "error": None,
    }

    if not ssrf_check["allowed"]:
        result["error"] = ssrf_check["reason"]
        return result

    async with browser_pool.semaphore:
        browser, owns_temp = await browser_pool.acquire_browser()
        context = None
        try:
            context = await browser.new_context(
                accept_downloads=False,
                viewport={"width": 412, "height": 915},
                is_mobile=True,
                has_touch=True,
                user_agent=MOBILE_USER_AGENT,
                permissions=[],
                locale="en-IN",
                timezone_id="Asia/Kolkata",
            )
            context.set_default_timeout(TIMEOUT_MS)

            # Anti-cloaking: hide headless automation fingerprint from evasive Indian scam sites
            await context.add_init_script(
                "Object.defineProperty(navigator, 'webdriver', { get: () => undefined });"
            )

            page = await context.new_page()

            # Popup, tab bomb & JS alert/confirm/prompt suppression
            page.on("popup", lambda popup_page: asyncio.create_task(popup_page.close()))
            page.on("dialog", lambda dialog: asyncio.create_task(dialog.dismiss()))

            ssrf_in_flight_block: dict[str, Any] | None = None
            nav_hop_count = 0
            redirect_loop_blocked = False

            async def _route_guard(route: Route) -> None:
                nonlocal ssrf_in_flight_block, nav_hop_count, redirect_loop_blocked
                req = route.request
                req_url = req.url

                if req.resource_type in BLOCKED_RESOURCE_TYPES:
                    await route.abort("blockedbyclient")
                    return

                if req.is_navigation_request() and req.frame == page.main_frame:
                    nav_hop_count += 1
                    if nav_hop_count > MAX_REDIRECT_HOPS + 1:
                        redirect_loop_blocked = True
                        await route.abort("blockedbyclient")
                        return

                hop_check = validate_url_ssrf(req_url)
                if not hop_check["allowed"]:
                    if req.is_navigation_request():
                        ssrf_in_flight_block = hop_check
                    await route.abort("blockedbyclient")
                    return

                await route.continue_()

            await page.route("**/*", _route_guard)

            intercepted_trap: dict[str, Any] | None = None

            def _on_download(download: Any) -> None:
                nonlocal intercepted_trap
                filename = getattr(download, "suggested_filename", None) or _extract_filename_from_disposition(
                    "", getattr(download, "url", target_url)
                )
                is_apk = filename.lower().endswith(".apk")
                intercepted_trap = {
                    "detected": True,
                    "filename": filename,
                    "mime_type": "application/vnd.android.package-archive" if is_apk else "application/octet-stream",
                    "severity": "CRITICAL",
                    "warning": (
                        f"Dangerous Trojan APK Detected ({filename}): This link attempts to install an Android app "
                        "that silently intercepts bank OTPs."
                        if is_apk
                        else f"Drive-By Malware Payload Detected ({filename}): Forced download aborted safely."
                    ),
                }
                asyncio.create_task(download.cancel())

            page.on("download", _on_download)

            frame_navigations: list[str] = []

            def _on_frame_navigated(frame: Any) -> None:
                if frame == page.main_frame and frame.url:
                    frame_navigations.append(frame.url)

            page.on("framenavigated", _on_frame_navigated)

            def _on_response(resp: Response) -> None:
                nonlocal intercepted_trap
                if resp.request.is_navigation_request():
                    trap = _detect_download_trap_from_headers(resp.headers, resp.url)
                    if trap and intercepted_trap is None:
                        intercepted_trap = trap

            page.on("response", _on_response)

            response: Response | None = None
            try:
                response = await page.goto(target_url, wait_until="load", timeout=TIMEOUT_MS)
                await page.wait_for_timeout(350)
            except Exception as nav_exc:  # noqa: BLE001
                if ssrf_in_flight_block is not None:
                    result["ssrf_blocked"] = True
                    result["ssrf_check"] = ssrf_in_flight_block
                    result["error"] = ssrf_in_flight_block["reason"]
                    result["redirect_chain"] = _merge_redirect_chains([], frame_navigations, target_url)
                    return result
                if redirect_loop_blocked:
                    result["error"] = f"Redirect loop aborted after exceeding {MAX_REDIRECT_HOPS} hops."
                    result["redirect_chain"] = _merge_redirect_chains([], frame_navigations, target_url)
                    return result
                if intercepted_trap is not None or "Download is starting" in str(nav_exc):
                    if intercepted_trap is None:
                        filename = _extract_filename_from_disposition("", target_url)
                        intercepted_trap = {
                            "detected": True,
                            "filename": filename,
                            "mime_type": "application/vnd.android.package-archive"
                            if filename.lower().endswith(".apk")
                            else "application/octet-stream",
                            "severity": "CRITICAL",
                            "warning": (
                                f"Dangerous Trojan APK Detected ({filename}): Attempted drive-by download "
                                "was intercepted and aborted before touching disk."
                            ),
                        }
                else:
                    raise

            if ssrf_in_flight_block is not None:
                result["ssrf_blocked"] = True
                result["ssrf_check"] = ssrf_in_flight_block
                result["error"] = ssrf_in_flight_block["reason"]
                result["redirect_chain"] = _merge_redirect_chains([], frame_navigations, target_url)
                return result

            if response is not None:
                result["http_status"] = response.status
                interesting_headers = (
                    "content-type",
                    "content-disposition",
                    "server",
                    "x-powered-by",
                    "location",
                    "strict-transport-security",
                    "content-security-policy",
                    "x-frame-options",
                    "x-content-type-options",
                )
                result["response_headers"] = {
                    k: v for k, v in response.headers.items() if k.lower() in interesting_headers
                }
                result["security_headers_audit"] = _audit_security_headers(response.headers)
                if intercepted_trap is None:
                    header_trap = _detect_download_trap_from_headers(response.headers, response.url)
                    if header_trap:
                        intercepted_trap = header_trap

            if intercepted_trap is not None:
                result["apk_trap"] = intercepted_trap
                result["final_url"] = target_url
                result["redirect_chain"] = _merge_redirect_chains(
                    _extract_http_redirect_chain(response), frame_navigations, target_url
                )
                result["page_title"] = f"[BLOCKED DOWNLOAD] {intercepted_trap['filename']}"
                return result

            http_chain = _extract_http_redirect_chain(response)
            final_url = page.url or target_url

            result["final_url"] = final_url
            result["redirect_chain"] = _merge_redirect_chains(
                http_chain, frame_navigations, final_url
            )
            result["page_title"] = await page.title()

            detected_forms, dom_inputs = await _inspect_dom_fields(page)
            result["detected_forms"] = detected_forms
            result["dom_inputs"] = dom_inputs

            urgency_flags, excerpt = await _inspect_page_text(page)
            result["urgency_flags"] = urgency_flags
            result["visible_text_excerpt"] = excerpt

            screenshot_bytes = await page.screenshot(type="png", full_page=True)
            result["screenshot_base64"] = base64.b64encode(screenshot_bytes).decode("utf-8")
            result["screenshot_sha256"] = compute_sha256(screenshot_bytes)
        except PlaywrightTimeoutError:
            result["error"] = f"Navigation timed out after {TIMEOUT_MS // 1000} seconds."
        except Exception as exc:  # noqa: BLE001
            result["error"] = f"Failed to detonate URL: {exc}"
        finally:
            if context is not None:
                try:
                    await context.close()
                except Exception:  # noqa: BLE001
                    pass
            if owns_temp:
                try:
                    await browser.close()
                except Exception:  # noqa: BLE001
                    pass
                temp_pw = getattr(browser, "_temp_pw", None)
                if temp_pw is not None:
                    try:
                        await temp_pw.stop()
                    except Exception:  # noqa: BLE001
                        pass

    return result
