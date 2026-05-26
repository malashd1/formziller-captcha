"""
FormZiller — reCAPTCHA v3 invisible bypass submitter.

Submits a Contact Form 7 form on a target site by:
  - launching patchright + stock Chrome (channel="chrome") in headed mode
    (use xvfb-run on a headless server)
  - using a persistent profile to accumulate cookies/history
  - performing a warm-up visit (homepage -> internal page) before the form
  - filling fields with humanized typing and bezier mouse paths
  - waiting until the CF7-reCAPTCHA plugin auto-injects a token into
    `_wpcf7_recaptcha_response`, with a manual `grecaptcha.execute()` fallback
  - capturing the CF7 REST response and DOM event

Known limitation: from a datacenter IP the reCAPTCHA v3 score is usually
below 0.5, so CF7 returns `status: spam` even when the rest of the flow is
perfect.  Plug in a residential proxy via the `proxy=` kwarg of
`submit_cf7_v3()` to lift the score into the passing range.

Public entry point:
    submit_cf7_v3(
        home_url="https://ncube.com/",
        target_url="https://ncube.com/contact-us",
        sitekey="6Lc...",
        form_values={"your-name": "...", ...},
        marker_field="form-location",
        marker_value="FORMZILLER_MONITOR <secret>",
        profile_dir="/var/lib/formziller/profiles/<form_id>",
        proxy=None,
        timeout=180,
    ) -> dict  # see return shape at bottom of submit_cf7_v3()
"""
from __future__ import annotations

import json
import math
import random
import time
from pathlib import Path
from typing import Any, Optional

from patchright.sync_api import sync_playwright

UA_CHROME_LINUX = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/148.0.0.0 Safari/537.36"
)

# --- Mouse helpers: humanized bezier paths -------------------------------

_mouse_state = {"x": 200.0, "y": 200.0}


def _bezier_path(x1, y1, x2, y2, steps):
    cx1 = x1 + (x2 - x1) * 0.3 + random.uniform(-60, 60)
    cy1 = y1 + (y2 - y1) * 0.3 + random.uniform(-60, 60)
    cx2 = x1 + (x2 - x1) * 0.7 + random.uniform(-60, 60)
    cy2 = y1 + (y2 - y1) * 0.7 + random.uniform(-60, 60)
    pts = []
    for i in range(1, steps + 1):
        t = i / steps
        t = t * t * (3 - 2 * t)  # ease-in-out
        u = 1 - t
        x = (u ** 3) * x1 + 3 * (u ** 2) * t * cx1 + 3 * u * (t ** 2) * cx2 + (t ** 3) * x2
        y = (u ** 3) * y1 + 3 * (u ** 2) * t * cy1 + 3 * u * (t ** 2) * cy2 + (t ** 3) * y2
        x += random.uniform(-1.5, 1.5)
        y += random.uniform(-1.5, 1.5)
        pts.append((x, y))
    return pts


def _human_mouse_move(page, x2, y2):
    x1, y1 = _mouse_state["x"], _mouse_state["y"]
    distance = math.hypot(x2 - x1, y2 - y1)
    steps = max(12, int(distance / 6) + random.randint(-3, 6))
    for px, py in _bezier_path(x1, y1, x2, y2, steps):
        page.mouse.move(px, py)
        time.sleep(random.uniform(0.003, 0.012))
    _mouse_state["x"], _mouse_state["y"] = x2, y2


def _wander_mouse(page, steps=6):
    vp = page.viewport_size or {"width": 1366, "height": 800}
    w, h = vp["width"], vp["height"]
    for _ in range(steps):
        _human_mouse_move(
            page,
            random.randint(60, w - 60),
            random.randint(60, h - 60),
        )
        if random.random() < 0.4:
            time.sleep(random.uniform(0.2, 0.7))


def _human_pause(min_ms=400, max_ms=1200):
    time.sleep(random.uniform(min_ms, max_ms) / 1000.0)


def _human_type(locator, text: str):
    for ch in text:
        locator.type(ch, delay=random.randint(45, 160))
        if random.random() < 0.07:
            time.sleep(random.uniform(0.15, 0.4))


# --- Event logging --------------------------------------------------------


class _EventLog:
    def __init__(self, sink=None):
        self.events: list[dict] = []
        self.sink = sink  # optional callable(dict)

    def __call__(self, **kw):
        kw.setdefault("ts", time.strftime("%H:%M:%S"))
        self.events.append(kw)
        if self.sink:
            try:
                self.sink(kw)
            except Exception:
                pass


# --- Manual grecaptcha.execute fallback -----------------------------------


def _execute_recaptcha_v3(page, sitekey: str, action: str, log: _EventLog) -> Optional[str]:
    log(event="grecaptcha_execute_begin", action=action)
    try:
        token = page.evaluate(
            """async (args) => {
                const { sitekey, action } = args;
                if (typeof grecaptcha === 'undefined') return null;
                await new Promise((resolve) => grecaptcha.ready(resolve));
                const tok = await grecaptcha.execute(sitekey, { action });
                return tok || null;
            }""",
            {"sitekey": sitekey, "action": action},
        )
    except Exception as exc:
        log(event="grecaptcha_execute_error", error=str(exc))
        return None
    if token:
        log(event="grecaptcha_execute_ok", token_len=len(token))
    else:
        log(event="grecaptcha_execute_empty")
    return token


# --- Cookie consent autoclick ---------------------------------------------


_COOKIE_SELECTORS = [
    "button:has-text('Accept')",
    "button:has-text('I agree')",
    "button:has-text('Got it')",
    "button:has-text('Allow all')",
    "#cookie-accept",
    ".cookie-accept",
    "[aria-label*='accept' i]",
]


def _try_cookie_consent(page, log: _EventLog) -> None:
    for sel in _COOKIE_SELECTORS:
        try:
            btn = page.locator(sel).first
            if btn.is_visible(timeout=300):
                box = btn.bounding_box()
                if box:
                    _human_mouse_move(page, box["x"] + box["width"] / 2, box["y"] + box["height"] / 2)
                    _human_pause(150, 400)
                btn.click()
                log(event="cookie_accepted", selector=sel)
                return
        except Exception:
            continue


# --- Warmup --------------------------------------------------------------


def _warmup_home(page, home_url: str, log: _EventLog) -> None:
    log(event="goto_home", url=home_url)
    page.goto(home_url, wait_until="domcontentloaded", timeout=45000)
    _human_pause(2200, 3800)
    _wander_mouse(page, steps=5)
    for _ in range(random.randint(2, 4)):
        page.evaluate(
            "(d) => window.scrollBy({ top: d, left: 0, behavior: 'smooth' })",
            random.randint(280, 520),
        )
        _human_pause(700, 1500)
        _wander_mouse(page, steps=2)
    _try_cookie_consent(page, log)
    for _ in range(random.randint(2, 3)):
        page.evaluate(
            "(d) => window.scrollBy({ top: d, left: 0, behavior: 'smooth' })",
            random.randint(300, 600),
        )
        _human_pause(800, 1700)
        _wander_mouse(page, steps=2)


def _warmup_inner_page(page, avoid_substr: str, log: _EventLog) -> None:
    try:
        inner = page.locator("a[href^='/'], a[href*='://']")
        cnt = inner.count()
        for i in range(min(cnt, 25)):
            a = inner.nth(i)
            try:
                href = a.get_attribute("href") or ""
                if (
                    not href
                    or href.startswith(("mailto:", "tel:", "#"))
                    or any(x in href for x in [avoid_substr, "privacy", "policy"])
                ):
                    continue
                if not a.is_visible(timeout=200):
                    continue
                box = a.bounding_box()
                if box:
                    _human_mouse_move(page, box["x"] + box["width"] / 2, box["y"] + box["height"] / 2)
                _human_pause(300, 700)
                a.click()
                page.wait_for_load_state("domcontentloaded", timeout=20000)
                log(event="warmup_inner_page", url=page.url)
                _human_pause(2000, 3500)
                for _ in range(random.randint(2, 4)):
                    page.evaluate(
                        "(d) => window.scrollBy({ top: d, left: 0, behavior: 'smooth' })",
                        random.randint(300, 600),
                    )
                    _human_pause(700, 1500)
                    _wander_mouse(page, steps=2)
                return
            except Exception:
                continue
    except Exception as e:
        log(event="warmup_inner_skip", error=str(e))


# --- Main entry -----------------------------------------------------------


def submit_cf7_v3(
    *,
    home_url: str,
    target_url: str,
    sitekey: str,
    form_values: dict[str, str],
    marker_field: Optional[str] = None,
    marker_value: Optional[str] = None,
    profile_dir: str,
    proxy: Optional[dict] = None,
    user_agent: str = UA_CHROME_LINUX,
    timezone_id: str = "America/New_York",
    locale: str = "en-US",
    timeout: int = 180,
    event_sink=None,
) -> dict[str, Any]:
    """
    Submit a CF7+reCAPTCHA v3 form. Returns:
        {
          "ok": bool,
          "cf7_status": "mail_sent" | "spam" | "validation_failed" | "mail_failed" | None,
          "cf7_message": str | None,
          "cf7_response": dict | None,
          "events": [ ... ],          # debug timeline
          "error": str | None,
        }
    """
    Path(profile_dir).mkdir(parents=True, exist_ok=True)
    log = _EventLog(sink=event_sink)
    result: dict[str, Any] = {
        "ok": False,
        "cf7_status": None,
        "cf7_message": None,
        "cf7_response": None,
        "events": log.events,
        "error": None,
    }

    try:
        with sync_playwright() as p:
            launch_kwargs: dict[str, Any] = dict(
                user_data_dir=profile_dir,
                channel="chrome",
                headless=False,
                no_viewport=True,
                user_agent=user_agent,
                locale=locale,
                timezone_id=timezone_id,
                color_scheme="light",
                args=["--start-maximized"],
                ignore_default_args=["--enable-automation"],
            )
            if proxy:
                launch_kwargs["proxy"] = proxy

            ctx = p.chromium.launch_persistent_context(**launch_kwargs)
            page = ctx.pages[0] if ctx.pages else ctx.new_page()
            try:
                page.set_viewport_size({"width": 1366, "height": 800})
            except Exception:
                pass

            # 1. Warm up on the homepage
            _warmup_home(page, home_url, log)

            # 2. Visit an inner page (not the form one) to look organic
            _warmup_inner_page(page, avoid_substr=target_url.rsplit("/", 1)[-1], log=log)

            # 3. Navigate to the form page (real click if possible, else direct)
            log(event="goto_target", url=target_url)
            try:
                slug = target_url.rsplit("/", 1)[-1] or "contact"
                nav_link = page.locator(f"a[href*='{slug}']").first
                if nav_link.is_visible(timeout=1500):
                    box = nav_link.bounding_box()
                    if box:
                        _human_mouse_move(page, box["x"] + box["width"] / 2, box["y"] + box["height"] / 2)
                    _human_pause(300, 700)
                    nav_link.click()
                    page.wait_for_load_state("domcontentloaded", timeout=30000)
                else:
                    raise RuntimeError("nav link not visible")
            except Exception:
                page.goto(target_url, wait_until="domcontentloaded", timeout=45000)

            _human_pause(2200, 3800)
            _wander_mouse(page, steps=4)
            page.evaluate(
                "(d) => window.scrollBy({ top: d, left: 0, behavior: 'smooth' })",
                random.randint(200, 400),
            )
            _human_pause(900, 1700)

            # 4. Find the first visible CF7 form
            form = None
            forms = page.locator("form.wpcf7-form")
            cnt = forms.count()
            log(event="wpcf7_forms_found", count=cnt)
            for i in range(cnt):
                f = forms.nth(i)
                try:
                    f.scroll_into_view_if_needed(timeout=2000)
                    if f.is_visible(timeout=500):
                        form = f
                        log(event="cf7_form_picked", index=i)
                        break
                except Exception:
                    continue
            if form is None and cnt > 0:
                form = forms.first
                log(event="cf7_form_fallback_first")
            if form is None:
                result["error"] = "cf7_form_not_found"
                ctx.close()
                return result

            # 5. Fill fields humanly
            for name, value in form_values.items():
                try:
                    inp = form.locator(f"[name='{name}']").first
                    inp.scroll_into_view_if_needed()
                    _human_pause(300, 700)
                    box = inp.bounding_box()
                    if box:
                        _human_mouse_move(
                            page,
                            box["x"] + box["width"] / 2 + random.uniform(-15, 15),
                            box["y"] + box["height"] / 2 + random.uniform(-4, 4),
                        )
                    _human_pause(120, 320)
                    inp.click()
                    _human_pause(150, 350)
                    _human_type(inp, value)
                    log(event="field_filled", name=name, length=len(value))
                    _human_pause(250, 600)
                except Exception as exc:
                    log(event="field_fill_error", name=name, error=str(exc))

            # Marker (e.g. form-location = "FORMZILLER_MONITOR <secret>")
            if marker_field and marker_value:
                try:
                    form.locator(f"[name='{marker_field}']").evaluate(
                        "(el, val) => { el.value = val; }", marker_value
                    )
                    log(event="marker_set", field=marker_field)
                except Exception as exc:
                    log(event="marker_error", error=str(exc))

            # 6. Wait for grecaptcha to load and for the auto-token to appear
            try:
                page.wait_for_load_state("networkidle", timeout=20000)
            except Exception:
                pass

            token_in_dom = None
            for _ in range(40):
                token_in_dom = page.evaluate(
                    """() => {
                        const els = document.getElementsByName('_wpcf7_recaptcha_response');
                        for (const el of els) {
                            if (el.value && el.value.length > 20) return el.value;
                        }
                        return null;
                    }"""
                )
                if token_in_dom:
                    log(event="cf7_token_present", length=len(token_in_dom))
                    break
                time.sleep(0.5)

            if not token_in_dom:
                log(event="cf7_token_missing_trying_manual_execute")
                for action in ("submit", "homepage", "contactform"):
                    tok = _execute_recaptcha_v3(page, sitekey, action=action, log=log)
                    if tok:
                        page.evaluate(
                            """(tok) => {
                                document.getElementsByName('_wpcf7_recaptcha_response')
                                    .forEach(el => el.value = tok);
                            }""",
                            tok,
                        )
                        log(event="manual_token_injected", action=action)
                        break

            # 7. Listeners
            page.evaluate("""() => {
                window.__fz_cf7 = { event: null, detail: null };
                const capture = (name) => document.addEventListener(name, (e) => {
                    try {
                        window.__fz_cf7 = { event: name, detail: e.detail ? JSON.parse(JSON.stringify(e.detail)) : null };
                    } catch (_) {
                        window.__fz_cf7 = { event: name, detail: null };
                    }
                }, true);
                ['wpcf7invalid','wpcf7spam','wpcf7mailsent','wpcf7mailfailed','wpcf7submit'].forEach(capture);
            }""")

            cf7_response_holder: dict[str, Any] = {"json": None, "status": None}

            def _on_response(resp):
                try:
                    if "/wp-json/contact-form-7/" in resp.url and "/feedback" in resp.url:
                        cf7_response_holder["status"] = resp.status
                        body = None
                        try:
                            body = resp.json()
                        except Exception:
                            try:
                                body = resp.text()
                            except Exception:
                                body = None
                        cf7_response_holder["json"] = body
                        log(event="cf7_response_seen", status=resp.status)
                except Exception:
                    pass

            page.on("response", _on_response)

            # 8. Submit
            _human_pause(900, 1800)
            _wander_mouse(page, steps=3)
            submit_btn = form.locator(
                ".wpcf7-submit, button[type=submit], input[type=submit]"
            ).first
            try:
                submit_btn.scroll_into_view_if_needed()
                _human_pause(400, 900)
                box = submit_btn.bounding_box()
                if box:
                    _human_mouse_move(
                        page,
                        box["x"] + box["width"] / 2 + random.uniform(-8, 8),
                        box["y"] + box["height"] / 2 + random.uniform(-3, 3),
                    )
                _human_pause(250, 550)
                submit_btn.click(delay=random.randint(50, 130))
                log(event="submit_clicked")
            except Exception as exc:
                log(event="submit_click_error", error=str(exc))

            # 9. Wait for the CF7 REST response
            deadline = time.time() + min(60, timeout)
            while time.time() < deadline and cf7_response_holder["json"] is None:
                time.sleep(0.3)

            cf7_body = cf7_response_holder["json"]
            if isinstance(cf7_body, dict):
                result["cf7_status"] = cf7_body.get("status")
                result["cf7_message"] = cf7_body.get("message")
                result["cf7_response"] = cf7_body
                result["ok"] = cf7_body.get("status") == "mail_sent"
            else:
                # Fallback: read the form's data-status attr
                try:
                    fs = page.evaluate(
                        "() => document.querySelector('form.wpcf7-form')?.getAttribute('data-status')"
                    )
                    log(event="form_data_status", value=fs)
                    result["cf7_status"] = fs
                except Exception:
                    pass

            ctx.close()
    except Exception as e:
        result["error"] = repr(e)
        log(event="fatal", error=repr(e))

    return result


# --- CLI for manual testing ----------------------------------------------

if __name__ == "__main__":
    import argparse
    import sys

    parser = argparse.ArgumentParser(description="FormZiller v3 submitter — manual test")
    parser.add_argument("--home", required=True, help="https://example.com/")
    parser.add_argument("--target", required=True, help="https://example.com/contact-us")
    parser.add_argument("--sitekey", required=True)
    parser.add_argument("--values", required=True,
                        help='JSON dict of field-name -> value, e.g. {"your-name":"X","your-email":"x@y.z"}')
    parser.add_argument("--profile", default="/var/lib/formziller/profiles/cli")
    parser.add_argument("--marker-field", default=None)
    parser.add_argument("--marker-value", default=None)
    parser.add_argument("--proxy", default=None, help="server URL, e.g. http://user:pass@host:port")

    args = parser.parse_args()
    proxy = None
    if args.proxy:
        proxy = {"server": args.proxy}

    def stream(ev):
        print(json.dumps(ev, ensure_ascii=False), flush=True)

    out = submit_cf7_v3(
        home_url=args.home,
        target_url=args.target,
        sitekey=args.sitekey,
        form_values=json.loads(args.values),
        marker_field=args.marker_field,
        marker_value=args.marker_value,
        profile_dir=args.profile,
        proxy=proxy,
        event_sink=stream,
    )
    out_no_events = {k: v for k, v in out.items() if k != "events"}
    print("==RESULT==")
    print(json.dumps(out_no_events, ensure_ascii=False, indent=2))
    sys.exit(0 if out["ok"] else 1)
