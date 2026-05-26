# formziller-captcha

reCAPTCHA v3 invisible submitter for FormZiller's Contact Form 7 monitoring.

## What this is

A Python module (`captcha/v3_submitter.py`) that submits a Contact Form 7
(WordPress) form protected by reCAPTCHA v3 invisible, by driving a real
Chrome browser through [patchright](https://github.com/Kaliiiiiiiiii-Vinyzu/patchright).

The module is designed to be called from FormZiller's checker pipeline when
a target form is gated by reCAPTCHA v3. It produces a humanized session:

- Stock Chrome (`channel="chrome"`, **not** `chromium-headless-shell`), headed
  via `xvfb-run` on a headless server.
- Persistent profile (`launch_persistent_context`) so cookies and Google's
  reCAPTCHA fingerprint accumulate between runs.
- Warm-up navigation: homepage → inner page → form page, with smooth scrolls
  and dwell time.
- Bezier mouse paths, hover-before-click, per-character typing with jitter.
- Waits for the CF7 plugin to auto-fill `_wpcf7_recaptcha_response`; falls
  back to a manual `grecaptcha.execute()` if the plugin is slow.
- Captures the CF7 REST response and the form's `data-status` attribute.

## What it does NOT do

It does not magically defeat reCAPTCHA v3. The dominant factor in v3 score
is **IP reputation**, and from a datacenter IP (Hetzner, OVH, DO, AWS, …)
the score typically lands at 0.1–0.3 — well below the CF7-reCAPTCHA default
threshold of 0.5. Expect `cf7_status == "spam"` until you route through a
residential proxy (`proxy=` kwarg) or lower the threshold on the target site.

## Requirements

System packages:

```
apt-get install -y xvfb wget gnupg
wget -O /tmp/chrome.deb https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb
apt-get install -y /tmp/chrome.deb
```

Python packages: see `requirements.txt`.

## CLI usage

```bash
xvfb-run -a --server-args="-screen 0 1366x800x24" \
  python -m captcha.v3_submitter \
    --home    https://example.com/ \
    --target  https://example.com/contact-us \
    --sitekey 6Lc... \
    --values  '{"your-name":"FormZiller Monitor","your-email":"monitor@example.com"}' \
    --profile /var/lib/formziller/profiles/example \
    --marker-field form-location \
    --marker-value "FORMZILLER_MONITOR <secret>"
```

## Programmatic usage

```python
from captcha.v3_submitter import submit_cf7_v3

result = submit_cf7_v3(
    home_url="https://example.com/",
    target_url="https://example.com/contact-us",
    sitekey="6Lc...",
    form_values={"your-name": "FormZiller Monitor", "your-email": "monitor@example.com"},
    marker_field="form-location",
    marker_value="FORMZILLER_MONITOR <secret>",
    profile_dir="/var/lib/formziller/profiles/<form_id>",
    proxy={"server": "http://user:pass@residential.proxy:8000"},  # optional but recommended
)

# result = {
#     "ok": True/False,
#     "cf7_status": "mail_sent" | "spam" | "validation_failed" | "mail_failed" | None,
#     "cf7_message": str | None,
#     "cf7_response": dict | None,
#     "events": [ ... ],   # timeline of internal events for debugging
#     "error": str | None,
# }
```

## Integration point (FormZiller checker)

In `backend/services/checker_runner.py`, the v3 branch currently early-exits
with `CAPTCHA_DETECTED`. To activate this module for a v3-gated form,
replace that early-exit with a call to `submit_cf7_v3(...)` and map
`result["cf7_status"]` back to the checker's result schema.
