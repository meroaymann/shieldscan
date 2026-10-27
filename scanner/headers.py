"""
HTTP security header analysis.

Checks: HSTS (HTTPS only), Content-Security-Policy, clickjacking protection
(X-Frame-Options or CSP frame-ancestors), X-Content-Type-Options,
Referrer-Policy and Permissions-Policy.

The CSP is parsed into directives, so only settings that really weaken it are reported
(e.g. 'unsafe-inline' in script-src without a nonce/hash), not every keyword it contains.
"""
import re

HSTS_MIN_AGE = 15552000  # 180 days
WEAK_REFERRER = ("unsafe-url", "no-referrer-when-downgrade")


def _finding(title, severity, description, recommendation=""):
    return {"category": "Headers", "title": title, "severity": severity,
            "description": description, "recommendation": recommendation}


def _hsts_max_age(value):
    for part in value.lower().split(";"):
        part = part.strip()
        if part.startswith("max-age="):
            try:
                return int(part.split("=", 1)[1].strip().strip('"'))
            except ValueError:
                return 0
    return 0


def _parse_csp(csp):
    """'default-src 'self'; script-src a b' -> {'default-src': ["'self'"], 'script-src': ['a', 'b']}"""
    directives = {}
    for part in re.split(r"[;,]", csp):          # several CSP headers are joined with ","
        tokens = part.strip().split()
        if tokens:
            directives.setdefault(tokens[0].lower(), [t.lower() for t in tokens[1:]])  # first one wins
    return directives


def _check_csp(headers):
    csp = headers.get("Content-Security-Policy", "")
    if not csp:
        if headers.get("Content-Security-Policy-Report-Only"):
            return _finding(
                "CSP is in report-only mode", "low",
                "The policy only reports violations and doesn't block anything.",
                "Switch to an enforced Content-Security-Policy header once it's tested.")
        return _finding(
            "Missing Content-Security-Policy (CSP)", "medium",
            "Without CSP, the browser has no extra protection against XSS and injected scripts.",
            "Add a CSP, starting with: Content-Security-Policy: default-src 'self'")

    directives = _parse_csp(csp)
    script = directives.get("script-src", directives.get("default-src"))
    if script is None:
        return _finding(
            "CSP doesn't restrict scripts", "low",
            "The CSP has no script-src or default-src, so any script can still run.",
            "Add script-src (or default-src 'self') to the policy.")

    has_nonce_or_hash = any(v.startswith(("'nonce-", "'sha256-", "'sha384-", "'sha512-")) or v == "'strict-dynamic'"
                            for v in script)
    weak = []
    if "'unsafe-inline'" in script and not has_nonce_or_hash:  # browsers ignore unsafe-inline when a nonce/hash exists
        weak.append("'unsafe-inline'")
    if "'unsafe-eval'" in script:
        weak.append("'unsafe-eval'")

    if weak:
        return _finding(
            f"CSP allows {' and '.join(weak)} for scripts", "low",
            "These keywords let injected scripts run, which weakens CSP's protection against XSS.",
            "Remove them from script-src and use nonces or hashes instead.")
    return _finding("Content-Security-Policy is set", "pass", "A CSP restricts which scripts can run.")


def check_headers(headers, is_https):
    findings = []

    # 1) Strict-Transport-Security (HSTS): browsers only honour it over HTTPS
    if is_https:
        hsts = headers.get("Strict-Transport-Security")
        if not hsts:
            findings.append(_finding(
                "Missing Strict-Transport-Security (HSTS)", "medium",
                "Browsers aren't told to always use HTTPS, so users can be downgraded to HTTP.",
                "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains"))
        elif _hsts_max_age(hsts) < HSTS_MIN_AGE:
            findings.append(_finding(
                "HSTS max-age is too short", "low",
                f"Current value: {hsts}",
                "Use a max-age of at least 31536000 (1 year)."))
        else:
            findings.append(_finding("HSTS is enabled", "pass", f"Value: {hsts}"))

    # 2) Content-Security-Policy
    findings.append(_check_csp(headers))

    # 3) Clickjacking: X-Frame-Options OR CSP frame-ancestors (but not "*")
    ancestors = _parse_csp(headers.get("Content-Security-Policy", "")).get("frame-ancestors")
    xfo = headers.get("X-Frame-Options", "").strip().upper()
    if (ancestors is not None and "*" not in ancestors) or xfo in ("DENY", "SAMEORIGIN"):
        findings.append(_finding("Clickjacking protection is set", "pass",
                                 "X-Frame-Options or CSP frame-ancestors is configured."))
    else:
        findings.append(_finding(
            "Missing clickjacking protection", "medium",
            "The site can be embedded in an iframe on another site and used for clickjacking.",
            "Add: X-Frame-Options: DENY (or CSP frame-ancestors 'none')"))

    # 4) X-Content-Type-Options
    if headers.get("X-Content-Type-Options", "").strip().lower() == "nosniff":
        findings.append(_finding("X-Content-Type-Options is set", "pass", "Value: nosniff"))
    else:
        findings.append(_finding(
            "Missing X-Content-Type-Options", "low",
            "Browsers may 'sniff' files as a different content type, which can lead to XSS.",
            "Add: X-Content-Type-Options: nosniff"))

    # 5) Referrer-Policy (the browser uses the LAST valid value in a list)
    referrer = headers.get("Referrer-Policy", "").strip().lower()
    last_policy = referrer.split(",")[-1].strip() if referrer else ""
    if not referrer:
        findings.append(_finding(
            "Missing Referrer-Policy", "low",
            "Full URLs (which may contain sensitive data) can leak to other sites.",
            "Add: Referrer-Policy: strict-origin-when-cross-origin"))
    elif last_policy in WEAK_REFERRER:
        findings.append(_finding(
            "Referrer-Policy is weak", "low",
            f"'{last_policy}' sends the full URL to other sites.",
            "Use: Referrer-Policy: strict-origin-when-cross-origin"))
    else:
        findings.append(_finding("Referrer-Policy is set", "pass", f"Value: {referrer}"))

    # 6) Permissions-Policy
    if headers.get("Permissions-Policy"):
        findings.append(_finding("Permissions-Policy is set", "pass",
                                 "Browser features like camera and microphone are restricted."))
    else:
        findings.append(_finding(
            "Missing Permissions-Policy", "low",
            "Browser features (camera, microphone, location) aren't explicitly restricted.",
            "Add: Permissions-Policy: camera=(), microphone=(), geolocation=()"))

    return findings