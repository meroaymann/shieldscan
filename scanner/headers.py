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


def check_headers(headers, is_https):
    findings = []
    csp = headers.get("Content-Security-Policy", "")

    # 1) Strict-Transport-Security (HSTS) — only meaningful over HTTPS
    if is_https:
        hsts = headers.get("Strict-Transport-Security")
        if not hsts:
            findings.append(_finding(
                "Missing Strict-Transport-Security (HSTS)", "medium",
                "Browsers aren't told to always use HTTPS, so users can be downgraded to HTTP.",
                "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains"))
        elif _hsts_max_age(hsts) < 15552000:  # 180 days
            findings.append(_finding(
                "HSTS max-age is too short", "low",
                f"Current value: {hsts}",
                "Use a max-age of at least 31536000 (1 year)."))
        else:
            findings.append(_finding("HSTS is enabled", "pass", f"Value: {hsts}"))

    # 2) Content-Security-Policy
    if not csp:
        if headers.get("Content-Security-Policy-Report-Only"):
            findings.append(_finding(
                "CSP is in report-only mode", "low",
                "The policy only reports violations and doesn't block anything.",
                "Switch to an enforced Content-Security-Policy header once it's tested."))
        else:
            findings.append(_finding(
                "Missing Content-Security-Policy (CSP)", "medium",
                "Without CSP, the browser has no extra protection against XSS and injected scripts.",
                "Add a CSP, starting with: Content-Security-Policy: default-src 'self'"))
    elif "'unsafe-inline'" in csp or "'unsafe-eval'" in csp:
        findings.append(_finding(
            "CSP allows unsafe-inline / unsafe-eval", "low",
            "These keywords weaken CSP's protection against XSS.",
            "Remove 'unsafe-inline' and 'unsafe-eval'; use nonces or hashes instead."))
    else:
        findings.append(_finding("Content-Security-Policy is set", "pass", "A CSP is in place."))

    # 3) Clickjacking: X-Frame-Options OR CSP frame-ancestors
    xfo = headers.get("X-Frame-Options", "").upper()
    if "frame-ancestors" in csp.lower() or xfo in ("DENY", "SAMEORIGIN"):
        findings.append(_finding("Clickjacking protection is set", "pass",
                                 "X-Frame-Options or CSP frame-ancestors is configured."))
    else:
        findings.append(_finding(
            "Missing clickjacking protection", "medium",
            "The site can be embedded in an iframe on another site and used for clickjacking.",
            "Add: X-Frame-Options: DENY (or CSP frame-ancestors 'none')"))

    # 4) X-Content-Type-Options
    if headers.get("X-Content-Type-Options", "").lower() == "nosniff":
        findings.append(_finding("X-Content-Type-Options is set", "pass", "Value: nosniff"))
    else:
        findings.append(_finding(
            "Missing X-Content-Type-Options", "low",
            "Browsers may 'sniff' files as a different content type, which can lead to XSS.",
            "Add: X-Content-Type-Options: nosniff"))

    # 5) Referrer-Policy
    referrer = headers.get("Referrer-Policy", "").lower()
    if not referrer:
        findings.append(_finding(
            "Missing Referrer-Policy", "low",
            "Full URLs (which may contain sensitive data) can leak to other sites.",
            "Add: Referrer-Policy: strict-origin-when-cross-origin"))
    elif "unsafe-url" in referrer:
        findings.append(_finding(
            "Referrer-Policy is unsafe", "low",
            "'unsafe-url' sends the full URL to every site, even over HTTP.",
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