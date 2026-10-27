import re
import requests
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urljoin
from bs4 import BeautifulSoup
from scanner.fetch import REQUEST_HEADERS
from scanner.validator import validate_target, TargetError

TIMEOUT = 5


def _finding(title, severity, description, recommendation=""):
    return {"category": "Misconfiguration", "title": title, "severity": severity,
            "description": description, "recommendation": recommendation}


def _names(items, limit=8):
    items = sorted(set(items))
    return ", ".join(items[:limit]) + (f" (+{len(items) - limit} more)" if len(items) > limit else "")


# ---------- 1) Technology / version leaks ----------
def check_info_leaks(headers):
    leaks = []
    server = headers.get("Server", "")
    if server and re.search(r"\d", server):
        leaks.append(f"Server: {server}")
    for name in ("X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version"):
        if headers.get(name):
            leaks.append(f"{name}: {headers[name]}")

    if leaks:
        return [_finding(
            "Server reveals technology or version", "low",
            "Attackers can look up known vulnerabilities for these exact versions: " + "; ".join(leaks),
            "Hide version numbers (e.g. 'server_tokens off' in Nginx, 'ServerTokens Prod' in Apache) "
            "and remove X-Powered-By.")]
    return [_finding("No version leaks in headers", "pass",
                     "The server doesn't reveal software versions.")]


# ---------- 2) Cookie flags ----------
def check_cookies(set_cookies, is_https):
    if not set_cookies:
        return []

    no_secure, no_httponly, no_samesite = [], [], []
    for raw in set_cookies:
        parts = [p.strip() for p in raw.split(";")]
        name = parts[0].split("=", 1)[0].strip() or "(unnamed)"
        attrs = {p.split("=", 1)[0].strip().lower() for p in parts[1:]}
        if is_https and "secure" not in attrs:
            no_secure.append(name)
        if "httponly" not in attrs:
            no_httponly.append(name)
        if "samesite" not in attrs:
            no_samesite.append(name)

    findings = []
    if no_secure:
        findings.append(_finding(
            "Cookies without the Secure flag", "medium",
            f"These cookies can be sent over unencrypted HTTP: {_names(no_secure)}",
            "Add the Secure flag to all cookies."))
    if no_httponly:
        findings.append(_finding(
            "Cookies without the HttpOnly flag", "low",
            f"JavaScript can read these cookies, so an XSS attack could steal them: {_names(no_httponly)}",
            "Add HttpOnly to cookies that JavaScript doesn't need (especially session cookies)."))
    if no_samesite:
        findings.append(_finding(
            "Cookies without the SameSite attribute", "low",
            f"These cookies may be sent with cross-site requests (CSRF risk): {_names(no_samesite)}",
            "Add SameSite=Lax (or Strict) to cookies."))
    if not findings:
        findings.append(_finding("Cookies are set securely", "pass",
                                 "All cookies use Secure, HttpOnly and SameSite."))
    return findings


# ---------- 3) HTTP → HTTPS redirect ----------
def check_https_redirect(target):
    http_url = f"http://{target['host']}/"
    try:
        validate_target(http_url)  # SSRF protection again
        resp = requests.get(http_url, headers=REQUEST_HEADERS, timeout=TIMEOUT, allow_redirects=False)
        resp.close()
    except (TargetError, requests.exceptions.RequestException):
        return [_finding("HTTP (port 80) is closed", "info",
                         "The site doesn't answer on plain HTTP, so there's nothing to redirect.")]

    location = urljoin(http_url, resp.headers.get("Location", ""))
    if resp.is_redirect and location.startswith("https://"):
        return [_finding("HTTP redirects to HTTPS", "pass",
                         f"http:// returns {resp.status_code} → {location}")]
    return [_finding(
        "HTTP doesn't redirect to HTTPS", "medium",
        "Visitors who type http:// stay on an unencrypted connection.",
        "Add a permanent (301) redirect from http:// to https://")]


# ---------- 4) Exposed sensitive files ----------
def _is_html(body):
    start = body[:200].lower()
    return b"<html" in start or b"<!doctype" in start


SENSITIVE_FILES = [
    ("/.env", "Environment file (.env) is public",
     "May contain passwords, API keys and database credentials.",
     lambda b: not _is_html(b) and re.search(rb"(?m)^[A-Z][A-Z0-9_]*=", b)),
    ("/.git/HEAD", "Git repository is exposed (.git)",
     "Attackers can download the full source code, history and any secrets in it.",
     lambda b: b.startswith(b"ref: refs/")),
    ("/.git/config", "Git config is exposed (.git/config)",
     "Reveals repository details and sometimes credentials.",
     lambda b: b"[core]" in b and not _is_html(b)),
    ("/.DS_Store", "macOS .DS_Store file is public",
     "Reveals the names of files and folders on the server.",
     lambda b: b[4:8] == b"Bud1"),
    ("/server-status", "Apache server-status page is public",
     "Shows live requests, client IPs and server details.",
     lambda b: b"Apache Server Status" in b),
    ("/phpinfo.php", "phpinfo() page is public",
     "Reveals the PHP version, configuration, paths and environment variables.",
     lambda b: b"phpinfo()" in b and b"PHP Version" in b),
]


def _probe(url, detector):
    try:
        resp = requests.get(url, headers=REQUEST_HEADERS, timeout=TIMEOUT,
                            allow_redirects=False, stream=True, verify=False)
        try:
            if resp.status_code != 200:
                return False
            body = resp.raw.read(4096, decode_content=True) or b""
            return bool(detector(body))
        finally:
            resp.close()
    except requests.exceptions.RequestException:
        return False


def check_exposed_files(base_url):
    with ThreadPoolExecutor(max_workers=len(SENSITIVE_FILES)) as pool:
        results = list(pool.map(lambda f: _probe(urljoin(base_url, f[0]), f[3]), SENSITIVE_FILES))

    findings = [
        _finding(title, "high", f"{urljoin(base_url, path)} is publicly accessible. {why}",
                 f"Block access to {path} in the web server config and remove it from the public folder.")
        for (path, title, why, _), exposed in zip(SENSITIVE_FILES, results) if exposed
    ]
    if not findings:
        findings.append(_finding("No sensitive files exposed", "pass",
                                 "Checked: " + ", ".join(f[0] for f in SENSITIVE_FILES)))
    return findings


# ---------- 5) HTML: directory listing, mixed content, insecure forms ----------
def check_html(html, final_url):
    findings = []
    soup = BeautifulSoup(html, "html.parser")

    title = (soup.title.string or "") if soup.title else ""
    if title.strip().lower().startswith("index of /"):
        findings.append(_finding(
            "Directory listing is enabled", "medium",
            "The server shows a list of files, which can reveal private or backup files.",
            "Disable directory listing (e.g. 'Options -Indexes' in Apache, 'autoindex off' in Nginx)."))

    if not final_url.startswith("https://"):
        return findings

    def insecure(value):
        return (value or "").strip().lower().startswith("http://")

    active = [t["src"] for t in soup.find_all(["script", "iframe"], src=True) if insecure(t["src"])]
    active += [t["href"] for t in soup.find_all("link", href=True)
               if "stylesheet" in [r.lower() for r in (t.get("rel") or [])] and insecure(t["href"])]
    passive = [t["src"] for t in soup.find_all(["img", "audio", "video", "source"], src=True)
               if insecure(t["src"])]
    forms = [f["action"] for f in soup.find_all("form", action=True) if insecure(f["action"])]

    if active:
        findings.append(_finding(
            "Mixed content: scripts or styles over HTTP", "medium",
            f"This HTTPS page loads {len(active)} script/style/iframe file(s) over HTTP. "
            "Browsers block them, and an attacker could modify them.",
            "Load all resources over https://"))
    if passive:
        findings.append(_finding(
            "Mixed content: images or media over HTTP", "low",
            f"This HTTPS page loads {len(passive)} image/media file(s) over HTTP.",
            "Load all resources over https://"))
    if forms:
        findings.append(_finding(
            "Form submits data over HTTP", "medium",
            f"{len(forms)} form(s) send data to an http:// address, so it isn't encrypted.",
            "Change form actions to https://"))
    if not (active or passive or forms):
        findings.append(_finding("No mixed content", "pass",
                                 "All scripts, styles, images and forms use HTTPS."))
    return findings


# ---------- Run all ----------
def check_misconfig(target, page, has_https):
    is_https = page["final_url"].startswith("https://")
    findings = []
    findings += check_info_leaks(page["headers"])
    findings += check_cookies(page["set_cookies"], is_https)
    if has_https:
        findings += check_https_redirect(target)
    findings += check_exposed_files(page["final_url"])
    findings += check_html(page["html"], page["final_url"])
    return findings