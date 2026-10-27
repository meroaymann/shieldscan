"""
Safe page download.

  - Every redirect is re-checked by validate_target (SSRF protection), max 5 redirects
  - Limits: 8s without data, 20s total, 500 KB of content
  - If the certificate is invalid, the page is fetched again without verification
    ONLY to read its headers; ssl_check.py reports the certificate problem itself
"""
import time
from urllib.parse import urljoin

import requests
import urllib3

from scanner.validator import validate_target, TargetError

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

TIMEOUT = 8              # seconds without receiving any data
TOTAL_TIMEOUT = 20       # seconds for the whole fetch (stops slow-drip servers)
MAX_REDIRECTS = 5
MAX_BYTES = 500_000
REQUEST_HEADERS = {"User-Agent": "ShieldScan/1.0 (non-intrusive security scanner; educational project)"}


class FetchError(Exception):
    """A user-facing problem reaching the website."""


def _get(url, verify):
    return requests.get(url, headers=REQUEST_HEADERS, timeout=TIMEOUT,
                        allow_redirects=False, verify=verify, stream=True)


def _request(url):
    error = None
    for attempt in range(2):  # one retry for flaky connections
        try:
            try:
                return _get(url, verify=True), True
            except requests.exceptions.SSLError:
                return _get(url, verify=False), False
        except requests.exceptions.RequestException as e:
            print(f"[fetch] attempt {attempt + 1} failed for {url}: {e!r}")
            error = e

    if isinstance(error, requests.exceptions.Timeout):
        raise FetchError("The website took too long to respond.")
    raise FetchError("Couldn't connect to the website. It may be down or blocking requests.")


def _read_body(resp, deadline):
    content = b""
    for chunk in resp.iter_content(65536):
        content += chunk
        if len(content) >= MAX_BYTES or time.monotonic() > deadline:
            break  # enough to analyse: stop instead of waiting for the rest
    return content[:MAX_BYTES]


def _decode(content, resp):
    # requests guesses ISO-8859-1 when no charset is given, which breaks UTF-8 pages
    declared = "charset=" in resp.headers.get("Content-Type", "").lower()
    try:
        return content.decode(resp.encoding if declared and resp.encoding else "utf-8", errors="replace")
    except LookupError:  # unknown charset name
        return content.decode("utf-8", errors="replace")


def fetch_page(target):
    """Download the target page and return its URL, status, headers, cookies and HTML."""
    url = target["url"]
    redirects = []
    deadline = time.monotonic() + TOTAL_TIMEOUT

    for _ in range(MAX_REDIRECTS + 1):
        if time.monotonic() > deadline:
            raise FetchError("The website took too long to respond.")

        resp, cert_verified = _request(url)

        if resp.is_redirect:
            next_url = urljoin(url, resp.headers.get("Location", ""))
            resp.close()
            redirects.append({"from": url, "to": next_url, "status": resp.status_code})
            try:
                validate_target(next_url)  # every redirect goes through SSRF protection again
            except TargetError as e:
                raise FetchError(f"The website redirected to a blocked address: {e}")
            url = next_url
            continue

        try:
            content = _read_body(resp, deadline)
        except requests.exceptions.RequestException:
            raise FetchError("The connection was interrupted while reading the page.")
        finally:
            resp.close()

        return {
            "final_url": url,
            "status": resp.status_code,
            "headers": resp.headers,                                # case-insensitive dict
            "set_cookies": resp.raw.headers.getlist("Set-Cookie"),  # each cookie separately
            "html": _decode(content, resp),
            "redirects": redirects,
            "cert_verified": cert_verified,
        }

    raise FetchError("The website redirected too many times.")