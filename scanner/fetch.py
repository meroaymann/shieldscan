import requests
import urllib3
from urllib.parse import urljoin
from scanner.validator import validate_target, TargetError

# We retry without certificate verification only to read headers;
# the SSL check reports the certificate problem separately.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

TIMEOUT = 8
MAX_REDIRECTS = 5
MAX_BYTES = 500_000
REQUEST_HEADERS = {"User-Agent": "ShieldScan/1.0 (passive security scanner)"}


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


def fetch_page(target):
    url = target["url"]
    redirects = []

    for _ in range(MAX_REDIRECTS + 1):
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

        # Read at most MAX_BYTES of the page
        content = b""
        for chunk in resp.iter_content(65536):
            content += chunk
            if len(content) >= MAX_BYTES:
                break
        resp.close()

        return {
            "final_url": url,
            "status": resp.status_code,
            "headers": resp.headers,                              # case-insensitive dict
            "set_cookies": resp.raw.headers.getlist("Set-Cookie"),  # each cookie separately
            "html": content.decode(resp.encoding or "utf-8", errors="replace"),
            "redirects": redirects,
            "cert_verified": cert_verified,
        }

    raise FetchError("The website redirected too many times.")