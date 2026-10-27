"""
Target validation and SSRF protection.

Every URL is checked before ShieldScan connects to it:
  - only http/https, no credentials, only standard web ports
  - the hostname is resolved, and EVERY resulting IP must be public
    (blocks localhost, private networks, cloud metadata 169.254.169.254, etc.)

This also runs again for every redirect (see fetch.py).
"""
import ipaddress
import socket
from urllib.parse import urlparse

ALLOWED_WEB_PORTS = {80, 443, 8080, 8443}
MAX_URL_LENGTH = 2048
FORBIDDEN_CHARS = set("\\ \t\r\n") | {chr(c) for c in range(32)}  # used in URL-parser bypass tricks


class TargetError(ValueError):
    """A user-facing problem with the target URL."""


def normalize_url(raw):
    """Check the URL's format and return its parts. Doesn't touch the network."""
    raw = (raw or "").strip()
    if not raw:
        raise TargetError("Please enter a website URL.")
    if len(raw) > MAX_URL_LENGTH:
        raise TargetError("This URL is too long.")
    if any(ch in FORBIDDEN_CHARS for ch in raw):
        raise TargetError("The URL contains characters that aren't allowed (spaces or backslashes).")
    if "://" not in raw:
        raw = "https://" + raw

    parsed = urlparse(raw)
    if parsed.scheme not in ("http", "https"):
        raise TargetError("Only http:// and https:// websites can be scanned.")
    if parsed.username or parsed.password:
        raise TargetError("URLs with a username or password aren't allowed.")

    host = (parsed.hostname or "").lower()
    if not host or "." not in host:
        raise TargetError("Please enter a valid website address, like example.com")

    try:
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
    except ValueError:
        raise TargetError("The port in this URL isn't valid.")
    if port not in ALLOWED_WEB_PORTS:
        raise TargetError("Only standard web ports (80, 443, 8080, 8443) are allowed.")

    default_port = 443 if parsed.scheme == "https" else 80
    netloc = host if port == default_port else f"{host}:{port}"
    query = f"?{parsed.query}" if parsed.query else ""
    return {
        "url": f"{parsed.scheme}://{netloc}{parsed.path or '/'}{query}",
        "scheme": parsed.scheme,
        "host": host,
        "port": port,
    }


def _is_public(ip_text):
    """True only for normal public internet addresses."""
    ip = ipaddress.ip_address(ip_text.split("%", 1)[0])  # drop IPv6 zone id (fe80::1%eth0)
    if ip.version == 6 and ip.ipv4_mapped:                # ::ffff:127.0.0.1 is really 127.0.0.1
        ip = ip.ipv4_mapped
    return ip.is_global and not ip.is_multicast


def resolve_public_ips(host):
    """Resolve the hostname. Every IP must be public, otherwise the scan is refused."""
    try:
        infos = socket.getaddrinfo(host, None)
    except (socket.gaierror, UnicodeError):
        raise TargetError("Couldn't find this website. Check the address and try again.")

    ips = sorted({info[4][0] for info in infos})
    if not ips:
        raise TargetError("Couldn't find this website. Check the address and try again.")
    for ip in ips:
        if not _is_public(ip):
            raise TargetError("Scanning internal or private network addresses isn't allowed.")
    return ips


def validate_target(raw):
    """Full check: format + DNS + public-IP rule. Returns url, scheme, host, port and ips."""
    target = normalize_url(raw)
    target["ips"] = resolve_public_ips(target["host"])
    return target