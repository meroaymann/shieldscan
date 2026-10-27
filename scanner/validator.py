import ipaddress
import socket
from urllib.parse import urlparse

ALLOWED_WEB_PORTS = {80, 443, 8080, 8443}


class TargetError(ValueError):
    """A user-facing problem with the target URL."""


def normalize_url(raw):
    raw = (raw or "").strip()
    if not raw:
        raise TargetError("Please enter a website URL.")
    if len(raw) > 2048:
        raise TargetError("This URL is too long.")
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
    return {
        "url": f"{parsed.scheme}://{netloc}{parsed.path or '/'}",
        "scheme": parsed.scheme,
        "host": host,
        "port": port,
    }


def resolve_public_ips(host):
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        raise TargetError("Couldn't find this website. Check the address and try again.")

    ips = sorted({info[4][0] for info in infos})
    for ip in ips:
        if not ipaddress.ip_address(ip).is_global:
            raise TargetError("Scanning internal or private network addresses isn't allowed.")
    return ips


def validate_target(raw):
    target = normalize_url(raw)
    target["ips"] = resolve_public_ips(target["host"])
    return target