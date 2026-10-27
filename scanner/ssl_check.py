"""
SSL/TLS inspection.

Connects to the already-validated IP (not the hostname again, to avoid DNS rebinding)
and checks: HTTPS support, certificate trust (expiry, self-signed, hostname match),
days until expiry, and the TLS version. Trusted roots come from certifi, so results
are the same on Windows and Linux.
"""
import socket
import ssl
import warnings
from datetime import datetime, timezone

import certifi

TIMEOUT = 6


def _finding(title, severity, description, recommendation=""):
    return {"category": "SSL/TLS", "title": title, "severity": severity,
            "description": description, "recommendation": recommendation}


def _connect(ip, host, port, verify):
    ctx = ssl.create_default_context(cafile=certifi.where())
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    sock = socket.create_connection((ip, port), timeout=TIMEOUT)
    try:
        return ctx.wrap_socket(sock, server_hostname=host)
    except Exception:
        sock.close()
        raise


def _connect_retry(ip, host, port, verify):
    try:
        return _connect(ip, host, port, verify)
    except ssl.SSLEOFError:
        return _connect(ip, host, port, verify)  # server closed the connection: retry once
    except (ssl.SSLError, ConnectionRefusedError):
        raise                                     # real answers from the server, no retry
    except OSError:
        return _connect(ip, host, port, verify)  # one retry for timeouts / resets


def _legacy_tls_version(ip, host, port):
    """Reconnect allowing TLS 1.0/1.1, ONLY to learn which version an old server uses.
    No data is exchanged on this connection, so its weak encryption doesn't matter."""
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)  # Python warns about TLSv1 itself
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.minimum_version = ssl.TLSVersion.TLSv1
            ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
        with socket.create_connection((ip, port), timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                return ssock.version()
    except (OSError, ValueError):  # ssl.SSLError is an OSError
        return None


def _read_tls_version(ip, host, port):
    """TLS version without verifying the certificate (modern first, then legacy)."""
    try:
        with _connect(ip, host, port, verify=False) as ssock:
            return ssock.version()
    except OSError:
        return _legacy_tls_version(ip, host, port)


def _tls_version_finding(version):
    if version == "TLSv1.3":
        return _finding("Uses TLS 1.3", "pass", "The newest and most secure TLS version.")
    if version == "TLSv1.2":
        return _finding("Uses TLS 1.2", "pass", "TLS 1.2 is secure. TLS 1.3 is faster and recommended.")
    return _finding(
        f"Outdated TLS version ({version})", "high",
        "TLS 1.0 and 1.1 have known weaknesses and are no longer supported by browsers.",
        "Disable TLS 1.0/1.1 and enable TLS 1.2 and 1.3 on the server.")


def _connection_problem(port, https_reached, error):
    print(f"[ssl] connection problem: {error!r}")
    if https_reached:
        # The page loaded over HTTPS, so HTTPS works. The check just couldn't finish.
        return _finding(
            "SSL check couldn't finish", "info",
            "The secure connection was closed, reset or timed out, so the certificate couldn't be checked. Try scanning again.")
    return _finding(
        "HTTPS is not supported", "high",
        f"Couldn't open a secure connection on port {port}. Data between visitors and the site isn't encrypted.",
        "Enable HTTPS with a free certificate from Let's Encrypt.")


def check_ssl(target, https_reached=False):
    """Returns (findings, info). info feeds the SSL/TLS card on the dashboard."""
    host = target["host"]
    port = target["port"] if target["scheme"] == "https" else 443
    ip = next((i for i in target["ips"] if ":" not in i), target["ips"][0])  # prefer IPv4

    findings = []
    info = {"https": False, "valid": False, "tls_version": None,
            "issuer": None, "expires": None, "days_left": None}

    # 1) Try a normal, verified connection
    try:
        ssock = _connect_retry(ip, host, port, verify=True)

    except ssl.SSLCertVerificationError as e:
        info["https"] = True
        reason = (e.verify_message or "the certificate couldn't be verified").rstrip(".")
        findings.append(_finding(
            "SSL certificate is not trusted", "high",
            f"Browsers will show a security warning to visitors. Reason: {reason}.",
            "Install a valid certificate from a trusted authority (e.g. Let's Encrypt) "
            "that matches the domain and isn't expired."))
        info["tls_version"] = _read_tls_version(ip, host, port)
        if info["tls_version"]:
            findings.append(_tls_version_finding(info["tls_version"]))
        return findings, info

    except ssl.SSLEOFError as e:
        info["https"] = https_reached
        findings.append(_connection_problem(port, https_reached, e))
        return findings, info

    except ssl.SSLError:
        info["https"] = True
        legacy = _legacy_tls_version(ip, host, port)
        if legacy in ("TLSv1", "TLSv1.1"):
            info["tls_version"] = legacy
            findings.append(_tls_version_finding(legacy))  # the real reason: outdated TLS
        else:
            findings.append(_finding(
                "TLS handshake failed", "high",
                "The server's TLS setup couldn't be negotiated securely. It may only support weak ciphers.",
                "Enable TLS 1.2 and TLS 1.3 with modern cipher suites."))
        return findings, info

    except OSError as e:
        info["https"] = https_reached
        findings.append(_connection_problem(port, https_reached, e))
        return findings, info

    # 2) Verified connection succeeded: read the details
    with ssock:
        info["https"] = True
        info["valid"] = True
        info["tls_version"] = ssock.version()
        cert = ssock.getpeercert()

    issuer = dict(item[0] for item in cert.get("issuer", ()))
    info["issuer"] = issuer.get("organizationName") or issuer.get("commonName")

    expires = datetime.fromtimestamp(ssl.cert_time_to_seconds(cert["notAfter"]), tz=timezone.utc)
    days_left = (expires - datetime.now(timezone.utc)).days
    info["expires"] = expires.strftime("%Y-%m-%d")
    info["days_left"] = days_left

    findings.append(_finding("Valid SSL certificate", "pass",
                             f"Issued by {info['issuer']}. Trusted and matches the domain."))

    # 3) Expiry
    if days_left < 15:
        findings.append(_finding(
            "SSL certificate expires very soon", "high",
            f"The certificate expires in {days_left} days ({info['expires']}).",
            "Renew the certificate now and enable auto-renewal."))
    elif days_left < 30:
        findings.append(_finding(
            "SSL certificate expires soon", "medium",
            f"The certificate expires in {days_left} days ({info['expires']}).",
            "Renew the certificate soon and enable auto-renewal."))
    else:
        findings.append(_finding("Certificate expiry is fine", "pass",
                                 f"Expires in {days_left} days ({info['expires']})."))

    # 4) TLS version
    findings.append(_tls_version_finding(info["tls_version"]))

    return findings, info