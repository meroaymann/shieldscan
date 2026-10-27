import os
import socket
from concurrent.futures import ThreadPoolExecutor

TIMEOUT = 1.5
ENABLED = os.getenv("ENABLE_PORT_CHECK", "1") == "1"

DB_DESC = "This database port is reachable from the internet, so attackers can try to log in or exploit it."
DB_FIX = "Block this port in the firewall and only allow access from your application server."

# port: (service, severity, description, recommendation)
PORTS = {
    21: ("FTP", "medium", "FTP sends passwords and files unencrypted.",
         "Close port 21 or switch to SFTP."),
    22: ("SSH", "info", "SSH is open for remote administration. This is normal, but it's a common brute-force target.",
         "Disable password login and allow SSH keys only."),
    23: ("Telnet", "high", "Telnet sends everything, including passwords, in plain text.",
         "Disable Telnet and use SSH instead."),
    25: ("SMTP", "info", "A mail server is reachable on this host.",
         "Make sure it isn't configured as an open relay."),
    3306: ("MySQL", "high", DB_DESC, DB_FIX),
    3389: ("Remote Desktop", "medium", "Remote Desktop (RDP) is a common target for brute-force attacks.",
           "Only allow RDP through a VPN or from specific IP addresses."),
    5432: ("PostgreSQL", "high", DB_DESC, DB_FIX),
    6379: ("Redis", "high", DB_DESC, DB_FIX),
    9200: ("Elasticsearch", "high", DB_DESC, DB_FIX),
    27017: ("MongoDB", "high", DB_DESC, DB_FIX),
}


def _finding(title, severity, description, recommendation=""):
    return {"category": "Ports", "title": title, "severity": severity,
            "description": description, "recommendation": recommendation}


def _is_open(ip, port):
    try:
        with socket.create_connection((ip, port), timeout=TIMEOUT):
            return True
    except OSError:
        return False


def check_ports(target):
    info = {"enabled": ENABLED, "checked": list(PORTS), "open": []}

    if not ENABLED:
        return [_finding("Port check is turned off", "info",
                         "To keep the online version fully passive, the port check only runs locally.")], info

    ip = next((i for i in target["ips"] if ":" not in i), target["ips"][0])  # the IP we already validated
    ports = list(PORTS)
    with ThreadPoolExecutor(max_workers=len(ports)) as pool:
        states = list(pool.map(lambda p: _is_open(ip, p), ports))

    info["open"] = [p for p, is_open in zip(ports, states) if is_open]

    findings = []
    for port in info["open"]:
        service, severity, description, recommendation = PORTS[port]
        findings.append(_finding(f"Port {port} ({service}) is open", severity, description, recommendation))

    if not any(PORTS[p][1] != "info" for p in info["open"]):
        findings.append(_finding("No risky ports open", "pass",
                                 "Checked: " + ", ".join(str(p) for p in ports)))
    return findings, info