"""
ShieldScan: a passive website security scanner (Flask).

Scan pipeline for POST /scan:
  1. validate_target  - checks the URL and blocks private/internal IPs (SSRF protection)
  2. fetch_page       - downloads the page safely (timeouts, size limit, checked redirects)
  3. check_headers    - HTTP security headers
  4. check_ssl        - certificate trust, expiry and TLS version
  5. check_misconfig  - version leaks, cookies, HTTP->HTTPS, exposed files, mixed content
  6. check_ports      - light TCP check of risky ports (local version only)
  7. build_report     - score (0-100), grade (A-F) and sorted findings

For educational and authorized testing only.
"""
import os
from flask import Flask, render_template, request, jsonify
from scanner.validator import validate_target, TargetError
from scanner.fetch import fetch_page, FetchError
from scanner.headers import check_headers
from scanner.ssl_check import check_ssl
from scanner.misconfig import check_misconfig
from scanner.ports import check_ports
from scanner.report import build_report

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024  # a scan request only needs a URL


@app.route("/")
def home():
    return render_template("index.html")


def _fetch_with_fallback(raw_url):
    """Fetch the site over HTTPS. If that fails and the user didn't type a scheme, try plain HTTP."""
    target = validate_target(raw_url)
    try:
        return target, fetch_page(target)
    except FetchError:
        if "://" in raw_url:
            raise                                      # the user chose the scheme, so don't change it
        target = validate_target("http://" + raw_url)
        return target, fetch_page(target)


@app.route("/scan", methods=["POST"])
def scan():
    data = request.get_json(silent=True) or {}
    if not data.get("authorized"):
        return jsonify({"error": "Please confirm you own this website or have permission to test it."}), 400

    raw_url = data.get("url")
    if not isinstance(raw_url, str):
        return jsonify({"error": "Please enter a website URL."}), 400

    try:
        target, page = _fetch_with_fallback(raw_url.strip())
        is_https = page["final_url"].startswith("https://")

        findings = check_headers(page["headers"], is_https)

        ssl_findings, ssl_info = check_ssl(target, https_reached=is_https)
        findings += ssl_findings

        findings += check_misconfig(target, page, ssl_info["https"])

        port_findings, ports_info = check_ports(target)
        findings += port_findings

    except TargetError as e:
        return jsonify({"error": str(e)}), 400
    except FetchError as e:
        return jsonify({"error": str(e)}), 502
    except Exception as e:
        print(f"[scan] unexpected error: {e!r}")  # details stay in the server log, never sent to the user
        return jsonify({"error": "Something went wrong during the scan. Please try again."}), 500

    report = build_report(findings)
    return jsonify({
        "target": target,
        "final_url": page["final_url"],
        "status": page["status"],
        "redirects": page["redirects"],
        "ssl": ssl_info,
        "ports": ports_info,
        **report,
    })


if __name__ == "__main__":
    app.run(debug=os.getenv("FLASK_DEBUG") == "1")