import os
from flask import Flask, render_template, request, jsonify
from scanner.validator import validate_target, TargetError
from scanner.fetch import fetch_page, FetchError
from scanner.headers import check_headers
from scanner.ssl_check import check_ssl
from scanner.misconfig import check_misconfig
from scanner.report import build_report
from scanner.ports import check_ports

app = Flask(__name__)


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/scan", methods=["POST"])
def scan():
    data = request.get_json(silent=True) or {}
    if not data.get("authorized"):
        return jsonify({"error": "Please confirm you own this website or have permission to test it."}), 400

    try:
        raw_url = (data.get("url") or "").strip()
        target = validate_target(raw_url)
        try:
            page = fetch_page(target)
        except FetchError:
            if "://" in raw_url:
                raise                      # the user chose the scheme, so don't change it
            target = validate_target("http://" + raw_url)  # no scheme typed: try plain HTTP
            page = fetch_page(target)

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
        print(f"[scan] unexpected error: {e}")
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