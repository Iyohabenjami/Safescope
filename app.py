import os
import json
import datetime
from collections.abc import Mapping, Iterable

from flask import Flask, request, render_template, redirect, url_for, flash, jsonify
from dotenv import load_dotenv
import vt
import whois
import dns.resolver
import requests
import socket

# DO NOT overwrite datetime module again
# Removed: from datetime import datetime

load_dotenv()
VT_API_KEY = os.getenv("VT_API_KEY")

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET", "change-this-secret")


def vt_client():
    if not VT_API_KEY:
        return None
    return vt.Client(VT_API_KEY)


def safe_serialize(obj):
    if obj is None or isinstance(obj, (str, int, float, bool)):
        return obj

    # FIXED datetime handling
    if isinstance(obj, datetime.datetime):
        return obj.isoformat()

    if isinstance(obj, (bytes, bytearray)):
        try:
            return obj.decode("utf-8", errors="replace")
        except Exception:
            return str(obj)

    if isinstance(obj, Mapping):
        out = {}
        for k, v in obj.items():
            try:
                out[str(k)] = safe_serialize(v)
            except Exception:
                out[str(k)] = str(v)
        return out

    if isinstance(obj, Iterable) and not isinstance(obj, (str, bytes, bytearray)):
        return [safe_serialize(i) for i in obj]

    if hasattr(obj, "to_json") and callable(getattr(obj, "to_json")):
        try:
            decoded = json.loads(obj.to_json())
            return safe_serialize(decoded)
        except Exception:
            pass

    if hasattr(obj, "to_dict") and callable(getattr(obj, "to_dict")):
        try:
            return safe_serialize(obj.to_dict())
        except Exception:
            pass

    if hasattr(obj, "items") and callable(getattr(obj, "items")):
        try:
            return {str(k): safe_serialize(v) for k, v in obj.items()}
        except Exception:
            pass

    try:
        return str(obj)
    except Exception:
        return repr(obj)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/scan-file", methods=["POST"])
def scan_file():
    f = request.files.get("file")
    if not f or f.filename == "":
        flash("No file selected", "warning")
        return redirect(url_for("index"))

    client = vt_client()
    if not client:
        flash("VirusTotal API key not configured.", "danger")
        return redirect(url_for("index"))

    os.makedirs("./uploads", exist_ok=True)
    path = f"./uploads/{f.filename}"
    f.save(path)

    try:
        with open(path, "rb") as fh:
            analysis = client.scan_file(fh, wait_for_completion=True)

        stats = analysis.stats if hasattr(analysis, "stats") else {}
        verdict = {"malicious_engines": stats.get("malicious", "N/A")}

        flash(f"Scan completed. Malicious engines: {verdict['malicious_engines']}", "success")
        return redirect(url_for("index"))

    except Exception as e:
        flash(f"Error scanning: {str(e)}", "danger")
        return redirect(url_for("index"))


@app.route("/check-domain", methods=["POST"])
def check_domain():
    domain = request.form.get("domain", "").strip()
    if not domain:
        flash("No domain provided", "warning")
        return redirect(url_for("index"))

    result = {"domain": domain}

    try:
        w = whois.whois(domain)
        result["whois"] = {
            "domain_name": safe_serialize(w.get("domain_name")),
            "registrar": safe_serialize(w.get("registrar")),
            "creation_date": safe_serialize(w.get("creation_date"))
        }
    except Exception as e:
        result["whois_error"] = str(e)

    try:
        answers = dns.resolver.resolve(domain, "A")
        result["a_records"] = [r.to_text() for r in answers]
    except Exception as e:
        result["dns_error"] = str(e)

    client = vt_client()
    if client:
        try:
            resource = client.get_object(f"/domains/{domain}")
            result["vt_last_analysis_stats"] = safe_serialize(getattr(resource, "last_analysis_stats", {}))
        except Exception as e:
            result["vt_error"] = str(e)
    else:
        result["vt_error"] = "VT API key not configured."

    safe_result = safe_serialize(result)
    return render_template("domain_result.html", result=safe_result)


@app.route("/check-ip", methods=["POST"])
def check_ip():
    ip = request.form.get("ip", "").strip()
    if not ip:
        flash("No IP provided", "warning")
        return redirect(url_for("index"))

    result = {"ip": ip}

    try:
        result["rev_dns"] = socket.gethostbyaddr(ip)[0]
    except Exception as e:
        result["rev_dns_error"] = str(e)

    try:
        r = requests.get(f"https://ipinfo.io/{ip}/json", timeout=8)
        if r.ok:
            result["ipinfo"] = r.json()
        else:
            result["ipinfo_error"] = r.text
    except Exception as e:
        result["ipinfo_error"] = str(e)

    client = vt_client()
    if client:
        try:
            resource = client.get_object(f"/ip_addresses/{ip}")
            result["vt_last_analysis_stats"] = safe_serialize(getattr(resource, "last_analysis_stats", {}))
        except Exception as e:
            result["vt_error"] = str(e)
    else:
        result["vt_error"] = "VT API key not configured."

    safe_result = safe_serialize(result)
    return render_template("ip_result.html", result=safe_result)


# ======================
# REPORT SYSTEM (IN-MEMORY)
# ======================

REPORT_STORE = []   # All reports will live in RAM

@app.route("/report", methods=["POST"])
def save_report():
    data = request.json
    if not data:
        return jsonify({"status": "error", "message": "No data received"}), 400

    data["timestamp"] = datetime.datetime.utcnow().isoformat() + "Z"
    REPORT_STORE.append(data)

    return jsonify({"status": "success"})


@app.route("/reports")
def list_reports():
    return render_template("reports.html", reports=REPORT_STORE)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True)