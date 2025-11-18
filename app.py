import os
import json
import hashlib
import datetime
from collections.abc import Mapping, Iterable

from flask import (
    Flask, request, render_template, redirect, url_for,
    flash, jsonify, send_from_directory
)
from dotenv import load_dotenv
import vt
import whois
import dns.resolver
import requests
import socket

load_dotenv()
VT_API_KEY = os.getenv("VT_API_KEY")

app = Flask(__name__, static_folder="static")
app.secret_key = os.getenv("FLASK_SECRET", "change-this-secret")


def vt_client():
    if not VT_API_KEY:
        return None
    try:
        return vt.Client(VT_API_KEY)
    except Exception:
        return None


def safe_serialize(obj):
    if obj is None or isinstance(obj, (str, int, float, bool)):
        return obj
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
    if hasattr(obj, "to_json"):
        try:
            return safe_serialize(json.loads(obj.to_json()))
        except Exception:
            pass
    if hasattr(obj, "to_dict"):
        try:
            return safe_serialize(obj.to_dict())
        except Exception:
            pass
    try:
        return str(obj)
    except Exception:
        return repr(obj)


def client_wants_json():
    accept = request.headers.get("Accept", "")
    return request.is_json or "application/json" in accept.lower()


@app.route("/")
def index():
    return render_template("index.html")


# -------------------------
# Scan File (returns JSON)
# -------------------------
@app.route("/scan-file", methods=["POST"])
def scan_file():
    file_obj = request.files.get("file")
    if not file_obj or file_obj.filename == "":
        if client_wants_json():
            return jsonify({"status": "error", "message": "No file selected"}), 400
        flash("No file selected", "warning")
        return redirect(url_for("index"))

    os.makedirs("./uploads", exist_ok=True)
    safe_filename = file_obj.filename.replace("/", "_").replace("..", "_")
    path = os.path.join("./uploads", safe_filename)
    file_obj.save(path)

    # basic metadata
    try:
        size = os.path.getsize(path)
    except Exception:
        size = None

    sha256 = ""
    try:
        h = hashlib.sha256()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(8192), b""):
                h.update(chunk)
        sha256 = h.hexdigest()
    except Exception:
        sha256 = ""

    result = {
        "type": "file",
        "filename": safe_filename,
        "size": size,
        "sha256": sha256,
        "uploaded_at": datetime.datetime.utcnow().isoformat() + "Z",
    }

    client = vt_client()
    if client:
        try:
            with open(path, "rb") as fh:
                analysis = client.scan_file(fh, wait_for_completion=True)
            result["vt_last_analysis_stats"] = safe_serialize(getattr(analysis, "stats", {}))
            result["vt_status"] = "scanned"
        except Exception as e:
            result["vt_error"] = str(e)
    else:
        result["vt_error"] = "VT API key not configured."

    # verdict
    stats = result.get("vt_last_analysis_stats", {}) or {}
    mal = stats.get("malicious", 0)
    sus = stats.get("suspicious", 0)
    harmless = stats.get("harmless", 0)
    if mal > 0:
        verdict = "Malicious"
    elif sus > 0:
        verdict = "Suspicious"
    elif harmless > 0:
        verdict = "Safe"
    else:
        verdict = "Unknown"
    result["verdict"] = verdict

    return jsonify(result)


# -------------------------
# Check Domain
# -------------------------
@app.route("/check-domain", methods=["POST"])
def check_domain():
    data = request.get_json(silent=True) or request.form or {}
    domain = (data.get("domain") or "").strip()
    if not domain:
        if client_wants_json():
            return jsonify({"status": "error", "message": "No domain provided"}), 400
        flash("No domain provided", "warning")
        return redirect(url_for("index"))

    result = {"type": "domain", "domain": domain}

    # WHOIS
    try:
        w = whois.whois(domain)
        result["whois"] = {
            "domain_name": safe_serialize(w.get("domain_name")),
            "registrar": safe_serialize(w.get("registrar")),
            "creation_date": safe_serialize(w.get("creation_date")),
            "expiration_date": safe_serialize(w.get("expiration_date")),
            "country": safe_serialize(w.get("country"))
        }
    except Exception as e:
        result["whois_error"] = str(e)

    # DNS A
    try:
        answers = dns.resolver.resolve(domain, "A")
        result["a_records"] = [r.to_text() for r in answers]
    except Exception as e:
        result["dns_error"] = str(e)

    # VirusTotal
    client = vt_client()
    if client:
        try:
            resource = client.get_object(f"/domains/{domain}")
            result["vt_last_analysis_stats"] = safe_serialize(getattr(resource, "last_analysis_stats", {}))
        except Exception as e:
            result["vt_error"] = str(e)
    else:
        result["vt_error"] = "VT API key not configured."

    # verdict
    stats = result.get("vt_last_analysis_stats", {}) or {}
    mal = stats.get("malicious", 0)
    sus = stats.get("suspicious", 0)
    harmless = stats.get("harmless", 0)
    if mal > 0:
        verdict = "Malicious"
    elif sus > 0:
        verdict = "Suspicious"
    elif harmless > 0:
        verdict = "Safe"
    else:
        verdict = "Unknown"
    result["verdict"] = verdict

    return jsonify(result)


# -------------------------
# Check IP
# -------------------------
@app.route("/check-ip", methods=["POST"])
def check_ip():
    data = request.get_json(silent=True) or request.form or {}
    ip = (data.get("ip") or "").strip()
    if not ip:
        if client_wants_json():
            return jsonify({"status": "error", "message": "No ip provided"}), 400
        flash("No IP provided", "warning")
        return redirect(url_for("index"))

    result = {"type": "ip", "ip": ip}

    try:
        result["rev_dns"] = socket.gethostbyaddr(ip)[0]
    except Exception:
        result["rev_dns_error"] = "reverse DNS lookup failed"

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

    # verdict
    stats = result.get("vt_last_analysis_stats", {}) or {}
    mal = stats.get("malicious", 0)
    sus = stats.get("suspicious", 0)
    harmless = stats.get("harmless", 0)
    if mal > 0:
        verdict = "Malicious"
    elif sus > 0:
        verdict = "Suspicious"
    elif harmless > 0:
        verdict = "Safe"
    else:
        verdict = "Unknown"
    result["verdict"] = verdict

    return jsonify(result)


# -------------------------
# Reports (in-memory)
# -------------------------
REPORT_STORE = []


@app.route("/report", methods=["POST"])
def save_report():
    data = request.get_json(silent=True) or {}
    if not data:
        return jsonify({"status": "error", "message": "No data received"}), 400

    data["timestamp"] = datetime.datetime.utcnow().isoformat() + "Z"
    REPORT_STORE.append(data)
    return jsonify({"status": "success"})


@app.route("/reports")
def list_reports():
    normalized = []
    for r in REPORT_STORE:
        normalized.append({"data": r, "filename": r.get("target", "")})
    return render_template("reports.html", reports=normalized)


@app.route("/uploads/<path:filename>")
def uploaded_file(filename):
    return send_from_directory("./uploads", filename, as_attachment=True)


if __name__ == "__main__":
    port = int(os.getenv("PORT", 8000))
    app.run(host="0.0.0.0", port=port, debug=True)