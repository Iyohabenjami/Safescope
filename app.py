import os
import json
import hashlib
import datetime
from collections.abc import Mapping, Iterable

from flask import Flask, request, render_template, redirect, url_for, flash, jsonify, send_from_directory
from dotenv import load_dotenv
import vt
import whois
import dns.resolver
import requests
import socket

load_dotenv()
VT_API_KEY = os.getenv("VT_API_KEY")

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET", "change-this-secret")


def vt_client():
    if not VT_API_KEY:
        return None
    try:
        return vt.Client(VT_API_KEY)
    except Exception:
        return None


def safe_serialize(obj):
    """Turn objects into JSON-serializable primitives."""
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


def client_wants_json():
    """Return True if the incoming request expects JSON (fetch/ajax)."""
    # request.is_json checks for application/json content-type
    accept = request.headers.get("Accept", "")
    return request.is_json or "application/json" in accept.lower()


@app.route("/")
def index():
    return render_template("index.html")


# ---- Scan file ----
@app.route("/scan-file", methods=["POST"])
def scan_file():
    # Handle file upload from form or fetch(FormData)
    f = request.files.get("file")
    if not f or f.filename == "":
        # If Ajax expects JSON, return JSON error
        if client_wants_json():
            return jsonify({"status": "error", "message": "No file selected"}), 400
        flash("No file selected", "warning")
        return redirect(url_for("index"))

    os.makedirs("./uploads", exist_ok=True)
    safe_filename = f.filename.replace("/", "_").replace("..", "_")
    path = os.path.join("./uploads", safe_filename)
    f.save(path)

    # compute basic metadata
    try:
        size = os.path.getsize(path)
    except Exception:
        size = None

    md5 = ""
    try:
        h = hashlib.md5()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(8192), b""):
                h.update(chunk)
        md5 = h.hexdigest()
    except Exception:
        md5 = ""

    result = {
        "filename": safe_filename,
        "size": size,
        "md5": md5,
        "uploaded_at": datetime.datetime.utcnow().isoformat() + "Z",
    }

    client = vt_client()
    if client:
        try:
            # open file again for vt client
            with open(path, "rb") as fh:
                analysis = client.scan_file(fh, wait_for_completion=True)
            # try to fetch some stats if available
            stats = getattr(analysis, "stats", None) or {}
            result["vt_last_analysis_stats"] = safe_serialize(stats)
            result["vt_status"] = "scanned"
        except Exception as e:
            result["vt_error"] = str(e)
    else:
        result["vt_error"] = "VT API key not configured."

    # Return JSON for AJAX clients; otherwise behave like before (flash + redirect)
    if client_wants_json():
        return jsonify(result)

    flash(f"Scan completed. File saved: {safe_filename}", "success")
    return redirect(url_for("index"))


# ---- Check domain ----
@app.route("/check-domain", methods=["POST"])
def check_domain():
    # Accept both form-data and JSON
    data = None
    if request.is_json:
        data = request.get_json(silent=True) or {}
        domain = (data.get("domain") or "").strip()
    else:
        domain = request.form.get("domain", "").strip()

    if not domain:
        if client_wants_json():
            return jsonify({"status": "error", "message": "No domain provided"}), 400
        flash("No domain provided", "warning")
        return redirect(url_for("index"))

    result = {"domain": domain}

    try:
        w = whois.whois(domain)
        result["whois"] = {
            "domain_name": safe_serialize(w.get("domain_name")),
            "registrar": safe_serialize(w.get("registrar")),
            "creation_date": safe_serialize(w.get("creation_date")),
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
            # optionally add last_analysis_results summary (small)
            try:
                la = getattr(resource, "last_analysis_results", None)
                result["vt_last_analysis_results"] = safe_serialize(la) if la else {}
            except Exception:
                pass
        except Exception as e:
            result["vt_error"] = str(e)
    else:
        result["vt_error"] = "VT API key not configured."

    safe_result = safe_serialize(result)

    if client_wants_json():
        return jsonify(safe_result)

    return render_template("domain_result.html", result=safe_result)


# ---- Check IP ----
@app.route("/check-ip", methods=["POST"])
def check_ip():
    # Accept both form-data and JSON
    data = None
    if request.is_json:
        data = request.get_json(silent=True) or {}
        ip = (data.get("ip") or "").strip()
    else:
        ip = request.form.get("ip", "").strip()

    if not ip:
        if client_wants_json():
            return jsonify({"status": "error", "message": "No ip provided"}), 400
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

    if client_wants_json():
        return jsonify(safe_result)

    return render_template("ip_result.html", result=safe_result)


# ======================
# REPORT SYSTEM (IN-MEMORY)
# ======================
REPORT_STORE = []  # All reports will live in RAM


@app.route("/report", methods=["POST"])
def save_report():
    data = request.get_json(silent=True) or request.json or {}
    if not data:
        return jsonify({"status": "error", "message": "No data received"}), 400

    data["timestamp"] = datetime.datetime.utcnow().isoformat() + "Z"
    REPORT_STORE.append(data)

    return jsonify({"status": "success"})


@app.route("/reports")
def list_reports():
    # If someone visits /reports via fetch expecting JSON, return JSON
    if client_wants_json():
        return jsonify(REPORT_STORE)
    # otherwise render template
    # convert REPORT_STORE entries into the shape expected by reports.html if necessary
    # the template expects report objects with 'data' and optional 'filename', but earlier implementation used different shapes
    # We'll normalize simple shape: { 'data': report }
    normalized = []
    for r in REPORT_STORE:
        normalized.append({"data": r, "filename": r.get("target", "")})
    return render_template("reports.html", reports=normalized)


# static files (optional helper)
@app.route("/uploads/<path:filename>")
def uploaded_file(filename):
    return send_from_directory("./uploads", filename, as_attachment=True)


if __name__ == "__main__":
    # Use 0.0.0.0 and port from env if provided by Render
    port = int(os.getenv("PORT", 8000))
    app.run(host="0.0.0.0", port=port, debug=True)