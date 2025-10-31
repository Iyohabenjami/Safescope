#!/bin/bash
set -e

# must be run inside venv
if [ -z "$VIRTUAL_ENV" ]; then
  echo "ERROR: virtualenv not active. Run: source venv/bin/activate"
  exit 1
fi

echo "Upgrading pip..."
pip install --upgrade pip

echo "Installing Python packages..."
pip install flask vt-py python-whois dnspython requests python-dotenv || { echo "pip install failed"; exit 2; }

echo "Creating project files..."

# app.py
cat > app.py <<'PY'
import os
from flask import Flask, request, render_template, redirect, url_for, flash
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
    return vt.Client(VT_API_KEY)

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

    path = f"./uploads/{f.filename}"
    os.makedirs("./uploads", exist_ok=True)
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
            "domain_name": w.get("domain_name"),
            "registrar": w.get("registrar"),
            "creation_date": str(w.get("creation_date"))
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
            result["vt_last_analysis_stats"] = getattr(resource, "last_analysis_stats", {})
        except Exception as e:
            result["vt_error"] = str(e)
    else:
        result["vt_error"] = "VT API key not configured."

    return render_template("domain_result.html", result=result)

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
            result["vt_last_analysis_stats"] = getattr(resource, "last_analysis_stats", {})
        except Exception as e:
            result["vt_error"] = str(e)
    else:
        result["vt_error"] = "VT API key not configured."

    return render_template("ip_result.html", result=result)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True)
PY

# templates
mkdir -p templates

cat > templates/index.html <<'HT'
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>VT SelfHost</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body class="bg-light">
  <div class="container py-4">
    <h1 class="mb-4">VirusTotal Self-Host (Light)</h1>

    {% with messages = get_flashed_messages(with_categories=true) %}
      {% if messages %}
        {% for cat, msg in messages %}
          <div class="alert alert-{{cat}}">{{msg}}</div>
        {% endfor %}
      {% endif %}
    {% endwith %}

    <div class="row g-4">
      <div class="col-md-6">
        <div class="card p-3">
          <h5>Scan File (VirusTotal)</h5>
          <form action="/scan-file" method="post" enctype="multipart/form-data">
            <input class="form-control" type="file" name="file" />
            <div class="mt-2">
              <button class="btn btn-primary">Scan file</button>
            </div>
          </form>
          <small class="text-muted">Requires VirusTotal API key in .env</small>
        </div>
      </div>

      <div class="col-md-6">
        <div class="card p-3">
          <h5>Check Domain</h5>
          <form action="/check-domain" method="post">
            <input class="form-control" name="domain" placeholder="example.com"/>
            <div class="mt-2"><button class="btn btn-secondary">Check domain</button></div>
          </form>
          <small class="text-muted">WHOIS + DNS + VirusTotal (if API key)</small>
        </div>

        <div class="card p-3 mt-3">
          <h5>Check IP</h5>
          <form action="/check-ip" method="post">
            <input class="form-control" name="ip" placeholder="8.8.8.8"/>
            <div class="mt-2"><button class="btn btn-warning">Check IP</button></div>
          </form>
          <small class="text-muted">Reverse DNS + ipinfo + VirusTotal (if API key)</small>
        </div>
      </div>
    </div>

    <hr class="my-4" />
    <p class="text-muted small">Built for Android Termux. Add <code>VT_API_KEY</code> in <code>.env</code>.</p>
  </div>
</body>
</html>
HT

cat > templates/domain_result.html <<'HT2'
<!doctype html>
<html>
<head>
<meta charset="utf-8"><title>Domain Result</title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body class="p-4">
<div class="container">
  <h3>Domain: {{ result.domain }}</h3>
  <pre>{{ result | tojson(indent=2) }}</pre>
  <a href="/" class="btn btn-sm btn-primary">Back</a>
</div>
</body>
</html>
HT2

cat > templates/ip_result.html <<'HT3'
<!doctype html>
<html>
<head>
<meta charset="utf-8"><title>IP Result</title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body class="p-4">
<div class="container">
  <h3>IP: {{ result.ip }}</h3>
  <pre>{{ result | tojson(indent=2) }}</pre>
  <a href="/" class="btn btn-sm btn-primary">Back</a>
</div>
</body>
</html>
HT3

# .env placeholder
cat > .env <<'ENV'
VT_API_KEY=YOUR_VIRUSTOTAL_API_KEY_HERE
FLASK_SECRET=change-this-secret
ENV

# run script
cat > run.sh <<'RUN'
#!/bin/bash
if [ -z "$VIRTUAL_ENV" ]; then
  echo "Activate your venv first: source venv/bin/activate"
  exit 1
fi
echo "Loading .env..."
python -c "from dotenv import load_dotenv; load_dotenv(); print('ENV OK')"
echo "Starting Flask app on http://0.0.0.0:8000 ..."
python app.py
RUN
chmod +x run.sh
echo "Done. Files created: app.py templates/ .env run.sh"
echo "Next: edit .env and replace VT_API_KEY with your key, then run: source venv/bin/activate && ./run.sh"
