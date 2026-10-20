from flask import Flask, request, render_template_string
from urllib.parse import urlparse
from datetime import datetime
import sqlite3
import re
import ipaddress

app = Flask(__name__)
DB = "sentinelx.db"

def init_db():
    with sqlite3.connect(DB) as con:
        con.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT NOT NULL,
                level TEXT NOT NULL,
                findings TEXT NOT NULL,
                scanned_at TEXT NOT NULL
            )
        """)

def analyze(url):
    url = url.strip()
    parsed = urlparse(url)
    findings = []

    if (parsed.scheme not in ("http", "https")
            or not parsed.hostname):
        return "INVALID", ["Enter a valid full HTTP/HTTPS URL."]

    if parsed.username or parsed.password:
        findings.append("URL contains embedded credentials.")

    if parsed.scheme != "https":
        findings.append("HTTPS is not used.")

    host = parsed.hostname.lower()

    try:
        ipaddress.ip_address(host)
        findings.append("URL uses an IP address instead of a domain.")
    except ValueError:
        pass

    if "xn--" in host:
        findings.append("Domain contains internationalized characters.")

    if host.count(".") >= 4:
        findings.append("Domain has an unusually large number of subdomains.")

    if re.search(r'@|%40', url, re.I):
        findings.append("URL contains an @ sign or encoded equivalent.")

    if not findings:
        findings.append("No configured warning patterns detected.")

    if any("credentials" in f or "@ sign" in f for f in findings):
        level = "HIGH"
    elif any("HTTPS" in f or "IP address" in f or
             "internationalized" in f or "subdomains" in f
             for f in findings):
        level = "REVIEW"
    else:
        level = "INFO"

    return level, findings

PAGE = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SentinelX AI v2</title>
<style>
*{box-sizing:border-box}
body{margin:0;background:#080d18;color:#e8efff;
font-family:Arial,sans-serif;padding:20px}
main{max-width:760px;margin:25px auto}
.brand{color:#54f0c0;letter-spacing:3px;font-size:14px}
h1{font-size:34px;margin-bottom:8px}
p{color:#a8b5cc;line-height:1.5}
.card{background:#111a2b;border:1px solid #26334a;
border-radius:15px;padding:20px;margin:18px 0}
input,button{width:100%;padding:14px;border-radius:9px;
font-size:16px;margin-top:10px}
input{background:#080d18;color:white;border:1px solid #35445e}
button{background:#54f0c0;border:0;font-weight:bold;color:#07120f}
table{width:100%;border-collapse:collapse}
td,th{text-align:left;padding:10px 5px;border-bottom:1px solid #29354a;
overflow-wrap:anywhere}
small{color:#9baac2}
.tag{font-weight:bold;color:#54f0c0}
li{margin:10px 0;color:#d1dced;overflow-wrap:anywhere}
</style>
</head>
<body><main>
<div class="brand">◈ SENTINELX AI / V2</div>
<h1>Security Scanner</h1>
<p>Local URL inspection and scan history.</p>

<div class="card">
<h3>Analyze a URL</h3>
<form method="post">
<input name="url" placeholder="https://example.com"
value="{{ url }}" required maxlength="2048">
<button type="submit">Analyze URL</button>
</form>
{% if findings %}
<div class="card">
<h3>Result: <span class="tag">{{ level }}</span></h3>
<ul>{% for f in findings %}<li>{{ f }}</li>{% endfor %}</ul>
<small>Heuristic indicators only; not a malware or reputation scan.</small>
</div>
{% endif %}
</div>

<div class="card">
<h3>Scan History</h3>
{% if scans %}
<table><tr><th>URL</th><th>Level</th><th>Time</th></tr>
{% for s in scans %}
<tr><td>{{ s[1] }}</td><td>{{ s[2] }}</td><td>{{ s[4] }}</td></tr>
{% endfor %}</table>
{% else %}<p>No scans saved yet.</p>{% endif %}
</div>
<p><small>SentinelX AI · Educational defensive security tool</small></p>
</main></body></html>
"""

@app.route("/", methods=["GET", "POST"])
def home():
    url, level, findings = "", "", []

    if request.method == "POST":
        url = request.form.get("url", "").strip()[:2048]
        level, findings = analyze(url)
        with sqlite3.connect(DB) as con:
            con.execute(
                "INSERT INTO scans(url,level,findings,scanned_at) VALUES(?,?,?,?)",
                (url, level, "\n".join(findings),
                 datetime.now().strftime("%Y-%m-%d %H:%M"))
            )

    with sqlite3.connect(DB) as con:
        scans = con.execute(
            "SELECT * FROM scans ORDER BY id DESC LIMIT 10"
        ).fetchall()

    return render_template_string(
        PAGE, url=url, level=level, findings=findings, scans=scans
    )

init_db()

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
