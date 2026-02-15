import os
import json
import subprocess
from flask import Flask, render_template, request, redirect

app = Flask(__name__)

UPLOAD_FOLDER = "uploads"
REPORT_FOLDER = "reports"

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(REPORT_FOLDER, exist_ok=True)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
REPORT_FOLDER = os.path.join(BASE_DIR, "reports")
LOG_FILE = os.path.join(REPORT_FOLDER, "last_scan.log")

def read_logs():
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, "r", encoding="utf-8", errors="ignore") as f:
            return f.read()
    return "No logs available."


# -------------------------
# Home Page
# -------------------------
@app.route("/")
def index():
    return render_template("index.html")


# -------------------------
# Upload & Scan
# -------------------------
@app.route("/scan", methods=["POST"])
def scan():

    if "apk" not in request.files:
        return redirect("/")

    apk = request.files["apk"]

    if apk.filename == "":
        return redirect("/")

    apk_path = os.path.join(UPLOAD_FOLDER, apk.filename)
    apk.save(apk_path)

    # Path to venv python (Windows)
    VENV_PYTHON = os.path.join(
        BASE_DIR,
        "venv",
        "Scripts",
        "python.exe"
    )

    # Run APKDeepLens using venv
    cmd = [
        VENV_PYTHON,
        "apkdeeplens.py",
        "-apk",
        apk_path,
        "-report",
        "json",
        "-o",
        REPORT_FOLDER
    ]

    result = subprocess.run(
        cmd,
        cwd=BASE_DIR,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="ignore"
    )

    stdout = result.stdout
    stderr = result.stderr

    # Save logs
    log_path = os.path.join(REPORT_FOLDER, "last_scan.log")

    with open(log_path, "w", encoding="utf-8") as f:
        f.write("=== STDOUT ===\n")
        f.write(stdout + "\n")
        f.write("=== STDERR ===\n")
        f.write(stderr + "\n")


    # APKDeepLens saves inside reports/reports/
    inner_reports = os.path.join(REPORT_FOLDER, "reports")

    report_file = f"report_{apk.filename}.json"
    report_path = os.path.join(inner_reports, report_file)

    if not os.path.exists(report_path):
        return "Report not found. Scan failed.", 500

    return redirect("/logs")




# -------------------------
# View Report
# -------------------------
@app.route("/logs")
def show_logs():
    logs = read_logs()
    return f"""
    <html>
    <head>
        <title>Scan Logs</title>
        <meta http-equiv="refresh" content="2">
        <style>
            body {{
                background: black;
                color: #00ff00;
                font-family: monospace;
                padding: 20px;
            }}
            pre {{
                white-space: pre-wrap;
            }}
        </style>
    </head>
    <body>
        <h2>APKDeepLens Live Logs</h2>
        <pre>{logs}</pre>
        <a href="/">⬅ Back</a>
    </body>
    </html>
    """

@app.route("/report/reports/<name>")
def report(name):

    path = os.path.join(REPORT_FOLDER, "reports", name)


    with open(path) as f:
        data = json.load(f)

    # Read logs
    log_file = os.path.join(REPORT_FOLDER, "last_scan.log")

    logs = ""

    if os.path.exists(log_file):
        with open(log_file) as f:
            logs = f.read()



    owasp_map = build_owasp_status(data)

    return render_template(
        "report.html",
        report=data,
        owasp=owasp_map,
        logs=logs
    )



# -------------------------
# OWASP Mapping
# -------------------------
def build_owasp_status(data):

    status = {
        "M1": False,
        "M2": False,
        "M3": False,
        "M4": False,
        "M5": False,
        "M6": False,
        "M7": False,
        "M8": False,
        "M9": False,
        "M10": False
    }

    for section in data.values():

        if not isinstance(section, list):
            continue

        for item in section:

            o = item.get("owasp", "")

            if o.startswith("M"):
                key = o.split(":")[0]
                status[key] = True

    return status


# -------------------------
# Run Server
# -------------------------
if __name__ == "__main__":
    app.run(debug=True)
