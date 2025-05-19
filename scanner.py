import os
import json
import sqlite3
import subprocess
from datetime import datetime 
from datetime import datetime, timezone
from flask import Flask, render_template, request, Response, send_file
from difflib import SequenceMatcher
import requests
import gzip
import logging
import shutil
from celery_worker import celery_app  # <-- Add this for Celery integration

import pandas as pd
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

app = Flask(__name__)
nvd_data = {}
DB_FILE = 'scan_history.db'


# ------------------ Load NVD Data ------------------
def load_nvd_data():
    global nvd_data
    try:
        with open('nvd_data.json', 'r') as f:
            nvd_data = json.load(f)
    except Exception as e:
        print(f"Error loading NVD data: {e}")

# Setup logging
logging.basicConfig(filename='app.log', level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')

def update_nvd_data():
    logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] [NVD Update] %(message)s')
    base_url = "https://nvd.nist.gov/feeds/json/cve/1.1/"
    years = ["2021", "2022", "2023", "2024", "2025"]  # Add more years if needed
    all_cves = {"CVE_Items": []}

    for year in years:
        url = f"{base_url}nvdcve-1.1-{year}.json.gz"
        try:
            logging.info(f"Downloading {url}")
            response = requests.get(url, timeout=60)
            response.raise_for_status()

            with open(f"nvdcve-{year}.json.gz", "wb") as f:
                f.write(response.content)

            with gzip.open(f"nvdcve-{year}.json.gz", 'rb') as f_in:
                with open(f"nvdcve-{year}.json", 'wb') as f_out:
                    shutil.copyfileobj(f_in, f_out)

            with open(f"nvdcve-{year}.json", "r") as f:
                data = json.load(f)
                all_cves["CVE_Items"].extend(data.get("CVE_Items", []))
                logging.info(f"Loaded {len(data.get('CVE_Items', []))} CVEs from {year}")

            os.remove(f"nvdcve-{year}.json.gz")
            os.remove(f"nvdcve-{year}.json")
        except Exception as e:
            logging.error(f"Failed to update NVD data for {year}: {e}")

    with open("nvd_data.json", "w") as f:
        json.dump(all_cves, f)

    logging.info(f"Update complete. Total CVEs loaded: {len(all_cves['CVE_Items'])}")
    
# ------------------ CVE Matching ------------------
def is_similar(a, b, threshold=0.6):
    return SequenceMatcher(None, a, b).ratio() > threshold

def find_cves(service_name, version):
    matched_cves = []
    service_name = service_name.lower().strip()
    version = version.lower().strip()

    for cve in nvd_data.get('CVE_Items', []):
        desc = cve['cve']['description']['description_data'][0]['value'].lower()

        # Exact or fuzzy match for service name or version
        if (service_name in desc and version in desc) or \
           is_similar(service_name, desc) or \
           (version and version in desc) or \
           (service_name and service_name in desc):

            cve_id = cve['cve']['CVE_data_meta']['ID']
            impact = cve.get('impact', {})
            cvss_score = None
            if 'baseMetricV3' in impact:
                cvss_score = impact['baseMetricV3']['cvssV3']['baseScore']
            elif 'baseMetricV2' in impact:
                cvss_score = impact['baseMetricV2']['cvssV2']['baseScore']

            severity = "Unknown"
            if cvss_score is not None:
                if cvss_score >= 9.0:
                    severity = "Critical"
                elif cvss_score >= 7.0:
                    severity = "High"
                elif cvss_score >= 4.0:
                    severity = "Medium"
                else:
                    severity = "Low"

            matched_cves.append({
                'id': cve_id,
                'description': desc,
                'cvss_score': cvss_score,
                'severity': severity
            })

    return matched_cves


# ------------------ SQLite Utilities ------------------
def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        target TEXT,
        scan_type TEXT,
        port_results TEXT,
        cve_results TEXT,
        timestamp TEXT
    )''')
    conn.commit()
    conn.close()


def save_scan(target, scan_type, port_results, cve_results):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('''INSERT INTO scans (target, scan_type, port_results, cve_results, timestamp)
                 VALUES (?, ?, ?, ?, ?)''',
              (target, scan_type, json.dumps(port_results), json.dumps(cve_results), datetime.now(timezone.utc).isoformat()))
    conn.commit()
    conn.close()


def fetch_scan(scan_id):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('SELECT * FROM scans WHERE id=?', (scan_id,))
    row = c.fetchone()
    conn.close()
    return row


# ------------------ Export Utilities ------------------
def export_txt(scan_data, output_path):
    with open(output_path, 'w') as f:
        f.write(f"Target: {scan_data[1]}\nScan Type: {scan_data[2]}\nTime: {scan_data[5]}\n\n")
        f.write("Open Ports:\n")
        for port in json.loads(scan_data[3]):
            f.write(f"- {port}\n")
        f.write("\nCVEs:\n")
        for cve in json.loads(scan_data[4]):
            f.write(f"- {cve['id']} ({cve['severity']}): {cve['description'][:100]}...\n")


def export_csv(scan_data, output_path):
    ports = pd.DataFrame(json.loads(scan_data[3]), columns=["Port", "Service", "Version"])
    ports.to_csv(output_path, index=False)


def export_pdf(scan_data, output_path):
    c = canvas.Canvas(output_path, pagesize=letter)
    c.setFont("Helvetica", 12)
    y = 750
    c.drawString(50, y, f"Target: {scan_data[1]} | Type: {scan_data[2]} | Date: {scan_data[5]}")
    y -= 30
    c.drawString(50, y, "Open Ports:")
    for port in json.loads(scan_data[3]):
        y -= 20
        c.drawString(70, y, f"- {port}")
    y -= 30
    c.drawString(50, y, "CVEs Found:")
    for cve in json.loads(scan_data[4]):
        y -= 20
        c.drawString(70, y, f"- {cve['id']} ({cve['severity']}): {cve['description'][:80]}...")
        if y < 100:
            c.showPage()
            y = 750
    c.save()


# ------------------ Flask Routes ------------------
@app.route('/')
def index():
    return render_template('index.html')


@app.route('/scan_stream', methods=['POST'])
def scan_stream():
    target = request.form.get('target')
    scan_type = request.form.get('scanType')
    port_range = request.form.get('portRange') or '1-65535'

    if not target or not scan_type:
        return "Missing required fields: 'target' and 'scanType'.", 400

    def generate():
        open_ports = []
        cves_found = []

        yield f"Starting {scan_type} scan on {target}...\n"

        if scan_type == 'basic':
            cmd = ["nmap", "-Pn", "-p", port_range, target]
        elif scan_type == 'fast':
            cmd = ["nmap", "-Pn", "-T4", "-F", target]
        elif scan_type == 'deep':
            cmd = ["nmap", "-Pn", "-sV", "-p", port_range, target]
        else:
            yield "Unknown scan type selected.\n"
            return

        yield f"Running command: {' '.join(cmd)}\n"

        try:
            result = subprocess.check_output(cmd, stderr=subprocess.STDOUT, timeout=600).decode()
            for line in result.splitlines():
                if "/tcp" in line and "open" in line:
                    parts = line.split()
                    port_info = parts[0]
                    service = parts[2] if len(parts) > 2 else "unknown"
                    version = parts[3] if len(parts) > 3 else ""
                    open_ports.append((port_info, service, version))
        except subprocess.TimeoutExpired:
            yield "Scan timed out.\n"
            return
        except Exception as e:
            yield f"Error running scan: {e}\n"
            return

        if not open_ports:
            yield "No open ports found.\n"

        for port, service, version in open_ports:
            yield f"Port {port}: {service} {version}\n"
            matched_cves = find_cves(service, version)
            cves_found.extend(matched_cves)

        # Save to DB
        save_scan(target, scan_type, open_ports, cves_found)

        yield "\nScan complete!\n"
        yield f"Total Open Ports Found: {len(open_ports)}\n"
        yield f"Total CVEs Matched: {len(cves_found)}\n\n"

        if cves_found:
            yield "Vulnerabilities Found:\n"
            for cve in cves_found:
                severity_symbol = {
                    "Critical": "🔥",
                    "High": "🧨",
                    "Medium": "🟡",
                    "Low": "🟢",
                    "Unknown": "⚪"
                }.get(cve['severity'], "⚪")
                yield f"{severity_symbol} {cve['id']} ({cve['severity']}) - {cve['description'][:120]}...\n"

    return Response(generate(), mimetype='text/plain')


@app.route('/download/<int:scan_id>/<string:format>')
def download_report(scan_id, format):
    scan_data = fetch_scan(scan_id)
    if not scan_data:
        return "Scan not found", 404

    filename = f"scan_{scan_id}.{format}"
    output_path = os.path.join("downloads", filename)
    os.makedirs("downloads", exist_ok=True)

    if format == 'txt':
        export_txt(scan_data, output_path)
    elif format == 'csv':
        export_csv(scan_data, output_path)
    elif format == 'pdf':
        export_pdf(scan_data, output_path)
    else:
        return "Invalid format", 400

    return send_file(output_path, as_attachment=True)


# ------------------ Full Scan Logic for Celery ------------------
def run_full_scan(target, scan_type='deep', port_range='1-65535'):
    open_ports = []
    cves_found = []

    if scan_type == 'basic':
        cmd = ["nmap", "-Pn", "-p", port_range, target]
    elif scan_type == 'fast':
        cmd = ["nmap", "-Pn", "-T4", "-F", target]
    elif scan_type == 'deep':
        cmd = ["nmap", "-Pn", "-sV", "-p", port_range, target]
    else:
        return {"error": "Unknown scan type."}

    try:
        result = subprocess.check_output(cmd, stderr=subprocess.STDOUT, timeout=600).decode()
        for line in result.splitlines():
            if "/tcp" in line and "open" in line:
                parts = line.split()
                port_info = parts[0]
                service = parts[2] if len(parts) > 2 else "unknown"
                version = parts[3] if len(parts) > 3 else ""
                open_ports.append((port_info, service, version))
    except Exception as e:
        return {"error": f"Scan failed: {e}"}

    for port, service, version in open_ports:
        matched_cves = find_cves(service, version)
        cves_found.extend(matched_cves)

    save_scan(target, scan_type, open_ports, cves_found)
    return {
        "target": target,
        "scan_type": scan_type,
        "open_ports": open_ports,
        "cves_found": cves_found,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }


# ------------------ Celery Task ------------------
@celery_app.task
def run_scan_task(target, scan_type='deep', port_range='1-65535'):
    return run_full_scan(target, scan_type, port_range)


# ------------------ Main ------------------
if __name__ == "__main__":
    load_nvd_data()
    init_db()
    app.run(debug=True)






























