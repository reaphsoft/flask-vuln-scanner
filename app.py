import os
import json
import sqlite3
import threading
from flask import Flask, request, jsonify, render_template, Response, send_file
from flask_socketio import SocketIO, emit
from celery.result import AsyncResult
from flask import Flask, render_template, request, redirect, url_for, jsonify
from models import db, Scan, Service, Vulnerability  # Ensure these match your models file

from celery_app import init_celery
from scanner import check_vulnerabilities  # Passive scan function
from scanner_core import run_full_scan      # Assume active scan logic is here
from update_nvd import update_nvd_data
from utils import export_scan_csv, export_scan_json, export_scan_pdf
from report_generator import generate_report

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret!'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///scan_history.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['CELERY_BROKER_URL'] = os.getenv('CELERY_BROKER_URL', 'redis://localhost:6379/0')
app.config['CELERY_RESULT_BACKEND'] = os.getenv('CELERY_RESULT_BACKEND', 'redis://localhost:6379/0')

# Initialize SQLAlchemy
from models import db
with app.app_context():
    db.init_app(app)
    db.create_all()

# Initialize SocketIO
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='eventlet')

# Initialize Celery
celery = init_celery(app)

# Ensure scan history database exists
def init_db():
    with sqlite3.connect("scan_history.db") as conn:
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT NOT NULL,
                result TEXT,
                host_info TEXT
            )
        """)
        conn.commit()

init_db()

# Save scan results to SQLite
def save_scan_result(target, scan_result, host_info):
    with sqlite3.connect("scan_history.db") as conn:
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO scans (target, result, host_info) VALUES (?, ?, ?)",
            (target, json.dumps(scan_result), json.dumps(host_info))
        )
        conn.commit()

# Sanitize port_range in perform_scan to prevent nmap errors from malformed input (e.g., multiple -p).
def sanitize_port_range(port_range):
    # Remove any -p and non-numeric, non-comma, non-dash characters
    import re
    port_range = re.sub(r"-p", "", port_range)
    port_range = re.sub(r"[^0-9,\-]", "", port_range)
    # Remove duplicate commas or dashes
    port_range = re.sub(r",+", ",", port_range)
    port_range = re.sub(r"-+", "-", port_range)
    return port_range.strip(',')

# Combined scan logic
def perform_scan(target, scan_type='deep', port_range='1-65535'):
    try:
        port_range = sanitize_port_range(port_range)
        active_result = {}
        passive_result = {}

        def active_scan():
            active_result['data'], active_result['host_info'] = run_full_scan(target, scan_type, port_range)

        t1 = threading.Thread(target=active_scan)
        t1.start()
        t1.join()

        # Passive scan: use real service/version from active scan results
        passive_cves = []
        active_data = active_result.get('data', [])
        for entry in active_data:
            service = entry.get('service', '')
            version = entry.get('version', '')
            if service:
                cves = check_vulnerabilities(service, version)
                if cves:
                    passive_cves.extend(cves)
        passive_result['data'] = passive_cves

        result = {
            "Active Scan": active_result.get("data", "No active scan result"),
            "Passive Scan": passive_result.get("data", []),
        }
        # Format CVEs for better readability in the frontend
        for scan_type in ["Active Scan", "Passive Scan"]:
            # Only format if the entry is a dict (active scan), not a list (passive scan)
            entries = result.get(scan_type, [])
            if isinstance(entries, list):
                for entry in entries:
                    if isinstance(entry, dict) and "cves" in entry and isinstance(entry["cves"], list):
                        entry["cves"] = [
                            f"{cve.get('id', '')} | {cve.get('severity', '').upper()} | {cve.get('published', '')} | {cve.get('description', '')[:120]}..."
                            if isinstance(cve, dict) else str(cve)
                            for cve in entry["cves"]
                        ]

        save_scan_result(target, result, active_result.get("host_info", {}))
        return result

    except Exception as e:
        print(f"Error during scanning: {e}")
        return {"error": str(e)}

# Patch DB schema if needed
with sqlite3.connect("scan_history.db") as conn:
    cursor = conn.cursor()
    # Add result and host_info columns if missing
    cursor.execute("PRAGMA table_info(scans)")
    columns = [row[1] for row in cursor.fetchall()]
    if "result" not in columns:
        cursor.execute("ALTER TABLE scans ADD COLUMN result TEXT")
    if "host_info" not in columns:
        cursor.execute("ALTER TABLE scans ADD COLUMN host_info TEXT")
    conn.commit()

# === CELERY TASK ===
from celery_app import celery_app

@celery_app.task(name='run_scan_task')
def run_scan_task(target, scan_type='deep', port_range='1-65535'):
    try:
        result = perform_scan(target, scan_type, port_range)
        return {
            "status": "success",
            "data": result
        }
    except Exception as e:
        return {
            "status": "error",
            "message": str(e)
        }

# === ROUTES ===

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/scan", methods=["POST"])
def start_scan():
    data = request.get_json()
    target = data.get("target")
    scan_type = data.get("scan_type", "deep")
    port_range = data.get("port_range", "1-65535")

    task = run_scan_task.delay(target, scan_type, port_range)
    return jsonify({"message": "Scan started", "task_id": task.id})

@app.route("/api/scan/<task_id>", methods=["GET"])
def scan_status(task_id):
    task_result = AsyncResult(task_id, app=celery)
    if task_result.state == "PENDING":
        return jsonify({"status": "pending"})
    elif task_result.state == "SUCCESS":
        return jsonify({"status": "completed", "result": task_result.result})
    elif task_result.state == "FAILURE":
        return jsonify({"status": "failed", "error": str(task_result.result)})
    return jsonify({"status": task_result.state})

@app.route("/api/history", methods=["GET"])
def get_scan_history():
    with sqlite3.connect("scan_history.db") as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id, target, result, host_info FROM scans ORDER BY id DESC")
        rows = cursor.fetchall()
        history = [
            {
                "id": row[0],
                "target": row[1],
                "result": json.loads(row[2]),
                "host_info": json.loads(row[3])
            }
            for row in rows
        ]
        return jsonify(history)
    
@app.route('/scan/<int:scan_id>')
def view_scan(scan_id):
    scan = Scan.query.get_or_404(scan_id)
    services = Service.query.filter_by(scan_id=scan.id).all()
    vulnerabilities = Vulnerability.query.filter_by(scan_id=scan.id).all()
    return render_template('result.html', scan=scan, services=services, vulnerabilities=vulnerabilities)

@app.route('/history')
def scan_history():
    with sqlite3.connect("scan_history.db") as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id, target, result, host_info FROM scans ORDER BY id DESC")
        rows = cursor.fetchall()
        scans = [
            {
                "id": row[0],
                "target": row[1],
                "result": json.loads(row[2]) if row[2] else {},
                "host_info": json.loads(row[3]) if row[3] else {}
            }
            for row in rows
        ]
    return render_template('history.html', scans=scans)

@app.route('/scan_details/<int:scan_id>')
def scan_details(scan_id):
    with sqlite3.connect("scan_history.db") as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id, target, result, host_info FROM scans WHERE id = ?", (scan_id,))
        row = cursor.fetchone()
        if not row:
            return "Scan not found", 404
        scan = {
            "id": row[0],
            "target": row[1],
            "result": json.loads(row[2]) if row[2] else {},
            "host_info": json.loads(row[3]) if row[3] else {}
        }
    return render_template('result.html', scan=scan, services=[], vulnerabilities=[])

@app.route('/update_nvd')
def update_nvd_route():
    try:
        update_nvd_data()
        return "NVD data successfully updated and reloaded.", 200
    except Exception as e:
        return f"Failed to update NVD data: {e}", 500

@app.route('/scan_history')
def scan_history_compat():
    # For compatibility with frontend links
    return scan_history()

@app.route('/scan_stream')
def scan_stream():
    target = request.args.get('target')
    scan_type = request.args.get('scan_type', 'deep')
    port_range = request.args.get('port_range', '1-65535')

    def generate():
        if not target:
            yield 'Error: Target is required.'
            return
        yield f"Starting {scan_type} scan on {target}...\n"
        try:
            result = perform_scan(target, scan_type, port_range)
            yield f"\nScan Results:\n"
            yield json.dumps(result, indent=2)
        except Exception as e:
            yield f"Error during scan: {str(e)}\n"
    return Response(generate(), mimetype='text/plain')

@app.route("/export/<int:scan_id>/<fmt>")
def export_scan(scan_id, fmt):
    scan = Scan.query.get(scan_id)
    scan_data = None
    if scan:
        scan_data = json.loads(scan.result)
    else:
        # Fallback to SQLite direct fetch
        with sqlite3.connect("scan_history.db") as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT result FROM scans WHERE id = ?", (scan_id,))
            row = cursor.fetchone()
            if row and row[0]:
                scan_data = json.loads(row[0])
    if not scan_data:
        return "Scan not found", 404
    if fmt == "csv":
        output = export_scan_csv(scan_data)
        return Response(output.getvalue(), mimetype="text/csv", headers={"Content-Disposition": f"attachment;filename=scan_{scan_id}.csv"})
    elif fmt == "json":
        output = export_scan_json(scan_data)
        return Response(output.getvalue(), mimetype="application/json", headers={"Content-Disposition": f"attachment;filename=scan_{scan_id}.json"})
    elif fmt == "pdf":
        output = export_scan_pdf(scan_data)
        return send_file(output, mimetype="application/pdf", as_attachment=True, download_name=f"scan_{scan_id}.pdf")
    else:
        return "Invalid format", 400

@app.route('/dashboard')
def dashboard():
    with sqlite3.connect("scan_history.db") as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id, target, result, host_info FROM scans ORDER BY id DESC")
        rows = cursor.fetchall()
        scans = [
            {
                "id": row[0],
                "target": row[1],
                "result": json.loads(row[2]) if row[2] else {},
                "host_info": json.loads(row[3]) if row[3] else {}
            }
            for row in rows
        ]
    return render_template("dashboard.html", scans=scans)

@app.route('/api/dashboard')
def dashboard_api():
    with sqlite3.connect("scan_history.db") as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id, target, result, host_info FROM scans ORDER BY id DESC LIMIT 20")
        rows = cursor.fetchall()
        scans = [
            {
                "id": row[0],
                "target": row[1],
                "result": json.loads(row[2]),
                "host_info": json.loads(row[3])
            }
            for row in rows
        ]
    return jsonify(scans)

@app.route("/report/<int:scan_id>/<rtype>")
def report_scan(scan_id, rtype):
    scan = Scan.query.get_or_404(scan_id)
    scan_data = json.loads(scan.result)
    output = generate_report(scan_data, report_type=rtype)
    return send_file(output, mimetype="application/pdf", as_attachment=True, download_name=f"scan_{scan_id}_{rtype}.pdf")

# === SOCKET.IO EVENTS ===

@socketio.on("start_scan")
def handle_start_scan(data):
    target = data.get("target")
    scan_type = data.get("scan_type", "deep")
    port_range = data.get("port_range", "1-65535")

    if not target:
        emit("scan_update", {"error": "Target is required", "status": "error"})
        return

    def background_scan():
        try:
            socketio.emit("scan_update", {"message": "Scan started...", "status": "info"})
            result = perform_scan(target, scan_type, port_range)
            socketio.emit("scan_update", {"result": result, "status": "completed"})
        except Exception as e:
            socketio.emit("scan_update", {"error": str(e), "status": "error"})

    threading.Thread(target=background_scan).start()

# === NON-BLOCKING NVD DATA UPDATE ===

def async_nvd_update():
    threading.Thread(target=update_nvd_data).start()

async_nvd_update()

if __name__ == "__main__":
    socketio.run(app, host="0.0.0.0", port=5000, debug=True)
import os
import json
import sqlite3
import threading
from flask import Flask, request, jsonify, render_template
from flask_socketio import SocketIO, emit
from celery.result import AsyncResult

from celery_app import init_celery
from scanner import check_vulnerabilities  # Passive scan function
from scanner_core import run_full_scan      # Assume active scan logic is here
from update_nvd import update_nvd_data
from tasks import run_scan_task

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret!'
app.config['CELERY_BROKER_URL'] = os.getenv('CELERY_BROKER_URL', 'redis://localhost:6379/0')
app.config['CELERY_RESULT_BACKEND'] = os.getenv('CELERY_RESULT_BACKEND', 'redis://localhost:6379/0')

# Initialize SocketIO
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='eventlet')

# Initialize Celery
celery = init_celery(app)

# Ensure scan history database exists
def init_db():
    with sqlite3.connect("scan_history.db") as conn:
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT NOT NULL,
                result TEXT,
                host_info TEXT
            )
        """)
        conn.commit()

init_db()

# Save scan results to SQLite
def save_scan_result(target, scan_result, host_info):
    with sqlite3.connect("scan_history.db") as conn:
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO scans (target, result, host_info) VALUES (?, ?, ?)",
            (target, json.dumps(scan_result), json.dumps(host_info))
        )
        conn.commit()

# Combined scan logic
def perform_scan(target, scan_type='deep', port_range='1-65535'):
    try:
        active_result = {}
        passive_result = {}

        def active_scan():
            active_result['data'], active_result['host_info'] = run_full_scan(target, scan_type, port_range)

        def passive_scan():
            passive_result['data'] = check_vulnerabilities(target)

        t1 = threading.Thread(target=active_scan)
        t2 = threading.Thread(target=passive_scan)

        t1.start()
        t2.start()
        t1.join()
        t2.join()

        result = {
            "Active Scan": active_result.get("data", "No active scan result"),
            "Passive Scan": passive_result.get("data", []),
        }

        save_scan_result(target, result, active_result.get("host_info", {}))
        return result

    except Exception as e:
        print(f"Error during scanning: {e}")
        return {"error": str(e)}

# === ROUTES ===

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/scan", methods=["POST"])
def start_scan():
    data = request.get_json()
    target = data.get("target")
    scan_type = data.get("scan_type", "deep")
    port_range = data.get("port_range", "1-65535")

    task = run_scan_task.delay(target, scan_type, port_range)
    return jsonify({"message": "Scan started", "task_id": task.id})

@app.route("/api/scan/<task_id>", methods=["GET"])
def scan_status(task_id):
    task_result = AsyncResult(task_id, app=celery)
    if task_result.state == "PENDING":
        return jsonify({"status": "pending"})
    elif task_result.state == "SUCCESS":
        return jsonify({"status": "completed", "result": task_result.result})
    elif task_result.state == "FAILURE":
        return jsonify({"status": "failed", "error": str(task_result.result)})
    return jsonify({"status": task_result.state})

@app.route("/api/history", methods=["GET"])
def get_scan_history():
    with sqlite3.connect("scan_history.db") as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id, target, result, host_info FROM scans ORDER BY id DESC")
        rows = cursor.fetchall()
        history = [
            {
                "id": row[0],
                "target": row[1],
                "result": json.loads(row[2]),
                "host_info": json.loads(row[3])
            }
            for row in rows
        ]
        return jsonify(history)

# === SOCKET.IO EVENTS ===

@socketio.on("start_scan")
def handle_start_scan(data):
    target = data.get("target")
    scan_type = data.get("scan_type", "deep")
    port_range = data.get("port_range", "1-65535")

    if not target:
        emit("scan_update", {"error": "Target is required", "status": "error"})
        return

    def background_scan():
        try:
            socketio.emit("scan_update", {"message": "Scan started...", "status": "info"})
            result = perform_scan(target, scan_type, port_range)
            socketio.emit("scan_update", {"result": result, "status": "completed"})
        except Exception as e:
            socketio.emit("scan_update", {"error": str(e), "status": "error"})

    threading.Thread(target=background_scan).start()

# === NON-BLOCKING NVD DATA UPDATE ===

def async_nvd_update():
    threading.Thread(target=update_nvd_data).start()

async_nvd_update()

if __name__ == "__main__":
    socketio.run(app, host="0.0.0.0", port=5000, debug=True)
