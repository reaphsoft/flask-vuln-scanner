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
