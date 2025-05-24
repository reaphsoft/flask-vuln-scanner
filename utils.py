# utils.py

import time
import logging
from functools import wraps
import csv
import pandas as pd
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from flask import send_file
import io
import json

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

def log_execution(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        start_time = time.time()
        logging.info(f"[START] {func.__name__} called with args={args}, kwargs={kwargs}")
        result = func(*args, **kwargs)
        elapsed = time.time() - start_time
        logging.info(f"[END] {func.__name__} completed in {elapsed:.2f}s")
        return result
    return wrapper

def export_scan_csv(scan_data):
    import csv
    import io
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Type", "Port", "Protocol", "Service", "Product", "Version", "CVEs"])
    for scan_type in ["Active Scan", "Passive Scan"]:
        entries = scan_data.get(scan_type, [])
        if not entries:
            # Write a row indicating no data for this scan type
            writer.writerow([scan_type, "", "", "", "", "", "No data"])
            continue
        for entry in entries:
            if isinstance(entry, dict):
                cves = entry.get("cves", [])
                if isinstance(cves, list):
                    cves_str = "; ".join([cve if isinstance(cve, str) else cve.get("id", str(cve)) for cve in cves])
                else:
                    cves_str = str(cves)
                writer.writerow([
                    scan_type,
                    entry.get("port", ""),
                    entry.get("protocol", ""),
                    entry.get("service", ""),
                    entry.get("product", ""),
                    entry.get("version", ""),
                    cves_str
                ])
            elif isinstance(entry, str):
                # For Passive Scan, sometimes entries are just CVE strings
                writer.writerow([scan_type, "", "", "", "", "", entry])
            else:
                writer.writerow([scan_type, "", "", "", "", "", str(entry)])
    output.seek(0)
    return output

def export_scan_json(scan_data):
    output = io.StringIO()
    output.write(json.dumps(scan_data, indent=2))
    output.seek(0)
    return output

def export_scan_pdf(scan_data):
    buffer = io.BytesIO()
    c = canvas.Canvas(buffer, pagesize=letter)
    width, height = letter
    c.setFont("Helvetica-Bold", 16)
    c.drawString(30, height - 40, "Scan Report")
    c.setFont("Helvetica", 10)
    y = height - 60
    for scan_type in ["Active Scan", "Passive Scan"]:
        c.setFont("Helvetica-Bold", 12)
        c.drawString(30, y, scan_type)
        y -= 16
        c.setFont("Helvetica", 10)
        for entry in scan_data.get(scan_type, []):
            if isinstance(entry, dict):
                line = f"Port: {entry.get('port', '')} | Service: {entry.get('service', '')} | Product: {entry.get('product', '')} | Version: {entry.get('version', '')}"
                c.drawString(40, y, line)
                y -= 14
                cves = entry.get("cves", [])
                if cves:
                    for cve in cves:
                        c.drawString(60, y, f"CVE: {cve}")
                        y -= 12
                if y < 60:
                    c.showPage()
                    y = height - 40
    c.save()
    buffer.seek(0)
    return buffer



