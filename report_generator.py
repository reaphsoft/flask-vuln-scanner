import io
import json
import csv
import pandas as pd
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from flask import send_file

def generate_report(scan_data, report_type="summary"):
    buffer = io.BytesIO()
    c = canvas.Canvas(buffer, pagesize=letter)
    width, height = letter
    c.setFont("Helvetica-Bold", 16)
    c.drawString(30, height - 40, "Scan Report")
    c.setFont("Helvetica", 10)
    y = height - 60
    if report_type == "summary":
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
    # Add more report types as needed
    c.save()
    buffer.seek(0)
    return buffer
