import nmap
import json
import os

# Load NVD dataset once
NVD_DATA_PATH = os.path.join(os.path.dirname(__file__), 'nvd_data.json')
with open(NVD_DATA_PATH, 'r') as f:
    nvd_data = json.load(f)

def load_nvd_data():
    return nvd_data

def match_cves(service_name, version):
    cves = []
    for entry in nvd_data:
        if service_name.lower() in entry.get("description", "").lower():
            if version and version in entry.get("description", ""):
                cves.append({
                    "id": entry.get("id"),
                    "description": entry.get("description"),
                    "severity": entry.get("severity", "unknown"),
                    "published": entry.get("published", "unknown")
                })
    return cves

def run_full_scan(target, scan_type="deep", port_range="1-65535"):
    nm = nmap.PortScanner()

    scan_args = "-sV"
    if scan_type == "fast":
        scan_args = "-T4 -F"
    elif scan_type == "basic":
        scan_args = "-T3 -p 1-1000"

    try:
        nm.scan(hosts=target, arguments=f"{scan_args} -p {port_range}")
    except Exception as e:
        return {"error": f"Nmap scan failed: {e}"}, {}

    results = []
    host_info = {}

    for host in nm.all_hosts():
        host_info["ip"] = host
        host_info["hostname"] = nm[host].hostname()
        host_info["status"] = nm[host].state()

        for proto in nm[host].all_protocols():
            ports = nm[host][proto].keys()
            for port in sorted(ports):
                service = nm[host][proto][port]
                name = service.get("name", "")
                version = service.get("version", "")
                product = service.get("product", "")
                full_version = f"{product} {version}".strip()

                cves = match_cves(product or name, version)

                results.append({
                    "port": port,
                    "protocol": proto,
                    "service": name,
                    "product": product,
                    "version": version,
                    "state": service.get("state"),
                    "cves": cves
                })

    return results, host_info
