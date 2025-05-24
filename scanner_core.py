import nmap
import json
import os
from difflib import SequenceMatcher

# Load NVD dataset once
NVD_DATA_PATH = os.path.join(os.path.dirname(__file__), 'nvd_data.json')
with open(NVD_DATA_PATH, 'r') as f:
    nvd_data = json.load(f)

def load_nvd_data():
    return nvd_data

def match_cves(service_name, version):
    cves = []
    vuln_list = nvd_data.get('vulnerabilities', []) if isinstance(nvd_data, dict) else nvd_data
    service_name = (service_name or '').lower().strip()
    version = (version or '').lower().strip()
    for entry in vuln_list:
        cve_info = entry.get('cve', {})
        descriptions = cve_info.get('descriptions', [])
        desc_text = ' '.join([d.get('value', '') for d in descriptions if isinstance(d, dict)]).lower()
        # Try to match service_name or product in description (case-insensitive, partial match)
        if service_name and service_name in desc_text:
            # If version is present, try to match version string or use fuzzy matching
            if version:
                if version in desc_text:
                    cves.append({
                        "id": cve_info.get("id"),
                        "description": desc_text,
                        "severity": cve_info.get("metrics", {}).get("cvssMetricV31", [{}])[0].get("cvssData", {}).get("baseSeverity", "unknown"),
                        "published": cve_info.get("published", "unknown")
                    })
                else:
                    # Fuzzy match: if version is similar (e.g., major.minor)
                    for word in desc_text.split():
                        if SequenceMatcher(None, version, word).ratio() > 0.7:
                            cves.append({
                                "id": cve_info.get("id"),
                                "description": desc_text,
                                "severity": cve_info.get("metrics", {}).get("cvssMetricV31", [{}])[0].get("cvssData", {}).get("baseSeverity", "unknown"),
                                "published": cve_info.get("published", "unknown")
                            })
                            break
            else:
                # If no version, match on service/product only
                cves.append({
                    "id": cve_info.get("id"),
                    "description": desc_text,
                    "severity": cve_info.get("metrics", {}).get("cvssMetricV31", [{}])[0].get("cvssData", {}).get("baseSeverity", "unknown"),
                    "published": cve_info.get("published", "unknown")
                })
    return cves

def run_full_scan(target, scan_type="deep", port_range="1-65535"):
    nm = nmap.PortScanner()
    scan_args = "-sV"
    if scan_type == "fast":
        scan_args = "-T4 -F"
    elif scan_type == "basic":
        scan_args = "-T3"
    try:
        print(f"[DEBUG] Running nmap scan: target={target}, scan_args={scan_args}, port_range={port_range}")
        nm.scan(hosts=target, arguments=f"{scan_args} -p {port_range}")
        print(f"[DEBUG] Nmap scan info: {nm.scaninfo()}")
        print(f"[DEBUG] Nmap all hosts: {nm.all_hosts()}")
        for host in nm.all_hosts():
            print(f"[DEBUG] Host {host} protocols: {nm[host].all_protocols()}")
            for proto in nm[host].all_protocols():
                print(f"[DEBUG] Protocol {proto} ports: {list(nm[host][proto].keys())}")
    except Exception as e:
        print(f"[ERROR] Nmap scan failed: {e}")
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
                name = (service.get("name", "") or '').lower().strip()
                version = (service.get("version", "") or '').lower().strip()
                product = (service.get("product", "") or '').lower().strip()
                # Try all combinations for best match
                cves = match_cves(product, version)
                if not cves and name:
                    cves = match_cves(name, version)
                if not cves and product:
                    cves = match_cves(product, '')
                if not cves and name:
                    cves = match_cves(name, '')
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
