import requests
import json
from datetime import datetime, timedelta, timezone
import tempfile
import shutil
import os

API_KEY = "2f14db5a-044b-41eb-8abe-623892f506c6"  # Replace with your NVD API key if available

# Adjust how far back you want to pull CVEs
DAYS_BACK = 365

def update_nvd_data():
    # NVD API only allows up to 120 days per request for cves/2.0 endpoint
    max_days = 120
    now = datetime.now(timezone.utc)
    all_vulns = []
    headers = {"apiKey": API_KEY} if API_KEY else {}
    results_per_page = 2000

    for offset in range(0, DAYS_BACK, max_days):
        start = now - timedelta(days=offset + max_days)
        end = now - timedelta(days=offset)
        start_date = start.isoformat(timespec='milliseconds').replace('+00:00', 'Z')
        end_date = end.isoformat(timespec='milliseconds').replace('+00:00', 'Z')
        start_index = 0
        total_results = None
        print(f"Fetching CVE data from {start_date} to {end_date} in pages...")
        while True:
            url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate={start_date}&pubEndDate={end_date}&resultsPerPage={results_per_page}&startIndex={start_index}"
            print(f"Fetching: {url}")
            try:
                response = requests.get(url, headers=headers, timeout=120)
            except Exception as e:
                print(f"❌ Request to NVD failed: {e}")
                return
            if response.status_code != 200:
                print(f"❌ Failed to fetch data from NVD. Status code: {response.status_code}")
                print(f"Response: {response.text[:500]}")
                break
            try:
                data = response.json()
            except Exception as e:
                print(f"❌ Failed to decode JSON from NVD. Status code: {response.status_code}")
                print(f"Response: {response.text[:500]}")
                break
            if not isinstance(data, dict) or 'vulnerabilities' not in data:
                print("❌ NVD data missing required 'vulnerabilities' key. Not updating main file.")
                break
            all_vulns.extend(data['vulnerabilities'])
            if total_results is None:
                total_results = data.get('totalResults', 0)
            start_index += results_per_page
            if start_index >= total_results:
                break
    if all_vulns:
        with tempfile.NamedTemporaryFile('w+', delete=False) as tmpf:
            json.dump({"vulnerabilities": all_vulns}, tmpf, indent=2)
            tmpf.flush()
            tmpf.close()
            shutil.move(tmpf.name, "nvd_data.json")
        print(f"✅ NVD data updated and saved to nvd_data.json. Total CVEs: {len(all_vulns)}")
    else:
        print("❌ No vulnerabilities fetched from NVD.")



