import requests
import json
from datetime import datetime, timedelta, timezone

API_KEY = "2f14db5a-044b-41eb-8abe-623892f506c6"  # Replace with your NVD API key if available

# Adjust how far back you want to pull CVEs
DAYS_BACK = 90
start_date = (datetime.now(timezone.utc) - timedelta(days=DAYS_BACK)).isoformat(timespec='milliseconds').replace('+00:00', 'Z')
end_date = datetime.now(timezone.utc).isoformat(timespec='milliseconds').replace('+00:00', 'Z')

headers = {
    "apiKey": API_KEY
} if API_KEY else {}

url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate={start_date}&pubEndDate={end_date}"

print(f"Fetching CVE data from: {url}")

response = requests.get(url, headers=headers)
if response.status_code == 200:
    with open("nvd_data.json", "w") as f:
        json.dump(response.json(), f, indent=2)
    print("✅ NVD data updated and saved to nvd_data.json")
else:
    print(f"❌ Failed to fetch data from NVD. Status code: {response.status_code}")
    print(f"Response: {response.text}")



