import json
import sys

def search_cve(cve_id, nvd_file='nvd_data.json'):
    try:
        with open(nvd_file, 'r') as file:
            data = json.load(file)

        matches = [
            item for item in data.get("CVE_Items", [])
            if item.get("cve", {}).get("CVE_data_meta", {}).get("ID") == cve_id
        ]

        if matches:
            print(f"\n✅ Found {len(matches)} match(es) for CVE ID: {cve_id}\n")
            for match in matches:
                print(json.dumps(match, indent=2))
        else:
            print(f"\n❌ No matches found for CVE ID: {cve_id}")

    except FileNotFoundError:
        print(f"⚠️ File '{nvd_file}' not found.")
    except json.JSONDecodeError:
        print("❌ Error parsing JSON. Make sure 'nvd_data.json' is properly formatted.")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python search_cve.py CVE-ID")
    else:
        search_cve(sys.argv[1])
