import requests

urls = [
    "https://www.quikafix.com",
    "https://google-gruyere.appspot.com",
    "https://reaphsoft.com"
]

headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
}

for url in urls:
    try:
        response = requests.get(url, headers=headers, timeout=10)
        print(f"URL: {url} - Status Code: {response.status_code}")
    except requests.exceptions.RequestException as e:
        print(f"URL: {url} - Error: {e}")
