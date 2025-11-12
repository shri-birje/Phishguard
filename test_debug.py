import requests, json

API = "http://127.0.0.1:5000/api/debug_features"
data = {"url": "https://paypa1.com"}

print(f"🔍 Sending request to {API} ...")
resp = requests.post(API, json=data)

print("Status code:", resp.status_code)
print("Raw response:")
print(resp.text)

try:
    print("\nParsed JSON:")
    parsed = resp.json()
    print(json.dumps(parsed, indent=2))
except Exception as e:
    print(f"\n❌ JSON parse error: {e}")
