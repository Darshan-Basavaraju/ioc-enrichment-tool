import requests
import sys

api_key = "195209d6b54f33dcad14cacc619ad0a58ddf50421d78c611a2e6051dbb6b4cc5"

# Take domain from command line
domain = sys.argv[1]

url = f"https://www.virustotal.com/api/v3/domains/{domain}"
headers = {"x-apikey": api_key}

response = requests.get(url, headers=headers)
result = response.json()

stats = result["data"]["attributes"]["last_analysis_stats"]
reputation = result["data"]["attributes"]["reputation"]

print("=" * 40)
print(f"Domain: {domain}")
print(f"Malicious: {stats['malicious']}")
print(f"Suspicious: {stats['suspicious']}")
print(f"Harmless: {stats['harmless']}")
print(f"Undetected: {stats['undetected']}")
print(f"Reputation Score: {reputation}")
print("Flagged as malicious by:")
analysis = result["data"]["attributes"]["last_analysis_results"]
for vendor, details in analysis.items():
    if details["category"] == "malicious":
        print(f"  - {vendor}")
print("=" * 40)