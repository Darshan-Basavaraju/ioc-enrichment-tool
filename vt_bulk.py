import requests
import time

api_key = "Your API_Key HERE"

def check_domain(domain):
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {"x-apikey": api_key}

    response = requests.get(url, headers=headers)
    result = response.json()

    stats = result["data"]["attributes"]["last_analysis_stats"]
    reputation = result["data"]["attributes"]["reputation"]
    malicious = stats["malicious"]

    if malicious > 0:
        return f"MALICIOUS | {domain}"
    elif reputation < 0:
        return f"SUSPICIOUS | {domain}"
    else:
        return f"CLEAN | {domain}"

with open("domains.txt", "r") as infile, open("results.txt", "w") as outfile:
    for line in infile:
        domain = line.strip()
        verdict = check_domain(domain)
        print(verdict)
        outfile.write(verdict + "\n")
        time.sleep(15)


