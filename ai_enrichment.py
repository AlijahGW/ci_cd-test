import json
import os
import requests
import time

API_KEY = os.environ.get("AI_API_KEY")
API_URL = f"https://api.asksage.ai.nasa.gov/server/anthropic/"

def get_ai_analysis(vuln_name, description):
    prompt = f"Act as a DevSecOps engineer. Briefly explain how an attacker might exploit this vulnerability, followed by exactly how to remediate it. Keep the response under 150 words. Vulnerability: {vuln_name}. Description: {description}"
    
    payload = {"contents": [{"parts": [{"text": prompt}]}]}
    headers = {"Content-Type": "application/json"}
    
    try:
        response = requests.post(API_URL, json=payload, headers=headers)
        response.raise_for_status()
        # Extract the text from the JSON response
        return response.json()['candidates'][0]['content']['parts'][0]['text']
    except Exception as e:
        print(f"[-] API call failed for {vuln_name}: {e}")
        return "AI analysis unavailable."

def main():
    if not API_KEY:
        print("[-] AI_API_KEY environment variable not set. Skipping AI enrichment.")
        return

    print("[*] Starting AI enrichment for HIGH and CRITICAL vulnerabilities...")
    
    with open('unified_report.json', 'r') as f:
        report = json.load(f)

    for vuln in report.get('findings', []):
        if vuln['severity'] in ['HIGH', 'CRITICAL']:
            print(f"[*] Querying AI for: {vuln['vulnerability']}")
            vuln['ai_analysis'] = get_ai_analysis(vuln['vulnerability'], vuln['description'])
            time.sleep(2) # Basic rate limiting

    with open('unified_report.json', 'w') as f:
        json.dump(report, f, indent=4)
        
    print("[+] AI enrichment complete.")

if __name__ == '__main__':
    main()