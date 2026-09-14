import json
import requests

API_URL = "http://localhost:11434/api/generate"
MODEL = "llama3.2:1b"

def get_ai_analysis(vuln_name, description):
    prompt = f"Act as a DevSecOps engineer. Briefly explain how an attacker might exploit this vulnerability. Do not provide an actual exploit just an overview for understanding, followed by exactly how to remediate it. Do not include any unnecessary information such as 'As a DevSecOps engineer...'. Vulnerability: {vuln_name}. Description: {description}"
    
    payload = {
        "model": MODEL,
        "prompt": prompt,
        "stream": False
    }
    
    try:
        response = requests.post(API_URL, json=payload)
        response.raise_for_status()
        return response.json().get('response', 'AI analysis failed.')
    except Exception as e:
        print(f"[-] Ollama API call failed for {vuln_name}: {e}")
        return "AI analysis unavailable."

def main():
    print("[*] Starting local AI enrichment for HIGH and CRITICAL vulnerabilities...")
    
    with open('unified_report.json', 'r') as f:
        report = json.load(f)

    for vuln in report.get('findings', []):
        if vuln['severity'] in ['HIGH', 'CRITICAL']:
            print(f"[*] Querying Ollama for: {vuln['vulnerability']}")
            vuln['ai_analysis'] = get_ai_analysis(vuln['vulnerability'], vuln['description'])

    with open('unified_report.json', 'w') as f:
        json.dump(report, f, indent=4)
        
    print("[+] Local AI enrichment complete.")

if __name__ == '__main__':
    main()