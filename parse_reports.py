import json

def load_semgrep(filepath):
    vulns = []
    try:
        with open(filepath, 'r') as f:
            data = json.load(f)
            for item in data.get('results', []):
                vulns.append({
                    'source': 'SAST (Semgrep)',
                    'vulnerability': item.get('check_id', 'Unknown'),
                    'severity': item.get('extra', {}).get('severity', 'UNKNOWN'),
                    'location': f"File: {item.get('path', 'Unknown')}:{item.get('start', {}).get('line', '0')}",
                    'description': item.get('extra', {}).get('message', '')
                })
    except FileNotFoundError:
        print(f"[-] Warning: {filepath} not found.")
    return vulns

def load_zap(filepath):
    vulns = []
    try:
        with open(filepath, 'r') as f:
            data = json.load(f)
            for site in data.get('site', []):
                for alert in site.get('alerts', []):
                    severity = alert.get('riskdesc', 'UNKNOWN').split(' ')[0]
                    uri = alert.get('instances', [{}])[0].get('uri', 'Unknown')
                    
                    vulns.append({
                        'source': 'DAST (ZAP)',
                        'vulnerability': alert.get('name', 'Unknown'),
                        'severity': severity.upper(),
                        'location': f"Endpoint: {uri}",
                        'description': alert.get('desc', '').replace('<p>', '').replace('</p>', '').strip()
                    })
    except FileNotFoundError:
        print(f"[-] Warning: {filepath} not found.")
    return vulns

def deduplicate_findings(vulns):
    seen_signatures = set()
    deduplicated = []
    
    for vuln in vulns:
        signature = f"{vuln['vulnerability']}::{vuln['location']}"
        if signature not in seen_signatures:
            seen_signatures.add(signature)
            deduplicated.append(vuln)
            
    return deduplicated

def main():
    sast_findings = load_semgrep('semgrep.json')
    dast_findings = load_zap('zap.json')
    unified_report = deduplicate_findings(sast_findings + dast_findings)

    with open('unified_report.json', 'w') as f:
        json.dump({
            'total_vulnerabilities': len(unified_report),
            'sast_count': len(sast_findings),
            'dast_count': len(dast_findings),
            'findings': unified_report
        }, f, indent=4)
    print(f"[+] Wrote {len(unified_report)} vulnerabilities to unified_report.json")

if __name__ == '__main__':
    main()