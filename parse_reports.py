import json

FALSE_POSITIVES = [
    "yaml.github-actions.security.github-actions-mutable-action-tag.github-actions-mutable-action-tag",
    "yaml.github-actions.security.gha-curl-pipe-shell.gha-curl-pipe-shell"
]

def load_semgrep(filepath):
    vulns = []
    try:
        with open(filepath, 'r') as f:
            data = json.load(f)
            for item in data.get('results', []):
                raw_id = item.get('check_id', 'Unknown')

                # Filter out known false positives
                if raw_id in FALSE_POSITIVES:
                    continue 

                readable_title = raw_id.split('.')[-1].replace('-', ' ').title()

                raw_severity = item.get('extra', {}).get('severity', 'UNKNOWN').upper()
                severity = 'HIGH' if raw_severity == 'ERROR' else 'MEDIUM' if raw_severity == 'WARNING' else 'LOW' if raw_severity == 'INFO' else raw_severity

                vulns.append({
                    'source': 'SAST (Semgrep)',
                    'vulnerability': readable_title,
                    'severity': severity,
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
                    severity = alert.get('riskdesc', 'UNKNOWN').split(' ')[0].upper()
                    uri = alert.get('instances', [{}])[0].get('uri', 'Unknown')
                    
                    vulns.append({
                        'source': 'DAST (ZAP)',
                        'vulnerability': alert.get('name', 'Unknown'),
                        'severity': severity,
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