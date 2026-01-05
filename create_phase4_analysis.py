import json
from collections import defaultdict

# --- Configuration ---
# A dictionary mapping the friendly name of the image to its Trivy JSON report file
HARDENED_REPORTS = {
    'Debian Slim': 'hardened-app-results.json',
    'Alpine': 'alpine-app-results.json',
    'Distroless': 'distroless-app-results.json'
}

def get_vulnerabilities_from_file(filename):
    """Reads a Trivy JSON report and returns a set of CVE IDs."""
    cve_ids = set()
    try:
        with open(filename, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        if 'Results' in data and isinstance(data['Results'], list):
            for result in data['Results']:
                if 'Vulnerabilities' in result and result['Vulnerabilities'] is not None:
                    for vuln in result['Vulnerabilities']:
                        cve_ids.add(vuln.get('VulnerabilityID'))
        return cve_ids
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"Error processing {filename}: {e}")
        return set()

if __name__ == '__main__':
    # Load all CVEs for each hardened image into a dictionary
    all_cves = {name: get_vulnerabilities_from_file(filename) 
                for name, filename in HARDENED_REPORTS.items()}

    # --- Find Persistent Vulnerabilities ---
    # This dictionary will store which images a specific CVE was found in
    cve_persistence = defaultdict(list)
    
    # Get a set of all unique CVEs found across all hardened images
    unique_cves = set().union(*all_cves.values())
    
    # For each unique CVE, check which images it appears in
    for cve in unique_cves:
        for name, cve_set in all_cves.items():
            if cve in cve_set:
                cve_persistence[cve].append(name)

    # --- Print the Results Table ---
    print("\n--- Vulnerability Persistence Analysis Results ---")
    print("This table lists vulnerabilities found in MORE THAN ONE hardened image.")
    print(f"\n| {'CVE ID':<25} | {'Found In':<50} |")
    print(f"|{'-'*27}|{'-'*52}|")

    found_persistent_vulns = False
    for cve, found_in_list in sorted(cve_persistence.items()):
        if len(found_in_list) > 1:
            found_persistent_vulns = True
            print(f"| {cve:<25} | {', '.join(sorted(found_in_list)):<50} |")
            
    if not found_persistent_vulns:
        print("| {'No vulnerabilities were found to persist across multiple images.':<78} |")

    print("--- End of Table ---")