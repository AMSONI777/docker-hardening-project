import json
import requests
import time
from collections import Counter
import matplotlib.pyplot as plt
import numpy as np
import sys
import os

# --- Configuration ---
NVD_API_KEY = "951ee4c9-bccc-4b89-855a-bd7ffb40d987" # Make sure your key is here

REPORTS = {
    'Baseline (Debian)': 'insecure-app-results.json',
    'Hardened (Debian Slim)': 'hardened-app-results.json',
    'Hardened (Alpine)': 'alpine-app-results.json',
    'Hardened (Distroless)': 'distroless-app-results.json'
}

# --- Chart Styling ---
plt.style.use('seaborn-v0_8-whitegrid')
COLORS = ['#d9534f', '#5cb85c', '#f0ad4e', '#5bc0de']

# --- Caching ---
# To avoid re-running API calls, we'll save results in a cache file.
CACHE_FILE = 'cwe_cache.json'

def load_cache():
    """Loads the CVE-to-CWE cache from a file."""
    if os.path.exists(CACHE_FILE):
        with open(CACHE_FILE, 'r') as f:
            return json.load(f)
    return {}

def save_cache(cache):
    """Saves the CVE-to-CWE cache to a file."""
    with open(CACHE_FILE, 'w') as f:
        json.dump(cache, f, indent=2)

def get_cves_from_file(filename):
    """Reads a Trivy JSON report and returns a list of CVE IDs."""
    # (This function remains the same as before)
    cve_ids = []
    try:
        with open(filename, 'r', encoding='utf-8') as f:
            data = json.load(f)
        if 'Results' in data and isinstance(data['Results'], list):
            for result in data['Results']:
                if 'Vulnerabilities' in result and result['Vulnerabilities'] is not None:
                    for vuln in result['Vulnerabilities']:
                        cve_ids.append(vuln.get('VulnerabilityID'))
        return list(set(cve_ids)) # Return unique CVEs
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"Error processing {filename}: {e}")
        return []


def get_cwes_for_cve(cve_id, api_key, cache):
    """Queries the NVD API (with caching) to get CWEs for a given CVE ID."""
    # If the result is already in our cache, return it instantly
    if cve_id in cache:
        return cache[cve_id]

    if not cve_id or not cve_id.startswith('CVE-'):
        return ["N/A"]
    
    headers = {'apiKey': api_key}
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    
    # NVD API has a rate limit, so we add a delay
    time.sleep(0.6) 
    
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        data = response.json()
        
        vulnerabilities = data.get('vulnerabilities', [])
        
        if not vulnerabilities:
            print(f"  --> Warning: NVD returned no data for {cve_id}. Caching as No-Data.")
            cache[cve_id] = ["No-Data"]
            return ["No-Data"]
        
        cve_item = vulnerabilities[0].get('cve', {})
        weaknesses = cve_item.get('weaknesses', [])
        
        if not weaknesses:
            cache[cve_id] = ["CWE-Other"]
            return ["CWE-Other"]
            
        cwe_list = []
        for weakness in weaknesses:
            for desc in weakness.get('description', []):
                if 'value' in desc:
                    cwe_list.append(desc['value'])
        
        result = cwe_list if cwe_list else ["CWE-Other"]
        cache[cve_id] = result
        return result

    except requests.exceptions.RequestException as e:
        print(f"API request failed for {cve_id}: {e}")
        cache[cve_id] = ["API-Error"]
        return ["API-Error"]

def create_summary_cwe_chart(all_cwe_data, top_n=5):
    """Creates a grouped bar chart comparing the top CWEs across all images."""
    # Find the overall top N CWEs from the baseline image
    baseline_counts = all_cwe_data['Baseline (Debian)']
    baseline_counts.pop("N/A", None)
    baseline_counts.pop("API-Error", None)
    baseline_counts.pop("No-Data", None)
    baseline_counts.pop("CWE-Other", None)
    
    top_cwes = [item[0] for item in baseline_counts.most_common(top_n)]
    
    labels = list(REPORTS.keys())
    x = np.arange(len(top_cwes))
    width = 0.2
    
    fig, ax = plt.subplots(figsize=(14, 8))
    
    for i, (name, cwe_counts) in enumerate(all_cwe_data.items()):
        counts = [cwe_counts.get(cwe, 0) for cwe in top_cwes]
        offset = width * (i - 1.5)
        rects = ax.bar(x + offset, counts, width, label=name, color=COLORS[i])
        ax.bar_label(rects, padding=3, fontsize=8)
        
    ax.set_ylabel('Vulnerability Count (Log Scale)')
    ax.set_title(f'Comparison of Top {top_n} Weakness Types (CWEs) Across Images', fontsize=16, fontweight='bold', pad=20)
    ax.set_xticks(x)
    ax.set_xticklabels(top_cwes, rotation=45, ha='right')
    ax.legend(title="Image Strategy")
    ax.set_yscale('log')
    
    fig.tight_layout(pad=2.0)
    plt.savefig('chart_6_cwe_summary_comparison.png', dpi=300)
    plt.close()
    print("\nChart 'chart_6_cwe_summary_comparison.png' has been saved.")


if __name__ == '__main__':
    if NVD_API_KEY == "YOUR_NVD_API_KEY_HERE" or not NVD_API_KEY:
        print("ERROR: Please add your NVD API Key to the script.")
        sys.exit(1)

    cwe_cache = load_cache()
    all_cwe_counts = {}

    print("--- Starting Full Qualitative Vulnerability Analysis (CWE Mapping) ---")
    
    for name, filename in REPORTS.items():
        print(f"\nAnalyzing image: '{name}' from file: {filename}...")
        cves = get_cves_from_file(filename)
        image_cwe_counts = Counter()
        
        for i, cve in enumerate(cves):
            cwes = get_cwes_for_cve(cve, NVD_API_KEY, cwe_cache)
            image_cwe_counts.update(cwes)
            # Print progress less frequently to avoid clutter
            if (i + 1) % 50 == 0 or (i + 1) == len(cves):
                print(f"  Processed {i+1}/{len(cves)} CVEs...")
        
        all_cwe_counts[name] = image_cwe_counts
        print(f"Finished analyzing '{name}'.")

    save_cache(cwe_cache)
    print("\nCWE cache has been updated and saved.")
    
    create_summary_cwe_chart(all_cwe_counts)

    print("\n--- CWE Analysis Complete ---")