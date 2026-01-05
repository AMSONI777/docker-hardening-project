import json
import matplotlib.pyplot as plt
import numpy as np
from collections import Counter
import sys

# --- Configuration ---
IMAGE_NAMES = ['Baseline (Debian)', 'Hardened (Debian Slim)', 'Hardened (Alpine)', 'Hardened (Distroless)']
TRIVY_FILES = ['insecure-app-results.json', 'hardened-app-results.json', 'alpine-app-results.json', 'distroless-app-results.json']
GRYPE_FILES = ['grype-insecure-app-results.json', 'grype-hardened-app-results.json', 'grype-alpine-app-results.json', 'grype-distroless-app-results.json']

# --- Chart Styling ---
plt.style.use('seaborn-v0_8-whitegrid')

def parse_trivy_json(filename):
    """Reads a Trivy JSON report and returns the total vulnerability count."""
    total_vulns = 0
    try:
        with open(filename, 'r', encoding='utf-8') as f:
            data = json.load(f)
        if 'Results' in data and isinstance(data['Results'], list):
            for result in data['Results']:
                total_vulns += len(result.get('Vulnerabilities', []))
        return total_vulns
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"Error processing {filename}: {e}")
        return 0

def parse_grype_json(filename):
    """Reads a Grype JSON report and returns the total vulnerability count."""
    try:
        with open(filename, 'r', encoding='utf-8') as f:
            data = json.load(f)
        return len(data.get('matches', []))
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"Error processing {filename}: {e}")
        return 0

def create_scanner_comparison_chart(labels, trivy_counts, grype_counts):
    """Generates a grouped bar chart comparing Trivy and Grype findings."""
    x = np.arange(len(labels))
    width = 0.35

    fig, ax = plt.subplots(figsize=(12, 7))
    rects1 = ax.bar(x - width/2, trivy_counts, width, label='Trivy', color='#1f77b4') # Blue
    rects2 = ax.bar(x + width/2, grype_counts, width, label='Grype', color='#ff7f0e') # Orange

    ax.set_ylabel('Total Vulnerability Count (Log Scale)')
    ax.set_title('Comparative Scanner Analysis: Trivy vs. Grype', fontsize=16, fontweight='bold', pad=20)
    ax.set_xticks(x)
    ax.set_xticklabels(labels, rotation=8, ha='right')
    ax.legend()
    ax.set_yscale('log')

    ax.bar_label(rects1, padding=3, fontsize=9)
    ax.bar_label(rects2, padding=3, fontsize=9)

    fig.tight_layout(pad=2.0)
    plt.savefig('chart_5_scanner_comparison.png', dpi=300)
    plt.close()
    print("\nChart 'chart_5_scanner_comparison.png' has been saved.")

if __name__ == '__main__':
    trivy_totals = [parse_trivy_json(f) for f in TRIVY_FILES]
    grype_totals = [parse_grype_json(f) for f in GRYPE_FILES]

    # --- Print the results table in a professional markdown format ---
    print("\n--- Comparative Scanner Analysis Results ---")
    print(f"| {'Docker Image':<25} | {'Vulnerabilities (Trivy)':<25} | {'Vulnerabilities (Grype)':<25} |")
    print(f"|{'-'*27}|{'-'*27}|{'-'*27}|")
    for i in range(len(IMAGE_NAMES)):
        print(f"| {IMAGE_NAMES[i]:<25} | {trivy_totals[i]:<25,} | {grype_totals[i]:<25,} |")
    print("--- End of Table ---")

    create_scanner_comparison_chart(IMAGE_NAMES, trivy_totals, grype_totals)