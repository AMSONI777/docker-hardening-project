import json
import matplotlib.pyplot as plt
import numpy as np
from collections import Counter
import sys

# --- Configuration ---
# Image sizes is provided here because they are not in the Trivy report. It needs to be hardcoded.
BASELINE_IMAGE_SIZE_MB = 1970
HARDENED_IMAGE_SIZE_MB = 555

# Filenames of the Trivy JSON reports
BASELINE_JSON_FILE = 'trivy-scan-results.json'
HARDENED_JSON_FILE = 'trivy-scan-results-hardened.json'


def parse_trivy_json(filename):
    """Reads a Trivy JSON report and returns a dictionary of severity counts."""
    severity_counts = Counter()
    try:
        with open(filename, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        if 'Results' in data and isinstance(data['Results'], list):
            for result in data['Results']:
                if 'Vulnerabilities' in result and result['Vulnerabilities'] is not None:
                    for vuln in result['Vulnerabilities']:
                        severity = vuln.get('Severity', 'UNKNOWN')
                        severity_counts[severity] += 1
        return severity_counts
    except FileNotFoundError:
        print(f"Error: The file '{filename}' was not found. Please generate the report first.")
        sys.exit(1)
    except json.JSONDecodeError:
        print(f"Error: Could not decode the JSON from '{filename}'. It may be corrupted.")
        sys.exit(1)


def create_image_size_chart(baseline_size, hardened_size):
    """Generates and saves a bar chart for image size comparison."""
    labels = ['Baseline (insecure-app)', 'Hardened (hardened-app)']
    sizes = [baseline_size, hardened_size]
    colors = ['#d9534f', '#5cb85c']

    plt.figure(figsize=(8, 6))
    bars = plt.bar(labels, sizes, color=colors)
    plt.ylabel('Image Size (MB)')
    plt.title('Docker Image Size Comparison', fontsize=16, fontweight='bold')
    plt.grid(axis='y', linestyle='--', alpha=0.7)

    for bar in bars:
        yval = bar.get_height()
        plt.text(bar.get_x() + bar.get_width()/2.0, yval + 15, f'{yval} MB', ha='center', va='bottom')

    plt.tight_layout()
    plt.savefig('image_size_comparison.png')
    plt.close()
    print("Chart 'image_size_comparison.png' has been saved.")


def create_vulnerability_charts(baseline_vulns, hardened_vulns):
    """Generates charts for total and per-severity vulnerability comparisons."""
    baseline_total = sum(baseline_vulns.values())
    hardened_total = sum(hardened_vulns.values())
    
    # --- Chart 2: Total Vulnerability Comparison ---
    labels = ['Baseline (insecure-app)', 'Hardened (hardened-app)']
    totals = [baseline_total, hardened_total]
    colors = ['#d9534f', '#5cb85c']

    plt.figure(figsize=(8, 6))
    bars = plt.bar(labels, totals, color=colors)
    plt.ylabel('Total Vulnerability Count')
    plt.title('Total Vulnerability Comparison', fontsize=16, fontweight='bold')
    plt.grid(axis='y', linestyle='--', alpha=0.7)

    for bar in bars:
        yval = bar.get_height()
        plt.text(bar.get_x() + bar.get_width()/2.0, yval + 10, int(yval), ha='center', va='bottom')

    plt.tight_layout()
    plt.savefig('total_vulnerabilities_comparison.png')
    plt.close()
    print("Chart 'total_vulnerabilities_comparison.png' has been saved.")

    # --- Chart 3: Detailed Vulnerability by Severity ---
    severities = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] # Order for the chart
    baseline_counts = [baseline_vulns.get(s, 0) for s in severities]
    hardened_counts = [hardened_vulns.get(s, 0) for s in severities]

    x = np.arange(len(severities))
    width = 0.35

    fig, ax = plt.subplots(figsize=(10, 6))
    rects1 = ax.bar(x - width/2, baseline_counts, width, label='Baseline', color='#d9534f')
    rects2 = ax.bar(x + width/2, hardened_counts, width, label='Hardened', color='#5cb85c')

    ax.set_ylabel('Vulnerability Count')
    ax.set_title('Vulnerability Breakdown by Severity', fontsize=16, fontweight='bold')
    ax.set_xticks(x)
    ax.set_xticklabels(severities)
    ax.legend()
    ax.grid(axis='y', linestyle='--', alpha=0.7)

    ax.bar_label(rects1, padding=3)
    ax.bar_label(rects2, padding=3)

    fig.tight_layout()
    plt.savefig('vulnerability_severity_comparison.png')
    plt.close()
    print("Chart 'vulnerability_severity_comparison.png' has been saved.")


if __name__ == '__main__':
    print("Parsing vulnerability reports...")
    baseline_vulnerability_data = parse_trivy_json(BASELINE_JSON_FILE)
    hardened_vulnerability_data = parse_trivy_json(HARDENED_JSON_FILE)
    
    print("\nGenerating result charts...")
    create_image_size_chart(BASELINE_IMAGE_SIZE_MB, HARDENED_IMAGE_SIZE_MB)
    create_vulnerability_charts(baseline_vulnerability_data, hardened_vulnerability_data)
    
    print("\nAll charts have been generated successfully.")