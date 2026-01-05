import json
import matplotlib.pyplot as plt
import numpy as np
from collections import Counter
import sys

# --- Configuration ---
# Update these values with the final sizes from your 'docker images' command.
IMAGE_SIZES_MB = {
    'Baseline (Debian)': 1650,  # 1.65GB
    'Hardened (Debian Slim)': 233,
    'Hardened (Alpine)': 125,
    'Hardened (Distroless)': 130
}

# Filenames of the Trivy JSON reports
JSON_FILES = {
    'Baseline (Debian)': 'insecure-app-results.json',
    'Hardened (Debian Slim)': 'hardened-app-results.json',
    'Hardened (Alpine)': 'alpine-app-results.json',
    'Hardened (Distroless)': 'distroless-app-results.json'
}

# --- Chart Styling ---
COLORS = ['#d9534f', '#5cb85c', '#f0ad4e', '#5bc0de'] # Red, Green, Yellow, Blue
plt.style.use('seaborn-v0_8-whitegrid') # Professional plot style

def parse_trivy_json(filename):
    """Reads a Trivy JSON report and returns vuln counts and package count."""
    severity_counts = Counter()
    package_count = 0
    try:
        with open(filename, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        if 'Results' in data and isinstance(data['Results'], list):
            for result in data['Results']:
                # Count OS packages
                if result.get('Type') in ['debian', 'alpine']:
                    package_count += len(result.get('Packages', []))
                
                # Count vulnerabilities
                if 'Vulnerabilities' in result and result['Vulnerabilities'] is not None:
                    for vuln in result['Vulnerabilities']:
                        severity = vuln.get('Severity', 'UNKNOWN')
                        severity_counts[severity] += 1
        return severity_counts, package_count
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"Error processing {filename}: {e}")
        return Counter(), 0

def create_chart(title, ylabel, labels, data, filename, is_log=False):
    """Generic function to create and save a professional bar chart."""
    plt.figure(figsize=(10, 7))
    bars = plt.bar(labels, data, color=COLORS)
    
    plt.title(title, fontsize=16, fontweight='bold', pad=20)
    plt.ylabel(ylabel, fontsize=12)
    plt.xticks(rotation=8, ha='right')
    
    if is_log:
        plt.yscale('log')
        plt.minorticks_off() # clean up log scale ticks

    # Add data labels
    for bar in bars:
        height = bar.get_height()
        plt.text(bar.get_x() + bar.get_width() / 2.0, height, f'{height:,.0f}', 
                 ha='center', va='bottom', fontsize=10, fontweight='bold')
    
    plt.tight_layout(pad=2.0)
    plt.savefig(filename, dpi=300) # Save in high resolution
    plt.close()
    print(f"Chart '{filename}' has been saved.")

def create_grouped_chart(title, labels, data_dict, filename):
    """Creates a professional grouped bar chart for severity breakdown."""
    severities = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
    x = np.arange(len(labels))
    width = 0.2
    
    fig, ax = plt.subplots(figsize=(12, 7))
    
    for i, severity in enumerate(severities):
        counts = [data.get(severity, 0) for data in data_dict.values()]
        offset = width * (i - 1.5)
        rects = ax.bar(x + offset, counts, width, label=severity)
        ax.bar_label(rects, padding=3, fontsize=8)
        
    ax.set_ylabel('Vulnerability Count')
    ax.set_title(title, fontsize=16, fontweight='bold', pad=20)
    ax.set_xticks(x)
    ax.set_xticklabels(labels, rotation=8, ha='right')
    ax.legend(title="Severity")
    ax.set_yscale('log') # Log scale is best for showing large differences
    
    fig.tight_layout(pad=2.0)
    plt.savefig(filename, dpi=300)
    plt.close()
    print(f"Chart '{filename}' has been saved.")

if __name__ == '__main__':
    all_vuln_data = {}
    all_pkg_data = {}

    print("Parsing vulnerability reports...")
    for name, filename in JSON_FILES.items():
        vuln_counts, pkg_count = parse_trivy_json(filename)
        all_vuln_data[name] = vuln_counts
        all_pkg_data[name] = pkg_count
        print(f"  - {name}: {sum(vuln_counts.values())} CVEs, {pkg_count} OS packages")

    # --- Generate Charts ---
    print("\nGenerating result charts...")
    
    # Chart 1: Image Size
    create_chart('Image Size Comparison', 'Image Size (MB)', 
                 list(IMAGE_SIZES_MB.keys()), list(IMAGE_SIZES_MB.values()), 
                 'chart_1_image_size.png')

    # Chart 2: OS Package Count
    create_chart('OS Package Count Comparison', 'Number of OS Packages', 
                 list(all_pkg_data.keys()), list(all_pkg_data.values()), 
                 'chart_2_os_packages.png', is_log=True)

    # Chart 3: Total Vulnerabilities
    total_vulns = {name: sum(counts.values()) for name, counts in all_vuln_data.items()}
    create_chart('Total Vulnerability Comparison', 'Total Vulnerability Count (Log Scale)', 
                 list(total_vulns.keys()), list(total_vulns.values()), 
                 'chart_3_total_vulnerabilities.png', is_log=True)

    # Chart 4: Severity Breakdown
    create_grouped_chart('Vulnerability Breakdown by Severity', 
                         list(all_vuln_data.keys()), all_vuln_data, 
                         'chart_4_severity_breakdown.png')
    
    print("\nAll Phase 2 charts have been generated successfully.")