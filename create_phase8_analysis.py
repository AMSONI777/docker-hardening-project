import subprocess
import json
import matplotlib.pyplot as plt
import os

# --- Configuration ---
IMAGES = {
    'Baseline (Debian)': 'insecure-app',
    'Hardened (Debian Slim)': 'hardened-app',
    'Hardened (Alpine)': 'alpine-app',
    'Hardened (Distroless)': 'distroless-app'
}

# --- Chart Styling ---
plt.style.use('seaborn-v0_8-whitegrid')
COLORS = ['#d9534f', '#5cb85c', '#f0ad4e', '#5bc0de']

def scan_and_count_licenses(image_tag):
    """Runs Trivy's license scanner and counts the number of unique licenses found."""
    print(f"  - Scanning '{image_tag}' for software licenses... (this may take a minute)")
    command = ['trivy', 'image', '--scanners', 'license', '--format', 'json', image_tag]
    
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=True, encoding='utf-8')
        data = json.loads(result.stdout)
        
        found_licenses = set()
        if 'Results' in data and data['Results']:
            for res in data['Results']:
                if 'Licenses' in res and res['Licenses']:
                    for lic in res['Licenses']:
                        found_licenses.add(lic.get('Name'))
        
        count = len(found_licenses)
        print(f"  - Found {count} unique licenses in '{image_tag}'.")
        return count
        
    except (subprocess.CalledProcessError, FileNotFoundError, json.JSONDecodeError) as e:
        print(f"  - ERROR: Could not scan or parse licenses for '{image_tag}'.")
        print(f"    Reason: {e}")
        return 0

def create_license_chart(license_counts):
    """Generates a professional bar chart for license complexity comparison."""
    labels = list(license_counts.keys())
    counts = list(license_counts.values())

    plt.figure(figsize=(10, 7))
    bars = plt.bar(labels, counts, color=COLORS)

    plt.title('Software License Complexity Comparison', fontsize=16, fontweight='bold', pad=20)
    plt.ylabel('Number of Unique Software Licenses', fontsize=12)
    plt.xticks(rotation=8, ha='right')

    for bar in bars:
        yval = bar.get_height()
        label = f'{yval:,.0f}'
        plt.text(bar.get_x() + bar.get_width()/2.0, yval, label, ha='center', va='bottom', fontsize=10, fontweight='bold')

    plt.tight_layout(pad=2.0)
    plt.savefig('chart_10_license_complexity.png', dpi=300)
    plt.close()
    print("\nChart 'chart_10_license_complexity.png' has been saved.")


if __name__ == '__main__':
    license_count_data = {}
    
    print("--- Starting Phase 8: Software License and Compliance Analysis ---")
    
    for name, tag in IMAGES.items():
        count = scan_and_count_licenses(tag)
        license_count_data[name] = count
    
    if license_count_data:
        print("\nAll license scans complete. Generating chart...")
        create_license_chart(license_count_data)
        print("Chart generation complete.")
    else:
        print("\nCould not collect license data. Chart generation skipped.")