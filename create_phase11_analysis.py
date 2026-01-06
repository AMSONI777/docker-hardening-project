import subprocess
import json
import matplotlib.pyplot as plt

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

def analyze_with_trivy_misconfig(image_tag):
    """Runs Trivy's 'misconfig' scanner and counts the number of FAIL findings."""
    print(f"  - Analyzing '{image_tag}' with Trivy for misconfigurations...")
    
    command = [
        'trivy', 'image', 
        '--scanners', 'misconfig', 
        '--format', 'json', 
        image_tag
    ]
    
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=True, encoding='utf-8')
        data = json.loads(result.stdout)
        
        issue_count = 0
        if 'Results' in data and data['Results']:
            for res in data['Results']:
                if 'Misconfigurations' in res and res['Misconfigurations']:
                    # We only count definite failures
                    for misconfig in res['Misconfigurations']:
                        if misconfig.get('Status') == 'FAIL':
                            issue_count += 1
        
        print(f"  - Found {issue_count} high-severity misconfigurations in '{image_tag}'.")
        return issue_count
        
    except (subprocess.CalledProcessError, FileNotFoundError, json.JSONDecodeError) as e:
        print(f"  - ERROR: Could not run or parse Trivy misconfig scan for '{image_tag}'.")
        print(f"    Reason: {e}")
        return -1

def create_misconfig_chart(issue_counts):
    """Generates a professional bar chart for misconfiguration compliance."""
    # Filter out any images that failed to scan
    filtered_counts = {name: count for name, count in issue_counts.items() if count != -1}
    
    labels = list(filtered_counts.keys())
    counts = list(filtered_counts.values())

    plt.figure(figsize=(10, 7))
    bars = plt.bar(labels, counts, color=COLORS)

    plt.title('Dockerfile Best Practice & CIS Compliance Score', fontsize=16, fontweight='bold', pad=20)
    plt.ylabel('Number of High-Severity Misconfigurations (FAILs)', fontsize=12)
    plt.xticks(rotation=8, ha='right')
    
    # Set y-axis to be integers
    ax = plt.gca()
    ax.yaxis.get_major_locator().set_params(integer=True)
    plt.ylim(bottom=0)


    for bar in bars:
        yval = bar.get_height()
        label = f'{yval:,.0f}'
        plt.text(bar.get_x() + bar.get_width()/2.0, yval, label, ha='center', va='bottom', fontsize=10, fontweight='bold')

    plt.tight_layout(pad=2.0)
    plt.savefig('chart_13_misconfig_compliance.png', dpi=300)
    plt.close()
    print("\nChart 'chart_13_misconfig_compliance.png' has been saved.")


if __name__ == '__main__':
    issue_count_data = {}
    
    print("--- Starting Final Phase 11: Misconfiguration Compliance Analysis (using Trivy) ---")
    
    for name, tag in IMAGES.items():
        count = analyze_with_trivy_misconfig(tag)
        issue_count_data[name] = count
    
    if issue_count_data:
        print("\nAll compliance scans complete. Generating chart...")
        create_misconfig_chart(issue_count_data)
        print("Chart generation complete.")
    else:
        print("\nCould not collect compliance data. Chart generation skipped.")