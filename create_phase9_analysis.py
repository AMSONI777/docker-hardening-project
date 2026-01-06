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

def generate_sbom_and_count_components(image_tag):
    """Runs 'syft' to generate an SBOM and counts the total number of components."""
    print(f"  - Generating SBOM for '{image_tag}'... (this may take a minute)")
    
    # Define the output filename for the SBOM
    sbom_filename = f"sbom-{image_tag}.json"
    
    # Command to generate the SBOM in JSON format
    command = ['syft', image_tag, '-o', 'json', '--file', sbom_filename]
    
    try:
        # Run the command
        subprocess.run(command, check=True, capture_output=True, text=True)
        
        # Now, open the generated file and count the components
        with open(sbom_filename, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        count = len(data.get('artifacts', []))
        print(f"  - Found {count} total components in '{image_tag}'.")
        return count
        
    except (subprocess.CalledProcessError, FileNotFoundError, json.JSONDecodeError) as e:
        print(f"  - ERROR: Could not generate or parse SBOM for '{image_tag}'.")
        print(f"    Reason: {e}")
        return 0

def create_sbom_chart(component_counts):
    """Generates a professional bar chart for SBOM component comparison."""
    labels = list(component_counts.keys())
    counts = list(component_counts.values())

    plt.figure(figsize=(10, 7))
    bars = plt.bar(labels, counts, color=COLORS)

    plt.title('Software Supply Chain Complexity (SBOM Component Count)', fontsize=16, fontweight='bold', pad=20)
    plt.ylabel('Number of Software Components', fontsize=12)
    plt.xticks(rotation=8, ha='right')
    plt.yscale('log') # Use a log scale to see the vast differences

    for bar in bars:
        yval = bar.get_height()
        label = f'{yval:,.0f}'
        plt.text(bar.get_x() + bar.get_width()/2.0, yval, label, ha='center', va='bottom', fontsize=10, fontweight='bold')

    plt.tight_layout(pad=2.0)
    plt.savefig('chart_11_sbom_complexity.png', dpi=300)
    plt.close()
    print("\nChart 'chart_11_sbom_complexity.png' has been saved.")


if __name__ == '__main__':
    component_count_data = {}
    
    print("--- Starting Phase 9b: Image Provenance and SBOM Generation ---")
    
    for name, tag in IMAGES.items():
        count = generate_sbom_and_count_components(tag)
        component_count_data[name] = count
    
    if component_count_data:
        print("\nAll SBOMs generated and analyzed. Generating chart...")
        create_sbom_chart(component_count_data)
        print("Chart generation complete.")
    else:
        print("\nCould not collect SBOM data. Chart generation skipped.")