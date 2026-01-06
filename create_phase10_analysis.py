import subprocess
import time
import matplotlib.pyplot as plt
import numpy as np

# --- Configuration ---
IMAGES = {
    'Baseline (Debian)': 'insecure-app',
    'Hardened (Debian Slim)': 'hardened-app',
    'Hardened (Alpine)': 'alpine-app',
    'Hardened (Distroless)': 'distroless-app'
}
NETWORK_UTILITIES = ['curl', 'wget', 'netcat', 'nc', 'ping']

def analyze_container_network(container_name):
    """Inspects a running container and returns a dictionary of network attributes."""
    analysis = {'status': 'Running', 'listening_ports': 'N/A', 'network_utilities': 'N/A'}

    try:
        # 1. Analyze Listening Ports
        # For this specific app, we know it listens on one port if it's running.
        analysis['listening_ports'] = 1
        
        # 2. Analyze installed network utilities
        found_utils = []
        for util in NETWORK_UTILITIES:
            try:
                cmd_which = ['docker', 'exec', container_name, 'which', util]
                subprocess.run(cmd_which, check=True, capture_output=True)
                found_utils.append(util)
            except subprocess.CalledProcessError:
                pass
        analysis['network_utilities'] = len(found_utils)
        
    except Exception:
         analysis['status'] = 'Error'
    
    return analysis

def create_table_graphic(results):
    """Generates a professional, infographic-style table graphic."""
    labels = list(results.keys())
    metrics = ['Operational Status', 'Network Utilities Present']
    
    # Prepare the data for the table
    cell_text = []
    cell_colors = []
    for name in labels:
        res = results[name]
        status = res['status']
        utils_count = res.get('network_utilities', 0)
        
        row_text = []
        row_colors = []
        
        # Column 1: Operational Status
        if status == 'Running':
            row_text.append(f"✓ Running")
            row_colors.append('#eafaf1') # Light Green
        else:
            row_text.append(f"✗ Failed to Run")
            row_colors.append('#fbeee6') # Light Red
            
        # Column 2: Network Utilities
        if status == 'Running':
            row_text.append(f"{utils_count}")
            row_colors.append('#eafaf1' if utils_count == 0 else '#fbeee6')
        else:
            row_text.append("N/A")
            row_colors.append('#f5f5f5') # Grey
            
        cell_text.append(row_text)
        cell_colors.append(row_colors)

    fig, ax = plt.subplots(figsize=(10, 4))
    ax.axis('off')

    table = ax.table(cellText=cell_text,
                     cellColours=cell_colors,
                     rowLabels=labels,
                     colLabels=metrics,
                     loc='center',
                     cellLoc='center')
    
    table.auto_set_font_size(False)
    table.set_fontsize(12)
    table.scale(1, 2.5)

    # Style the table
    for (i, j), cell in table.get_celld().items():
        cell.set_edgecolor('white')
        cell.set_linewidth(3)
        if i == 0 or j == -1: # Header row or column
            cell.set_text_props(weight='bold', color='black')
    
    ax.set_title('Network Footprint and Operational Viability', fontsize=16, fontweight='bold', pad=20)
    plt.tight_layout()
    
    plt.savefig('chart_12_network_viability_table.png', dpi=300)
    plt.close()
    print("\nTable graphic 'chart_12_network_viability_table.png' has been saved.")


if __name__ == '__main__':
    results_data = {}
    
    print("--- Starting Final Phase: Network & Viability Analysis ---")

    for name, tag in IMAGES.items():
        container_name = f"{tag}-net-test"
        print(f"\nStarting and analyzing container for '{name}'...")
        try:
            subprocess.run(['docker', 'rm', '-f', container_name], capture_output=True)
            run_result = subprocess.run(['docker', 'run', '-d', '--name', container_name, tag], check=True, capture_output=True)
            time.sleep(3)
            
            # Check if container is actually running
            ps_result = subprocess.run(['docker', 'ps', '-f', f"name={container_name}"], capture_output=True, text=True)
            if container_name in ps_result.stdout:
                analysis_result = analyze_container_network(container_name)
                results_data[name] = analysis_result
            else:
                 raise subprocess.CalledProcessError(1, "Container failed to stay running.")

        except subprocess.CalledProcessError:
            print(f"  - ERROR: Container for '{name}' failed to run. Marking as 'Failed'.")
            results_data[name] = {'status': 'Failed to Run'}
    
    print("\n--- Cleaning up containers ---")
    all_container_names = [f"{tag}-net-test" for tag in IMAGES.values()]
    subprocess.run(['docker', 'stop'] + all_container_names, capture_output=True)
    subprocess.run(['docker', 'rm'] + all_container_names, capture_output=True)

    if results_data:
        create_table_graphic(results_data)
        print("Analysis and graphic generation complete.")
    else:
        print("\nCould not collect data. Graphic generation skipped.")