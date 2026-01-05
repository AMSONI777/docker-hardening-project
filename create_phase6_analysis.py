import subprocess
import re
import os
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

def get_history_and_count_layers(image_tag):
    """Runs 'docker history', saves it to a file, and counts the layers."""
    filename = f"history-{image_tag}.txt"
    try:
        result = subprocess.run(['docker', 'history', image_tag], capture_output=True, text=True, check=True, encoding='utf-8')
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(result.stdout)
        
        # Count lines, subtracting 1 for the header
        num_layers = len(result.stdout.strip().split('\n')) - 1
        return num_layers
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        print(f"Error getting history for {image_tag}: {e}")
        return 0

def analyze_with_dive(image_tag):
    """Runs 'dive' and parses the output for wasted space in Kilobytes (KB)."""
    try:
        env = os.environ.copy()
        env['CI'] = 'true'
        command = ['dive', image_tag]
        result = subprocess.run(command, capture_output=True, text=True, check=True, env=env, encoding='utf-8')
        output = result.stdout
    except subprocess.CalledProcessError as e:
        output = e.stdout # Still parse output even if a check 'fails'

    wasted_kb = 0
    try:
        # Search for wasted bytes in different units (B, kB, MB, GB)
        wasted_bytes_match = re.search(r"wastedBytes:\s*\d+\s*bytes\s*\(([\d.]+)\s*([GgMmKk]?B)\)", output)
        if wasted_bytes_match:
            value = float(wasted_bytes_match.group(1))
            unit = wasted_bytes_match.group(2).upper()
            if unit == 'GB':
                wasted_kb = value * 1024 * 1024
            elif unit == 'MB':
                wasted_kb = value * 1024
            elif unit == 'KB':
                wasted_kb = value
            elif unit == 'B':
                wasted_kb = value / 1024
        return wasted_kb
    except Exception as e:
        print(f"Error parsing dive output for {image_tag}: {e}")
        return 0

def create_bar_chart(title, ylabel, labels, data, filename, is_log=False):
    """Generic function to create and save a professional bar chart."""
    plt.figure(figsize=(10, 7))
    bars = plt.bar(labels, data, color=COLORS)
    
    plt.title(title, fontsize=16, fontweight='bold', pad=20)
    plt.ylabel(ylabel, fontsize=12)
    plt.xticks(rotation=8, ha='right')
    
    if is_log:
        plt.yscale('log')
        plt.minorticks_off()

    for bar in bars:
        height = bar.get_height()
        label = f'{height:,.1f}' if height < 1 else f'{height:,.0f}'
        plt.text(bar.get_x() + bar.get_width() / 2.0, height, label, 
                 ha='center', va='bottom', fontsize=10, fontweight='bold')
    
    plt.tight_layout(pad=2.0)
    plt.savefig(filename, dpi=300)
    plt.close()
    print(f"Chart '{filename}' has been saved.")

if __name__ == '__main__':
    layer_counts = {}
    wasted_space_kb_counts = {}
    
    print("--- Starting Phase 6: Architectural and Performance Analysis ---")
    
    for name, tag in IMAGES.items():
        print(f"\nAnalyzing image: {tag}...")
        layer_counts[name] = get_history_and_count_layers(tag)
        wasted_space_kb_counts[name] = analyze_with_dive(tag)
        print(f"  - Found {layer_counts[name]} layers and {wasted_space_kb_counts[name]:,.2f} KB of wasted space.")
        
    # --- Generate Charts ---
    print("\nGenerating Phase 6 charts...")
    
    # Chart 1: Layer Count
    create_bar_chart('Image Layer Count Comparison', 'Number of Layers', 
                     list(layer_counts.keys()), list(layer_counts.values()), 
                     'chart_7_layer_count.png')

    # Chart 2: Wasted Space
    create_bar_chart('Filesystem Wasted Space Comparison', 'Wasted Space (in KB, Log Scale)', 
                     list(wasted_space_kb_counts.keys()), list(wasted_space_kb_counts.values()), 
                     'chart_8_wasted_space.png', is_log=True)

    print("\nPhase 6 analysis complete.")