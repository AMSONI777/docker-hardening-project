import subprocess
import json
import time
import matplotlib.pyplot as plt
import os
import sys

# --- Configuration ---
IMAGES = {
    'Baseline (Debian)': {'tag': 'insecure-app', 'file': 'Dockerfile.insecure'},
    'Hardened (Debian Slim)': {'tag': 'hardened-app', 'file': 'Dockerfile.secure'},
    'Hardened (Alpine)': {'tag': 'alpine-app', 'file': 'Dockerfile.alpine'},
    'Hardened (Distroless)': {'tag': 'distroless-app', 'file': 'Dockerfile.distroless'}
}
RESULTS_FILE = 'build-times.json'

# --- Chart Styling ---
plt.style.use('seaborn-v0_8-whitegrid')
COLORS = ['#d9534f', '#5cb85c', '#f0ad4e', '#5bc0de']

def measure_build_time(tag, dockerfile):
    """Measures the 'cold build' time with robust output handling."""
    print(f"  - Measuring build time for '{tag}'... (this will take several minutes)")
    command = f'docker build --no-cache -t {tag} -f {dockerfile} .'
    
    start_time = time.time()
    try:
        # Redirect output to DEVNULL to avoid terminal encoding errors
        subprocess.run(command, shell=True, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        end_time = time.time()
        duration = end_time - start_time
        print(f"  - Build for '{tag}' completed in {duration:.2f} seconds.")
        return duration
    except subprocess.CalledProcessError as e:
        print(f"  - ERROR: Build failed for '{tag}'.")
        return None

def create_build_time_chart(build_times):
    """Generates a professional bar chart from the build time data."""
    labels = list(build_times.keys())
    times = list(build_times.values())

    plt.figure(figsize=(10, 7))
    bars = plt.bar(labels, times, color=COLORS)

    plt.title('Build Execution Time Comparison (with cached base images)', fontsize=16, fontweight='bold', pad=20)
    plt.ylabel('Build Time (Seconds)', fontsize=12)
    plt.xticks(rotation=8, ha='right')

    for bar in bars:
        yval = bar.get_height()
        label = f'{yval:.1f} s'
        plt.text(bar.get_x() + bar.get_width()/2.0, yval, label, ha='center', va='bottom', fontsize=10, fontweight='bold')

    plt.tight_layout(pad=2.0)
    plt.savefig('chart_9_build_time.png', dpi=300)
    plt.close()
    print("\nChart 'chart_9_build_time.png' has been saved.")

if __name__ == '__main__':
    # Check if the user wants to force a new measurement
    if '--measure' in sys.argv:
        print("--- Starting new build time analysis (this will take 10-15 minutes) ---")
        build_times_data = {}
        for name, details in IMAGES.items():
            duration = measure_build_time(details['tag'], details['file'])
            if duration is not None:
                build_times_data[name] = duration
        
        with open(RESULTS_FILE, 'w') as f:
            json.dump(build_times_data, f, indent=2)
        print(f"\nBuild time results have been saved to '{RESULTS_FILE}'.")
    
    # Generate the chart from existing data
    elif os.path.exists(RESULTS_FILE):
        print(f"Found existing results file ('{RESULTS_FILE}'). Loading data to generate chart...")
        with open(RESULTS_FILE, 'r') as f:
            build_times_data = json.load(f)
    else:
        print(f"Error: No results file found. Please run the script with the '--measure' flag first.")
        print("Example: python create_phase7_analysis.py --measure")
        build_times_data = None

    if build_times_data:
        create_build_time_chart(build_times_data)
        print("Chart generation complete.")
    else:
        print("\nChart generation skipped due to missing data.")