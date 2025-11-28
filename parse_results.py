import json
from collections import Counter
import sys

# This script will read a filename provided from the command line.

# Checking if a filename was provided as an argument
if len(sys.argv) < 2:
    print("Error: Please provide the JSON filename as an argument.")
    print("Usage: python parse_results.py <filename>")
    sys.exit(1)

# The name of the Trivy JSON report file is the first argument
filename = sys.argv[1]

# A counter to hold the counts of severities
severity_counts = Counter()
total_vulnerabilities = 0

try:
    # Opening and loading the JSON file
    with open(filename, 'r', encoding='utf-8') as f:
        data = json.load(f)

    # The report might be a single object or a list of objects
    report_data = data if isinstance(data, list) else [data]

    for report in report_data:
        # Checking if 'Results' key exists and is a list
        if 'Results' in report and isinstance(report['Results'], list):
            # Iterating through each result section (e.g., OS packages, Python packages)
            for result in report['Results']:
                # Checking if 'Vulnerabilities' key exists in the result
                if 'Vulnerabilities' in result and result['Vulnerabilities'] is not None:
                    # Adding the number of vulnerabilities in this section to our total
                    total_vulnerabilities += len(result['Vulnerabilities'])
                    # Iterating through each vulnerability found
                    for vuln in result['Vulnerabilities']:
                        # Getting the severity and incrementing our counter for that severity
                        severity = vuln.get('Severity', 'UNKNOWN')
                        severity_counts[severity] += 1

    # --- Printing the results in a clean table ---
    print(f"\n--- Vulnerability Scan Summary for: {filename} ---")
    
    # Printing the counts for each severity in a specific order
    for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]:
        count = severity_counts.get(severity, 0)
        print(f"{severity:<10}: {count}")
    
    print("-------------------------------------------------")
    print(f"{'TOTAL':<10}: {total_vulnerabilities}")
    print("--- End of Summary ---\n")

except FileNotFoundError:
    print(f"Error: The file '{filename}' was not found.")
except json.JSONDecodeError:
    print(f"Error: Could not decode the JSON from '{filename}'. It might be empty or corrupted.")
except Exception as e:
    print(f"An unexpected error occurred: {e}")