import os
import subprocess
import hashlib
import requests
import json
from datetime import datetime

# Constants
VIRUSTOTAL_API_KEY = "c66032da1d11cd42735ce5f5e32267160621929ae7563b624a5438573666ca26"

# Step 1: Collect Windows Event Logs
def collect_logs(log_name="System", output_file="system_logs.evtx"):
    try:
        subprocess.run(
            ["wevtutil", "epl", log_name, output_file],
            check=True
        )
        print(f"Logs collected: {output_file}")
    except Exception as e:
        print(f"Error collecting logs: {e}")

# Step 2: Hash Files and Check with VirusTotal
def hash_file(file_path):
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except Exception as e:
        print(f"Error hashing file {file_path}: {e}")
        return None

def check_virustotal(file_hash):
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            return response.json()
        else:
            print(f"Error checking VirusTotal: {response.status_code}")
            return None
    except Exception as e:
        print(f"Error contacting VirusTotal: {e}")
        return None

# Step 3: Threat Hunting - Monitor Processes
def monitor_processes():
    try:
        result = subprocess.run(["tasklist"], capture_output=True, text=True)
        processes = result.stdout
        print("Active Processes:\n", processes)
    except Exception as e:
        print(f"Error monitoring processes: {e}")

# Step 4: Generate Report
def generate_report(data, output_file="incident_report.json"):
    try:
        with open(output_file, "w") as f:
            json.dump(data, f, indent=4)
        print(f"Report generated: {output_file}")
    except Exception as e:
        print(f"Error generating report: {e}")

# Main Function
if __name__ == "__main__":
    # Collect logs
    collect_logs()

    # Example: Analyze a suspicious file
    suspicious_file = "image.log"
    file_hash = hash_file(suspicious_file)
    if file_hash:
        vt_result = check_virustotal(file_hash)
        print(json.dumps(vt_result, indent=4))

    # Monitor processes
    monitor_processes()

    # Generate a sample report
    report_data = {
        "timestamp": datetime.now().isoformat(),
        "logs": "system_logs.evtx",
        "suspicious_files": [file_hash],
        "processes": "tasklist output"
    }
    generate_report(report_data)
