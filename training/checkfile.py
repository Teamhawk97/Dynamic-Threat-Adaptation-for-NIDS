import pandas as pd
import os

# Put all 18 file paths into a single list
dataset_files = [
    "../dataset/portscan.csv",
    "../dataset/botnet_ares.csv",
    "../dataset/ddos_loit.csv",
    "../dataset/dos_golden_eye.csv",
    "../dataset/dos_hulk.csv",
    "../dataset/heartbleed.csv",
    "../dataset/web_sql_injection.csv",
    "../dataset/monday_benign.csv",
    "../dataset/tuesday_benign.csv",
    "../dataset/wednesday_benign.csv",
    "../dataset/thursday_benign.csv",
    "../dataset/friday_benign.csv",
    "../dataset/web_xss.csv",
    "../dataset/dos_slowhttptest.csv",
    "../dataset/dos_slowloris.csv",
    "../dataset/ftp_patator.csv",
    "../dataset/ssh_patator-new.csv",
    "../dataset/web_brute_force.csv"
]

print("Scanning dataset headers...\n")

for file_path in dataset_files:
    try:
        # nrows=0 loads ONLY the column headers, preventing memory crashes
        df = pd.read_csv(file_path, nrows=0)
        
        # Extract just the file name (e.g., "PORTSCAN.CSV") for a cleaner printout
        file_name = os.path.basename(file_path).upper()
        
        print(f"=== {file_name} ===")
        print(df.columns.tolist())
        print("-" * 50)
        
    except FileNotFoundError:
        print(f"[!] Error: Could not find {file_path}")
        print("-" * 50)