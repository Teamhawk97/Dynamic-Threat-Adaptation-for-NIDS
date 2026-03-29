import pandas as pd
import numpy as np
import random

def generate_highly_realistic_cicids(num_rows=20000):
    print(f"[+] Generating {num_rows} highly realistic network flows (80% Normal, 20% Attacks)...")
    
    data = []
    
    # Highly realistic network imbalance
    counts = {
        "NORMAL": int(num_rows * 0.80),           # 80% Normal (16,000 flows)
        "SYN_SCAN": int(num_rows * 0.03),         # 3%
        "DDOS": int(num_rows * 0.03),             # 3%
        "UDP_FLOOD": int(num_rows * 0.03),        # 3%
        "DOS_SLOWLORIS": int(num_rows * 0.02),    # 2%
        "DOS_SLOWHTTPTEST": int(num_rows * 0.02), # 2%
        "FTP_PATATOR": int(num_rows * 0.015),     # 1.5%
        "SSH_PATATOR": int(num_rows * 0.015),     # 1.5%
        "WEB_BRUTEFORCE": int(num_rows * 0.015),  # 1.5%
        "WEB_XSS": int(num_rows * 0.01),          # 1%
        "WEB_SQL_INJECTION": int(num_rows * 0.01),# 1%
        "HEARTBLEED": int(num_rows * 0.005)       # 0.5% (Extremely rare)
    }
    
    # 1. NORMAL TRAFFIC (Wide variance, simulates watching Netflix, browsing, etc.)
    for _ in range(counts["NORMAL"]):
        packets = int(max(5, np.random.normal(150, 80)))
        data.append({
            "packets_count": packets,
            "syn_flag_counts": max(0, int(packets * np.random.uniform(0.01, 0.05))),
            "rst_flag_counts": max(0, int(packets * np.random.uniform(0.0, 0.02))),
            "protocol": 6, "unique_ports_count": random.randint(1, 5),
            "packets_IAT_mean": max(10, np.random.normal(120, 60)),
            "payload_bytes_std": max(50, np.random.normal(350, 150)),
            "flow_duration": max(0.5, np.random.normal(5.0, 3.0)),
            "total_bytes": max(1000, int(packets * np.random.normal(600, 200))),
            "Label": "NORMAL"
        })

    # 2. VOLUMETRIC ATTACKS (Very distinct from Normal)
    for _ in range(counts["SYN_SCAN"]):
        packets = int(max(10, np.random.normal(50, 10)))
        data.append({
            "packets_count": packets, "syn_flag_counts": int(packets * np.random.uniform(0.5, 0.8)), 
            "rst_flag_counts": int(packets * np.random.uniform(0.2, 0.4)), 
            "protocol": 6, "unique_ports_count": random.randint(50, 200),
            "packets_IAT_mean": max(0.1, np.random.normal(2.0, 1.0)),
            "payload_bytes_std": 0.0, "flow_duration": max(0.1, np.random.normal(0.5, 0.2)),
            "total_bytes": packets * 54, "Label": "SYN_SCAN"
        })

    for _ in range(counts["DDOS"]):
        packets = int(max(500, np.random.normal(1500, 300)))
        data.append({
            "packets_count": packets, "syn_flag_counts": int(packets * 0.05), "rst_flag_counts": int(packets * 0.02),
            "protocol": 6, "unique_ports_count": 1,
            "packets_IAT_mean": max(0.1, np.random.normal(0.5, 0.2)),
            "payload_bytes_std": max(500, np.random.normal(1200, 200)),
            "flow_duration": max(0.1, np.random.normal(1.0, 0.5)),
            "total_bytes": packets * 1000, "Label": "DDOS"
        })

    for _ in range(counts["UDP_FLOOD"]):
        packets = int(max(800, np.random.normal(2000, 400)))
        data.append({
            "packets_count": packets, "syn_flag_counts": 0, "rst_flag_counts": 0,
            "protocol": 17, "unique_ports_count": 1,
            "packets_IAT_mean": max(0.01, np.random.normal(0.2, 0.1)),
            "payload_bytes_std": max(1.0, np.random.normal(15, 5)),
            "flow_duration": max(0.1, np.random.normal(0.8, 0.2)),
            "total_bytes": packets * 40, "Label": "UDP_FLOOD"
        })

    # 3. SLOW ATTACKS (Distinct timing, low volume)
    for _ in range(counts["DOS_SLOWLORIS"]):
        packets = int(max(10, np.random.normal(30, 5)))
        data.append({
            "packets_count": packets, "syn_flag_counts": 1, "rst_flag_counts": 0,
            "protocol": 6, "unique_ports_count": 1,
            "packets_IAT_mean": max(2000, np.random.normal(8000, 1500)), 
            "payload_bytes_std": max(5, np.random.normal(20, 10)),
            "flow_duration": max(20.0, np.random.normal(60.0, 10.0)), 
            "total_bytes": packets * 100, "Label": "DOS_SLOWLORIS"
        })

    for _ in range(counts["DOS_SLOWHTTPTEST"]):
        packets = int(max(10, np.random.normal(35, 8)))
        data.append({
            "packets_count": packets, "syn_flag_counts": 1, "rst_flag_counts": 0,
            "protocol": 6, "unique_ports_count": 1,
            "packets_IAT_mean": max(1500, np.random.normal(6000, 1000)),
            "payload_bytes_std": max(10, np.random.normal(30, 15)),
            "flow_duration": max(15.0, np.random.normal(45.0, 8.0)),
            "total_bytes": packets * 120, "Label": "DOS_SLOWHTTPTEST"
        })

    # 4. STEALTH/WEB ATTACKS (Designed to statistically mimic NORMAL traffic)
    # Notice how these numbers overlap heavily with the Normal traffic generation above!
    for _ in range(counts["FTP_PATATOR"]):
        packets = int(max(20, np.random.normal(80, 20)))
        data.append({
            "packets_count": packets, "syn_flag_counts": 1, "rst_flag_counts": 1,
            "protocol": 6, "unique_ports_count": 1, 
            "packets_IAT_mean": max(20, np.random.normal(100, 30)), # Camouflaged IAT
            "payload_bytes_std": max(10, np.random.normal(50, 20)),
            "flow_duration": max(1.0, np.random.normal(4.0, 1.0)),
            "total_bytes": packets * 90, "Label": "FTP_PATATOR"
        })

    for _ in range(counts["SSH_PATATOR"]):
        packets = int(max(30, np.random.normal(90, 25)))
        data.append({
            "packets_count": packets, "syn_flag_counts": 1, "rst_flag_counts": 1,
            "protocol": 6, "unique_ports_count": 1, 
            "packets_IAT_mean": max(30, np.random.normal(110, 40)),
            "payload_bytes_std": max(20, np.random.normal(80, 25)), 
            "flow_duration": max(1.5, np.random.normal(5.0, 1.5)),
            "total_bytes": packets * 150, "Label": "SSH_PATATOR"
        })

    for _ in range(counts["WEB_BRUTEFORCE"]):
        packets = int(max(40, np.random.normal(100, 30)))
        data.append({
            "packets_count": packets, "syn_flag_counts": 2, "rst_flag_counts": 1,
            "protocol": 6, "unique_ports_count": 1,
            "packets_IAT_mean": max(40, np.random.normal(130, 40)), # Looks exactly like normal web browsing
            "payload_bytes_std": max(50, np.random.normal(250, 60)),
            "flow_duration": max(1.0, np.random.normal(6.0, 2.0)),
            "total_bytes": packets * 350, "Label": "WEB_BRUTEFORCE"
        })

    for _ in range(counts["WEB_XSS"]):
        packets = int(max(15, np.random.normal(50, 15)))
        data.append({
            "packets_count": packets, "syn_flag_counts": 1, "rst_flag_counts": 1,
            "protocol": 6, "unique_ports_count": 1,
            "packets_IAT_mean": max(30, np.random.normal(140, 30)),
            "payload_bytes_std": max(100, np.random.normal(300, 80)),
            "flow_duration": max(0.5, np.random.normal(3.0, 1.0)),
            "total_bytes": packets * 450, "Label": "WEB_XSS"
        })

    for _ in range(counts["WEB_SQL_INJECTION"]):
        packets = int(max(10, np.random.normal(35, 10)))
        data.append({
            "packets_count": packets, "syn_flag_counts": 1, "rst_flag_counts": 1,
            "protocol": 6, "unique_ports_count": 1,
            "packets_IAT_mean": max(40, np.random.normal(150, 40)),
            "payload_bytes_std": max(150, np.random.normal(400, 100)),
            "flow_duration": max(0.5, np.random.normal(2.5, 0.8)),
            "total_bytes": packets * 550, "Label": "WEB_SQL_INJECTION"
        })

    for _ in range(counts["HEARTBLEED"]):
        packets = int(max(5, np.random.normal(10, 3)))
        data.append({
            "packets_count": packets, "syn_flag_counts": 1, "rst_flag_counts": 1,
            "protocol": 6, "unique_ports_count": 1,
            "packets_IAT_mean": max(5, np.random.normal(20, 5)),
            "payload_bytes_std": max(2000, np.random.normal(6000, 1500)), 
            "flow_duration": max(0.1, np.random.normal(0.3, 0.1)),
            "total_bytes": max(10000, packets * 3000), "Label": "HEARTBLEED"
        })

    random.shuffle(data)
    df = pd.DataFrame(data)
    df.to_csv("my_test_dataset.csv", index=False)
    
    print(f"[+] Success! Dataset saved with {len(df)} rows.")

if __name__ == "__main__":
    generate_highly_realistic_cicids()