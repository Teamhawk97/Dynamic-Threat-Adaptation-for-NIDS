import pandas as pd
import numpy as np
import json
import glob
import os

DATASET_DIR = "../dataset/"
OUTPUT_MODEL = "../model.json"

# ----------------------------
# Load CSV files
# ----------------------------
def load_datasets():
    files = glob.glob(os.path.join(DATASET_DIR, "*.csv"))
    dfs = []

    for f in files:
        fname = os.path.basename(f)
        print("Loading:", fname)
        
        # Read the file and append the source file name as a column
        df = pd.read_csv(f)
        df = df.assign(source_file=fname)
        dfs.append(df)

    # Combine all files into one massive DataFrame
    df = pd.concat(dfs, ignore_index=True)
    return df


# ----------------------------
# Clean dataset
# ----------------------------
def clean_dataset(df):
    print("\nCleaning data (handling NaNs and Infs)...")
    df = df.replace([np.inf, -np.inf], np.nan)
    df = df.dropna()
    df = df.drop_duplicates()
    return df


# ----------------------------
# Map attack labels
# ----------------------------
def map_labels(df):
    print("Mapping distinct attack labels...")
    labels = []

    for f in df["source_file"]:
        fname = f.lower()

        # Group all Benign traffic into one NORMAL class
        if "benign" in fname:
            labels.append("NORMAL")
            
        # Keep every specific attack exactly as its own class
        elif "portscan" in fname: labels.append("PORTSCAN")
        elif "botnet_ares" in fname: labels.append("BOTNET_ARES")
        elif "ddos_loit" in fname: labels.append("DDOS_LOIT")
        elif "dos_golden_eye" in fname: labels.append("DOS_GOLDEN_EYE")
        elif "dos_hulk" in fname: labels.append("DOS_HULK")
        elif "heartbleed" in fname: labels.append("HEARTBLEED")
        elif "web_sql_injection" in fname: labels.append("WEB_SQL_INJECTION")
        elif "web_xss" in fname: labels.append("WEB_XSS")
        elif "dos_slowhttptest" in fname: labels.append("DOS_SLOWHTTPTEST")
        elif "dos_slowloris" in fname: labels.append("DOS_SLOWLORIS")
        elif "ftp_patator" in fname: labels.append("FTP_PATATOR")
        elif "ssh_patator" in fname: labels.append("SSH_PATATOR")
        elif "web_brute_force" in fname: labels.append("WEB_BRUTE_FORCE")
        else:
            labels.append(None) # Fallback, will be dropped

    df["attack_type"] = labels
    df = df[df["attack_type"].notnull()]
    return df


# ----------------------------
# Build ML feature vectors (Matched to Schema)
# ----------------------------
def build_feature_vectors(df):
    print("Extracting NIDS statistical features...")
    
    def norm(series, max_val):
        return np.minimum(series, max_val) / max_val

    # Base values using exact schema columns
    pkt_count = df["packets_count"].clip(lower=1)
    duration = df["duration"].replace(0, 0.001) 
    total_bytes = df["total_payload_bytes"] + df["total_header_bytes"]

    # 1. SHAPE FEATURES
    syn_ratio = df["syn_flag_counts"] / pkt_count
    rst_ratio = df["rst_flag_counts"] / pkt_count
    udp_ratio = (df["protocol"] == 17).astype(float)
    icmp_ratio = (df["protocol"] == 1).astype(float)

    # 2. VELOCITY FEATURES
    pps = pkt_count / duration
    bps = total_bytes / duration
    pps = norm(pps, 50000)      # Max cap: 50k packets per sec
    bps = norm(bps, 10000000)   # Max cap: 10MB per sec

    # 3. FOOTPRINT FEATURES
    pkt_size_std = norm(df["payload_bytes_std"], 1500)
    avg_interarrival = norm(df["packets_IAT_mean"].clip(upper=2000), 2000)

    # Keep unique ports zeroed for prototype training to prevent false port associations
    unique_ports_log = pd.Series(0.0, index=df.index) 
    packet_count_log = norm(np.log1p(pkt_count), 10)

    # 4. TIME FEATURE
    duration_log = norm(np.log1p(duration), 10)

    # FINAL VECTOR (11 FEATURES)
    vectors = np.column_stack([
        syn_ratio, rst_ratio, udp_ratio, icmp_ratio,
        pps, bps, pkt_size_std, avg_interarrival,
        unique_ports_log, packet_count_log, duration_log
    ])
    return vectors


# ----------------------------
# Smart Dataset Balancing (Cap-based)
# ----------------------------
def balance_dataset(df, vectors, max_samples_per_class=10000):
    """
    Instead of reducing all classes to the absolute minimum (which deletes millions of rows 
    if Heartbleed only has 10 rows), this keeps ALL minority rows but caps massive volumetric 
    attacks at 10,000 samples to prevent prototype skew and memory crashes.
    """
    grouped = {}

    for label in df["attack_type"].unique():
        idx = df[df["attack_type"] == label].index
        grouped[label] = vectors[idx]

    print("\nSamples per class before balancing:")
    for k, v in grouped.items():
        print(f"  {k}: {len(v)}")

    balanced = {}
    print(f"\nBalancing: Capping majority classes to {max_samples_per_class} samples maximum...")

    for label, vecs in grouped.items():
        if len(vecs) > max_samples_per_class:
            idx = np.random.choice(len(vecs), max_samples_per_class, replace=False)
            balanced[label] = vecs[idx]
        else:
            balanced[label] = vecs

    return balanced


# ----------------------------
# Train prototype model
# ----------------------------
def train():
    df = load_datasets()
    df = clean_dataset(df)
    df = map_labels(df)
    df = df.reset_index(drop=True)

    vectors = build_feature_vectors(df)
    balanced = balance_dataset(df, vectors, max_samples_per_class=15000)

    model = {"classes": {}}
    print("\nTraining prototypes...")

    for label, vecs in balanced.items():
        # Calculate the mathematical center of the cluster for this specific attack
        prototype = vecs.mean(axis=0)

        model["classes"][label] = {
            "prototype": prototype.tolist(),
            "count": len(vecs)
        }
        print(f" [+] Prototype successfully mapped for: {label}")

    with open(OUTPUT_MODEL, "w") as f:
        json.dump(model, f, indent=4)

    print("\n[SUCCESS] Model saved to:", OUTPUT_MODEL)


if __name__ == "__main__":
    train()