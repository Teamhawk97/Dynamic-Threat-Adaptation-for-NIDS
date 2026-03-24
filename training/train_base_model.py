import pandas as pd
import numpy as np
import json
import glob
import os
import math

DATASET_DIR = "../dataset/"
OUTPUT_MODEL = "../model.json"


# ----------------------------
# Load CSV files
# ----------------------------
def load_datasets():

    files = glob.glob(DATASET_DIR + "*.csv")

    dfs = []

    for f in files:

        fname = os.path.basename(f)

        # Skip very small attack datasets
        if "heartbleed" in fname.lower() or "sql" in fname.lower():
            print("Skipping small dataset:", fname)
            continue

        print("Loading:", fname)

        df = pd.read_csv(f)

        df = df.assign(source_file=fname)

        dfs.append(df)

    df = pd.concat(dfs, ignore_index=True)

    return df


# ----------------------------
# Clean dataset
# ----------------------------
def clean_dataset(df):

    df = df.replace([np.inf, -np.inf], np.nan)

    df = df.dropna()

    df = df.drop_duplicates()

    return df


# ----------------------------
# Map attack labels
# ----------------------------
def map_labels(df):

    labels = []

    for f in df["source_file"]:

        fname = f.lower()

        if "portscan" in fname:
            labels.append("syn_scan")

        elif "dos_hulk" in fname or "golden_eye" in fname:
            labels.append("dos")

        elif "ddos" in fname:
            labels.append("ddos")

        elif "botnet" in fname:
            labels.append("botnet")

        elif "benign" in fname:
            labels.append("normal")

        else:
            labels.append(None)

    df["attack_type"] = labels

    df = df[df["attack_type"].notnull()]

    return df


# ----------------------------
# Build ML feature vectors (CORRECTED FOR COSINE & NIDS)
# ----------------------------
def build_feature_vectors(df):
    def norm(series, max_val):
        return np.minimum(series, max_val) / max_val

    # Base values
    pkt_count = df["packets_count"].clip(lower=1)
    duration = df.get("flow_duration", pd.Series(1.0, index=df.index)).replace(0, 0.001)
    total_bytes = df.get("flow_bytes", df.get("bytes_rate", 0) * duration)

    # 1. SHAPE FEATURES (Full strength, no 0.2 penalty!)
    syn_ratio = df["syn_flag_counts"] / pkt_count
    rst_ratio = df["rst_flag_counts"] / pkt_count
    udp_ratio = (df["protocol"] == 17).astype(float)
    icmp_ratio = (df["protocol"] == 1).astype(float)

    # 2. VELOCITY FEATURES (Raised caps so attacks separate from normal traffic)
    pps = pkt_count / duration
    bps = total_bytes / duration
    pps = norm(pps, 50000)      # Max cap: 50k packets per sec
    bps = norm(bps, 10000000)   # Max cap: 10MB per sec

    # 3. FOOTPRINT FEATURES
    pkt_size_std = norm(df["payload_bytes_std"], 1500)
    avg_interarrival = norm(df["packets_IAT_mean"].clip(upper=2000), 2000)

    # 🔥 CRITICAL FIX: We cannot use literal dst_port.
    # Since the CSV groups flows, we assume the dataset aggregates scans differently. 
    # For now, we will zero this out in training so the model doesn't falsely associate 
    # port 443 with "Normal" and port 8080 with "Attack". Your live WindowManager 
    # will handle unique port counting correctly.
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
# Balance dataset
# ----------------------------
def balance_dataset(df, vectors):

    grouped = {}

    for label in df["attack_type"].unique():

        idx = df[df["attack_type"] == label].index

        grouped[label] = vectors[idx]

    print("\nSamples before balancing:")

    for k in grouped:
        print(k, len(grouped[k]))

    min_samples = min(len(v) for v in grouped.values())

    print("\nBalancing classes to", min_samples)

    balanced = {}

    for label, vecs in grouped.items():

        idx = np.random.choice(len(vecs), min_samples, replace=False)

        balanced[label] = vecs[idx]

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

    balanced = balance_dataset(df, vectors)

    model = {"classes": {}}

    print("\nTraining prototypes...")

    for label, vecs in balanced.items():

        prototype = vecs.mean(axis=0)

        model["classes"][label] = {
            "prototype": prototype.tolist(),
            "count": len(vecs)
        }

        print("Prototype created for:", label)

    with open(OUTPUT_MODEL, "w") as f:
        json.dump(model, f, indent=4)

    print("\nModel saved to:", OUTPUT_MODEL)


# ----------------------------
# Run training
# ----------------------------
if __name__ == "__main__":
    train()