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
# Build ML feature vectors
# ----------------------------
def build_feature_vectors(df):

    pkt_count = df["packets_count"].clip(lower=1)

    # ----------------------------
    # Ratios
    # ----------------------------
    syn_ratio = df["syn_flag_counts"] / pkt_count
    rst_ratio = df["rst_flag_counts"] / pkt_count

    udp_ratio = (df["protocol"] == 17).astype(int)
    icmp_ratio = (df["protocol"] == 1).astype(int)

    # ----------------------------
    # Log + normalization
    # ----------------------------
    packet_count_log = np.log1p(pkt_count) / 10.0
    unique_ports_log = np.log1p(df["dst_port"]) / 10.0

    # ----------------------------
    # Timing
    # ----------------------------
    avg_interarrival = df["packets_IAT_mean"].clip(upper=2000) / 2000.0

    # ----------------------------
    # Packet size
    # ----------------------------
    pkt_size_std = df["payload_bytes_std"].clip(upper=1500) / 1500.0

    # ----------------------------
    # Rate features (DIRECTLY AVAILABLE ✅)
    # ----------------------------
    pps = df["packets_rate"].clip(upper=10000) / 10000.0
    bps = df["bytes_rate"].clip(upper=1_000_000) / 1_000_000.0

    # ----------------------------
    # Final vector (10D)
    # ----------------------------
    vectors = np.column_stack([
        packet_count_log,
        unique_ports_log,
        syn_ratio,
        rst_ratio,
        udp_ratio,
        icmp_ratio,
        avg_interarrival,
        pkt_size_std,
        pps,
        bps
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