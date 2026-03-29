import pandas as pd
import numpy as np
from sklearn.metrics import accuracy_score, f1_score
from model import PrototypeClassifier

def build_aligned_vector(row_dict):
    def norm(val, max_val): return min(float(val), max_val) / max_val
    pkt_count = max(row_dict.get("packets_count", 1), 1)
    duration = max(row_dict.get("flow_duration", 1.0), 0.001)
    total_bytes = row_dict.get("total_bytes", 0)

    syn_ratio = row_dict.get("syn_flag_counts", 0) / pkt_count
    rst_ratio = row_dict.get("rst_flag_counts", 0) / pkt_count
    udp_ratio = 1.0 if row_dict.get("protocol", 6) == 17 else 0.0
    icmp_ratio = 1.0 if row_dict.get("protocol", 6) == 1 else 0.0
    pps = norm(pkt_count / duration, 50000)
    bps = norm(total_bytes / duration, 10000000)
    pkt_size_std = norm(row_dict.get("payload_bytes_std", 0), 1500)
    avg_interarrival = norm(min(row_dict.get("packets_IAT_mean", 0), 2000), 2000)
    
    return np.array([
        syn_ratio, rst_ratio, udp_ratio, icmp_ratio,
        pps, bps, pkt_size_std, avg_interarrival,
        0.0, norm(np.log1p(pkt_count), 10), norm(np.log1p(duration), 10)
    ])

def run_ideal_benchmark():
    df = pd.read_csv("my_test_dataset.csv")
    actual_labels = df['Label'].tolist()
    
    # 1. TRAIN ON THE SYNTHETIC DOMAIN (Perfectly aligned Upper Bound)
    print("[+] Extracting ideal prototypes directly from the test environment...")
    ideal_prototypes = {}
    for label in df['Label'].unique():
        subset = df[df['Label'] == label]
        vectors = np.array([build_aligned_vector(row.to_dict()) for _, row in subset.iterrows()])
        ideal_prototypes[label] = vectors.mean(axis=0)
        
    benchmark_model = PrototypeClassifier()
    for label, proto in ideal_prototypes.items():
        benchmark_model.add_example(label, proto)

    # 2. TEST THE MODEL
    print("[+] Running Classification...")
    predictions = []
    for index, row in df.iterrows():
        vector = build_aligned_vector(row.to_dict())
        label_guess, _ = benchmark_model.classify(vector)
        predictions.append(label_guess)

    # 3. SCORECARD
    acc = accuracy_score(actual_labels, predictions) * 100
    f1 = f1_score(actual_labels, predictions, average='weighted', zero_division=0)
    
    print("\n" + "="*80)
    print("STANDARD FULLY TRAINED BENCHMARK (APPLES-TO-APPLES UPPER BOUND)")
    print("="*80)
    print(f"Accuracy : {acc:.2f}%")
    print(f"F1 Score : {f1:.4f}")
    
    print("\n[ FULL 14-CLASS CONFUSION MATRIX ]")
    cm = pd.crosstab(pd.Series(actual_labels, name='Actual Data'), pd.Series(predictions, name='Model Prediction'))
    print(cm)

if __name__ == "__main__":
    run_ideal_benchmark()