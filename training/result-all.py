import pandas as pd
import numpy as np
import json
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score
from model import PrototypeClassifier

# ==========================================
# MATHEMATICALLY ALIGNED VECTOR BUILDER
# ==========================================
def build_aligned_vector(row_dict):
    """
    Precisely matches the 11-feature normalization logic used in train.py.
    """
    def norm(val, max_val):
        return min(float(val), max_val) / max_val

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
    unique_ports_log = 0.0 
    packet_count_log = norm(np.log1p(pkt_count), 10)
    duration_log = norm(np.log1p(duration), 10)

    return np.array([
        syn_ratio, rst_ratio, udp_ratio, icmp_ratio,
        pps, bps, pkt_size_std, avg_interarrival,
        unique_ports_log, packet_count_log, duration_log
    ])

# ==========================================
# EVALUATION METRICS
# ==========================================
def get_binary_labels(labels):
    return [0 if label == 'NORMAL' else 1 for label in labels]

def get_binary_preds(preds):
    return [0 if pred == 'NORMAL' else 1 for pred in preds]

def calculate_nids_fpr(y_true, y_pred):
    y_true_bin = np.array(get_binary_labels(y_true))
    y_pred_bin = np.array(get_binary_preds(y_pred))
    tn = np.sum((y_true_bin == 0) & (y_pred_bin == 0))
    fp = np.sum((y_true_bin == 0) & (y_pred_bin == 1))
    if (fp + tn) == 0: return 0.0
    return (fp / (fp + tn)) * 100

def run_standard_evaluation():
    print("[+] Loading Synthetic 14-Class Dataset...")
    try:
        df = pd.read_csv("my_test_dataset.csv")
    except FileNotFoundError:
        print("[!] Error: 'my_test_dataset.csv' not found. Run build_dataset.py first.")
        return

    print("[+] Loading ALL 14 mathematical prototypes from model.json...")
    try:
        with open("model.json", "r") as f: 
            model_data = json.load(f)
    except FileNotFoundError:
        print("[!] Error: 'model.json' not found. Run train.py first.")
        return
    
    actual_labels = df['Label'].tolist()
    
    # ==========================================
    # LOAD THE FULLY TRAINED MODEL
    # ==========================================
    print("\n[+] Initializing Standard Model (All 14 Classes Known)...")
    standard_model = PrototypeClassifier()
    
    # Dynamically load every class that exists in the JSON
    for label, data in model_data["classes"].items():
        prototype_vector = np.array(data["prototype"])
        standard_model.add_example(label, prototype_vector)
        print(f"    -> Loaded memory for: {label}")

    print("\n[+] Running Classification Stream...")
    predictions = []
    
    for index, row in df.iterrows():
        vector = build_aligned_vector(row.to_dict())
        label_guess, _ = standard_model.classify(vector)
        predictions.append(label_guess)

    # ==========================================
    # THE SCORECARD
    # ==========================================
    print("\n" + "="*80)
    print("STANDARD FULLY TRAINED BENCHMARK (UPPER BOUND)")
    print("="*80)
    
    # Multiclass Metrics
    acc = accuracy_score(actual_labels, predictions) * 100
    f1 = f1_score(actual_labels, predictions, average='weighted', zero_division=0)
    
    # Binary Metrics
    actual_bin = get_binary_labels(actual_labels)
    pred_bin = get_binary_preds(predictions)

    bin_acc = accuracy_score(actual_bin, pred_bin) * 100
    bin_f1 = f1_score(actual_bin, pred_bin, zero_division=0)
    fpr = calculate_nids_fpr(actual_labels, predictions)
    
    print("\n[ MULTICLASS METRICS ]")
    print(f"Accuracy : {acc:.2f}%")
    print(f"F1 Score : {f1:.4f}")
    
    print("\n[ BINARY METRICS ]")
    print(f"Accuracy : {bin_acc:.2f}%")
    print(f"F1 Score : {bin_f1:.4f}")
    print(f"FPR      : {fpr:.2f}%")
    print("=" * 80)

    print("\n[ FULL 14-CLASS CONFUSION MATRIX ]")
    cm = pd.crosstab(pd.Series(actual_labels, name='Actual Data'), pd.Series(predictions, name='Model Prediction'))
    print(cm)

if __name__ == "__main__":
    run_standard_evaluation()