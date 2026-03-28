import pandas as pd
import numpy as np
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score
from data_to_model import build_vector_from_dict
from model import PrototypeClassifier

def get_binary_labels(labels):
    """Converts specific attack names into a simple 0 (Normal) or 1 (Attack)"""
    return [0 if label == 'NORMAL' else 1 for label in labels]

def get_binary_preds(preds):
    """Converts predictions into 0 (Normal) or 1 (Attack/Anomaly)"""
    # Note: If the model predicts 'UNKNOWN', it means it caught an anomaly! That is a successful detection (1).
    return [0 if pred == 'NORMAL' else 1 for pred in preds]

def calculate_nids_fpr(y_true, y_pred):
    y_true_bin = np.array(get_binary_labels(y_true))
    y_pred_bin = np.array(get_binary_preds(y_pred))
    
    # TN: Actually 0, Predicted 0
    tn = np.sum((y_true_bin == 0) & (y_pred_bin == 0))
    # FP: Actually 0, Predicted 1
    fp = np.sum((y_true_bin == 0) & (y_pred_bin == 1))
    
    if (fp + tn) == 0: return 0.0
    return (fp / (fp + tn)) * 100

def run_fscil_simulation():
    print("[+] Loading Highly Realistic 12-Class Dataset...")
    try:
        df = pd.read_csv("my_test_dataset.csv")
    except FileNotFoundError:
        print("[!] Error: 'my_test_dataset.csv' not found.")
        return
    
    actual_labels = df['Label'].tolist()
    
    # Define Base Knowledge
    normal_profile = {
        "packets_count": 150, "syn_flag_counts": 3, "rst_flag_counts": 1,
        "protocol": 6, "unique_ports_count": 2, "packets_IAT_mean": 120, 
        "payload_bytes_std": 350, "flow_duration": 5.0, "total_bytes": 90000
    }
    syn_scan_profile = {
        "packets_count": 50, "syn_flag_counts": 30, "rst_flag_counts": 15,
        "protocol": 6, "unique_ports_count": 100, "packets_IAT_mean": 2.0, 
        "payload_bytes_std": 0, "flow_duration": 0.5, "total_bytes": 3000
    }
    ddos_profile = {
        "packets_count": 1500, "syn_flag_counts": 75, "rst_flag_counts": 30,
        "protocol": 6, "unique_ports_count": 1, "packets_IAT_mean": 0.5, 
        "payload_bytes_std": 1200, "flow_duration": 1.0, "total_bytes": 1500000
    }

    # ==========================================
    # PHASE 1 & 2: TRAINING AND SIMULATION
    # ==========================================
    base_model = PrototypeClassifier()
    base_model.add_example("NORMAL", build_vector_from_dict(normal_profile))
    base_model.add_example("SYN_SCAN", build_vector_from_dict(syn_scan_profile))
    base_model.add_example("DDOS", build_vector_from_dict(ddos_profile))
    
    base_predictions = []
    for index, row in df.iterrows():
        vector = build_vector_from_dict(row.to_dict())
        label_guess, _ = base_model.classify(vector)
        base_predictions.append(label_guess)

    print("\n[+] Running Dynamic NIDS (Real-Time Few-Shot Learning)...")
    adapted_model = PrototypeClassifier()
    adapted_model.add_example("NORMAL", build_vector_from_dict(normal_profile))
    adapted_model.add_example("SYN_SCAN", build_vector_from_dict(syn_scan_profile))
    adapted_model.add_example("DDOS", build_vector_from_dict(ddos_profile))
    
    adapted_predictions = []
    learned_classes = {"NORMAL", "SYN_SCAN", "DDOS"}
    
    for index, row in df.iterrows():
        vector = build_vector_from_dict(row.to_dict())
        actual_attack = row['Label']
        label_guess, _ = adapted_model.classify(vector)
        
        if label_guess == "UNKNOWN":
            adapted_predictions.append("UNKNOWN")
            if actual_attack not in learned_classes and actual_attack != "NORMAL":
                adapted_model.add_example(actual_attack, vector)
                learned_classes.add(actual_attack)
        else:
            adapted_predictions.append(label_guess)

    # ==========================================
    # PHASE 3: THE SCORECARD
    # ==========================================
    print("\n" + "="*80)
    print("FINAL RESULTS FOR ICOEI PAPER")
    print("="*80)
    
    # 1. MULTICLASS METRICS (Did it guess the exact name?)
    base_acc = accuracy_score(actual_labels, base_predictions) * 100
    base_f1 = f1_score(actual_labels, base_predictions, average='weighted', zero_division=0)
    
    adapted_acc = accuracy_score(actual_labels, adapted_predictions) * 100
    adapted_f1 = f1_score(actual_labels, adapted_predictions, average='weighted', zero_division=0)
    
    # 2. BINARY METRICS (Normal vs. Any Attack)
    actual_bin = get_binary_labels(actual_labels)
    base_pred_bin = get_binary_preds(base_predictions)
    adapted_pred_bin = get_binary_preds(adapted_predictions)

    base_bin_acc = accuracy_score(actual_bin, base_pred_bin) * 100
    base_bin_f1 = f1_score(actual_bin, base_pred_bin, zero_division=0)
    base_fpr = calculate_nids_fpr(actual_labels, base_predictions)
    
    adapted_bin_acc = accuracy_score(actual_bin, adapted_pred_bin) * 100
    adapted_bin_f1 = f1_score(actual_bin, adapted_pred_bin, zero_division=0)
    adapted_fpr = calculate_nids_fpr(actual_labels, adapted_predictions)
    
    print("\n[ TABLE 1: MULTICLASS ACCURACY (Exact Threat Identification) ]")
    print("Evaluates if the model correctly applied the specific zero-day label after learning.")
    print("-" * 80)
    print(f"{'Metric':<25} | {'Static Baseline':<22} | {'Dynamic NIDS (Proposed)'}")
    print("-" * 80)
    print(f"{'Accuracy':<25} | {base_acc:>19.2f}%   | {adapted_acc:>23.2f}%")
    print(f"{'F1 Score (Weighted)':<25} | {base_f1:>19.4f}    | {adapted_f1:>23.4f}")
    
    print("\n[ TABLE 2: BINARY CLASSIFICATION (Normal vs. Attack) ]")
    print("Evaluates if the model successfully separated safe traffic from malicious anomalies.")
    print("-" * 80)
    print(f"{'Metric':<25} | {'Static Baseline':<22} | {'Dynamic NIDS (Proposed)'}")
    print("-" * 80)
    print(f"{'Binary Accuracy':<25} | {base_bin_acc:>19.2f}%   | {adapted_bin_acc:>23.2f}%")
    print(f"{'Binary F1 Score':<25} | {base_bin_f1:>19.4f}    | {adapted_bin_f1:>23.4f}")
    print(f"{'False Positive Rate':<25} | {base_fpr:>19.2f}%   | {adapted_fpr:>23.2f}%")
    print("=" * 80)

    print("\n[ PROPOSED DYNAMIC NIDS CONFUSION MATRIX ]")
    cm_adapted = pd.crosstab(pd.Series(actual_labels, name='Actual Data'), pd.Series(adapted_predictions, name='Model Prediction'))
    print(cm_adapted)

if __name__ == "__main__":
    run_fscil_simulation()