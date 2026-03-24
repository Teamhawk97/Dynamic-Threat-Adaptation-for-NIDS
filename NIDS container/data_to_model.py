# data_to_model.py
import math
from model import PrototypeClassifier

# ----------------------------
# Convert dict → ML vector
# ----------------------------
def build_vector_from_dict(data):
    def norm(x, max_val):
        return min(x, max_val) / max_val

    pkt_count = max(data.get("packets_count", 1), 1)
    duration = max(data.get("flow_duration", 0.001), 0.001)
    total_bytes = data.get("total_bytes", pkt_count * data.get("payload_bytes_std", 0))

    # 1. SHAPE FEATURES
    syn_ratio = data.get("syn_flag_counts", 0) / pkt_count
    rst_ratio = data.get("rst_flag_counts", 0) / pkt_count

    # 🔥 FIX: Removed the * 0.2 multiplier. Let the tripwires work at full 1.0 strength!
    udp_ratio = 1.0 if data.get("protocol") == 17 else 0.0
    icmp_ratio = 1.0 if data.get("protocol") == 1 else 0.0

    # 2. VELOCITY FEATURES
    pps = pkt_count / duration
    bps = total_bytes / duration
    pps = norm(pps, 50000)      # Raised cap so floods stand out from normal traffic
    bps = norm(bps, 10000000)   # Raised cap for data exfiltration

    # 3. FOOTPRINT FEATURES
    pkt_size_std = norm(data.get("payload_bytes_std", 0.0), 1500.0)
    avg_interarrival = norm(min(data.get("packets_IAT_mean", 0.0), 2000.0), 2000.0)

    # 🔥 FIX: Use a dedicated 'unique_ports_count' field, not the literal port number!
    unique_ports_log = norm(math.log1p(data.get("unique_ports_count", 1)), 10)
    packet_count_log = norm(math.log1p(pkt_count), 10)

    # 4. TIME FEATURE
    duration_log = norm(math.log1p(duration), 10)

    return [
        syn_ratio, rst_ratio, udp_ratio, icmp_ratio,
        pps, bps, pkt_size_std, avg_interarrival,
        unique_ports_log, packet_count_log, duration_log
    ]


# ----------------------------
# Run inference
# ----------------------------
def infer_from_dict(name, data, model):
    vector = build_vector_from_dict(data)
    label, dist = model.classify(vector)

    if label == "UNKNOWN":
        print(f"[ALERT] {name:<12} -> Labeled: {label:<8} | Cosine Dist: {dist:.4f} (Anomaly Triggered!)")
    else:
        print(f"[PASS]  {name:<12} -> Labeled: {label:<8} | Cosine Dist: {dist:.4f}")
    return label, dist


# ----------------------------
# Example test cases
# ----------------------------
def run_examples(model):
    print("\n=== Phase 1: Training Baselines ===")
    
    # NORMAL TRAFFIC
    normal = {
        "packets_count": 200, "syn_flag_counts": 5, "rst_flag_counts": 1,
        "protocol": 6, "unique_ports_count": 1, 
        "packets_IAT_mean": 150, "payload_bytes_std": 400,
        "flow_duration": 8, "total_bytes": 200 * 500
    }
    
    print("Teaching model 'NORMAL' behavior...")
    model.add_example("NORMAL", build_vector_from_dict(normal))
    print(f"Current Known Classes: {list(model.classes.keys())}")

    print("\n=== Phase 2: Testing Attacks (Threshold: 0.2) ===")
    
    # SYN SCAN (High SYN, Many Ports)
    # MATCHING THE CIC-IDS2017 REALITY (Bidirectional)
    syn_scan = {
        "packets_count": 80, 
        "syn_flag_counts": 40,   # 50% SYNs from the attacker
        "rst_flag_counts": 40,   # 50% RSTs from the victim
        "protocol": 6, 
        "unique_ports_count": 1, # (Keep 1, since we zeroed this out in training)
        "packets_IAT_mean": 5, 
        "payload_bytes_std": 0,
        "flow_duration": 1, 
        "total_bytes": 80 * 60
    }

    # DDoS (Massive Volume, High SYN)
    ddos = {
        "packets_count": 500, 
        "syn_flag_counts": 25,   # Low SYN ratio (5%)
        "rst_flag_counts": 5, 
        "protocol": 6, "unique_ports_count": 1,
        "packets_IAT_mean": 1, 
        "payload_bytes_std": 1450, # Massive packet variance (HTTP data)
        "flow_duration": 1, "total_bytes": 500 * 800
    }

    # UDP FLOOD (100% UDP Tripwire)
    udp_flood = {
        "packets_count": 1200, "syn_flag_counts": 0, "rst_flag_counts": 0,
        "protocol": 17, "unique_ports_count": 1,
        "packets_IAT_mean": 1, "payload_bytes_std": 20,
        "flow_duration": 1, "total_bytes": 1200 * 50
    }

    infer_from_dict("Normal_Test", normal, model)  # Should return NORMAL with distance 0.0
    infer_from_dict("SYN_Scan", syn_scan, model)   # Should return syn_scan
    infer_from_dict("DDoS", ddos, model)           # Should return ddos
    infer_from_dict("UDP_Flood", udp_flood, model) # Should return UNKNOWN


# ----------------------------
# Main
# ----------------------------
if __name__ == "__main__":
    MODEL_PATH = "model.json"
    print("[+] Loading model...")
    model = PrototypeClassifier.load(MODEL_PATH)

    while True:
        print("\n=== MENU ===")
        print("1. Run example tests")
        print("2. Exit")

        choice = input("Choose option: ").strip()

        if choice == "1":
            run_examples(model)
        elif choice == "2":
            print("Exiting...")
            break
        else:
            print("Invalid choice")