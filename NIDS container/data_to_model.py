# data_to_model.py

import math
from model import PrototypeClassifier


# ----------------------------
# Convert dict → ML vector
# ----------------------------
def build_vector_from_dict(data):

    pkt_count = max(data.get("packets_count", 1), 1)

    syn_ratio = data.get("syn_flag_counts", 0) / pkt_count
    rst_ratio = data.get("rst_flag_counts", 0) / pkt_count

    udp_ratio = 1.0 if data.get("protocol") == 17 else 0.0
    icmp_ratio = 1.0 if data.get("protocol") == 1 else 0.0

    packet_count_log = math.log1p(pkt_count) / 10.0
    unique_ports_log = math.log1p(data.get("dst_port", 0)) / 10.0

    avg_inter_ms = min(data.get("packets_IAT_mean", 0.0), 2000.0) / 2000.0
    pkt_size_std = min(data.get("payload_bytes_std", 0.0), 1500.0) / 1500.0

    duration = data.get("flow_duration", 1.0)

    pps = min(pkt_count / max(duration, 0.001), 10000.0) / 10000.0
    bps = min(data.get("payload_bytes_std", 0.0) * pkt_count, 1_000_000.0) / 1_000_000.0

    vector = [
        packet_count_log,
        unique_ports_log,
        syn_ratio,
        rst_ratio,
        udp_ratio,
        icmp_ratio,
        avg_inter_ms,
        pkt_size_std,
        pps,
        bps
    ]

    return vector


# ----------------------------
# Run inference
# ----------------------------
def infer_from_dict(data, model):

    vector = build_vector_from_dict(data)

    label, dist = model.classify(vector)

    print("\n[TEST RESULT]")
    print("Input Data:", data)
    print("Vector:", [round(v, 4) for v in vector])
    print(f"Prediction: {label} (dist={dist:.2f})")

    return label, dist


# ----------------------------
# Interactive mode
# ----------------------------
def manual_input_mode(model):

    print("\n=== Manual Input Mode ===")

    try:
        pkt_count = int(input("packets_count: "))
        syn = int(input("syn_flag_counts: "))
        rst = int(input("rst_flag_counts: "))
        proto = int(input("protocol (6=TCP, 17=UDP, 1=ICMP): "))
        port = int(input("dst_port: "))
        iat = float(input("packets_IAT_mean (ms): "))
        std = float(input("payload_bytes_std: "))
        duration = float(input("flow_duration (seconds): "))

        data = {
            "packets_count": pkt_count,
            "syn_flag_counts": syn,
            "rst_flag_counts": rst,
            "protocol": proto,
            "dst_port": port,
            "packets_IAT_mean": iat,
            "payload_bytes_std": std,
            "flow_duration": duration
        }

        infer_from_dict(data, model)

    except Exception as e:
        print("[ERROR] Invalid input:", e)


# ----------------------------
# Example test cases
# ----------------------------
def run_examples(model):

    print("\n=== Running Example Tests ===")

    # SYN scan-like
    syn_scan = {
        "packets_count": 50,
        "syn_flag_counts": 50,
        "rst_flag_counts": 0,
        "protocol": 6,
        "dst_port": 80,
        "packets_IAT_mean": 10,
        "payload_bytes_std": 0,
        "flow_duration": 1
    }

    # Normal traffic
    normal = {
        "packets_count": 100,
        "syn_flag_counts": 2,
        "rst_flag_counts": 1,
        "protocol": 6,
        "dst_port": 443,
        "packets_IAT_mean": 200,
        "payload_bytes_std": 300,
        "flow_duration": 5
    }

    # DDoS-like
    ddos = {
        "packets_count": 1000,
        "syn_flag_counts": 800,
        "rst_flag_counts": 50,
        "protocol": 6,
        "dst_port": 80,
        "packets_IAT_mean": 1,
        "payload_bytes_std": 50,
        "flow_duration": 1
    }

    infer_from_dict(syn_scan, model)
    infer_from_dict(normal, model)
    infer_from_dict(ddos, model)


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
        print("2. Manual input")
        print("3. Exit")

        choice = input("Choose option: ").strip()

        if choice == "1":
            run_examples(model)
        elif choice == "2":
            manual_input_mode(model)
        elif choice == "3":
            print("Exiting...")
            break
        else:
            print("Invalid choice")