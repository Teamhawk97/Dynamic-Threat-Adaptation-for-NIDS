# detection.py

import time
import math
import socket
from utils import features_from_packets
from unknown_buffer import UnknownBuffer
from anomaly_detector import StatisticalAnomalyDetector

# ----------------------------
# Configuration
# ----------------------------
SYN_RATIO_THRESHOLD = 0.8
PORT_SCAN_THRESHOLD = 10
ALERT_COOLDOWN = 5.0

# DDoS thresholds (tune later)
PPS_THRESHOLD = 500       # packets/sec
SYN_FLOOD_RATIO = 0.6

# Data exfiltration thresholds
BYTES_EXFIL_THRESHOLD = 500000  # ~500 KB per window/flow
DURATION_THRESHOLD = 2.0

# ----------------------------
# State Tracking
# ----------------------------
last_alert_time = {}

unknown_buffer = UnknownBuffer()
anomaly_detector = StatisticalAnomalyDetector()

SELF_IP = socket.gethostbyname(socket.gethostname())


# ----------------------------
# ML Feature Builder
# ----------------------------
def build_ml_vector(fv: dict):

    pkt_count = fv.get("packet_count", 0) or 1

    # ratios
    tcp_syn_ratio = fv.get("tcp_syn_count", 0) / pkt_count
    tcp_rst_ratio = fv.get("tcp_rst_count", 0) / pkt_count
    udp_ratio     = fv.get("udp_count", 0) / pkt_count
    icmp_ratio    = fv.get("icmp_count", 0) / pkt_count

    # normalized logs
    packet_count_log = math.log1p(pkt_count) / 10.0
    unique_ports_log = math.log1p(fv.get("unique_dst_ports_count", 0)) / 10.0

    # normalized timing
    avg_inter_ms = min(fv.get("avg_interarrival_ms", 0.0), 2000.0) / 2000.0

    # normalized size
    pkt_size_std = min(fv.get("pkt_size_std", 0.0), 1500.0) / 1500.0

    # rate features (NEW - IMPORTANT)
    pps = fv.get("packets_per_second", 0.0)
    pps = min(pps, 10000.0) / 10000.0

    bps = fv.get("bytes_per_second", 0.0)
    bps = min(bps, 1_000_000.0) / 1_000_000.0

    return [
        packet_count_log,
        unique_ports_log,
        tcp_syn_ratio,
        tcp_rst_ratio,
        udp_ratio,
        icmp_ratio,
        avg_inter_ms,
        pkt_size_std,
        pps,
        bps
    ]

# ----------------------------
# Alert Throttling
# ----------------------------
def should_alert(src):
    now = time.time()
    last = last_alert_time.get(src, 0)
    if now - last > ALERT_COOLDOWN:
        last_alert_time[src] = now
        return True
    return False


# ----------------------------
# Shared Detection Logic
# ----------------------------
def process_behavior(key, pkts, model, context="WINDOW"):
    """
    Shared detection logic for both window + flow
    """

    if not pkts or len(pkts) < 5:
        return

    if key == "unknown" or key == SELF_IP:
        return

    # ----------------------------
    # Feature Extraction
    # ----------------------------
    fv = features_from_packets(pkts)
    vector = build_ml_vector(fv)

    pkt_count = fv.get("packet_count", 1)
    syn_count = fv.get("tcp_syn_count", 0)
    unique_ports = fv.get("unique_dst_ports_count", 0)
    syn_ratio = syn_count / pkt_count

    duration = fv.get("flow_duration", 1.0)
    total_bytes = fv.get("total_bytes", 0)

    pps = pkt_count / max(duration, 0.001)

    # ----------------------------
    # 1. SYN Scan Detection
    # ----------------------------
    is_port_scan = unique_ports > PORT_SCAN_THRESHOLD
    is_syn_heavy = syn_ratio > SYN_RATIO_THRESHOLD

    if is_port_scan and is_syn_heavy:
        if should_alert(key):
            print(f"[ALERT][{context}] SYN Scan detected from {key}")
            print(f"        {unique_ports} ports, {syn_count} SYNs ({syn_ratio:.1%})")

    elif is_port_scan:
        if should_alert(key):
            print(f"[ALERT][{context}] Port Scan from {key} ({unique_ports} ports)")

    # ----------------------------
    # 2. DDoS Detection
    # ----------------------------
    if pps > PPS_THRESHOLD and syn_ratio > SYN_FLOOD_RATIO:
        if should_alert(key):
            print(f"[ALERT][{context}] Possible DDoS from {key}")
            print(f"        PPS={pps:.1f}, SYN ratio={syn_ratio:.2f}")

    # ----------------------------
    # 3. Data Exfiltration Detection
    # ----------------------------
    if total_bytes > BYTES_EXFIL_THRESHOLD and duration > DURATION_THRESHOLD:
        if should_alert(key):
            print(f"[ALERT][{context}] Possible Data Exfiltration from {key}")
            print(f"        Bytes={total_bytes}, Duration={duration:.2f}s")

    # ----------------------------
    # 4. ML Classification
    # ----------------------------
    label, dist = model.classify(vector)

    if model.classes:
        if label == "UNKNOWN":
            print(f"[ML][{context}] UNKNOWN behavior from {key} (dist={dist:.2f})")
            unknown_buffer.add(vector)
            print("[DEBUG] unknown buffer size:", unknown_buffer.size())
        else:
            print(f"[ML][{context}] KNOWN:{label} from {key} (dist={dist:.2f})")


# ----------------------------
# Window-based Entry
# ----------------------------
def handle_window(key, pkts, model):
    process_behavior(key, pkts, model, context="WINDOW")


# ----------------------------
# Flow-based Entry
# ----------------------------
def handle_flow(flow_key, pkts, model):
    """
    flow_key = (src_ip, dst_ip, sport, dport, proto)
    """
    try:
        src_ip = flow_key[0]
    except Exception:
        src_ip = "unknown"

    process_behavior(src_ip, pkts, model, context="FLOW")


# ----------------------------
# Packet feeder (unused)
# ----------------------------
def analyze_packet(packet):
    pass