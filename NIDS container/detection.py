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
# RULE-BASED DETECTION ONLY
# ----------------------------
def detect_rules(key, fv, context):

    pkt_count = fv.get("packet_count", 1)
    syn_count = fv.get("tcp_syn_count", 0)
    unique_ports = fv.get("unique_dst_ports_count", 0)
    syn_ratio = syn_count / pkt_count

    duration = fv.get("flow_duration", 1.0)
    total_bytes = fv.get("total_bytes", 0)

    pps = pkt_count / max(duration, 0.001)

    # SYN scan
    if unique_ports > PORT_SCAN_THRESHOLD and syn_ratio > SYN_RATIO_THRESHOLD:
        if should_alert(key):
            print(f"[ALERT][{context}] SYN Scan detected from {key}")
            print(f"        {unique_ports} ports, {syn_count} SYNs ({syn_ratio:.1%})")

    elif unique_ports > PORT_SCAN_THRESHOLD:
        if should_alert(key):
            print(f"[ALERT][{context}] Port Scan from {key} ({unique_ports} ports)")

    # DDoS
    if pps > PPS_THRESHOLD and syn_ratio > SYN_FLOOD_RATIO:
        if should_alert(key):
            print(f"[ALERT][{context}] Possible DDoS from {key}")
            print(f"        PPS={pps:.1f}, SYN ratio={syn_ratio:.2f}")

    # Data Exfiltration
    if total_bytes > BYTES_EXFIL_THRESHOLD and duration > DURATION_THRESHOLD:
        if should_alert(key):
            print(f"[ALERT][{context}] Possible Data Exfiltration from {key}")
            print(f"        Bytes={total_bytes}, Duration={duration:.2f}s")


# ----------------------------
# ML CLASSIFICATION ONLY
# ----------------------------
def run_ml(key, fv, model, context):

    vector = build_ml_vector(fv)
    label, dist = model.classify(vector)

    if not model.classes:
        return

    if label == "UNKNOWN":
        print(f"[ML][{context}] UNKNOWN behavior from {key} (dist={dist:.2f})")
        unknown_buffer.add(vector)
        print("[DEBUG] unknown buffer size:", unknown_buffer.size())
    else:
        print(f"[ML][{context}] KNOWN:{label} from {key} (dist={dist:.2f})")


# ----------------------------
# WINDOW → RULES ONLY
# ----------------------------
def handle_window(key, pkts, model):

    if not pkts or len(pkts) < 5:
        return

    if key == "unknown" or key == SELF_IP:
        return

    fv = features_from_packets(pkts)

    # RULES HERE
    detect_rules(key, fv, context="WINDOW")
    # ML WNDOW 
    run_ml(key, fv, model, context="WINDOW")
    


# ----------------------------
# FLOW → ML ONLY
# ----------------------------
def handle_flow(flow_key, pkts, model):

    # ----------------------------
    # Basic validation
    # ----------------------------
    if not pkts:
        return

    if isinstance(flow_key, tuple) and len(flow_key) >= 1:
        src_ip = flow_key[0]
    else:
        src_ip = "unknown"

    if src_ip == "unknown" or src_ip == SELF_IP:
        return

    # ----------------------------
    # Feature extraction
    # ----------------------------
    fv = features_from_packets(pkts)

    pkt_count = fv.get("packet_count", 0)
    duration = fv.get("flow_duration", 0.0)
    total_bytes = fv.get("packet_count", 0) * fv.get("avg_packet_size", 0.0)

    # ----------------------------
    # 🔥 FLOW FILTERING (IMPORTANT)
    # ----------------------------

    # 1. Ignore tiny flows (most important)
    if pkt_count < 3:
        return

    # 2. Ignore ultra-short flows (noise)
    if duration < 0.05:
        return

    # 3. Ignore very small data transfers
    if total_bytes < 100:
        return

    # ----------------------------
    # ML classification
    # ----------------------------
    run_ml(src_ip, fv, model, context="FLOW")



# ----------------------------
# Packet feeder (unused)
# ----------------------------
def analyze_packet(packet):
    pass