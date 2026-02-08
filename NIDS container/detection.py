# detection.py
import time
import math
from utils import features_from_packets

# Configuration
SYN_RATIO_THRESHOLD = 0.8  # If >80% of TCP traffic is pure SYN
PORT_SCAN_THRESHOLD = 10   # >10 unique ports
ALERT_COOLDOWN = 5.0

# State Tracking
last_alert_time = {}


def build_ml_vector(fv: dict):
    """
    Convert features_from_packets output -> fixed 8D ML vector.
    Applies minimal normalization (safe defaults).
    """
    pkt_count = fv.get("packet_count", 0) or 1  # avoid div by zero

    # ratios
    tcp_syn_ratio = fv.get("tcp_syn_count", 0) / pkt_count
    tcp_rst_ratio = fv.get("tcp_rst_count", 0) / pkt_count
    udp_ratio     = fv.get("udp_count", 0) / pkt_count
    icmp_ratio    = fv.get("icmp_count", 0) / pkt_count

    # log-scale counts (stabilizes distance)
    packet_count_log = math.log1p(fv.get("packet_count", 0))
    unique_ports_log = math.log1p(fv.get("unique_dst_ports_count", 0))

    # clamp timing to reduce outliers
    avg_inter_ms = min(fv.get("avg_interarrival_ms", 0.0), 2000.0)

    pkt_size_std = fv.get("pkt_size_std", 0.0)

    return [
        packet_count_log,       # 0
        unique_ports_log,       # 1
        tcp_syn_ratio,          # 2
        tcp_rst_ratio,          # 3
        udp_ratio,              # 4
        icmp_ratio,             # 5
        avg_inter_ms,           # 6
        pkt_size_std,           # 7
    ]


def should_alert(src):
    """Returns True if we haven't alerted for this SRC in the last ALERT_COOLDOWN seconds."""
    now = time.time()
    last = last_alert_time.get(src, 0)
    if now - last > ALERT_COOLDOWN:
        last_alert_time[src] = now
        return True
    return False

def analyze_packet(packet):
    """
    Feeder function. 
    Goal 4: No detection logic here to prevent per-packet false positives.
    """
    pass 

def handle_window(key, pkts, model):
    """
    Judge function.
    Decides based on the aggregate window stats.
    """
    # print(f"[DEBUG] window key={key}, pkts={len(pkts)}") #for debugging
    # 1. Validation: Ignore tiny windows (noise)
    if not pkts or len(pkts) < 5:
        return

    # Ignore non-IP traffic (ARP, etc.)
    if key == "unknown":
        return
        
    # 2. Feature Extraction
    fv = features_from_packets(pkts)
    
    # 3. Logic: Reliable SYN Scan Detection (Goal 1)
    unique_ports = fv.get("unique_dst_ports_count", 0)
    syn_count = fv.get("tcp_syn_count", 0)
    packet_count = fv.get("packet_count", 1)
    syn_ratio = syn_count / packet_count
    
    is_port_scan = unique_ports > PORT_SCAN_THRESHOLD
    is_syn_heavy = syn_ratio > SYN_RATIO_THRESHOLD

    # 4. Decision & Throttling (Goal 3)
    if is_port_scan and is_syn_heavy:
        if should_alert(key):
            print(f"[ALERT] SYN Scan detected from {key}")
            print(
                f"        Stats: {unique_ports} ports targetted, "
                f"{syn_count} SYNs ({syn_ratio:.1%} of traffic)"
            )
            
    elif is_port_scan:
        if should_alert(key):
            print(f"[ALERT] General Port Scan detected from {key} -> {unique_ports} unique ports")

    # 5. ML classification (observer-only)
    #print(f"[DEBUG-ML] model id={id(model)}, classes={list(model.classes.keys())}") # for debugging
    vector = build_ml_vector(fv)
    label, dist = model.classify(vector)

    # Only speak when model actually knows something
    if model.classes:
        if label == "UNKNOWN":
            print(f"[ML] UNKNOWN behavior from {key} (dist={dist:.2f})")
        else:
            print(f"[ML] KNOWN:{label} from {key} (dist={dist:.2f})")

