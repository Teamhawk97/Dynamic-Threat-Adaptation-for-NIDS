# detection.py
import time
from utils import features_from_packets

# Configuration
SYN_RATIO_THRESHOLD = 0.8  # If >80% of TCP traffic is pure SYN
PORT_SCAN_THRESHOLD = 10   # >10 unique ports
ALERT_COOLDOWN = 5.0

# State Tracking
last_alert_time = {}

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

def handle_window(key, pkts):
    """
    Judge function.
    Decides based on the aggregate window stats.
    """
    # 1. Validation: Ignore tiny windows (noise)
    if not pkts or len(pkts) < 5:
        return
        
    # 2. Feature Extraction
    fv = features_from_packets(pkts)
    
    # 3. Logic: Reliable SYN Scan Detection (Goal 1)
    # logic: High Port Count + High SYN Ratio = SYN Scan
    unique_ports = fv.get("unique_dst_ports_count", 0)
    syn_count = fv.get("tcp_syn_count", 0)
    packet_count = fv.get("packet_count", 1)
    
    # Calculate SYN ratio (avoid division by zero)
    syn_ratio = syn_count / packet_count
    
    is_port_scan = unique_ports > PORT_SCAN_THRESHOLD
    is_syn_heavy = syn_ratio > SYN_RATIO_THRESHOLD

    # 4. Decision & Throttling (Goal 3)
    if is_port_scan and is_syn_heavy:
        if should_alert(key):
            print(f"[ALERT] SYN Scan detected from {key}")
            print(f"        Stats: {unique_ports} ports targetted, {syn_count} SYNs ({syn_ratio:.1%} of traffic)")
            
    elif is_port_scan:
        # A normal scan (could be UDP or full connect)
        if should_alert(key):
            print(f"[ALERT] General Port Scan detected from {key} -> {unique_ports} unique ports")

    # 5. Placeholder for ML (Goal: Future Proofing)
    else:
        # classify_vector(fv)
        pass