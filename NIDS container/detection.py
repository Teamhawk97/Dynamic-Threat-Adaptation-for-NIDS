# detection.py
import numpy as np
import time
from collections import defaultdict
from utils import extract_features
from utils import features_from_packets

PORT_SCAN_THRESHOLD = 10
ip_port_history = defaultdict(set)
ip_port_counter = {}
last_alert_time = {}
ALERT_COOLDOWN = 5.0

def should_alert(src):
    now = time.time()
    last = last_alert_time.get(src, 0)
    if now - last > ALERT_COOLDOWN:
        last_alert_time[src] = now
        return True
    return False

def analyze_packet(packet):
    features = extract_features(packet)

    if features is None:
        return

    src = features["src"]
    dst_port = features["dst_port"]

    # Count how many different ports attacker hits
    key = (src, dst_port)
    ip_port_counter.setdefault(src, set()).add(dst_port)

    port_count = len(ip_port_counter[src])

    if port_count > PORT_SCAN_THRESHOLD:
        print(f"[ALERT] Port scan detected from {src} → {port_count} ports probed")

def handle_window(key, pkts):
    # ignore tiny windows
    if not pkts or len(pkts) < 5:
        return
        
    # compute features (vector) for this window
    fv = features_from_packets(pkts)  # returns a dict or vector
    # simple heuristic example: unique dst ports in this window
    unique_ports = fv.get("unique_dst_ports_count", 0)
    print(f"[WIN] src={key}, window pkts={len(pkts)}, unique ports={unique_ports}")
    if unique_ports > PORT_SCAN_THRESHOLD:
        print(f"[ALERT] Port scan detected from {key} → {unique_ports} ports in last window")
        

    else:
        # here is where you'd call classify_vector(fv_vector) for ML
        pass
