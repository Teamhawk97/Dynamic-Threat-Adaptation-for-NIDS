# detection.py
import time
import math
import socket
import requests
from utils import features_from_packets
from unknown_buffer import UnknownBuffer
from anomaly_detector import StatisticalAnomalyDetector
from swarm_manager import swarm

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
#LEADER_URL = "172.16.0.3:8000" # Default Leader URL (will be updated if this node becomes leader)


# ----------------------------
# ML Feature Builder
# ----------------------------
def build_ml_vector(fv: dict):
    def norm(x, max_val):
        return min(x, max_val) / max_val

    # Base values
    pkt_count = fv.get("packet_count", 1) or 1
    duration = fv.get("flow_duration", 0.001)
    if duration <= 0:
        duration = 0.001

    # 🔥 FIX: Use the exact total_bytes already calculated in fv
    total_bytes = fv.get("total_bytes", 0)

    # 1. SHAPE FEATURES (bounded)
    syn_ratio = fv.get("tcp_syn_count", 0) / pkt_count
    rst_ratio = fv.get("tcp_rst_count", 0) / pkt_count
    
    # 🔥 FIX: Removed the * 0.2 so the UDP/ICMP tripwires fire at full strength
    udp_ratio = fv.get("udp_count", 0) / pkt_count
    icmp_ratio = fv.get("icmp_count", 0) / pkt_count

    # 2. VELOCITY FEATURES (scaled)
    pps = pkt_count / duration
    bps = total_bytes / duration

    # 🔥 FIX: Matched the caps to training.py
    pps = norm(pps, 50000.0)
    bps = norm(bps, 10000000.0)

    # 3. FOOTPRINT FEATURES
    pkt_size_std = norm(fv.get("pkt_size_std", 0.0), 1500.0)
    avg_interarrival = norm(min(fv.get("avg_interarrival_ms", 0.0), 2000.0), 2000.0)
    unique_ports_log = norm(math.log1p(fv.get("unique_dst_ports_count", 0)), 10.0)
    packet_count_log = norm(math.log1p(pkt_count), 10.0)

    # 4. TIME FEATURE
    duration_log = norm(math.log1p(duration), 10.0)

    # FINAL VECTOR (11 FEATURES)
    return [
        syn_ratio, rst_ratio, udp_ratio, icmp_ratio,
        pps, bps, pkt_size_std, avg_interarrival,
        unique_ports_log, packet_count_log, duration_log
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
NODE_ID = "A"
def run_ml(key, fv, model, context, manual_vector=None):
    vector = build_ml_vector(fv)
    if manual_vector:
        vector = manual_vector
    else:
        vector = build_ml_vector(fv)
    label, dist = model.classify(vector)

    if not model.classes:
        return

    if label == "UNKNOWN":
        print(f"[ML][{context}] UNKNOWN behavior from {key} (dist={dist:.2f})")
        unknown_buffer.add(vector)
        
        # ==========================================
        # PERSISTENT DYNAMIC NAMING (ZD_Local_X#_...)
        # ==========================================
        max_id = 0
        search_prefix = f"ZD_Local_{NODE_ID}"
        
        # Check existing classes in memory to find the highest number for THIS specific node
        for existing_label in model.classes.keys():
            if existing_label.startswith(search_prefix):
                # Splits "ZD_Local_A1_1712345678" into ["ZD", "Local", "A1", "1712345678"]
                parts = existing_label.split("_")
                if len(parts) >= 4:
                    node_and_num = parts[2] # Grabs the "A1" or "B1" part
                    try:
                        # Strip the Node ID letter(s) and convert the rest to an integer
                        num_str = node_and_num[len(NODE_ID):]
                        num = int(num_str) 
                        if num > max_id:
                            max_id = num
                    except ValueError:
                        pass # Ignore if it doesn't parse cleanly
        
        next_id = max_id + 1
        zd_name = f"ZD_Local_{NODE_ID}{next_id}_{int(time.time())}"
        # ==========================================
        
        model.add_example(zd_name, vector)
        model.save("/root/app/model.json")
        print(f"   [+] Local immunity generated: {zd_name}")
        
        # Push to Hive Mind
        try:
            payload = {
                "label": zd_name,  
                "prototype": vector, 
                "container_id": swarm.my_ip
            }
            # Use dynamic URL from the Swarm Manager
            requests.post(f"{swarm.get_leader_url()}/update_global_model", json=payload, timeout=2)
            print(f"   [FL-SYNC] 🌐 Successfully beamed {zd_name} to the Hive Mind!")
        except Exception as e:
            print(f"   [FL-ERROR] Could not reach Leader: {e}")
            
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
    #run_ml(key, fv, model, context="WINDOW") #it is removed
    


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