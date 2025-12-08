# detection.py
from utils import extract_features

PORT_SCAN_THRESHOLD = 10
ip_port_counter = {}

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
