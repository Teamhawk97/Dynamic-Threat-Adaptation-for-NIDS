# utils.py
from scapy.layers.inet import IP, TCP, UDP, ICMP

def extract_features(pkt):
    if IP not in pkt:
        return None

    features = {
        "src": pkt[IP].src,
        "dst": pkt[IP].dst,
        "proto": pkt[IP].proto
    }

    # TCP PACKETS
    if TCP in pkt:
        features["dst_port"] = pkt[TCP].dport
        features["flags"] = pkt[TCP].flags

    # UDP PACKETS
    elif UDP in pkt:
        features["dst_port"] = pkt[UDP].dport
        features["flags"] = None

    # ICMP (no port)
    elif ICMP in pkt:
        features["dst_port"] = None
        features["flags"] = None

    else:
        return None

    return features
