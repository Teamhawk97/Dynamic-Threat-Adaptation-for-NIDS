# utils.py
from scapy.layers.inet import IP, TCP, UDP, ICMP
import numpy as np


def features_from_packets(pkts):
    """
    Input: list of scapy packets.
    Output: dict of features (see plan).
    """
    if not pkts:
        return {}

    pkt_sizes = []
    unique_dst_ports = set()
    tcp_syn = tcp_rst = tcp_ack = udp_count = icmp_count = 0
    timestamps = []

    for p in pkts:
        # timestamps
        ts = getattr(p, "time", None)
        if ts is not None:
            timestamps.append(ts)
        # sizes
        try:
            pkt_sizes.append(len(p))
        except Exception:
            pkt_sizes.append(0)

        if TCP in p:
            flags = p[TCP].flags
            # Scapy flag check: 'S' in flags etc.
            if flags & 0x02:  # SYN
                tcp_syn += 1
            if flags & 0x04:  # RST
                tcp_rst += 1
            if flags & 0x10:  # ACK
                tcp_ack += 1
            try:
                unique_dst_ports.add(int(p[TCP].dport))
            except Exception:
                pass
        elif UDP in p:
            udp_count += 1
            try:
                unique_dst_ports.add(int(p[UDP].dport))
            except Exception:
                pass
        elif ICMP in p:
            icmp_count += 1

    pkt_count = len(pkts)
    avg_pkt_size = float(np.mean(pkt_sizes)) if pkt_sizes else 0.0
    std_pkt_size = float(np.std(pkt_sizes)) if pkt_sizes else 0.0
    flow_duration = (max(timestamps) - min(timestamps)) if timestamps and len(timestamps) > 1 else 0.0
    interarrival = 0.0
    if len(timestamps) > 1:
        diffs = [t2 - t1 for t1, t2 in zip(timestamps, timestamps[1:])]
        interarrival = float(np.mean(diffs)) * 1000.0  # ms

    features = {
        "packet_count": pkt_count,
        "unique_dst_ports_count": len(unique_dst_ports),
        "tcp_syn_count": tcp_syn,
        "tcp_rst_count": tcp_rst,
        "tcp_ack_count": tcp_ack,
        "udp_count": udp_count,
        "icmp_count": icmp_count,
        "avg_packet_size": avg_pkt_size,
        "pkt_size_std": std_pkt_size,
        "flow_duration": flow_duration,
        "avg_interarrival_ms": interarrival,
        "ratio_tcp_to_total": (tcp_syn + tcp_rst + tcp_ack) / pkt_count if pkt_count else 0.0
    }
    return features



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
