# utils.py
from scapy.layers.inet import IP, TCP, UDP, ICMP
import numpy as np


def features_from_packets(pkts):
    """
    Input: list of scapy packets
    Output: dict of flow/window features
    """

    if not pkts:
        return {}

    pkt_sizes = []
    unique_dst_ports = set()
    tcp_syn = tcp_rst = tcp_ack = udp_count = icmp_count = 0
    timestamps = []

    # ----------------------------
    # Packet loop
    # ----------------------------
    for p in pkts:

        ts = getattr(p, "time", None)
        if ts is not None:
            timestamps.append(ts)

        try:
            size = len(p)
            pkt_sizes.append(size)
        except Exception:
            size = 0
            pkt_sizes.append(0)

        if TCP in p:
            flags = p[TCP].flags

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

    # ----------------------------
    # Basic stats
    # ----------------------------
    pkt_count = len(pkts)

    avg_pkt_size = float(np.mean(pkt_sizes)) if pkt_sizes else 0.0
    std_pkt_size = float(np.std(pkt_sizes)) if pkt_sizes else 0.0

    total_bytes = float(np.sum(pkt_sizes)) if pkt_sizes else 0.0

    # ----------------------------
    # Time features
    # ----------------------------
    if timestamps and len(timestamps) > 1:
        flow_duration = max(timestamps) - min(timestamps)
    else:
        flow_duration = 0.0

    # Interarrival
    interarrival = 0.0
    if len(timestamps) > 1:
        timestamps.sort()
        diffs = [t2 - t1 for t1, t2 in zip(timestamps, timestamps[1:])]
        interarrival = float(np.mean(diffs)) * 1000.0  # ms

    # ----------------------------
    # Rate features (NEW)
    # ----------------------------
    duration_safe = max(flow_duration, 0.001)

    packets_per_second = pkt_count / duration_safe
    bytes_per_second = total_bytes / duration_safe

    # ----------------------------
    # Final feature dict
    # ----------------------------
    features = {
        "packet_count": pkt_count,
        "total_bytes": total_bytes,

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

        "packets_per_second": packets_per_second,
        "bytes_per_second": bytes_per_second,

        "ratio_tcp_to_total": (
            (tcp_syn + tcp_rst + tcp_ack) / pkt_count
            if pkt_count else 0.0
        ),
    }

    return features