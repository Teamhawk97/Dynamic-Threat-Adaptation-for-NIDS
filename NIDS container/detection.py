from scapy.all import IP, TCP, UDP
from collections import defaultdict
import time
from utils import log_alert, log_notice

# ===== THRESHOLDS =====
DOS_THRESHOLD = 50
PORT_SCAN_THRESHOLD = 10
SUSPICIOUS_PORTS = {22, 23, 3389}

# ===== STATE =====
packet_timestamps = defaultdict(list)
ports_seen = defaultdict(set)

def check_dos(src, dst, now):
    key = (src, dst)
    packet_timestamps[key].append(now)

    packet_timestamps[key] = [
        t for t in packet_timestamps[key] if now - t <= 1.0
    ]

    if len(packet_timestamps[key]) > DOS_THRESHOLD:
        log_alert(f"DoS attack detected: High rate from {src} -> {dst} ({len(packet_timestamps[key])}/s)")

def check_port_scan(src, dst, dport):
    if dport is None:
        return
    key = (src, dst)
    ports_seen[key].add(dport)

    if len(ports_seen[key]) == PORT_SCAN_THRESHOLD + 1:
        log_alert(f"Port scan detected from {src} -> {dst}. Ports: {list(ports_seen[key])[:10]}")

def check_suspicious_port(src, dst, dport):
    if dport in SUSPICIOUS_PORTS:
        log_notice(f"Suspicious port access: {src} -> {dst} on port {dport}")

def get_ports(pkt):
    dport = None
    sport = None
    if TCP in pkt:
        sport = pkt[TCP].sport
        dport = pkt[TCP].dport
    elif UDP in pkt:
        sport = pkt[UDP].sport
        dport = pkt[UDP].dport
    return sport, dport

def handle_packet(pkt):
    if IP not in pkt:
        return

    src = pkt[IP].src
    dst = pkt[IP].dst
    now = time.time()

    sport, dport = get_ports(pkt)

    check_dos(src, dst, now)
    check_port_scan(src, dst, dport)
    check_suspicious_port(src, dst, dport)
