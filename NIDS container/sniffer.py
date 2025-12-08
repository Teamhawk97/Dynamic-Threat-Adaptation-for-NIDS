
from scapy.all import sniff
from detection import analyze_packet

def start_sniffer(interface="eth0"):
    print(f"[+] Starting packet capture on {interface} ...")
    sniff(iface=interface, prn=analyze_packet, store=False)
