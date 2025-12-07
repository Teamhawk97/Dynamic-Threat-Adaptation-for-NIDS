from scapy.all import sniff
from detection import handle_packet

def start_sniffer():
    sniff(prn=handle_packet, store=False)
