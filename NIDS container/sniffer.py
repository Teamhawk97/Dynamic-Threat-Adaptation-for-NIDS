
from scapy.all import sniff
from detection import analyze_packet
from windowing import WindowManager
from detection import handle_window

# choose grouping: by src IP (default) or lambda pkt: (pkt[IP].src, pkt[IP].dst)
wm = WindowManager(window_seconds=1.0, emit_interval=0.5, max_pkts=5000, packet_capacity_per_key=1000)

def wm_callback(key, pkts):
    """
    key: the grouping key (e.g. source IP)
    pkts: list of scapy packets within the window
    """
    # Send to your detection pipeline (feature extraction + classifier)
    handle_window(key, pkts)

wm.set_window_callback(wm_callback)

def combined_handler(pkt):
    analyze_packet(pkt)     # per-packet logic (optional)
    wm.add_packet(pkt)  

def start_sniffer(interface="eth0"):
    print(f"[+] Starting packet capture on {interface} ...")
    wm.start()
    sniff(iface=interface, prn=combined_handler, store=False)


    #sniff(iface=interface, prn=analyze_packet, store=False)
    #sniff(iface=interface, prn=wm.add_packet, store=False)
    #sniff(... prn=wm.add_packet ...) means each packet is handed to WindowManager.add_packet.
    #WindowManager periodically calls wm_callback with a snapshot of packets in that key window.
