# sniffer.py
from scapy.all import sniff
from detection import analyze_packet, handle_window
from windowing import WindowManager

# Window manager is fine as a module-level object
wm = WindowManager(
    window_seconds=1.0,
    emit_interval=0.5,
    max_pkts=5000,
    packet_capacity_per_key=1000
)

def start_sniffer(model, interface="eth0"):
    print(f"[+] Starting packet capture on {interface} ...")

    # define callback WITH access to model (closure)
    def wm_callback(key, pkts):
        """
        key: the grouping key (e.g. source IP)
        pkts: list of scapy packets within the window
        """
        handle_window(key, pkts, model)

    wm.set_window_callback(wm_callback)
    wm.start()

    def combined_handler(pkt):
        analyze_packet(pkt)   # still empty (correct)
        wm.add_packet(pkt)

    sniff(
        iface=interface,
        prn=combined_handler,
        store=False
    )
