# sniffer.py

from scapy.all import sniff
from detection import analyze_packet, handle_window, handle_flow
from windowing import WindowManager
from flowing import FlowManager
from swarm_manager import swarm

# ----------------------------
# TOGGLES
# ----------------------------
USE_WINDOW = True
USE_FLOW = True

# ----------------------------
# Managers
# ----------------------------
wm = WindowManager(
    window_seconds=1.0,
    emit_interval=0.5,
    max_pkts=5000,
    packet_capacity_per_key=1000
)

fm = FlowManager(
    flow_timeout=2.0,
    active_timeout=2.0,
    emit_interval=1.0,
    max_flows=1000,
    packet_capacity_per_flow=5000
)

def promotion_check(packet):
    if swarm.is_leader:
        print("\n[NIDS] Shutting down packet capture.")
        print("[SWARM] Transitioning to Dedicated Control Plane...\n")
        return True # Returning True tells Scapy to stop sniffing immediately!
    return False

def start_sniffer(model, interface="eth0"):
    print(f"[+] Starting packet capture on {interface} ...")

    # ----------------------------
    # WINDOW CALLBACK
    # ----------------------------
    if USE_WINDOW:
        def wm_callback(key, pkts):
            handle_window(key, pkts, model)

        wm.set_window_callback(wm_callback)
        wm.start()
        print("[+] WindowManager ENABLED")

    # ----------------------------
    # FLOW CALLBACK
    # ----------------------------
    if USE_FLOW:
        def fm_callback(flow_key, pkts):
            handle_flow(flow_key, pkts, model)

        fm.set_flow_callback(fm_callback)
        fm.start()
        print("[+] FlowManager ENABLED")

    # ----------------------------
    # Packet handler
    # ----------------------------
    def combined_handler(pkt):
        analyze_packet(pkt)

        if USE_WINDOW:
            wm.add_packet(pkt)

        if USE_FLOW:
            fm.add_packet(pkt)

    sniff(
        iface=interface,
        prn=combined_handler,
        store=False,
        filter="src net 172.16.0.0/12 and dst net 172.16.0.0/12",
        stop_filter=promotion_check
    )