import threading
import time
from collections import defaultdict
from typing import Callable
from scapy.layers.inet import IP, TCP, UDP


# ----------------------------
# Flow key extractor (5-tuple)
# ----------------------------
def default_flow_key(pkt):
    try:
        if IP not in pkt:
            return None

        ip = pkt[IP]
        proto = ip.proto

        if proto == 6 and TCP in pkt:  # TCP
            return (
                ip.src,
                ip.dst,
                pkt[TCP].sport,
                pkt[TCP].dport,
                "TCP"
            )

        elif proto == 17 and UDP in pkt:  # UDP
            return (
                ip.src,
                ip.dst,
                pkt[UDP].sport,
                pkt[UDP].dport,
                "UDP"
            )

        else:
            return (ip.src, ip.dst, 0, 0, str(proto))

    except Exception:
        return "unknown"


# ----------------------------
# Flow Manager
# ----------------------------
class FlowManager:
    def __init__(
        self,
        flow_timeout: float = 5.0,     # Idle timeout: seconds of inactivity
        active_timeout: float = 30.0,  # 🔥 NEW: Active timeout: max lifespan of a flow
        emit_interval: float = 1.0,
        max_flows: int = 5000,
        keyfn: Callable = None,
        packet_capacity_per_flow: int = 100,
    ):
        """
        flow_timeout: seconds of inactivity before flow is emitted
        active_timeout: maximum seconds a flow can stay open before forced emission
        emit_interval: how often to check flows
        max_flows: max number of flows (memory safety)
        packet_capacity_per_flow: max packets per flow
        """

        self.flow_timeout = float(flow_timeout)
        self.active_timeout = float(active_timeout) # Apply active timeout
        self.emit_interval = float(emit_interval)
        self.max_flows = int(max_flows)
        self.packet_capacity_per_flow = int(packet_capacity_per_flow)

        self.keyfn = keyfn if keyfn else default_flow_key

        # flow_key -> {"pkts": [...], "last_seen": timestamp, "start_time": timestamp}
        self.flows = {}
        self.lock = threading.Lock()

        self.running = False
        self._worker = None
        self._callback = None

    # ----------------------------
    # Set callback
    # ----------------------------
    def set_flow_callback(self, fn: Callable):
        self._callback = fn

    # ----------------------------
    # Add packet
    # ----------------------------
    def add_packet(self, pkt):

        key = self.keyfn(pkt)
        if key is None:
            return

        ts = getattr(pkt, "time", time.time())

        with self.lock:

            if key not in self.flows:
                self.flows[key] = {
                    "pkts": [],
                    "last_seen": ts,
                    "start_time": ts  # 🔥 NEW: Record exactly when the flow was created
                }

            flow = self.flows[key]

            flow["pkts"].append(pkt)
            flow["last_seen"] = ts

            # enforce per-flow packet cap
            if len(flow["pkts"]) > self.packet_capacity_per_flow:
                flow["pkts"].pop(0)

            # global safety: remove oldest flows
            if len(self.flows) > self.max_flows:
                self._evict_oldest_flow()

    # ----------------------------
    # Evict oldest flow
    # ----------------------------
    def _evict_oldest_flow(self):
        oldest_key = min(self.flows, key=lambda k: self.flows[k]["last_seen"])
        del self.flows[oldest_key]

    # ----------------------------
    # Start / Stop
    # ----------------------------
    def start(self):
        if self.running:
            return

        self.running = True
        self._worker = threading.Thread(target=self._loop, daemon=True)
        self._worker.start()

    def stop(self):
        self.running = False
        if self._worker:
            self._worker.join(timeout=2.0)

    # ----------------------------
    # Background loop
    # ----------------------------
    def _loop(self):

        while self.running:

            now = time.time()

            with self.lock:
                keys = list(self.flows.keys())

            for key in keys:
                self._check_flow_timeout(key, now)

            time.sleep(self.emit_interval)

    # ----------------------------
    # Flow timeout check
    # ----------------------------
    def _check_flow_timeout(self, key, now):

        with self.lock:
            if key not in self.flows:
                return

            flow = self.flows[key]

            idle_time = now - flow["last_seen"]
            active_time = now - flow["start_time"]

            # 🔥 NEW: Check BOTH idle and active timeouts. 
            # If neither threshold is crossed, keep the flow in memory.
            if idle_time < self.flow_timeout and active_time < self.active_timeout:
                return

            pkts = flow["pkts"]
            del self.flows[key]

        if pkts and self._callback:
            try:
                self._callback(key, pkts)
            except Exception as e:
                print("[flowing] callback error:", e)