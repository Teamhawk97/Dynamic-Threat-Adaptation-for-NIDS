# windowing.py
"""
Lightweight sliding-window packet aggregator.

Usage:
    from windowing import WindowManager

    def on_window(key, pkts):
        # pkts is a list of scapy packets within the window for that key
        features = extract_features_from_pkts(pkts)
        classify_and_act(key, features)

    wm = WindowManager(window_seconds=1.0, emit_interval=0.5, max_pkts=500, keyfn=lambda p: p[IP].src)
    wm.set_window_callback(on_window)
    wm.start()
    # call wm.add_packet(pkt) from the scapy prn callback
    # when done, wm.stop()
"""

import threading
import time
from collections import defaultdict, deque
from typing import Callable
from scapy.layers.inet import IP


# default: group by src IP (safe for many NIDS tasks)
def default_keyfn(pkt):
    try:
        if IP in pkt:
            return pkt[IP].src
        else:
            return None   # ignore packets that don't have IP layer (ARP, LLDP, etc.)
    except Exception:
        return "unknown"

class WindowManager:
    def __init__(self,
                 window_seconds: float = 1.0,
                 emit_interval: float = 0.5,
                 max_pkts: int = 5000,
                 keyfn: Callable = None,
                 packet_capacity_per_key: int = 1000):
        """
        window_seconds: sliding window length in seconds (e.g. 1.0)
        emit_interval: how often to evaluate windows and emit completed windows (seconds)
        max_pkts: global safety cap for memory (evict oldest keys if exceeded)
        keyfn: function(pkt) -> key (default uses pkt[IP].src)
        packet_capacity_per_key: max packets retained per key
        """
        self.window_seconds = float(window_seconds)
        self.emit_interval = float(emit_interval)
        self.max_pkts = int(max_pkts)
        self.packet_capacity_per_key = int(packet_capacity_per_key)
        self.keyfn = keyfn if keyfn is not None else default_keyfn

        # per-key deque of (timestamp, packet)
        self.windows = defaultdict(deque)
        self.windows_lock = threading.Lock()
        self.running = False
        self._worker = None
        self._callback = None  # function(key, list_of_pkts)
        self._last_gc = time.time()

    def set_window_callback(self, fn: Callable[[str, list], None]):
        """Set function called when a window is emitted."""
        self._callback = fn

    def add_packet(self, pkt):
        """Add a scapy packet into the window store."""
        try:
            key = self.keyfn(pkt)
            if key is None:
                return
        except Exception:
            key = "unknown"

        ts = getattr(pkt, "time", time.time())
        with self.windows_lock:
            dq = self.windows[key]
            dq.append((ts, pkt))
            # enforce per-key capacity
            if len(dq) > self.packet_capacity_per_key:
                # drop oldest
                dq.popleft()

            # global GC if too many packets across all keys
            total_pkts = sum(len(dq2) for dq2 in self.windows.values())
            if total_pkts > self.max_pkts and (time.time() - self._last_gc) > 1.0:
                self._garbage_collect()
                self._last_gc = time.time()

    def _garbage_collect(self):
        """Simple GC: remove oldest entry from largest queues."""
        # very simple heuristic: prune half of the keys' oldest items
        keys = list(self.windows.keys())
        keys.sort(key=lambda k: -len(self.windows[k]))  # largest first
        for k in keys[:max(1, len(keys)//3)]:
            dq = self.windows[k]
            remove_n = max(1, len(dq)//2)
            for _ in range(remove_n):
                if dq:
                    dq.popleft()
            if not dq:
                del self.windows[k]

    def start(self):
        if self.running:
            return
        self.running = True
        self._worker = threading.Thread(target=self._emit_loop, daemon=True)
        self._worker.start()

    def stop(self):
        self.running = False
        if self._worker:
            self._worker.join(timeout=2.0)

    def _emit_loop(self):
        while self.running:
            now = time.time()
            # copy keys to avoid holding lock long
            with self.windows_lock:
                keys = list(self.windows.keys())
            for key in keys:
                self._maybe_emit_for_key(key, now)
            time.sleep(self.emit_interval)

    def _maybe_emit_for_key(self, key, now_ts):
        """Emit a list of packets for a key that are within the sliding window."""
        with self.windows_lock:
            if key not in self.windows:
                return
            dq = self.windows[key]

            # remove items older than (now - window_seconds)
            cutoff = now_ts - self.window_seconds
            # find first index that >= cutoff
            # since deque doesn't support bisect, pop left until oldest >= cutoff
            while dq and dq[0][0] < cutoff:
                dq.popleft()

            # after pruning, if there are packets, emit them as a snapshot copy
            if dq:
                snapshot = [p for (_t, p) in dq]
            else:
                snapshot = []

        if snapshot and self._callback:
            try:
                # callback must be fast; heavy processing should be offloaded
                self._callback(key, snapshot)
            except Exception as e:
                # never let user callback break the loop
                print("[windowing] callback error:", e)
