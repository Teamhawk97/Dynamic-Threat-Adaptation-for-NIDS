import builtins
import threading
import time
import requests

# ==========================================
# NODE IDENTITY
# ==========================================
NODE_ID = "A" # <-- Set to A for Victim 1, B for Victim 2

# ==========================================
# 🪄 THE LOG SHIPPER OVERRIDE
# ==========================================
if not getattr(builtins, "dashboard_active", False):
    builtins.dashboard_active = True
    builtins.local_log_buffer = []
    builtins.original_print = builtins.print

    def custom_print(*args, **kwargs):
        builtins.original_print(*args, **kwargs)
        msg = " ".join(str(a) for a in args)
        builtins.local_log_buffer.append(msg)

    builtins.print = custom_print
# ==========================================

from sniffer import start_sniffer
from model import PrototypeClassifier
from swarm_manager import swarm
import os
import numpy as np

MODEL_PATH = "/root/app/model.json"

from detection import run_ml

def manual_injection_loop(model):
    """Watches for inject.txt to manually feed the ML model during live demos"""
    while True:
        time.sleep(1) 
        if os.path.exists("inject.txt"):
            try:
                with open("inject.txt", "r") as f:
                    line = f.read().strip()
                
                if line:
                    parts = line.split(",")
                    # Convert everything to floats
                    values = [float(x) for x in parts]
                    
                    print(f"\n[🔬 DEMO INJECT] Manual Vector Received: {values}")

                    # If you provided exactly 11 features, we bypass build_ml_vector!
                    if len(values) == 11:
                        # We call run_ml but pass the vector directly as a 'pre_built_vector'
                        # We need a tiny tweak to run_ml to handle this (see below)
                        run_ml("DEMO_INJECTOR", {}, model, context="MANUAL", manual_vector=values)
                    else:
                        print("[🚨 ERROR] Injection must be exactly 11 features!")
                        
            except Exception as e:
                print(f"[🚨 INJECT ERROR] {e}")
            finally:
                if os.path.exists("inject.txt"): os.remove("inject.txt")

def log_shipper_loop():
    """Runs in the background, sending logs to the Leader every 1.5 seconds"""
    while True:
        time.sleep(1.5)
        if builtins.local_log_buffer:
            # Grab the logs and empty the local buffer immediately
            logs_to_send = builtins.local_log_buffer.copy()
            builtins.local_log_buffer.clear()
            
            try:
                payload = {"node_id": NODE_ID, "logs": logs_to_send}
                requests.post(f"{swarm.get_leader_url()}/submit_logs", json=payload, timeout=1)
            except Exception:
                # If leader is down/electing, drop the logs to prevent memory leaks
                pass

def main():
    print(f"[NIDS] Starting Log Forwarder NIDS on {swarm.my_ip}...")
    global_model_ref = PrototypeClassifier.load(MODEL_PATH)

    if not global_model_ref.classes:
        print("[ML] No existing model found. Starting fresh.")
    else:
        print(f"[ML] Loaded model with classes: {list(global_model_ref.classes.keys())}")

    # 1. Start Swarm Heartbeat
    threading.Thread(target=swarm.heartbeat_loop, args=(global_model_ref,), daemon=True).start()

    # 2. Start Log Shipper
    threading.Thread(target=log_shipper_loop, daemon=True).start()

    # 3. Start Manual Injection Loop (for demos)
    threading.Thread(target=manual_injection_loop, args=(global_model_ref,), daemon=True).start()

    # 4. Main Thread: The Sniffer! (No GIL contention!)
    start_sniffer(global_model_ref)

    if swarm.is_leader:
        print("[SWARM] Sniffer retired. Swarm Manager is booting the Leader API...")
        while True:
            time.sleep(10)

if __name__ == "__main__":
    main()