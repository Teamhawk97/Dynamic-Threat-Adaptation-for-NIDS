from sniffer import start_sniffer
from model import PrototypeClassifier
import threading
from swarm_manager import swarm
import time

MODEL_PATH = "/root/app/model.json"

def main():
    print(f"[NIDS] Starting NIDS on {swarm.my_ip}...")
    model = PrototypeClassifier.load(MODEL_PATH)

    print("[+] Starting Swarm Heartbeat thread...")
    threading.Thread(target=swarm.heartbeat_loop, args=(model,), daemon=True).start()

    if not model.classes:
        print("[ML] No existing model found. Starting fresh.")
    else:
        print(f"[ML] Loaded model with classes: {list(model.classes.keys())}")

    start_sniffer(model)

    if swarm.is_leader:
        print("[SWARM] Sniffer retired. Main thread standing by to keep the Dashboard alive...")
        while True:
            time.sleep(10)

if __name__ == "__main__":
    main()