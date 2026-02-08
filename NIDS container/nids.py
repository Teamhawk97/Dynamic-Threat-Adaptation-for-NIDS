# nids.py
from sniffer import start_sniffer
from model import PrototypeClassifier
import os

MODEL_PATH = "/root/app/model.json"

def main():
    print("[NIDS] Starting NIDS...")

    # Create or load model
    model = PrototypeClassifier.load(MODEL_PATH)

    if not model.classes:
        print("[ML] No existing model found. Starting fresh.")
    else:
        print(f"[ML] Loaded model with classes: {list(model.classes.keys())}")

    # Start sniffer and pass model reference
    start_sniffer(model)

if __name__ == "__main__":
    main()
