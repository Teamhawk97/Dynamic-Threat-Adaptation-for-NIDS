import json
import os
import math
from typing import List, Dict

# 🔥 FIX 1: Point to the Shared Docker Volume!
MODEL_FILE = "/shared/global_model.json"
MERGE_THRESHOLD = 0.15

# Global state
global_classes: Dict[str, dict] = {}

def load_memory():
    """Wakes up and reads the hard drive."""
    global global_classes
    if os.path.exists(MODEL_FILE):
        # 🔥 FIX 2: Protect against empty/corrupted JSON files!
        try:
            with open(MODEL_FILE, "r") as f:
                global_classes = json.load(f)
            print(f"[LEADER-MODEL] Memory Restored: Loaded {len(global_classes)} immunities from disk.")
        except json.JSONDecodeError:
            print("[LEADER-MODEL] ⚠️ Shared memory file is empty. Starting fresh.")
            global_classes = {}
    else:
        global_classes = {}

def save_memory():
    """Saves the current state to the hard drive."""
    with open(MODEL_FILE, "w") as f:
        # I added indent=4 just so it's readable if you ever open the file!
        json.dump(global_classes, f, indent=4) 

def euclidean_distance(v1: List[float], v2: List[float]) -> float:
    """Calculates the mathematical difference between two attacks."""
    return math.sqrt(sum((a - b) ** 2 for a, b in zip(v1, v2)))

def process_update(incoming_label: str, incoming_vector: List[float], container_id: str) -> dict:
    """Handles the deduplication and merging logic."""
    global global_classes
    closest_label = None
    min_dist = float('inf')
    
    # Check incoming against known attacks
    for existing_label, data in global_classes.items():
        dist = euclidean_distance(incoming_vector, data["prototype"])
        if dist < min_dist:
            min_dist = dist
            closest_label = existing_label
            
    # Merge if it's the same attack
    if closest_label and min_dist < MERGE_THRESHOLD:
        data = global_classes[closest_label]
        n = data["count"]
        global_classes[closest_label]["prototype"] = [
            (data["prototype"][i] * n + incoming_vector[i]) / (n + 1)
            for i in range(len(incoming_vector))
        ]
        global_classes[closest_label]["count"] = n + 1
        print(f"[LEADER-MODEL] DEDUPLICATED: Merged '{incoming_label}' into '{closest_label}' (Dist: {min_dist:.2f})")
        
        save_memory()
        return {"status": "merged", "true_label": closest_label}
        
    # Create brand new attack
    global_classes[incoming_label] = {"prototype": incoming_vector, "count": 1}
    print(f"[LEADER-MODEL] 🌐 NEW Global Immunity: {incoming_label} (From: {container_id})")
    
    save_memory()
    return {"status": "created", "true_label": incoming_label}

# Automatically load memory when this file is imported
load_memory()