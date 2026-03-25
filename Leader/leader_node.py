import uvicorn
from fastapi import FastAPI
from pydantic import BaseModel
from typing import List, Dict

# We will use this later when you build your dashboard!
# from fastapi.templating import Jinja2Templates
# from fastapi import WebSocket

app = FastAPI(title="NIDS Federated Leader")

# Global memory to store the Zero-Day immunities
global_classes: Dict[str, dict] = {}

class UpdateRequest(BaseModel):
    label: str
    prototype: List[float]
    container_id: str

@app.post("/update_global_model")
def update_global_model(req: UpdateRequest):
    global global_classes
    label = req.label
    vector = req.prototype
    
    if label not in global_classes:
        global_classes[label] = {"prototype": vector, "count": 1}
        print(f"[LEADER] 🌐 NEW Global Immunity: {label} (From: {req.container_id})")
    else:
        # Refine the math if another container reports the same attack
        data = global_classes[label]
        n = data["count"]
        global_classes[label]["prototype"] = [
            (data["prototype"][i] * n + vector[i]) / (n + 1)
            for i in range(len(vector))
        ]
        global_classes[label]["count"] = n + 1
        print(f"[LEADER] 🔄 Refined Immunity: {label} (From: {req.container_id})")
    
    return {"status": "success"}

@app.get("/get_global_model")
def get_global_model():
    return {"classes": global_classes}

if __name__ == "__main__":
    print("[+] Starting Leader Node on port 8000...")
    uvicorn.run(app, host="0.0.0.0", port=8000)