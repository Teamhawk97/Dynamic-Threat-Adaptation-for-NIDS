import builtins
import uvicorn
import os
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List
from fastapi.responses import FileResponse

# Master Log Storage for all 3 nodes
global_logs = {
    "leader": [],
    "A": [], # Victim 1
    "B": []  # Victim 2
}

# ==========================================
# 🪄 THE LEADER'S PRINT OVERRIDE
# ==========================================
if not getattr(builtins, "dashboard_active", False):
    builtins.dashboard_active = True
    builtins.original_print = builtins.print

    def custom_print(*args, **kwargs):
        builtins.original_print(*args, **kwargs)
        msg = " ".join(str(a) for a in args)
        global_logs["leader"].append(msg)
        if len(global_logs["leader"]) > 150:
            global_logs["leader"].pop(0)

    builtins.print = custom_print
# ==========================================

try:
    import global_model 
except ImportError:
    from leader_app import global_model

app = FastAPI(title="NIDS Federated Leader API")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

class UpdateRequest(BaseModel):
    label: str
    prototype: List[float]
    container_id: str

class LogSubmitRequest(BaseModel):
    node_id: str
    logs: List[str]

@app.post("/update_global_model")
def update_global_model(req: UpdateRequest):
    return global_model.process_update(req.label, req.prototype, req.container_id)

@app.get("/get_global_model")
def get_global_model():
    return {"classes": global_model.global_classes}

@app.get("/health")
def health_check():
    return {"status": "alive"}

# THE NEW LOG RECEIVER
@app.post("/submit_logs")
def receive_logs(req: LogSubmitRequest):
    if req.node_id in global_logs:
        global_logs[req.node_id].extend(req.logs)
        # Keep only the last 150 lines to save memory
        global_logs[req.node_id] = global_logs[req.node_id][-150:]
    return {"status": "received"}

# THE UNIFIED DASHBOARD ENDPOINT
@app.get("/api/dashboard")
def get_dashboard_data():
    return {
        "leader": {
            "status": "ONLINE (HIVE MIND)",
            "classes": list(global_model.global_classes.keys()),
            "logs": global_logs["leader"]
        },
        "victim1": {
            "status": "ONLINE (FORWARDING LOGS)",
            "logs": global_logs["A"]
        },
        "victim2": {
            "status": "ONLINE (FORWARDING LOGS)",
            "logs": global_logs["B"]
        }
    }

@app.get("/")
def serve_dashboard():
    if os.path.exists("index.html"): return FileResponse("index.html")
    if os.path.exists("../index.html"): return FileResponse("../index.html")
    return {"error": "index.html not found"}

if __name__ == "__main__":
    print("[+] Starting Central SIEM Leader API on port 8000...")
    uvicorn.run(app, host="0.0.0.0", port=8000, access_log=False)