import uvicorn
from fastapi import FastAPI
from pydantic import BaseModel
from typing import List

# Import our dedicated math and memory logic!
import global_model 

app = FastAPI(title="NIDS Federated Leader API")

class UpdateRequest(BaseModel):
    label: str
    prototype: List[float]
    container_id: str

@app.post("/update_global_model")
def update_global_model(req: UpdateRequest):
    # The API doesn't do any math. It just hands the data to the model logic.
    result = global_model.process_update(req.label, req.prototype, req.container_id)
    return result

@app.get("/get_global_model")
def get_global_model():
    # Fetch the state directly from the global_model file
    return {"classes": global_model.global_classes}

@app.get("/health")
def health_check():
    return {"status": "alive"}

if __name__ == "__main__":
    print("[+] Starting Leader API on port 8000...")
    uvicorn.run(app, host="0.0.0.0", port=8000)