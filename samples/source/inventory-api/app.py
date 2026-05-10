import requests
from fastapi import FastAPI, Request

app = FastAPI()


@app.post("/internal/reconcile")
async def reconcile(request: Request):
    payload = await request.json()
    callback = payload.get("callback", "https://inventory.internal/events")
    requests.post(callback, json=payload, timeout=2)
    return {"status": "queued"}
