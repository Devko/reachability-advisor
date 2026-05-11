from fastapi import FastAPI, Request
import requests

app = FastAPI()


@app.get("/proxy")
async def proxy(request: Request):
    target = request.query_params.get("url")
    response = requests.get(target)
    return {"status": response.status_code}
