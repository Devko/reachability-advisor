import requests
from fastapi import FastAPI, Request

app = FastAPI()


@app.get("/proxy")
async def proxy(request: Request):
    url = request.query_params["url"]
    return requests.get(url, timeout=2).text
