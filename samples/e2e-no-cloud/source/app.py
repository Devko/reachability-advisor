from fastapi import FastAPI, Request
import requests

app = FastAPI()


@app.get("/proxy")
async def proxy(request: Request):
    url = request.query_params["url"]
    return requests.get(url, timeout=2).text
