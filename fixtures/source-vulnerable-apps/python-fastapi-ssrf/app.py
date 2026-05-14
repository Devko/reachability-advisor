import requests
from fastapi import FastAPI, Request

app = FastAPI()


@app.get("/fetch")
def fetch(request: Request):
    return requests.get(request.query_params["url"]).text
