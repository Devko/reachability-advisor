from fastapi import FastAPI, Request
import requests

app = FastAPI()


@app.get("/fetch")
def fetch(request: Request):
    return requests.get(request.query_params["url"]).text
