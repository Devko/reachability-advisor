import requests
from flask import Flask, request

app = Flask(__name__)

@app.route('/orders', methods=['POST'])
def create_order():
    payload = request.json or {}
    callback = payload.get('callback_url')
    if callback:
        requests.post(callback, json=payload, timeout=2)
    return {'status': 'ok'}
