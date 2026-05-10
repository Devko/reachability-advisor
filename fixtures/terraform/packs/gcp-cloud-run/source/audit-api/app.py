from flask import Flask, request
import requests

app = Flask(__name__)

@app.route('/audit')
def audit():
    target = request.args.get('url')
    response = requests.get(target)
    return response.text
