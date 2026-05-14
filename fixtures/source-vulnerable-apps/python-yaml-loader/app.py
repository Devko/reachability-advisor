import yaml
from flask import Flask, request

app = Flask(__name__)


@app.post("/load")
def load_yaml():
    return yaml.load(request.data, Loader=yaml.Loader)
