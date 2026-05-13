from flask import Flask, request
import yaml

app = Flask(__name__)


@app.post("/load")
def load_yaml():
    return yaml.load(request.data, Loader=yaml.Loader)
