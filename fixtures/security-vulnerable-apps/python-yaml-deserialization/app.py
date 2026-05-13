from flask import Flask, request
import yaml

app = Flask(__name__)


@app.post("/import")
def import_yaml():
    return yaml.load(request.data, Loader=yaml.Loader)
