import sqlite3

from flask import Flask, request

app = Flask(__name__)


@app.get("/user")
def user_lookup():
    user_id = request.args["id"]
    db = sqlite3.connect("app.db")
    return db.execute(f"select * from users where id = {user_id}").fetchone()
