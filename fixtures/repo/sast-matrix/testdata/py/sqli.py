import sqlite3
from flask import request
def h():
    c = sqlite3.connect("d.db").cursor()
    c.execute("SELECT * FROM users WHERE name = '" + request.args.get("n","") + "'")
