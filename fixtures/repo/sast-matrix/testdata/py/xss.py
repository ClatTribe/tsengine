from flask import request
def h(): return "<h1>" + request.args.get("name", "") + "</h1>"
