from flask import request
def h(): return open("/var/data/" + request.args.get("f","")).read()
