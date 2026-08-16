import requests
from flask import request
def h(): return requests.get(request.args.get("url","")).text
