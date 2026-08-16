import os
from flask import request
def h(): os.system("ping -c 1 " + request.args.get("host",""))
