from flask import request, redirect
def h(): return redirect(request.args.get("next", ""))
