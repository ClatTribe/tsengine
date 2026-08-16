from flask import request, render_template_string
def h(): return render_template_string("Hello " + request.args.get("n", ""))
