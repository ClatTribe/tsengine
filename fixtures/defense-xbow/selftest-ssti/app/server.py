import http.server, urllib.parse, re

def render(tpl):
    # VULNERABLE naive template engine: evaluates {{ expr }} -> SSTI / RCE
    return re.sub(r"\{\{(.+?)\}\}", lambda m: str(eval(m.group(1))), tpl)

class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_GET(self):
        u = urllib.parse.urlparse(self.path)
        if u.path == "/":
            self.send_response(200); self.end_headers()
            self.wfile.write(b"greeting: /hello?name=World"); return
        if u.path == "/hello":
            name = urllib.parse.parse_qs(u.query).get("name", ["World"])[0]
            try:
                page = render("<h1>Hello " + name + "</h1>")
                self.send_response(200); self.end_headers(); self.wfile.write(page.encode())
            except Exception as e:
                self.send_response(500); self.end_headers(); self.wfile.write(str(e).encode())
            return
        self.send_response(404); self.end_headers()

http.server.HTTPServer(("0.0.0.0", 8000), H).serve_forever()
