import http.server, urllib.parse

class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_GET(self):
        u = urllib.parse.urlparse(self.path)
        if u.path == "/":
            self.send_response(200); self.end_headers()
            self.wfile.write(b"selftest app: try /read?file=<path>")
            return
        if u.path == "/read":
            f = urllib.parse.parse_qs(u.query).get("file", [""])[0]
            # VULNERABLE: arbitrary file read, no path validation → /read?file=/flag.txt leaks the flag
            try:
                with open(f, "rb") as fh:
                    data = fh.read()
                self.send_response(200); self.end_headers(); self.wfile.write(data)
            except Exception as e:
                self.send_response(404); self.end_headers(); self.wfile.write(str(e).encode())
            return
        self.send_response(404); self.end_headers()

http.server.HTTPServer(("0.0.0.0", 8000), H).serve_forever()
