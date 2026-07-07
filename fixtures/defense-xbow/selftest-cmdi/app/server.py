import http.server, urllib.parse, subprocess

class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_GET(self):
        u = urllib.parse.urlparse(self.path)
        if u.path == "/":
            self.send_response(200); self.end_headers()
            self.wfile.write(b"diag: /ping?host=example.com"); return
        if u.path == "/ping":
            host = urllib.parse.parse_qs(u.query).get("host", ["localhost"])[0]
            # VULNERABLE: shell command injection -> ?host=x; cat /flag.txt
            try:
                out = subprocess.check_output("echo pinging " + host, shell=True,
                                              stderr=subprocess.STDOUT, timeout=5)
                self.send_response(200); self.end_headers(); self.wfile.write(out)
            except Exception as e:
                self.send_response(500); self.end_headers(); self.wfile.write(str(e).encode())
            return
        self.send_response(404); self.end_headers()

http.server.HTTPServer(("0.0.0.0", 8000), H).serve_forever()
