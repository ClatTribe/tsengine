import http.server, urllib.parse

FLAG = open("/flag.txt").read().strip()
NOTES = {1: ("alice", "alice's shopping list"), 2: ("admin", FLAG)}

def current_user(headers):
    for part in headers.get("Cookie", "").split(";"):
        part = part.strip()
        if part.startswith("user="):
            return part[5:]
    return ""

class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_GET(self):
        u = urllib.parse.urlparse(self.path)
        if u.path == "/":
            self.send_response(200); self.end_headers()
            self.wfile.write(b"notes app: GET /note?id=1 with Cookie: user=alice"); return
        if u.path == "/note":
            try:
                nid = int(urllib.parse.parse_qs(u.query).get("id", ["0"])[0])
            except ValueError:
                nid = 0
            if nid not in NOTES:
                self.send_response(404); self.end_headers(); return
            owner, body = NOTES[nid]
            # VULNERABLE: no ownership check -> any logged-in user reads any note (IDOR)
            self.send_response(200); self.end_headers(); self.wfile.write(body.encode())
            return
        self.send_response(404); self.end_headers()

http.server.HTTPServer(("0.0.0.0", 8000), H).serve_forever()
