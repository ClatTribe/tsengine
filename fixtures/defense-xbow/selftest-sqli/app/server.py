import http.server, urllib.parse, sqlite3

FLAG = open("/flag.txt").read().strip()
db = sqlite3.connect(":memory:", check_same_thread=False)
db.execute("CREATE TABLE users(id INTEGER, name TEXT)")
db.executemany("INSERT INTO users VALUES (?,?)", [(1, "alice"), (2, "bob"), (99, FLAG)])
db.commit()

class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_GET(self):
        u = urllib.parse.urlparse(self.path)
        if u.path == "/":
            self.send_response(200); self.end_headers()
            self.wfile.write(b"user lookup: /user?id=1"); return
        if u.path == "/user":
            i = urllib.parse.parse_qs(u.query).get("id", ["1"])[0]
            # VULNERABLE: string-built SQL -> ?id=1 OR 1=1 returns every row incl. the flag row
            try:
                rows = db.execute("SELECT name FROM users WHERE id = %s" % i).fetchall()
                self.send_response(200); self.end_headers()
                self.wfile.write(("\n".join(r[0] for r in rows)).encode())
            except Exception as e:
                self.send_response(500); self.end_headers(); self.wfile.write(str(e).encode())
            return
        self.send_response(404); self.end_headers()

http.server.HTTPServer(("0.0.0.0", 8000), H).serve_forever()
