import http.server, urllib.parse, sqlite3

FLAG = open("/flag.txt").read().strip()
db = sqlite3.connect(":memory:", check_same_thread=False)
db.execute("CREATE TABLE users(id INTEGER, name TEXT)")
db.executemany("INSERT INTO users VALUES (?,?)", [(1, "alice"), (2, "bob"), (3, "carol")])
db.execute("CREATE TABLE secrets(token TEXT)")   # the flag is here — NOT exposed by any endpoint
db.execute("INSERT INTO secrets VALUES (?)", (FLAG,))
db.commit()

class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_GET(self):
        u = urllib.parse.urlparse(self.path)
        if u.path == "/":
            self.send_response(200); self.end_headers()
            self.wfile.write(b"user search: /search?name=al"); return
        if u.path == "/search":
            name = urllib.parse.parse_qs(u.query).get("name", [""])[0]
            # VULNERABLE: string-built query -> UNION injection reaches the secrets table
            q = "SELECT name FROM users WHERE name LIKE '%s%%'" % name
            try:
                rows = db.execute(q).fetchall()
                self.send_response(200); self.end_headers()
                self.wfile.write(("\n".join(r[0] for r in rows)).encode())
            except Exception as e:
                self.send_response(500); self.end_headers(); self.wfile.write(str(e).encode())
            return
        self.send_response(404); self.end_headers()

http.server.HTTPServer(("0.0.0.0", 8000), H).serve_forever()
