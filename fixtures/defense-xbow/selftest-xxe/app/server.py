import http.server
from lxml import etree

class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_GET(self):
        if self.path == "/":
            self.send_response(200); self.end_headers()
            self.wfile.write(b"xml preview: POST /parse with an XML body"); return
        self.send_response(404); self.end_headers()
    def do_POST(self):
        if self.path != "/parse":
            self.send_response(404); self.end_headers(); return
        n = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(n)
        # VULNERABLE: resolves external entities (XXE) -> a SYSTEM file:// entity is read
        parser = etree.XMLParser(resolve_entities=True, load_dtd=True, no_network=True)
        try:
            root = etree.fromstring(body, parser)
            self.send_response(200); self.end_headers(); self.wfile.write(etree.tostring(root))
        except Exception as e:
            self.send_response(400); self.end_headers(); self.wfile.write(str(e).encode())

http.server.HTTPServer(("0.0.0.0", 8000), H).serve_forever()
