from http.server import BaseHTTPRequestHandler, HTTPServer

count = 0

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        global count
        count += 1

        print(f"[+] Request #{count}: {self.path}")

        title = "SAFE" if count == 1 else "SECOND"

        body = f"""<!doctype html>
<html>
<head>
    <title>{title}</title>
</head>
<body>hello</body>
</html>
""".encode()

        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        pass

HTTPServer(("0.0.0.0", 8000), Handler).serve_forever()