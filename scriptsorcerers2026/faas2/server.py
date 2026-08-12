
from http.server import HTTPServer, SimpleHTTPRequestHandler
import datetime

class LoggingHandler(SimpleHTTPRequestHandler):
    def do_GET(self):
        self.log_request_info("GET")
        # /srv/what_even_is_this_file_name.txt
        if self.path == "/":
            body = b"upload-file = /srv/secretbinary1337"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        super().do_GET()

    def do_POST(self):
        self.log_request_info("POST")

        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length)

        print(f"BODY: {body}")
        print(f"BODY (hex): {body.hex()}")

        self.send_response(200)
        self.end_headers()

    def do_PUT(self):
        self.log_request_info("PUT")

        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length)

        print(f"BODY: {body}")
        print(f"BODY (hex): {body.hex()}")

        self.send_response(200)
        self.end_headers()

    def log_request_info(self, method):
        print(f"\n[{datetime.datetime.now()}] {method} da {self.client_address}")
        print(f"Path: {self.path}")
        print(f"Headers: {dict(self.headers)}")
        print("-" * 50)


if __name__ == "__main__":
    server = HTTPServer(("0.0.0.0", 8000), LoggingHandler)
    print("Server in ascolto su porta 8000...")
    server.serve_forever()
