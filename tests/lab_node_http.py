import os
import socketserver
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

node, vip, port, flags = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4]


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        failing = self.path == "/healthz" and os.path.exists(os.path.join(flags, f"{node}.fail"))
        body = (node + "\n").encode()
        self.send_response(503 if failing else 200)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Node", node)
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        return None


class Server(socketserver.ThreadingMixIn, HTTPServer):
    allow_reuse_address = True
    daemon_threads = True
    request_queue_size = 256


Server((vip, port), Handler).serve_forever()
