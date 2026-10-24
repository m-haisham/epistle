"""Local-only webhook recorder and deterministic OAuth issuer for integration tests."""
import json, os, threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs
state = {"events": [], "status": 200, "token_calls": 0, "revoked": False}
lock = threading.Lock()
class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args): pass
    def reply(self, code, body):
        payload = json.dumps(body).encode()
        self.send_response(code); self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload))); self.end_headers(); self.wfile.write(payload)
    def do_GET(self):
        with lock:
            if self.path == "/events": return self.reply(200, state)
            if self.path == "/introspect":
                token = self.headers.get("Authorization", "").removeprefix("Bearer ")
                return self.reply(200, {"active": not state["revoked"] and token.startswith("test-access-"), "email": "oauth@example.test"})
        self.reply(404, {})
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        with lock:
            if self.path == "/webhook":
                state["events"].append({"headers": dict(self.headers), "body": json.loads(body), "raw": body.decode()})
                return self.reply(state["status"], {})
            if self.path == "/control":
                update = json.loads(body)
                state.update({k:v for k,v in update.items() if k in state})
                return self.reply(200, {})
            if self.path == "/token":
                state["token_calls"] += 1
                if state["revoked"]: return self.reply(400, {"error": "invalid_grant"})
                return self.reply(200, {"access_token": "test-access-"+str(state["token_calls"]), "refresh_token": "rotated-"+str(state["token_calls"]), "expires_in": 3600, "scope": "https://mail.google.com/"})
        self.reply(404, {})
ThreadingHTTPServer(("0.0.0.0", 8090), Handler).serve_forever()
