"""Local-only webhook recorder and deterministic OAuth issuer for integration tests."""
import json, threading, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs
state = {
    "events": [], "status": 200, "token_calls": 0, "revoked": False,
    "token_lifetime": 3600, "strict_rotation": False, "expected_refresh": None,
    "issued_tokens": {}, "refresh_history": [], "token_failures": 0,
    "introspections": [],
    "refresh_expires_at": None,
}
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
                expiry = state["issued_tokens"].get(token, 0)
                active = not state["revoked"] and time.time() < expiry
                state["introspections"].append({"token": token, "active": active})
                return self.reply(200, {"active": active, "email": "oauth@example.test"})
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
                if state["token_failures"]:
                    state["token_failures"] -= 1
                    return self.reply(503, {"error": "temporarily_unavailable"})
                supplied = parse_qs(body.decode()).get("refresh_token", [None])[0]
                expired = state["refresh_expires_at"] is not None and time.time() >= state["refresh_expires_at"]
                if state["revoked"] or expired or (state["strict_rotation"] and supplied != state["expected_refresh"]):
                    return self.reply(400, {"error": "invalid_grant"})
                access = "test-access-"+str(state["token_calls"])
                refresh = "rotated-"+str(state["token_calls"])
                state["issued_tokens"][access] = time.time() + state["token_lifetime"]
                state["expected_refresh"] = refresh
                state["refresh_history"].append({"used": supplied, "issued": refresh})
                response = {"access_token": access, "refresh_token": refresh, "expires_in": state["token_lifetime"], "scope": "https://mail.google.com/ https://outlook.office.com/IMAP.AccessAsUser.All offline_access"}
                if state["refresh_expires_at"] is not None:
                    response["refresh_token_expires_in"] = max(0, int(state["refresh_expires_at"] - time.time()))
                return self.reply(200, response)
        self.reply(404, {})
ThreadingHTTPServer(("0.0.0.0", 8090), Handler).serve_forever()
