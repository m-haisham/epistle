"""Local SMTP fixture sharing the OAuth issuer's tokens and test controls."""
import base64
import socketserver
import threading
import time


def start_smtp(state, lock):
    class Handler(socketserver.StreamRequestHandler):
        def reply(self, text):
            self.wfile.write(text.encode())
            self.wfile.flush()

        def handle(self):
            self.connection.settimeout(90)
            self.reply("220 fixture ESMTP\r\n")
            authenticated = False
            recipients = []
            while line := self.rfile.readline(8192):
                command = line.decode().strip()
                if command.startswith("EHLO"):
                    self.reply("250-fixture\r\n250-8BITMIME\r\n250 AUTH PLAIN XOAUTH2\r\n")
                elif command.startswith("AUTH"):
                    _, mechanism, encoded = command.split(" ", 2)
                    credentials = base64.b64decode(encoded).decode()
                    with lock:
                        if mechanism == "XOAUTH2":
                            token = credentials.split("auth=Bearer ", 1)[1].split("\x01", 1)[0]
                            authenticated = not state["revoked"] and state["issued_tokens"].get(token, 0) > time.time()
                        else:
                            authenticated = credentials.endswith("\0test-password")
                        state["smtp_auth"].append({"mechanism": mechanism, "accepted": authenticated})
                    self.reply("235 authenticated\r\n" if authenticated else "535 rejected\r\n")
                elif command.startswith("MAIL"):
                    recipients = []
                    self.reply("250 sender\r\n" if authenticated else "530 authenticate\r\n")
                elif command.startswith("RCPT"):
                    recipients.append(command)
                    self.reply("250 recipient\r\n")
                elif command == "DATA":
                    self.reply("354 content\r\n")
                    body = bytearray()
                    while part := self.rfile.readline(65536):
                        if part == b".\r\n":
                            break
                        body.extend(part[1:] if part.startswith(b"..") else part)
                    with lock:
                        state["smtp_messages"].append({"raw": bytes(body).decode(), "recipients": recipients})
                        paused = state["pause_smtp"]
                        if paused:
                            state["blocked_smtp"] += 1
                        disconnect = state["disconnect_smtp"]
                    while paused:
                        time.sleep(.02)
                        with lock:
                            paused = state["pause_smtp"]
                    if disconnect:
                        return
                    self.reply("250 accepted\r\n")
                elif command == "QUIT":
                    self.reply("221 bye\r\n")
                    return
                else:
                    self.reply("500 unknown command\r\n")

    class Server(socketserver.ThreadingTCPServer):
        allow_reuse_address = True
        daemon_threads = True

        def handle_error(self, request, client_address):
            # Disconnects are deliberate test cases; never print message/auth data.
            pass

    server = Server(("0.0.0.0", 2525), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
