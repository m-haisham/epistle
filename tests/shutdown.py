#!/usr/bin/env python3
"""Graceful signals during OAuth refresh and webhook delivery, on host or distroless."""
import argparse
import signal
import subprocess
import tempfile
import time
import uuid

from integration import eventually, events, mail, mailbox, request
from token_expiry import Service, control, issuer


def signal_stop(service, sig):
    if service.image:
        subprocess.run(["docker", "kill", "--signal", sig.name, service.name], check=True, capture_output=True)
    else:
        service.process.send_signal(sig)

    # Wait for the shutdown signal to reach the service, without releasing its gate.
    def draining():
        service.log.flush()
        service.log.seek(0)
        logs = service.log.read()
        assert service.process.poll() is None, f"service exited during drain: {service.process.returncode}; {logs}"
        return "shutdown requested; draining" in logs
    eventually(draining)
    assert service.process.poll() is None, "shutdown dropped an in-flight operation"


def finish_stop(service):
    assert service.process.wait(timeout=20) == 0
    service.process = None
    service.log.flush()
    service.log.seek(0)
    logs = service.log.read()
    assert "shutdown complete; all workers and database writes drained" in logs
    for secret in ("initial-refresh", "rotated-1", "test-access-1", "must-not-log-code"):
        assert secret not in logs, "tracing exposed credentials"


def exercise(service):
    control(events=[], token_calls=0, revoked=False, status=200, token_lifetime=3600,
            strict_rotation=True, expected_refresh="initial-refresh", issued_tokens={},
            refresh_history=[], token_failures=0, refresh_expires_at=None,
            pause_tokens=True, pause_webhooks=False, blocked_tokens=0, blocked_webhooks=0)
    box = mailbox("oauth@example.test")
    assert request("/openapi.json?code=must-not-log-code", auth=False)[0] == 200
    folder = "Shutdown-" + uuid.uuid4().hex
    assert box.create(folder)[0] == "OK"
    code, _, created = request("/email/accounts", "POST", {
        "external_ref": folder, "email": "oauth@example.test", "auth_kind": "google_oauth",
        "config": {"host": "dovecot" if service.image else "127.0.0.1",
                   "port": 143 if service.image else 1143, "tls": False, "folders": [folder]},
        "credentials": {"refresh_token": "initial-refresh"},
    })
    assert code == 201, created
    account = created["account"]["id"]
    eventually(lambda: issuer()["blocked_tokens"] == 1)
    signal_stop(service, signal.SIGTERM)
    control(pause_tokens=False)
    finish_stop(service)
    assert issuer()["token_calls"] == 1

    service.start()
    eventually(lambda: request(f"/email/accounts/{account}")[2]["status"] == "active")
    assert issuer()["token_calls"] == 1, "restart lost the committed access/refresh credentials"
    eventually(lambda: request("/outbox")[2] == [])
    print("PASS: SIGTERM drains OAuth exchange, persists rotated credentials and restarts without another refresh", flush=True)

    control(pause_webhooks=True)
    first, second = uuid.uuid4().hex, uuid.uuid4().hex
    assert box.append(folder, None, None, mail(first, "in-flight webhook", attachment=True))[0] == "OK"
    eventually(lambda: issuer()["blocked_webhooks"] == 1)
    # Clear the old log marker so the signal wait verifies this shutdown.
    service.log.seek(0)
    service.log.truncate()
    signal_stop(service, signal.SIGINT)
    assert box.append(folder, None, None, mail(second, "arrived during shutdown"))[0] == "OK"
    control(pause_webhooks=False)
    finish_stop(service)

    service.start()
    def delivered():
        return [e["body"]["message"]["envelope"]["message_id"].split("@")[0]
                for e in events(account, "email.message.received")]
    eventually(lambda: first in delivered() and second in delivered())
    # Let reconciliation and delivery run again to expose a lost acknowledgment.
    time.sleep(2)
    assert delivered().count(first) == 1
    assert delivered().count(second) == 1
    assert request(f"/email/accounts/{account}", "DELETE")[0] == 204
    box.logout()
    print("PASS: SIGINT drains webhook acknowledgment; restart catches queued mail without duplicating the acknowledged delivery", flush=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--image")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="epistle-shutdown-") as directory:
        service = Service(directory, args.image)
        service.env["RUST_LOG"] = "info,epistle_auth=debug"
        try:
            service.start()
            exercise(service)
        except BaseException:
            service.log.flush()
            service.log.seek(0)
            print(service.log.read())
            raise
        finally:
            control(pause_tokens=False, pause_webhooks=False)
            service.close()
    print("PASS: graceful shutdown suite" + (" on " + args.image if args.image else " on host"), flush=True)


if __name__ == "__main__":
    main()
