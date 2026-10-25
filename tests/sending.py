#!/usr/bin/env python3
"""Outbound API, shared OAuth, crash-window and shutdown tests on host or glibc image."""
import argparse
from email import policy
from email.parser import Parser
import signal
import tempfile
import uuid

from integration import eventually, mailbox, request
from shutdown import finish_stop, signal_stop
from token_expiry import Service, control, issuer


def create_account(service, kind):
    email = "client@example.test" if kind == "password" else "oauth@example.test"
    box = mailbox(email)
    folder = "Send-" + uuid.uuid4().hex
    assert box.create(folder)[0] == "OK"
    code, _, body = request("/email/accounts", "POST", {
        "external_ref": folder, "email": email, "auth_kind": kind,
        "config": {"host": "dovecot" if service.image else "127.0.0.1",
                   "port": 143 if service.image else 1143, "tls": False, "folders": [folder]},
        "credentials": {"password": "test-password"} if kind == "password" else {"refresh_token": "initial-refresh"},
    })
    assert code == 201, body
    account = body["account"]["id"]
    code, _, updated = request(f"/email/accounts/{account}/smtp", "POST", {
        "host": "mock" if service.image else "127.0.0.1", "port": 2525, "security": "plain",
    })
    assert code == 200, updated
    eventually(lambda: request(f"/email/accounts/{account}")[2]["status"] == "active")
    return account, box, folder


def enqueue(account, key):
    body = {"idempotency_key": key, "to": ["to@example.test"], "bcc": ["private@example.test"],
            "subject": "Sending test ✓", "text": "Hello", "html": "<p>Hello</p>",
            "attachments": [{"filename": "test.bin", "content_type": "application/octet-stream", "content_base64": "AQIDBA=="}]}
    code, _, job = request(f"/email/accounts/{account}/send", "POST", body)
    assert code == 202, job
    again = request(f"/email/accounts/{account}/send", "POST", body)
    assert again[0] == 202 and again[2]["id"] == job["id"]
    body["subject"] = "Changed"
    assert request(f"/email/accounts/{account}/send", "POST", body)[0] == 409
    return job["id"]


def state(job, expected):
    body = request(f"/email/sends/{job}")[2]
    return body if body["state"] == expected else False


def exercise(service):
    schema = request("/openapi.json", auth=False)[2]
    for path, method in [("/email/accounts/{id}/send", "post"), ("/email/accounts/{id}/smtp", "post"),
                         ("/email/sends/{id}", "get"), ("/email/sends/{id}", "delete"),
                         ("/email/sends/{id}/retry", "post")]:
        assert schema["paths"][path][method]["security"] == [{"apiKey": []}]
    assert "202" in schema["paths"]["/email/accounts/{id}/send"]["post"]["responses"]
    assert request("/email/accounts/unknown/send", "POST", {}, auth=False)[0] == 401

    for kind in ("password", "google_oauth", "microsoft_oauth"):
        control(events=[], token_calls=0, revoked=False, status=200, token_lifetime=8,
                strict_rotation=True, expected_refresh="initial-refresh", issued_tokens={},
                refresh_history=[], token_failures=0, refresh_expires_at=None,
                pause_tokens=False, pause_webhooks=False, pause_smtp=False,
                disconnect_smtp=False, smtp_messages=[], smtp_auth=[], blocked_smtp=0)
        account, box, folder = create_account(service, kind)
        job = enqueue(account, "first")
        eventually(lambda: state(job, "sent"))
        message = issuer()["smtp_messages"][0]
        parsed = Parser(policy=policy.default).parsestr(message["raw"])
        assert parsed["Subject"] == "Sending test ✓"
        assert parsed["Bcc"] is None
        assert list(parsed.iter_attachments())[0].get_payload(decode=True) == bytes([1, 2, 3, 4])
        assert "private@example.test" not in message["raw"]
        assert any("private@example.test" in recipient for recipient in message["recipients"])

        if kind != "password":
            eventually(lambda: issuer()["token_calls"] >= 2, timeout=20)
            after_expiry = enqueue(account, "after-expiry")
            eventually(lambda: state(after_expiry, "sent"))
            history = issuer()["refresh_history"]
            assert all(current["used"] == previous["issued"] for previous, current in zip(history, history[1:]))
            assert all(auth["mechanism"] == "XOAUTH2" and auth["accepted"] for auth in issuer()["smtp_auth"])

        assert request(f"/email/accounts/{account}", "DELETE")[0] == 204
        box.delete(folder)
        box.logout()
        print("PASS:", kind, "SMTP shares account authentication and persists idempotent MIME submission", flush=True)

    control(pause_smtp=True, blocked_smtp=0, smtp_messages=[], token_lifetime=3600)
    account, box, folder = create_account(service, "password")
    job = enqueue(account, "crash")
    eventually(lambda: issuer()["blocked_smtp"] == 1)
    service.stop(crash=True)
    control(pause_smtp=False)
    service.start()
    eventually(lambda: state(job, "unknown"))
    assert request(f"/email/sends/{job}/retry", "POST", {})[0] == 409
    assert request("/health")[2]["sending"]["unknown"] == 1
    assert request(f"/email/sends?account_id={account}&state=unknown")[2][0]["id"] == job
    assert request("/email/sends?state=invalid")[0] == 400
    assert len(issuer()["smtp_messages"]) == 1
    assert request(f"/email/sends/{job}/retry", "POST", {"allow_duplicate": True})[0] == 202
    eventually(lambda: state(job, "sent"))
    messages = issuer()["smtp_messages"]
    assert len(messages) == 2 and messages[0]["raw"] == messages[1]["raw"]
    print("PASS: SIGKILL after DATA quarantines the job; explicit retry preserves Message-ID and bytes", flush=True)

    control(pause_smtp=True, blocked_smtp=0)
    job = enqueue(account, "shutdown")
    eventually(lambda: issuer()["blocked_smtp"] == 1)
    signal_stop(service, signal.SIGTERM)
    control(pause_smtp=False)
    finish_stop(service)
    service.start()
    assert state(job, "sent")
    assert len(issuer()["smtp_messages"]) == 3
    assert request(f"/email/accounts/{account}", "DELETE")[0] == 204
    box.delete(folder)
    box.logout()
    print("PASS: SIGTERM waits for SMTP acceptance and persists it before closing the database", flush=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--image")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="epistle-sending-") as directory:
        service = Service(directory, args.image)
        service.env["EPISTLE_SENDING__TIMEOUT_SECS"] = "15"
        service.env["RUST_LOG"] = "info"
        try:
            service.start()
            exercise(service)
        except BaseException:
            service.log.flush()
            service.log.seek(0)
            print(service.log.read())
            raise
        finally:
            control(pause_smtp=False)
            service.close()
    print("PASS: outbound suite" + (" on " + args.image if args.image else " on host"), flush=True)


if __name__ == "__main__":
    main()
