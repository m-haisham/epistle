#!/usr/bin/env python3
"""Folder failure isolation and recovery against Dovecot, on host or distroless."""
import argparse, subprocess, tempfile, uuid
from integration import request, eventually, mailbox, mail, events
from token_expiry import Service, control


def verify_image_pin(directory, image):
    alias = "epistle-pin-probe-" + uuid.uuid4().hex + ":latest"
    subprocess.run(["docker", "image", "tag", image, alias], check=True, capture_output=True)
    probe = None
    try:
        probe = Service(directory, alias)
        def image_id(ref):
            return subprocess.check_output(["docker", "image", "inspect", ref, "--format", "{{.Id}}"], text=True).strip()
        original = image_id(probe.image)
        # The mock's base image is already present in the required Compose stack.
        subprocess.run(["docker", "image", "tag", "python:3.13-slim", alias], check=True, capture_output=True)
        assert image_id(alias) != original
        assert image_id(probe.image) == original
    finally:
        if probe is not None:
            probe.close()  # Also exercise cleanup before any container was started.
        subprocess.run(["docker", "image", "rm", alias], check=True, capture_output=True)
    print("PASS: container harness retains its image across retagging and cleans up unstarted services", flush=True)


def exercise(service):
    control(events=[], status=200, revoked=False, token_lifetime=3600,
            strict_rotation=False, token_failures=0, refresh_expires_at=None)
    email = "recovery-" + uuid.uuid4().hex + "@example.test"
    box = mailbox(email)
    healthy, missing = "Healthy", "Recreated"
    assert box.create(healthy)[0] == "OK"
    assert box.append(healthy, None, None, mail(uuid.uuid4().hex, "healthy before missing folder"))[0] == "OK"
    code, _, created = request("/email/accounts", "POST", {
        "external_ref": email, "email": email, "auth_kind": "password",
        "config": {"host": "dovecot" if service.image else "127.0.0.1",
                   "port": 143 if service.image else 1143, "tls": False,
                   "folders": [healthy, missing]},
        "credentials": {"password": "test-password"},
    })
    assert code == 201, created
    account = created["account"]["id"]
    def health():
        return next(a for a in request("/health")[2]["accounts"] if a["id"] == account)
    def delivered():
        return [e["body"]["message"] for e in events(account, "email.message.received")]
    eventually(lambda: len(delivered()) == 1 and health()["status"] == "active")
    assert health()["folder_errors"][0]["reason"] == "mailbox_missing"
    code, _, job = request(f"/email/accounts/{account}/backfills", "POST", {
        "since": "2020-01-01T00:00:00Z", "folders": [missing],
    })
    assert code == 202, job
    job_id = job["backfill_id"]
    eventually(lambda: request(f"/backfills/{job_id}")[2]["state"] == "failed")
    assert request(f"/backfills/{job_id}")[2]["last_error"] == "mailbox_missing"
    assert health()["status"] == "active"
    assert box.create(missing)[0] == "OK"
    assert box.append(missing, None, None, mail(uuid.uuid4().hex, "newly available folder"))[0] == "OK"
    eventually(lambda: len(delivered()) == 2 and health()["folder_errors"] == [])
    removed_message = next(m for m in delivered() if m["envelope"]["subject"] == "newly available folder")
    assert box.delete(missing)[0] == "OK"
    eventually(lambda: len(health()["folder_errors"]) == 1)
    code, _, command = request(f"/email/messages/{removed_message['id']}/read", "POST", {"read": True})
    assert code == 202
    eventually(lambda: request(f"/commands/{command['command_id']}")[2]["state"] == "gone")
    assert box.append(healthy, None, None, mail(uuid.uuid4().hex, "healthy after deletion"))[0] == "OK"
    eventually(lambda: len(delivered()) == 3)
    assert health()["status"] == "active"
    assert request(f"/email/accounts/{account}", "DELETE")[0] == 204
    box.logout()
    print("PASS: missing folder isolation, failed backfill isolation, automatic folder recovery, deleted-folder command and continued live sync", flush=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--image")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="epistle-recovery-") as directory:
        if args.image:
            verify_image_pin(directory, args.image)
        service = Service(directory, args.image)
        try:
            service.start()
            code, headers, html = request("/scalar", auth=False)
            assert code == 200 and "text/html" in headers.get("content-type", headers.get("Content-Type", ""))
            assert b"/openapi.json" in html and b"Scalar.createApiReference" in html
            assert request("/health", auth=False)[0] == 401
            exercise(service)
        except BaseException:
            service.log.flush(); service.log.seek(0); print(service.log.read())
            raise
        finally:
            service.close()
    print("PASS: recovery suite" + (" on " + args.image if args.image else " on host"), flush=True)


if __name__ == "__main__":
    main()
