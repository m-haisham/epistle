#!/usr/bin/env python3
"""Short-lived OAuth tokens against real Dovecot; optionally test the Docker image.
Run after docker compose up -d dovecot mock. No real provider credentials are used.
"""
import argparse, imaplib, os, pathlib, subprocess, tempfile, time, uuid
from integration import ROOT, BASE, MOCK, KEY, SECRET, request, eventually, mailbox, mail, events


def control(**changes):
    assert request("/control", "POST", changes, base=MOCK, auth=False)[0] == 200


def issuer():
    return request("/events", base=MOCK, auth=False)[2]


class Service:
    def __init__(self, directory, image):
        self.name = "epistle-expiry-" + uuid.uuid4().hex
        self.volume = self.name + "-data"
        self.image = None
        if image:
            # Keep an actual reference: containerd may collect an untagged manifest
            # after a rebuild even when its digest was saved by the test process.
            image_id = subprocess.check_output(
                ["docker", "image", "inspect", image, "--format", "{{.Id}}"], text=True
            ).strip()
            self.image = self.name + "-image:latest"
            subprocess.run(["docker", "image", "tag", image_id, self.image], check=True, capture_output=True)
        self.log = open(pathlib.Path(directory) / "service.log", "w+")
        self.process = None
        self.env = {
            "API_KEY": KEY, "MASTER_KEY": "01" * 32, "WEBHOOK_SECRET": SECRET,
            "WEBHOOK_URL": ("http://mock:8090" if image else MOCK) + "/webhook",
            "TOKEN_ENDPOINT_OVERRIDE": ("http://mock:8090" if image else MOCK) + "/token",
            "PUBLIC_URL": BASE, "ALLOW_INSECURE_TEST_ENDPOINTS": "true",
            "DATA_DIR": "/home/epistle/data" if image else directory,
            "BIND_ADDR": "0.0.0.0:8080" if image else "127.0.0.1:18080",
            "GOOGLE_CLIENT_ID": "test", "GOOGLE_CLIENT_SECRET": "test",
            "MICROSOFT_CLIENT_ID": "test", "MICROSOFT_CLIENT_SECRET": "test",
            "RECONCILE_SECS": "1", "WATCHDOG_SECS": "5", "DISK_RESERVE_BYTES": "0",
        }

    def start(self):
        if self.image:
            command = ["docker", "run", "--rm", "--name", self.name,
                       "--network", "epistle_default", "--read-only", "--cap-drop=ALL",
                       "--security-opt=no-new-privileges", "-p", "127.0.0.1:18080:8080",
                       "-v", self.volume + ":/home/epistle/data"]
            for key, value in self.env.items():
                command.extend(["-e", key + "=" + value])
            command.append(self.image)
        else:
            command = [str(ROOT / "target/debug/epistle-server")]
        self.process = subprocess.Popen(command, env={**os.environ, **self.env}, stdout=self.log, stderr=self.log)
        eventually(lambda: request("/health")[0] == 200)

    def stop(self, crash=False):
        if self.process is None:
            return
        if self.process.poll() is not None:
            self.process.wait()
        elif self.image:
            subprocess.run(["docker", "kill" if crash else "stop", self.name], check=True, capture_output=True)
        elif crash:
            self.process.kill()
        else:
            self.process.terminate()
        self.process.wait(timeout=15)
        self.process = None

    def close(self):
        try:
            self.stop()
            if self.image:
                result = subprocess.run(["docker", "volume", "rm", self.volume], capture_output=True)
                if result.returncode and b"no such volume" not in result.stderr.lower():
                    result.check_returncode()
        finally:
            if self.image:
                subprocess.run(["docker", "image", "rm", self.image], check=True, capture_output=True)
            self.log.close()


def exercise(service, kind):
    control(events=[], status=200, token_calls=0, revoked=False, token_lifetime=12,
            strict_rotation=True, expected_refresh="initial-refresh", issued_tokens={},
            refresh_history=[], token_failures=0, introspections=[], refresh_expires_at=None)
    box = mailbox("oauth@example.test")
    folder = "Expiry-" + uuid.uuid4().hex
    assert box.create(folder)[0] == "OK"
    expected = set()
    def append(label):
        mid = uuid.uuid4().hex
        expected.add(mid)
        result = box.append(folder, None, None, mail(mid, label, attachment=True))
        assert result[0] == "OK", result
    def delivered():
        return [e["body"]["message"] for e in events(account, "email.message.received")]
    def caught_up():
        return expected.issubset({m["envelope"]["message_id"].split("@")[0] for m in delivered()})
    append("before first token")
    code, _, created = request("/email/accounts", "POST", {
        "external_ref": folder, "email": "oauth@example.test", "auth_kind": kind,
        "config": {"host": "dovecot" if service.image else "127.0.0.1",
                   "port": 143 if service.image else 1143, "tls": False, "folders": [folder]},
        "credentials": {"refresh_token": "initial-refresh"},
    })
    assert code == 201, created
    account = created["account"]["id"]
    eventually(caught_up)
    first_access = next(iter(issuer()["issued_tokens"]))
    # Natural wall-clock expiry: no DB timestamps, credential updates, or test-only
    # application settings. The issuer rejects both expired access and old refresh tokens.
    for generation in (2, 3):
        eventually(lambda: len(issuer()["refresh_history"]) >= generation, timeout=25)
        append("during token generation " + str(generation))
        eventually(caught_up)
    assert 3 <= issuer()["token_calls"] <= 4, "refresh/reconnect storm"
    assert any(e["body"].get("status_reason") == "token_recycle" or e["body"].get("reason") == "token_recycle"
               for e in events(account, "account.status_changed"))
    expired = imaplib.IMAP4("127.0.0.1", 1143)
    try:
        expired.authenticate("XOAUTH2", lambda challenge: b"" if challenge else
                             ("user=oauth@example.test\x01auth=Bearer " + first_access + "\x01\x01").encode())
        raise AssertionError("Dovecot accepted expired access token")
    except imaplib.IMAP4.error:
        pass
    finally:
        expired.shutdown()
    assert any(i["token"] == first_access and not i["active"] for i in issuer()["introspections"])
    print("PASS:", kind, "three short-lived token generations, no reconnect storm", flush=True)

    # Crash, let every access token expire, then restart using the same data volume.
    service.stop(crash=True)
    before = issuer()
    remaining = max(before["issued_tokens"].values()) - time.time()
    time.sleep(max(0, remaining) + .2)
    append("while service is stopped and token expires")
    service.start()
    eventually(caught_up)
    history = issuer()["refresh_history"]
    assert len(history) > len(before["refresh_history"])
    assert history[len(before["refresh_history"])]["used"] == before["expected_refresh"]
    # Command and attachment paths also work after restart, with exactly-once discovery.
    messages = delivered()
    assert len(messages) == len(expected)
    assert len({m["id"] for m in messages}) == len(expected)
    message = messages[-1]
    attachment = next(f for f in message["files"] if f["role"] == "attachment")
    assert request(f"/email/messages/{message['id']}/files/{attachment['id']}")[2] == bytes([1, 2, 3, 4])
    command = request(f"/email/messages/{message['id']}/read", "POST", {"read": True})[2]["command_id"]
    assert request(f"/commands/{command}?wait=5s")[2]["state"] == "done"
    print("PASS:", kind, "expired-token restart uses persisted rotated refresh token; files and commands work", flush=True)

    # Simulate a provider disconnect and a temporary token endpoint failure together.
    control(token_failures=1)
    subprocess.run(["docker", "compose", "exec", "-T", "dovecot", "doveadm", "kick", "oauth@example.test"], cwd=ROOT, check=True, capture_output=True)
    box.shutdown()
    box = mailbox("oauth@example.test")
    append("during provider outage")
    eventually(lambda: issuer()["token_failures"] == 0, timeout=40)
    eventually(lambda: request(f"/email/accounts/{account}")[2]["status"] == "active", timeout=45)
    eventually(caught_up)
    assert not any(e["body"]["status"] == "needs_reauth" for e in events(account, "account.status_changed"))
    history = issuer()["refresh_history"]
    assert history[0]["used"] == "initial-refresh"
    assert all(curr["used"] == prev["issued"] for prev, curr in zip(history, history[1:]))
    assert len(delivered()) == len(expected)
    assert request(f"/email/accounts/{account}", "DELETE")[0] == 204
    box.delete(folder); box.logout()
    print("PASS:", kind, "forced disconnect and token endpoint outage recover without re-consent or duplicate mail", flush=True)


def exercise_refresh_deadline(service):
    """A fixed grant deadline is not renewed just because its token rotates."""
    deadline = time.time() + 18
    control(events=[], status=200, token_calls=0, revoked=False, token_lifetime=12,
            strict_rotation=True, expected_refresh="initial-refresh", issued_tokens={},
            refresh_history=[], token_failures=0, introspections=[], refresh_expires_at=deadline)
    box = mailbox("oauth@example.test")
    folder = "Grant-" + uuid.uuid4().hex
    assert box.create(folder)[0] == "OK"
    code, _, created = request("/email/accounts", "POST", {
        "external_ref": folder, "email": "oauth@example.test", "auth_kind": "google_oauth",
        "config": {"host": "dovecot" if service.image else "127.0.0.1",
                   "port": 143 if service.image else 1143, "tls": False, "folders": [folder]},
        "credentials": {"refresh_token": "initial-refresh"},
    })
    assert code == 201, created
    account = created["account"]["id"]
    def health_deadline():
        return next(a for a in request("/health")[2]["accounts"] if a["id"] == account)["refresh_token_expires_at"]
    first = eventually(health_deadline)
    assert deadline - 2 <= first <= deadline
    eventually(lambda: len(issuer()["refresh_history"]) >= 2, timeout=20)
    assert abs(health_deadline() - first) <= 1
    eventually(lambda: request(f"/email/accounts/{account}")[2]["status"] == "needs_reauth", timeout=30)
    assert request(f"/email/accounts/{account}")[2]["status_reason"] == "refresh_token_expired"
    calls = issuer()["token_calls"]
    time.sleep(1.2)
    assert issuer()["token_calls"] == calls
    # Importing newly authorized credentials clears the obsolete deadline.
    control(refresh_expires_at=None, expected_refresh="new-consent", token_lifetime=3600)
    assert request(f"/email/accounts/{account}/credentials", "POST", {"refresh_token": "new-consent"})[0] == 200
    eventually(lambda: request(f"/email/accounts/{account}")[2]["status"] == "active")
    assert health_deadline() is None
    assert request(f"/email/accounts/{account}", "DELETE")[0] == 204
    box.delete(folder); box.logout()
    print("PASS: reported refresh-token deadline survives rotation, appears in health, parks on expiry and resets with new credentials", flush=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--image", help="Test this image in place of the host debug binary")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="epistle-expiry-") as directory:
        service = Service(directory, args.image)
        succeeded = False
        try:
            service.start()
            for kind in ("google_oauth", "microsoft_oauth"):
                exercise(service, kind)
            exercise_refresh_deadline(service)
            succeeded = True
        except BaseException:
            service.log.flush(); service.log.seek(0); print(service.log.read())
            raise
        finally:
            try:
                service.close()
            except subprocess.CalledProcessError as error:
                print("Cleanup failed for", service.name, service.volume, error.stderr)
                if succeeded:
                    raise
            control(strict_rotation=False, token_lifetime=3600, token_failures=0, refresh_expires_at=None)
    print("PASS: OAuth expiry suite" + (" on " + args.image if args.image else " on host"), flush=True)

if __name__ == "__main__":
    main()
