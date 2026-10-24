#!/usr/bin/env python3
"""End-to-end tests against real Dovecot; run after docker compose up -d dovecot mock.
No third-party Python packages required. All accounts and data are test-only.
"""
import hashlib, hmac, imaplib, json, os, pathlib, random, sqlite3, subprocess, tempfile, time, urllib.request, urllib.error, uuid
ROOT = pathlib.Path(__file__).resolve().parents[1]
KEY = "integration-api-key-000000000000000"
SECRET = "integration-webhook-secret-00000000"
BASE = "http://127.0.0.1:18080"
MOCK = "http://127.0.0.1:8090"

def request(path, method="GET", body=None, headers=None, base=BASE, auth=True):
    hdrs = {"Authorization": "Bearer " + KEY} if auth else {}
    if body is not None: hdrs["Content-Type"] = "application/json"
    hdrs.update(headers or {})
    req = urllib.request.Request(base + path, data=None if body is None else json.dumps(body).encode(), headers=hdrs, method=method)
    try: response = urllib.request.urlopen(req, timeout=10)
    except urllib.error.HTTPError as error: response = error
    with response:
        data = response.read()
        return response.status, dict(response.headers), json.loads(data) if "application/json" in response.headers.get("Content-Type", "") and data else data

def eventually(fn, timeout=35):
    end = time.monotonic()+timeout
    last = None
    while time.monotonic()<end:
        try:
            last=fn()
            if last: return last
        except (ConnectionError, urllib.error.URLError): pass
        time.sleep(.2)
    raise AssertionError("condition timed out: " + repr(last))

def mail(mid, subject="integration", attachment=False):
    head = f"From: Sender <sender@example.test>\r\nTo: inbox@example.test\r\nMessage-ID: <{mid}@example.test>\r\nSubject: {subject}\r\nDate: Sat, 24 Oct 2026 10:00:00 +0000\r\nMIME-Version: 1.0\r\n"
    if attachment:
        return (head + 'Content-Type: multipart/mixed; boundary="boundary"\r\n\r\n--boundary\r\nContent-Type: text/plain\r\n\r\nHello from Dovecot\r\n--boundary\r\nContent-Type: application/octet-stream\r\nContent-Disposition: attachment; filename="test.bin"\r\nContent-Transfer-Encoding: base64\r\n\r\nAQIDBA==\r\n--boundary--\r\n').encode()
    return (head + "Content-Type: text/plain\r\n\r\nHello from Dovecot\r\n").encode()

def mailbox(email):
    imap=imaplib.IMAP4("127.0.0.1",1143)
    assert imap.login(email,"test-password")[0]=="OK"
    return imap

def events(account=None,kind=None):
    all_events=request("/events",base=MOCK,auth=False)[2]["events"]
    return [e for e in all_events if (kind is None or e["body"]["kind"]==kind) and (account is None or e["body"].get("account_id",e["body"].get("message",{}).get("account_id"))==account)]

def main():
    request("/control","POST",{"events":[],"status":200,"revoked":False,"token_calls":0},base=MOCK,auth=False)
    with tempfile.TemporaryDirectory(prefix="epistle-integration-") as data:
        env={**os.environ,"API_KEY":KEY,"MASTER_KEY":"01"*32,"WEBHOOK_SECRET":SECRET,"WEBHOOK_URL":MOCK+"/webhook","PUBLIC_URL":BASE,"DATA_DIR":data,"BIND_ADDR":"127.0.0.1:18080","ALLOW_INSECURE_TEST_ENDPOINTS":"true","TOKEN_ENDPOINT_OVERRIDE":MOCK+"/token","GOOGLE_CLIENT_ID":"test","GOOGLE_CLIENT_SECRET":"test","RECONCILE_SECS":"1","WATCHDOG_SECS":"10","FILE_RETENTION_SECS":"12","DISK_RESERVE_BYTES":"0"}
        log=open(pathlib.Path(data)/"service.log","w+")
        def start():
            p=subprocess.Popen([str(ROOT/"target/debug/epistle-server")],env=env,stdout=log,stderr=log)
            try: eventually(lambda: request("/health")[0]==200)
            except BaseException:
                p.terminate();p.wait(timeout=5);log.flush();log.seek(0);print(log.read());raise
            return p
        p=start()
        try:
            assert request("/health",auth=False)[0]==401
            schema=request("/openapi.json",auth=False)[2]
            assert "/email/messages/{id}/files/{file_id}" in schema["paths"]
            assert schema["paths"]["/email/accounts"]["post"]["security"]==[{"apiKey":[]}]
            second=subprocess.run([str(ROOT/"target/debug/epistle-server")],env=env,capture_output=True,timeout=10)
            assert second.returncode!=0 and b"another instance" in second.stdout+second.stderr
            email="test-"+uuid.uuid4().hex+"@example.test"
            box=mailbox(email)
            raw=mail(uuid.uuid4().hex,attachment=True)
            assert box.append("INBOX",None,None,raw)[0]=="OK"
            status,_,created=request("/email/accounts","POST",{"external_ref":email,"email":email,"auth_kind":"password","config":{"host":"127.0.0.1","port":1143,"tls":False,"folders":["INBOX"]},"credentials":{"password":"test-password"}})
            assert status==201, created
            account=created["account"]["id"]
            first=eventually(lambda: events(account,"email.message.received"))[-1]
            message=first["body"]["message"];mid=message["id"]
            assert message["origin"]=="backfill" and message["text"].startswith("Hello")
            assert "uid" not in json.dumps(message).lower()
            sig=first["headers"]["x-epistle-signature"]
            expected="v1="+hmac.new(SECRET.encode(),(first["headers"]["x-epistle-timestamp"]+"."+first["raw"]).encode(),hashlib.sha256).hexdigest()
            assert hmac.compare_digest(sig,expected)
            attachment=next(f for f in message["files"] if f["role"]=="attachment")
            file_path=f"/email/messages/{mid}/files/{attachment['id']}"
            code,headers,content=request(file_path)
            assert code==200 and content==bytes([1,2,3,4])
            assert headers.get("etag",headers.get("ETag"))=='"'+hashlib.sha256(content).hexdigest()+'"'
            assert request(file_path,headers={"Range":"bytes=1-2"})[2]==bytes([2,3])
            assert request(file_path,headers={"Range":"bytes=-1"})[2]==bytes([4])
            assert request(file_path,headers={"Range":"bytes=99-"})[0]==416
            assert request(file_path,headers={"If-None-Match":'"'+attachment["sha256"]+'"'})[0]==304
            command=request(f"/email/messages/{mid}/read","POST",{"read":True})[2]["command_id"]
            assert request(f"/commands/{command}?wait=5s")[2]["state"]=="done"
            box.select("INBOX");assert box.uid("search",None,"SEEN")[1][0]
            command=request(f"/email/messages/{mid}/read","POST",{"read":False})[2]["command_id"]
            assert request(f"/commands/{command}?wait=5s")[2]["state"]=="done"
            eventually(lambda: (box.noop(), box.uid("search",None,"UNSEEN")[1][0])[1])
            # Live arrivals and cross-folder duplicates: compare the server model to delivered ids.
            ids=[uuid.uuid4().hex for _ in range(8)]
            box.create("Sent")
            for i,msg in enumerate(ids):
                box.append("INBOX",None,None,mail(msg))
                if i%2==0: box.append("Sent",None,None,mail(msg))
            eventually(lambda: len(events(account,"email.message.received"))>=9)
            backfill=request(f"/email/accounts/{account}/backfills","POST",{"since":"2020-01-01T00:00:00Z","folders":["Sent"]})[2]["backfill_id"]
            eventually(lambda: request(f"/backfills/{backfill}")[2]["state"]=="done")
            assert len(events(account,"email.message.received"))==9
            # Durable restart and catch-up: append while the process is dead.
            p.kill();p.wait(timeout=10)
            box.append("INBOX",None,None,mail(uuid.uuid4().hex))
            p=start()
            eventually(lambda: len(events(account,"email.message.received"))>=10)
            assert request(f"/email/accounts/{account}")[2]["status"]=="active"
            # Backfill redelivery is explicit and carries its job id.
            backfill=request(f"/email/accounts/{account}/backfills","POST",{"since":"2020-01-01T00:00:00Z","folders":["Sent"],"redeliver":True,"unread_only":True})[2]["backfill_id"]
            eventually(lambda: request(f"/backfills/{backfill}")[2]["state"]=="done")
            redelivered=[e for e in events(account,"email.message.received") if e["body"]["message"].get("backfill_id")==backfill]
            assert len(redelivered)==4
            # UIDVALIDITY fallback: backfill an un-watched mailbox, recreate it, then command by opaque id.
            box.create("Reset")
            reset_raw=mail(uuid.uuid4().hex,"reset")
            box.append("Reset",None,None,reset_raw)
            backfill=request(f"/email/accounts/{account}/backfills","POST",{"since":"2020-01-01T00:00:00Z","folders":["Reset"]})[2]["backfill_id"]
            reset_event=eventually(lambda: next((e for e in events(account,"email.message.received") if e["body"]["message"].get("backfill_id")==backfill),None))
            reset_mid=reset_event["body"]["message"]["id"]
            box.delete("Reset");time.sleep(1.1);box.create("Reset");box.append("Reset",None,None,reset_raw)
            command=request(f"/email/messages/{reset_mid}/read","POST",{"read":True})[2]["command_id"]
            assert request(f"/commands/{command}?wait=5s")[2]["state"]=="done"
            box.select("Reset");assert box.uid("search",None,"SEEN")[1][0]
            # Permanent HTTP failure keeps files and can be replayed.
            request("/control","POST",{"status":400},base=MOCK,auth=False)
            box.append("INBOX",None,None,mail(uuid.uuid4().hex,"dead"))
            dead=eventually(lambda: next((r for r in request("/outbox")[2] if r["kind"]=="email.message.received" and r["state"]=="dead"),None))
            request("/control","POST",{"status":200},base=MOCK,auth=False)
            assert request(f"/outbox/{dead['id']}/replay","POST",{})[0]==202
            eventually(lambda: all(r["id"]!=dead["id"] for r in request("/outbox")[2]))
            # OAuth refresh and real XOAUTH2 against Dovecot introspection.
            obox=mailbox("oauth@example.test");obox.append("INBOX",None,None,mail(uuid.uuid4().hex,"oauth"))
            code,_,oauth=request("/email/accounts","POST",{"external_ref":"oauth","email":"oauth@example.test","auth_kind":"google_oauth","config":{"host":"127.0.0.1","port":1143,"tls":False,"folders":["INBOX"]},"credentials":{"refresh_token":"initial-refresh"}})
            assert code==201,oauth
            oa=oauth["account"]["id"]
            eventually(lambda: events(oa,"email.message.received"))
            assert request("/events",base=MOCK,auth=False)[2]["token_calls"]==1
            # Revoke and replace credentials to force refresh; permanent auth failure parks the account.
            request("/control","POST",{"revoked":True},base=MOCK,auth=False)
            request(f"/email/accounts/{oa}/credentials","POST",{"refresh_token":"revoked-refresh"})
            eventually(lambda: request(f"/email/accounts/{oa}")[2]["status"]=="needs_reauth")
            calls=request("/events",base=MOCK,auth=False)[2]["token_calls"]
            time.sleep(1.5)
            assert request("/events",base=MOCK,auth=False)[2]["token_calls"]==calls
            request("/control","POST",{"revoked":False},base=MOCK,auth=False)
            request(f"/email/accounts/{oa}/credentials","POST",{"refresh_token":"recovered-refresh"})
            eventually(lambda: request(f"/email/accounts/{oa}")[2]["status"]=="active")
            assert request(f"/email/accounts/{account}","PATCH",{"enabled":False})[2]["status"]=="disabled"
            # No credentials in SQLite plaintext; files expire from ack, with explicit 410 tombstones.
            with sqlite3.connect(pathlib.Path(data)/"epistle.sqlite") as db:
                sealed=db.execute("SELECT ciphertext FROM credentials").fetchall()
                assert all("test-password" not in row[0] and "refresh" not in row[0] for row in sealed)
            eventually(lambda: request(file_path)[0]==410,timeout=20)
            seqs=[e["body"]["status_seq"] for e in events(account,"account.status_changed")]
            assert seqs==sorted(seqs) and len(seqs)==len(set(seqs))
            assert request(f"/email/accounts/{account}","DELETE")[0]==204
            assert request(f"/email/accounts/{account}")[0]==404
            print("PASS: API auth/OpenAPI, lock, initial/live sync, MIME/files/ranges, signed delivery, read/unread, dedupe, backfills, restart, UIDVALIDITY fallback, dead replay, real XOAUTH2/refresh/revocation/recovery, encryption, retention, status ordering, removal",flush=True)
        except BaseException:
            log.flush();log.seek(0);print(log.read())
            raise
        finally:
            p.terminate()
            try:p.wait(timeout=10)
            except subprocess.TimeoutExpired:p.kill();p.wait()
            log.close()
if __name__=="__main__":main()
