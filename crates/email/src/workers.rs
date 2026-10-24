use crate::{Error, Service, enqueue, handoff, parse_message};
use epistle_core::{Account, Pointer, backoff, id, now};
use epistle_imap::Connection;
use sqlx::Row;
use std::time::{Duration, Instant};
impl Service {
    pub(crate) async fn watch(&self, a: &Account) -> Result<(), Error> {
        self.store.worker_state(&a.id, "authenticating").await?;
        let (mut conn, expiry) = self.connect(a).await?;
        let names = conn.folders(a).await?;
        self.store.worker_state(&a.id, "syncing").await?;
        loop {
            if now() >= expiry - 60 - (a.id.bytes().next().unwrap_or(0) as i64 % 30) {
                conn.logout().await;
                return Err(Error::Recycle);
            }
            for name in &names {
                let mailbox = conn.examine(name).await?;
                let validity = i64::from(mailbox.uid_validity.ok_or(epistle_imap::Error {
                    reason: "uidvalidity_missing",
                    permanent: true,
                    auth: false,
                })?);
                let next = i64::from(mailbox.uid_next.unwrap_or(1));
                let existing = sqlx::query(
                    "SELECT id,uidvalidity,cursor_uid FROM folders WHERE account_id=? AND name=?",
                )
                .bind(&a.id)
                .bind(name)
                .fetch_optional(&self.store.reads)
                .await?;
                let (fid, cursor) = if let Some(row) = existing {
                    let fid: String = row.try_get("id")?;
                    let cursor = if row.try_get::<i64, _>("uidvalidity")? == validity {
                        row.try_get::<i64, _>("cursor_uid")?
                    } else {
                        0
                    };
                    (fid, cursor)
                } else {
                    (id(), next.saturating_sub(1))
                };
                let f = fid.clone();
                let account = a.id.clone();
                let n = name.clone();
                let days = a.config.initial_sync_days;
                let modseq = mailbox.highest_modseq.and_then(|x| i64::try_from(x).ok());
                self.store.write(move|c|Box::pin(async move{
     let inserted=sqlx::query("
INSERT OR IGNORE INTO
folders(id,account_id,name,uidvalidity,uidnext,cursor_uid,highestmodseq)
VALUES(?,?,?,?,?,?,?)
").bind(&f).bind(&account).bind(&n).bind(validity).bind(next).bind(cursor).bind(modseq).execute(&mut *c).await?.rows_affected();
     sqlx::query("UPDATE folders SET uidvalidity=?,uidnext=?,cursor_uid=?,highestmodseq=? WHERE id=?").bind(validity).bind(next).bind(cursor).bind(modseq).bind(&f).execute(&mut *c).await?;
     if inserted>0 {sqlx::query("INSERT INTO backfill_jobs(id,account_id,since,until,folders_json,created_at) VALUES(?,?,?,?,?,?)").bind(id()).bind(account).bind(now()-i64::from(days)*86400).bind(now()+1).bind(serde_json::to_string(&vec![n])?).bind(now()).execute(&mut *c).await?;
}Ok(())
    })).await?;
                let ids = conn
                    .search(&format!("UID {}:*", cursor.saturating_add(1)))
                    .await?;
                let ids: Vec<_> = ids
                    .into_iter()
                    .filter(|uid| i64::from(*uid) > cursor)
                    .collect();
                for chunk in ids.chunks(500) {
                    let set = chunk
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                        .join(",");
                    let items = conn.metadata(a, &fid, name, validity, &set).await?;
                    let f = fid.clone();
                    let max = chunk.last().copied().map(i64::from).unwrap_or(cursor);
                    self.store.write(move|c|Box::pin(async move{for p in items{enqueue(c,&p,"live",None,false).await?;
}sqlx::query("UPDATE folders SET cursor_uid=MAX(cursor_uid,?),last_synced_at=?,state='idle' WHERE id=?").bind(max).bind(now()).bind(f).execute(c).await?;
Ok(())})).await?;
                }
            }
            self.store
                .status_for_revision(&a.id, a.revision, "active", None, 0)
                .await?;
            let account = a.id.clone();
            self.store
                .write(move |c| {
                    Box::pin(async move {
                        sqlx::query("UPDATE accounts SET last_success_at=? WHERE id=?")
                            .bind(now())
                            .bind(account)
                            .execute(c)
                            .await?;
                        Ok(())
                    })
                })
                .await?;
            self.store.worker_state(&a.id, "idle").await?;
            let seconds = self
                .config
                .reconcile_secs
                .min((expiry - now() - 90).max(1) as u64);
            conn = conn.idle(seconds).await?;
        }
    }
    async fn active(&self, a: &Account) -> Result<bool, Error> {
        Ok(self.store.account(&a.id).await?.status == "active")
    }
    pub(crate) async fn fetch_worker(&self, a: &Account) -> Result<(), Error> {
        let mut connection: Option<(Connection, i64)> = None;
        let mut last_work = Instant::now();
        loop {
            tokio::time::sleep(Duration::from_millis(300)).await;
            if !self.active(a).await? {
                continue;
            }
            let jobs:i64=sqlx::query_scalar("SELECT COUNT(*) FROM backfill_jobs WHERE account_id=? AND state IN ('pending','scanning')").bind(&a.id).fetch_one(&self.store.reads).await?;
            let rows = sqlx::query(
                "
SELECT * FROM fetch_queue WHERE account_id=? AND state='pending' AND next_attempt_at<=?
ORDER BY created_at,id LIMIT ?
",
            )
            .bind(&a.id)
            .bind(now())
            .bind(self.config.fetch_batch_count as i64)
            .fetch_all(&self.store.reads)
            .await?;
            if rows.is_empty() && jobs == 0 {
                if last_work.elapsed() > Duration::from_secs(30)
                    && let Some((c, _)) = connection.take()
                {
                    c.logout().await;
                }
                self.finish_backfills(a).await?;
                continue;
            }
            if connection
                .as_ref()
                .is_none_or(|(_, expiry)| *expiry <= now() + 60)
            {
                if let Some((c, _)) = connection.take() {
                    c.logout().await;
                }
                connection = Some(self.connect(a).await?);
            }
            let Some((conn, _)) = connection.as_mut() else {
                continue;
            };
            if jobs > 0 {
                self.scan_backfill(a, conn).await?;
            }
            let mut bytes = 0;
            for row in rows {
                let p: Pointer = serde_json::from_str(&row.try_get::<String, _>("pointer")?)?;
                if bytes > 0 && bytes + p.size > self.config.fetch_batch_bytes {
                    break;
                }
                bytes += p.size;
                let stub: String = row.try_get("id")?;
                let fetch = conn.fetch(&p).await;
                let fetched = match fetch {
                    Ok(f) => f,
                    Err(e) => {
                        let attempts = row.try_get::<i64, _>("attempts")? + 1;
                        let reason = e.reason;
                        let max = self.config.max_attempts;
                        self.store.write(move|c|Box::pin(async move{sqlx::query("UPDATE fetch_queue SET attempts=?,state=?,last_error=?,next_attempt_at=? WHERE id=?").bind(attempts).bind(if attempts>=max{"dead"}else{"pending"}).bind(reason).bind(now()+backoff(attempts)).bind(stub).execute(c).await?;
Ok(())})).await?;
                        return Err(e.into());
                    }
                };
                if let Some((resolved, raw)) = fetched {
                    let mid: String = row.try_get("message_key")?;
                    let origin: String = row.try_get("origin")?;
                    let job: Option<String> = row.try_get("backfill_id")?;
                    let cap = self.config.inline_body_cap;
                    let p = resolved.clone();
                    let parsed = tokio::task::spawn_blocking(move || {
                        parse_message(mid, &p, raw, origin, job, cap)
                    })
                    .await?;
                    let prepared = self
                        .files
                        .prepare(parsed.0, parsed.1, row.try_get("idempotency_key")?)
                        .await?;
                    handoff(&self.store, stub, prepared).await?;
                } else {
                    self.store
                        .write(move |c| {
                            Box::pin(async move {
                                sqlx::query("UPDATE fetch_queue SET state='gone' WHERE id=?")
                                    .bind(stub)
                                    .execute(c)
                                    .await?;
                                Ok(())
                            })
                        })
                        .await?;
                }
                last_work = Instant::now();
            }
            self.finish_backfills(a).await?;
        }
    }
    async fn scan_backfill(&self, a: &Account, conn: &mut Connection) -> Result<(), Error> {
        let row = sqlx::query(
            "
SELECT * FROM backfill_jobs WHERE account_id=? AND state IN ('pending','scanning') ORDER
BY created_at LIMIT 1
",
        )
        .bind(&a.id)
        .fetch_optional(&self.store.reads)
        .await?;
        let Some(row) = row else { return Ok(()) };
        let job: String = row.try_get("id")?;
        let since: i64 = row.try_get("since")?;
        let until: Option<i64> = row.try_get("until")?;
        let unread: bool = row.try_get("unread_only")?;
        let redeliver: bool = row.try_get("redeliver")?;
        let requested: Option<Vec<String>> = row
            .try_get::<Option<String>, _>("folders_json")?
            .map(|s| serde_json::from_str(&s))
            .transpose()?;
        let names = if let Some(names) = requested {
            names
        } else {
            conn.folders(a).await?
        };
        for name in names {
            let mailbox = conn.examine(&name).await?;
            let validity = i64::from(mailbox.uid_validity.ok_or(epistle_imap::Error {
                reason: "uidvalidity_missing",
                permanent: true,
                auth: false,
            })?);
            let fid = sqlx::query_scalar::<_, String>(
                "SELECT id FROM folders WHERE account_id=? AND name=?",
            )
            .bind(&a.id)
            .bind(&name)
            .fetch_optional(&self.store.reads)
            .await?
            .unwrap_or_else(id);
            let f = fid.clone();
            let account = a.id.clone();
            let n = name.clone();
            self.store.write(move|c|Box::pin(async move{sqlx::query("INSERT OR IGNORE INTO folders(id,account_id,name,uidvalidity,state) VALUES(?,?,?,?,'backfill')").bind(f).bind(account).bind(n).bind(validity).execute(c).await?;
Ok(())})).await?;
            let done: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM backfill_folders WHERE job_id=? AND folder_id=?",
            )
            .bind(&job)
            .bind(&fid)
            .fetch_one(&self.store.reads)
            .await?;
            if done > 0 {
                continue;
            }
            let date = chrono::DateTime::from_timestamp(since.saturating_sub(86400), 0)
                .ok_or(epistle_store::Error::Conflict("invalid date"))?
                .format("%d-%b-%Y")
                .to_string();
            let ids = conn
                .search(&format!(
                    "SINCE {date}{}",
                    if unread { " UNSEEN" } else { "" }
                ))
                .await?;
            for chunk in ids.chunks(500) {
                let current: Option<String> =
                    sqlx::query_scalar("SELECT state FROM backfill_jobs WHERE id=?")
                        .bind(&job)
                        .fetch_optional(&self.store.reads)
                        .await?;
                if current.as_deref() == Some("cancelled") || current.is_none() {
                    return Ok(());
                }
                let set = chunk
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(",");
                let items = conn.metadata(a, &fid, &name, validity, &set).await?;
                let j = job.clone();
                self.store.write(move|c|Box::pin(async move{for p in items{if p.internal_date<since||until.is_some_and(|u|p.internal_date>=u){continue;
}let inserted=sqlx::query("INSERT OR IGNORE INTO backfill_matches(job_id,identity,pointer) VALUES(?,?,?)").bind(&j).bind(p.identity()).bind(serde_json::to_string(&p)?).execute(&mut *c).await?.rows_affected();
sqlx::query("UPDATE backfill_jobs SET matched=matched+?,state='scanning' WHERE id=? AND state!='cancelled'").bind(inserted as i64).bind(&j).execute(&mut *c).await?;
}Ok(())})).await?;
            }
            let j = job.clone();
            self.store
                .write(move |c| {
                    Box::pin(async move {
                        sqlx::query("INSERT OR IGNORE INTO backfill_folders VALUES(?,?)")
                            .bind(j)
                            .bind(fid)
                            .execute(c)
                            .await?;
                        Ok(())
                    })
                })
                .await?;
        }
        loop {
            let matches=sqlx::query("SELECT identity,pointer FROM backfill_matches WHERE job_id=? AND enqueued=0 LIMIT 500").bind(&job).fetch_all(&self.store.reads).await?;
            if matches.is_empty() {
                break;
            }
            let j = job.clone();
            self.store.write(move|c|Box::pin(async move{
    let state:Option<String>=sqlx::query_scalar("SELECT state FROM backfill_jobs WHERE id=?").bind(&j).fetch_optional(&mut *c).await?;
    if state.as_deref()==Some("cancelled")||state.is_none(){return Ok(());
}
    for row in matches{let p:Pointer=serde_json::from_str(&row.try_get::<String,_>("pointer")?)?;
let added=enqueue(c,&p,"backfill",Some(&j),redeliver).await?;
     sqlx::query("UPDATE backfill_matches SET enqueued=1 WHERE job_id=? AND identity=?").bind(&j).bind(row.try_get::<String,_>("identity")?).execute(&mut *c).await?;
     if added{sqlx::query("UPDATE backfill_jobs SET enqueued=enqueued+1 WHERE id=?").bind(&j).execute(&mut *c).await?;
}
    }Ok(())
   })).await?;
            let state: Option<String> =
                sqlx::query_scalar("SELECT state FROM backfill_jobs WHERE id=?")
                    .bind(&job)
                    .fetch_optional(&self.store.reads)
                    .await?;
            if state.as_deref() == Some("cancelled") || state.is_none() {
                return Ok(());
            }
        }
        self.store.write(move|c|Box::pin(async move{sqlx::query("UPDATE backfill_jobs SET state='running' WHERE id=? AND state!='cancelled'").bind(job).execute(c).await?;
Ok(())})).await?;
        Ok(())
    }
    async fn finish_backfills(&self, a: &Account) -> Result<(), Error> {
        let account = a.id.clone();
        self.store
            .write(move |c| {
                Box::pin(async move {
                    sqlx::query(
                        "
UPDATE backfill_jobs SET state=CASE WHEN EXISTS(SELECT 1 FROM fetch_queue WHERE
backfill_id=backfill_jobs.id AND state='dead') THEN 'failed' ELSE 'done'
END,completed_at=? WHERE account_id=? AND state='running' AND NOT EXISTS(SELECT 1 FROM
fetch_queue WHERE backfill_id=backfill_jobs.id AND state='pending') AND NOT
EXISTS(SELECT 1 FROM outbox WHERE backfill_id=backfill_jobs.id)
",
                    )
                    .bind(now())
                    .bind(account)
                    .execute(c)
                    .await?;
                    Ok(())
                })
            })
            .await?;
        Ok(())
    }
    pub(crate) async fn command_worker(&self, a: &Account) -> Result<(), Error> {
        loop {
            tokio::time::sleep(Duration::from_millis(300)).await;
            if !self.active(a).await? {
                continue;
            }
            let rows = sqlx::query(
                "
SELECT * FROM commands cmd WHERE account_id=? AND state='pending' AND next_attempt_at<=?
AND NOT EXISTS(SELECT 1 FROM commands prior WHERE prior.message_key=cmd.message_key AND
prior.state='pending' AND prior.rowid<cmd.rowid) ORDER BY rowid LIMIT 50
",
            )
            .bind(&a.id)
            .bind(now())
            .fetch_all(&self.store.reads)
            .await?;
            if rows.is_empty() {
                continue;
            }
            let (mut conn, _) = self.connect(a).await?;
            for row in rows {
                let command: String = row.try_get("id")?;
                let mid: String = row.try_get("message_key")?;
                let pointer: Option<String> =
                    sqlx::query_scalar("SELECT pointer FROM message_index WHERE message_key=?")
                        .bind(&mid)
                        .fetch_optional(&self.store.reads)
                        .await?;
                let outcome = if let Some(pointer) = pointer {
                    let p: Pointer = serde_json::from_str(&pointer)?;
                    conn.mark_read(&p, row.try_get("read_value")?).await
                } else {
                    Ok(None)
                };
                match outcome {
                    Ok(p) => {
                        let state = if p.is_some() { "done" } else { "gone" };
                        self.store.write(move|c|Box::pin(async move{sqlx::query("UPDATE commands SET state=?,completed_at=? WHERE id=?").bind(state).bind(now()).bind(command).execute(&mut *c).await?;
      if let Some(p)=p{sqlx::query("UPDATE message_index SET uidvalidity=?,uid=?,pointer=? WHERE message_key=?").bind(p.uidvalidity).bind(p.uid).bind(serde_json::to_string(&p)?).bind(mid).execute(c).await?;
}Ok(())})).await?;
                    }
                    Err(e) => {
                        let attempts = row.try_get::<i64, _>("attempts")? + 1;
                        let reason = e.reason;
                        let dead = e.permanent || attempts >= self.config.max_attempts;
                        self.store.write(move|c|Box::pin(async move{sqlx::query("UPDATE commands SET state=?,attempts=?,next_attempt_at=?,last_error=? WHERE id=?").bind(if dead{"failed"}else{"pending"}).bind(attempts).bind(now()+backoff(attempts)).bind(reason).bind(command).execute(c).await?;
Ok(())})).await?;
                        return Err(e.into());
                    }
                }
            }
            conn.logout().await;
        }
    }
}
