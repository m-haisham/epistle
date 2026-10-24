//! Mailbox discovery, message fetching and persisted commands.

use crate::{Error, Service, enqueue, handoff, parse_message};
use epistle_core::{Account, Pointer, id, now};
use epistle_imap::Connection;
use sqlx::Row;
use std::time::{Duration, Instant};
use tokio_util::sync::CancellationToken;

impl Service {
    #[tracing::instrument(skip_all, fields(worker = "watch", account_id = %a.id))]
    pub(crate) async fn watch(&self, a: &Account, cancel: &CancellationToken) -> Result<(), Error> {
        if cancel.is_cancelled() {
            return Ok(());
        }

        self.store.worker_state(&a.id, "authenticating").await?;
        let (mut conn, recycle_at) = self.connect(a).await?;
        let names = conn.folders(a).await?;
        self.store.worker_state(&a.id, "syncing").await?;

        loop {
            if cancel.is_cancelled() {
                conn.logout().await;

                return Ok(());
            }

            if now() >= recycle_at {
                conn.logout().await;

                return Err(Error::Recycle);
            }

            let mut healthy_folder = None;
            let mut selected = false;

            for name in &names {
                if cancel.is_cancelled() {
                    conn.logout().await;

                    return Ok(());
                }

                let mailbox = match conn.examine(name).await {
                    Ok(mailbox) => mailbox,
                    Err(e) if e.reason == "mailbox_missing" => {
                        let account = a.id.clone();
                        let name = name.clone();
                        self.store
                            .write(move |c| {
                                Box::pin(async move {
                                    sqlx::query("INSERT INTO folders(id,account_id,name,uidvalidity,state,last_error) VALUES(?,?,?,0,'error','mailbox_missing') ON CONFLICT(account_id,name) DO UPDATE SET state='error',last_error='mailbox_missing'")
                                        .bind(id())
                                        .bind(account)
                                        .bind(name)
                                        .execute(c)
                                        .await?;

                                    Ok(())
                                })
                            })
                            .await?;
                        selected = false;
                        continue;
                    }
                    Err(e) => return Err(e.into()),
                };
                healthy_folder = Some(name);
                selected = true;
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
                let (fid, cursor, initial) = if let Some(row) = existing {
                    let fid: String = row.try_get("id")?;
                    let initial = row.try_get::<i64, _>("uidvalidity")? == 0;
                    let cursor = if initial {
                        next.saturating_sub(1)
                    } else if row.try_get::<i64, _>("uidvalidity")? == validity {
                        row.try_get::<i64, _>("cursor_uid")?
                    } else {
                        0
                    };
                    (fid, cursor, initial)
                } else {
                    (id(), next.saturating_sub(1), false)
                };
                let f = fid.clone();
                let account = a.id.clone();
                let n = name.clone();
                let days = a.config.initial_sync_days;
                let modseq = mailbox.highest_modseq.and_then(|x| i64::try_from(x).ok());
                self.store
                    .write(move |c| {
                        Box::pin(async move {
                            let inserted = sqlx::query("
INSERT OR IGNORE INTO
folders(id,account_id,name,uidvalidity,uidnext,cursor_uid,highestmodseq)
VALUES(?,?,?,?,?,?,?)
")
                                .bind(&f)
                                .bind(&account)
                                .bind(&n)
                                .bind(validity)
                                .bind(next)
                                .bind(cursor)
                                .bind(modseq)
                                .execute(&mut *c)
                                .await?
                                .rows_affected();
                            sqlx::query("UPDATE folders SET uidvalidity=?,uidnext=?,cursor_uid=?,highestmodseq=?,state='idle',last_error=NULL,last_synced_at=? WHERE id=?")
                                .bind(validity)
                                .bind(next)
                                .bind(cursor)
                                .bind(modseq)
                                .bind(now())
                                .bind(&f)
                                .execute(&mut *c)
                                .await?;

                            if inserted > 0 || initial {
                                sqlx::query("INSERT INTO backfill_jobs(id,account_id,since,until,folders_json,created_at) VALUES(?,?,?,?,?,?)")
                                    .bind(id())
                                    .bind(account)
                                    .bind(now() - i64::from(days) * 86400)
                                    .bind(now() + 1)
                                    .bind(serde_json::to_string(&vec![n])?)
                                    .bind(now())
                                    .execute(&mut *c)
                                    .await?;
                            }

                            Ok(())
                        })
                    })
                    .await?;
                let ids = conn
                    .search(&format!("UID {}:*", cursor.saturating_add(1)))
                    .await?;
                let ids: Vec<_> = ids
                    .into_iter()
                    .filter(|uid| i64::from(*uid) > cursor)
                    .collect();

                for chunk in ids.chunks(500) {
                    if cancel.is_cancelled() {
                        conn.logout().await;

                        return Ok(());
                    }

                    let set = chunk
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                        .join(",");

                    let items = conn.metadata(a, &fid, name, validity, &set).await?;
                    let f = fid.clone();
                    let max = chunk.last().copied().map(i64::from).unwrap_or(cursor);
                    self.store
                        .write(move |c| {
                            Box::pin(async move {
                                for p in items {
                                    enqueue(c, &p, "live", None, false).await?;
                                }
                                sqlx::query("UPDATE folders SET cursor_uid=MAX(cursor_uid,?),last_synced_at=?,state='idle' WHERE id=?")
                                    .bind(max)
                                    .bind(now())
                                    .bind(f)
                                    .execute(c)
                                    .await?;

                                Ok(())
                            })
                        })
                        .await?;
                }
            }
            if let Some(name) = healthy_folder {
                // A failed EXAMINE may deselect the previous mailbox.
                if !selected {
                    conn.examine(name).await?;
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
            } else {
                self.store
                    .status_for_revision(&a.id, a.revision, "degraded", Some("mailbox_missing"), 0)
                    .await?;
            }

            let seconds = self
                .config
                .reconcile_secs
                .min((recycle_at - now()).max(1) as u64);

            if healthy_folder.is_some() {
                // IDLE has no pending mutation; dropping this session is safe.
                conn = tokio::select! {
                    biased;
                    _ = cancel.cancelled() => return Ok(()),
                    result = conn.idle(seconds) => result?,
                };
            } else {
                tokio::select! {
                    biased;
                    _ = cancel.cancelled() => {
                        conn.logout().await;

                        return Ok(());
                    }
                    _ = tokio::time::sleep(Duration::from_secs(seconds)) => {}
                }
            }
        }
    }

    async fn active(&self, a: &Account) -> Result<bool, Error> {
        let current = self.store.account(&a.id).await?;

        Ok(current.enabled && current.revision == a.revision && current.status == "active")
    }

    #[tracing::instrument(skip_all, fields(worker = "fetch_worker", account_id = %a.id))]
    pub(crate) async fn fetch_worker(
        &self,
        a: &Account,
        cancel: &CancellationToken,
    ) -> Result<(), Error> {
        let mut connection: Option<(Connection, i64)> = None;
        let mut last_work = Instant::now();

        loop {
            tokio::select! {
                biased;
                _ = cancel.cancelled() => break,
                _ = tokio::time::sleep(Duration::from_millis(300)) => {}
            }
            if !self.active(a).await? {
                continue;
            }

            let jobs: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM backfill_jobs WHERE account_id=? AND state IN ('pending','scanning')")
                .bind(&a.id)
                .fetch_one(&self.store.reads)
                .await?;

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
                .is_none_or(|(_, recycle_at)| *recycle_at <= now())
            {
                if cancel.is_cancelled() {
                    break;
                }

                if let Some((c, _)) = connection.take() {
                    c.logout().await;
                }
                connection = Some(self.connect(a).await?);
            }

            let Some((conn, recycle_at)) = connection.as_mut() else {
                continue;
            };

            if jobs > 0 {
                self.scan_backfill(a, conn, cancel).await?;
            }

            let mut bytes = 0;

            for row in rows {
                if cancel.is_cancelled() || now() >= *recycle_at || !self.active(a).await? {
                    break;
                }

                let original_pointer: String = row.try_get("pointer")?;
                let p: Pointer = serde_json::from_str(&original_pointer)?;

                if bytes > 0 && bytes + p.size > self.config.fetch_batch_bytes {
                    break;
                }
                bytes += p.size;
                let stub: String = row.try_get("id")?;
                let fetch = conn.fetch(&p).await;
                let fetched = match fetch {
                    Ok(f) => f,
                    Err(e) => {
                        // Socket/auth/provider failures belong to the account,
                        // not this message. An outage must not exhaust its queue.
                        if e.reason != "invalid_message_id" {
                            return Err(e.into());
                        }

                        let reason = e.reason;
                        self.store
                            .write(move |c| {
                                Box::pin(async move {
                                    sqlx::query("UPDATE fetch_queue SET attempts=attempts+1,state='dead',last_error=? WHERE id=? AND pointer=?")
                                        .bind(reason)
                                        .bind(stub)
                                        .bind(original_pointer)
                                        .execute(c)
                                        .await?;

                                    Ok(())
                                })
                            })
                            .await?;
                        continue;
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
                                sqlx::query(
                                    "UPDATE fetch_queue SET state='gone' WHERE id=? AND pointer=?",
                                )
                                .bind(stub)
                                .bind(original_pointer)
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

        if let Some((conn, _)) = connection {
            conn.logout().await;
        }

        Ok(())
    }

    async fn scan_backfill(
        &self,
        a: &Account,
        conn: &mut Connection,
        cancel: &CancellationToken,
    ) -> Result<(), Error> {
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
            if cancel.is_cancelled() {
                return Ok(());
            }

            let mailbox = match conn.examine(&name).await {
                Ok(mailbox) => mailbox,
                Err(e) if e.reason == "mailbox_missing" => {
                    self.store
                        .write(move |c| {
                            Box::pin(async move {
                                sqlx::query("UPDATE backfill_jobs SET state='failed',last_error='mailbox_missing',completed_at=? WHERE id=? AND state IN ('pending','scanning')")
                                    .bind(now())
                                    .bind(job)
                                    .execute(c)
                                    .await?;

                                Ok(())
                            })
                        })
                        .await?;

                    return Ok(());
                }
                Err(e) => return Err(e.into()),
            };
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
            self.store
                .write(move |c| {
                    Box::pin(async move {
                        sqlx::query("INSERT OR IGNORE INTO folders(id,account_id,name,uidvalidity,state) VALUES(?,?,?,?,'backfill')")
                            .bind(f)
                            .bind(account)
                            .bind(n)
                            .bind(validity)
                            .execute(c)
                            .await?;

                        Ok(())
                    })
                })
                .await?;
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
                if cancel.is_cancelled() {
                    return Ok(());
                }

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
                self.store
                    .write(move |c| {
                        Box::pin(async move {
                            for p in items {
                                if p.internal_date < since
                                    || until.is_some_and(|u| p.internal_date >= u)
                                {
                                    continue;
                                }

                                let inserted = sqlx::query("INSERT OR IGNORE INTO backfill_matches(job_id,identity,pointer) VALUES(?,?,?)")
                                    .bind(&j)
                                    .bind(p.identity())
                                    .bind(serde_json::to_string(&p)?)
                                    .execute(&mut *c)
                                    .await?
                                    .rows_affected();
                                sqlx::query("UPDATE backfill_jobs SET matched=matched+?,state='scanning' WHERE id=? AND state!='cancelled'")
                                    .bind(inserted as i64)
                                    .bind(&j)
                                    .execute(&mut *c)
                                    .await?;
                            }

                            Ok(())
                        })
                    })
                    .await?;
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
            if cancel.is_cancelled() {
                return Ok(());
            }

            let matches = sqlx::query("SELECT identity,pointer FROM backfill_matches WHERE job_id=? AND enqueued=0 LIMIT 500")
                .bind(&job)
                .fetch_all(&self.store.reads)
                .await?;

            if matches.is_empty() {
                break;
            }

            let j = job.clone();
            self.store
                .write(move |c| {
                    Box::pin(async move {
                        let state: Option<String> =
                            sqlx::query_scalar("SELECT state FROM backfill_jobs WHERE id=?")
                                .bind(&j)
                                .fetch_optional(&mut *c)
                                .await?;

                        if state.as_deref() == Some("cancelled") || state.is_none() {
                            return Ok(());
                        }
                        for row in matches {
                            let p: Pointer =
                                serde_json::from_str(&row.try_get::<String, _>("pointer")?)?;
                            let added = enqueue(c, &p, "backfill", Some(&j), redeliver).await?;
                            sqlx::query("UPDATE backfill_matches SET enqueued=1 WHERE job_id=? AND identity=?")
                                .bind(&j)
                                .bind(row.try_get::<String, _>("identity")?)
                                .execute(&mut *c)
                                .await?;

                            if added {
                                sqlx::query(
                                    "UPDATE backfill_jobs SET enqueued=enqueued+1 WHERE id=?",
                                )
                                .bind(&j)
                                .execute(&mut *c)
                                .await?;
                            }
                        }

                        Ok(())
                    })
                })
                .await?;
            let state: Option<String> =
                sqlx::query_scalar("SELECT state FROM backfill_jobs WHERE id=?")
                    .bind(&job)
                    .fetch_optional(&self.store.reads)
                    .await?;

            if state.as_deref() == Some("cancelled") || state.is_none() {
                return Ok(());
            }
        }

        self.store
            .write(move |c| {
                Box::pin(async move {
                    sqlx::query("UPDATE backfill_jobs SET state='running' WHERE id=? AND state!='cancelled'").bind(job).execute(c).await?;

                    Ok(())
                })
            })
            .await?;

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

    #[tracing::instrument(skip_all, fields(worker = "command_worker", account_id = %a.id))]
    pub(crate) async fn command_worker(
        &self,
        a: &Account,
        cancel: &CancellationToken,
    ) -> Result<(), Error> {
        loop {
            tokio::select! {
                biased;
                _ = cancel.cancelled() => break,
                _ = tokio::time::sleep(Duration::from_millis(300)) => {}
            }
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

            if cancel.is_cancelled() {
                break;
            }

            if rows.is_empty() {
                continue;
            }

            let (mut conn, recycle_at) = self.connect(a).await?;

            for row in rows {
                if cancel.is_cancelled() || now() >= recycle_at || !self.active(a).await? {
                    break;
                }

                let command: String = row.try_get("id")?;
                let mid: String = row.try_get("message_key")?;
                let pointer: Option<String> =
                    sqlx::query_scalar("SELECT pointer FROM message_index WHERE message_key=?")
                        .bind(&mid)
                        .fetch_optional(&self.store.reads)
                        .await?;
                let original_pointer = pointer.clone();
                let outcome = if let Some(pointer) = pointer {
                    let p: Pointer = serde_json::from_str(&pointer)?;
                    conn.mark_read(&p, row.try_get("read_value")?).await
                } else {
                    Ok(None)
                };

                match outcome {
                    Ok(p) => {
                        let state = if p.is_some() { "done" } else { "gone" };
                        self.store
                            .write(move |c| {
                                Box::pin(async move {
                                    let current: Option<String> = sqlx::query_scalar(
                                        "SELECT pointer FROM message_index WHERE message_key=?",
                                    )
                                    .bind(&mid)
                                    .fetch_optional(&mut *c)
                                    .await?;

                                    if current != original_pointer {
                                        return Ok(());
                                    }
                                    sqlx::query(
                                        "UPDATE commands SET state=?,completed_at=? WHERE id=?",
                                    )
                                    .bind(state)
                                    .bind(now())
                                    .bind(command)
                                    .execute(&mut *c)
                                    .await?;

                                    if let Some(p) = p {
                                        sqlx::query("UPDATE message_index SET uidvalidity=?,uid=?,pointer=? WHERE message_key=?")
                                            .bind(p.uidvalidity)
                                            .bind(p.uid)
                                            .bind(serde_json::to_string(&p)?)
                                            .bind(mid)
                                            .execute(c)
                                            .await?;
                                    }

                                    Ok(())
                                })
                            })
                            .await?;
                    }
                    Err(e) => {
                        if e.reason != "invalid_message_id" {
                            return Err(e.into());
                        }

                        let reason = e.reason;
                        self.store
                            .write(move |c| {
                                Box::pin(async move {
                                    sqlx::query("UPDATE commands SET state='failed',attempts=attempts+1,completed_at=?,last_error=? WHERE id=?")
                                        .bind(now())
                                        .bind(reason)
                                        .bind(command)
                                        .execute(c)
                                        .await?;

                                    Ok(())
                                })
                            })
                            .await?;
                        continue;
                    }
                }
            }
            conn.logout().await;
        }

        Ok(())
    }
}
