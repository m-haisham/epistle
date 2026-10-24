//! Durable files and signed, retryable webhook delivery.

use epistle_core::{Config, FileManifest, Message, backoff, hash, id, now};
use epistle_store::Store;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use sqlx::Row;
use std::{
    collections::HashSet,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use thiserror::Error;
use tokio_util::sync::CancellationToken;

#[derive(Debug, Error)]
pub enum Error {
    #[error("file storage failed")]
    Io(#[from] std::io::Error),
    #[error("storage transaction failed")]
    Store(#[from] epistle_store::Error),
    #[error("storage query failed")]
    Sql(#[from] sqlx::Error),
    #[error("payload serialization failed")]
    Json(#[from] serde_json::Error),
    #[error("webhook client initialization failed")]
    Http(#[from] reqwest::Error),
    #[error("signing failed")]
    Signing,
    #[error("file worker stopped")]
    Join(#[from] tokio::task::JoinError),
}

/// Extracted file bytes awaiting durable storage.
pub struct FileDraft {
    pub role: String,
    pub filename: String,
    pub content_type: String,
    pub content_id: Option<String>,
    pub content_disposition: Option<String>,
    pub content_description: Option<String>,
    pub content_location: Option<String>,
    pub bytes: Vec<u8>,
}

/// File manifest paired with its internal storage path.
#[derive(Clone)]
pub struct StoredFile {
    pub manifest: FileManifest,
    pub path: String,
}

/// Durable payload and files ready for transactional handoff.
pub struct Prepared {
    pub message: Message,
    pub files: Vec<StoredFile>,
    pub payload_path: String,
    pub payload_size: i64,
}

/// Immutable message files and their retention lifecycle.
#[derive(Clone)]
pub struct FileStore {
    root: PathBuf,
}

impl FileStore {
    /// Uses the message-file directory beneath the service data directory.
    pub fn new(data: &Path) -> Self {
        Self {
            root: data.join("files"),
        }
    }

    /// Flushes immutable payload and file bytes before database handoff.
    #[tracing::instrument(skip_all, fields(message_id = %message.id))]
    pub async fn prepare(
        &self,
        mut message: Message,
        drafts: Vec<FileDraft>,
        event_key: String,
    ) -> Result<Prepared, Error> {
        let root = self.root.clone();
        tokio::task::spawn_blocking(move || {
            // Immutable generations prevent redelivery from overwriting retained files.
            let dir = root.join(&message.id).join(id());
            std::fs::create_dir_all(&dir)?;
            let mut files = vec![];

            for d in drafts {
                let fid = id();
                let path = dir.join(&fid);
                durable_write(&path, &d.bytes)?;
                let manifest = FileManifest {
                    id: fid,
                    role: d.role,
                    filename: d.filename,
                    content_type: d.content_type,
                    size: d.bytes.len() as i64,
                    sha256: hash(&d.bytes),
                    content_id: d.content_id,
                    content_disposition: d.content_disposition,
                    content_description: d.content_description,
                    content_location: d.content_location,
                };
                message.files.push(manifest.clone());
                files.push(StoredFile {
                    manifest,
                    path: path.to_string_lossy().into_owned(),
                });
            }

            let event = serde_json::json!({
                "id":id(),
                "kind":"email.message.received",
                "channel":"email",
                "idempotency_key":format!("email:{}",hash(event_key.as_bytes())),
                "message":message,
            });
            let payload = serde_json::to_vec(&event)?;
            let payload_path = dir.join("payload.json");
            durable_write(&payload_path, &payload)?;
            std::fs::File::open(&dir)?.sync_all()?;
            std::fs::File::open(root.join(&message.id))?.sync_all()?;
            std::fs::File::open(&root)?.sync_all()?;

            Ok(Prepared {
                message,
                files,
                payload_path: payload_path.to_string_lossy().into_owned(),
                payload_size: payload.len() as i64,
            })
        })
        .await?
    }

    /// Expires eligible files and removes startup orphans.
    pub async fn sweep(&self, store: &Store, config: &Config, startup: bool) -> Result<(), Error> {
        tokio::fs::create_dir_all(&self.root).await?;
        let pressure = fs2::available_space(&self.root)? < config.storage.disk_reserve_bytes;

        let rows = sqlx::query(
            "
SELECT file_id,path FROM message_files WHERE expired=0 AND expires_at IS NOT NULL AND
(expires_at<=? OR ?=1) AND NOT EXISTS(SELECT 1 FROM outbox WHERE
outbox.message_key=message_files.message_key)
",
        )
        .bind(now())
        .bind(pressure)
        .fetch_all(&store.reads)
        .await?;

        for row in rows {
            let fid: String = row.try_get("file_id")?;
            let path: String = row.try_get("path")?;
            let expired = store
                .write(move |c| {
                    Box::pin(async move {
                        let changed = sqlx::query("UPDATE message_files SET expired=1 WHERE file_id=? AND expired=0 AND expires_at IS NOT NULL AND (expires_at<=? OR ?=1) AND NOT EXISTS(SELECT 1 FROM outbox WHERE outbox.message_key=message_files.message_key)")
                            .bind(fid)
                            .bind(now())
                            .bind(pressure)
                            .execute(c)
                            .await?
                            .rows_affected();

                        Ok(changed > 0)
                    })
                })
                .await?;
            // Commit the tombstone before unlinking. A crash leaves either a
            // retained file, or an expired orphan removable at the next startup.
            if expired {
                remove_if_exists(&path).await?;
            }
        }

        let rows = sqlx::query(
            "
SELECT id,payload_path FROM messages WHERE expired=0 AND expires_at IS NOT NULL AND
(expires_at<=? OR ?=1) AND NOT EXISTS(SELECT 1 FROM outbox WHERE
outbox.message_key=messages.id)
",
        )
        .bind(now())
        .bind(pressure)
        .fetch_all(&store.reads)
        .await?;

        for row in rows {
            let mid: String = row.try_get("id")?;
            let path: String = row.try_get("payload_path")?;
            let stored_path = path.clone();
            let expired = store
                .write(move |c| {
                    Box::pin(async move {
                        let changed = sqlx::query("UPDATE messages SET expired=1 WHERE id=? AND payload_path=? AND expired=0 AND expires_at IS NOT NULL AND (expires_at<=? OR ?=1) AND NOT EXISTS(SELECT 1 FROM outbox WHERE outbox.message_key=messages.id)")
                            .bind(mid)
                            .bind(stored_path)
                            .bind(now())
                            .bind(pressure)
                            .execute(c)
                            .await?
                            .rows_affected();

                        Ok(changed > 0)
                    })
                })
                .await?;

            if expired {
                remove_if_exists(&path).await?;
            }
        }

        let payloads = sqlx::query(
            "
SELECT path FROM message_payloads WHERE expired=0 AND expires_at IS NOT NULL AND
(expires_at<=? OR ?=1) AND NOT EXISTS(SELECT 1 FROM outbox WHERE
outbox.message_key=message_payloads.message_key)
",
        )
        .bind(now())
        .bind(pressure)
        .fetch_all(&store.reads)
        .await?;

        for row in payloads {
            let path: String = row.try_get("path")?;
            let stored_path = path.clone();
            let expired = store
                .write(move |c| {
                    Box::pin(async move {
                        let changed = sqlx::query("UPDATE message_payloads SET expired=1 WHERE path=? AND expired=0 AND expires_at IS NOT NULL AND (expires_at<=? OR ?=1) AND NOT EXISTS(SELECT 1 FROM outbox WHERE outbox.message_key=message_payloads.message_key)")
                            .bind(stored_path)
                            .bind(now())
                            .bind(pressure)
                            .execute(c)
                            .await?
                            .rows_affected();

                        Ok(changed > 0)
                    })
                })
                .await?;

            if expired {
                remove_if_exists(&path).await?;
            }
        }

        let cutoff = now() - config.storage.index_retention_secs;
        store
            .write(move |c| {
                Box::pin(async move {
                    sqlx::query(
                        "
DELETE FROM message_index WHERE created_at<? AND NOT EXISTS(SELECT 1 FROM fetch_queue
WHERE fetch_queue.message_key=message_index.message_key) AND NOT EXISTS(SELECT 1 FROM
commands WHERE commands.message_key=message_index.message_key AND state='pending') AND
NOT EXISTS(SELECT 1 FROM outbox WHERE outbox.message_key=message_index.message_key)
",
                    )
                    .bind(cutoff)
                    .execute(&mut *c)
                    .await?;
                    sqlx::query("DELETE FROM oauth_states WHERE expires_at<?")
                        .bind(now())
                        .execute(c)
                        .await?;

                    Ok(())
                })
            })
            .await?;

        if startup {
            let rows: Vec<String> = sqlx::query_scalar(
                "
SELECT path FROM message_files WHERE expired=0 UNION SELECT payload_path FROM outbox
WHERE payload_path IS NOT NULL UNION SELECT path FROM message_payloads WHERE expired=0
UNION SELECT payload_path FROM messages WHERE expired=0
",
            )
            .fetch_all(&store.reads)
            .await?;
            let keep: HashSet<_> = rows.into_iter().collect();
            let root = self.root.clone();
            tokio::task::spawn_blocking(move || sweep_orphans(&root, &keep)).await??;
        }

        Ok(())
    }
}

fn durable_write(path: &Path, bytes: &[u8]) -> Result<(), std::io::Error> {
    use std::io::Write;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

fn sweep_orphans(dir: &Path, keep: &HashSet<String>) -> Result<(), std::io::Error> {
    for entry in std::fs::read_dir(dir)? {
        let e = entry?;
        let path = e.path();

        if e.file_type()?.is_dir() {
            sweep_orphans(&path, keep)?;

            if std::fs::read_dir(&path)?.next().is_none() {
                std::fs::remove_dir(path)?;
            }
        } else if !keep.contains(path.to_string_lossy().as_ref()) {
            std::fs::remove_file(path)?;
        }
    }

    Ok(())
}

async fn remove_if_exists(path: &str) -> Result<(), std::io::Error> {
    match tokio::fs::remove_file(path).await {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

/// Signs the timestamp and exact webhook body bytes.
pub fn signature(secret: &str, timestamp: i64, body: &[u8]) -> Result<String, Error> {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).map_err(|_| Error::Signing)?;
    mac.update(timestamp.to_string().as_bytes());
    mac.update(b".");
    mac.update(body);

    Ok(format!("v1={}", hex::encode(mac.finalize().into_bytes())))
}

/// Checks a webhook signature and its timestamp tolerance.
pub fn verify_signature(
    secret: &str,
    timestamp: i64,
    body: &[u8],
    signature: &str,
    at: i64,
    tolerance: i64,
) -> bool {
    if (i128::from(at) - i128::from(timestamp)).unsigned_abs() > tolerance.max(0) as u128 {
        return false;
    }

    let Some(raw) = signature
        .strip_prefix("v1=")
        .and_then(|s| hex::decode(s).ok())
    else {
        return false;
    };

    let Ok(mut mac) = Hmac::<Sha256>::new_from_slice(secret.as_bytes()) else {
        return false;
    };

    mac.update(timestamp.to_string().as_bytes());
    mac.update(b".");
    mac.update(body);
    mac.verify_slice(&raw).is_ok()
}

/// Signed webhook delivery with persisted retries.
#[derive(Clone)]
pub struct Delivery {
    store: Store,
    config: Arc<Config>,
    client: reqwest::Client,
}

impl Delivery {
    /// Builds a bounded HTTP client without redirecting signed requests.
    pub fn new(store: Store, config: Arc<Config>) -> Result<Self, Error> {
        Ok(Self {
            store,
            config,
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(30))
                .redirect(reqwest::redirect::Policy::none())
                .build()?,
        })
    }

    /// Delivers one batch and commits every independent outcome.
    #[tracing::instrument(skip_all, name = "delivery_batch")]
    pub async fn tick(&self) -> Result<usize, Error> {
        let rows = sqlx::query(
            "
SELECT * FROM outbox o WHERE state='pending' AND next_attempt_at<=? AND NOT
EXISTS(SELECT 1 FROM outbox earlier WHERE earlier.message_key=o.message_key AND
earlier.seq<o.seq AND earlier.state='pending') ORDER BY seq LIMIT 16
",
        )
        .bind(now())
        .fetch_all(&self.store.reads)
        .await?;
        let count = rows.len();
        let mut tasks = tokio::task::JoinSet::new();

        for row in rows {
            let worker = self.clone();
            tasks.spawn(tracing::Instrument::in_current_span(async move {
                worker.deliver(row).await
            }));
        }
        // Drain every independent delivery even when one fails to commit. Dropping
        // the JoinSet here would abort unrelated requests after remote acceptance.
        let mut failure = None;
        while let Some(result) = tasks.join_next().await {
            if let Err(error) = result.map_err(Error::Join).and_then(|r| r) {
                failure.get_or_insert(error);
            }
        }
        if let Some(error) = failure {
            return Err(error);
        }

        Ok(count)
    }

    #[tracing::instrument(skip_all, fields(delivery_id = tracing::field::Empty))]
    async fn deliver(&self, row: sqlx::sqlite::SqliteRow) -> Result<(), Error> {
        let seq: i64 = row.try_get("seq")?;
        tracing::Span::current().record("delivery_id", seq);
        let key: String = row.try_get("idempotency_key")?;
        let message_key: String = row.try_get("message_key")?;
        let body = if let Some(p) = row.try_get::<Option<String>, _>("payload")? {
            p.into_bytes()
        } else {
            match tokio::fs::read(row.try_get::<String, _>("payload_path")?).await {
                Ok(body) => body,
                Err(error) => {
                    let missing = error.kind() == std::io::ErrorKind::NotFound;
                    self.fail_delivery(
                        seq,
                        row.try_get::<i64, _>("attempts")? + 1,
                        if missing {
                            "payload_missing".into()
                        } else {
                            "payload_unreadable".into()
                        },
                        !missing,
                        None,
                    )
                    .await?;

                    return Ok(());
                }
            }
        };
        let timestamp = now();
        let sig = signature(&self.config.delivery.webhook_secret, timestamp, &body)?;

        let response = self
            .client
            .post(&self.config.delivery.webhook_url)
            .header("content-type", "application/json")
            .header("x-epistle-timestamp", timestamp.to_string())
            .header("x-epistle-signature", sig)
            .header("idempotency-key", format!("email:{}", hash(key.as_bytes())))
            .header("x-epistle-delivery-id", seq.to_string())
            .body(body)
            .send()
            .await;
        let status = response.as_ref().ok().map(|r| r.status().as_u16());

        if status.is_some_and(|s| (200..300).contains(&s)) {
            let retention = self.config.storage.file_retention_secs;
            let backfill_id: Option<String> = row.try_get("backfill_id")?;
            self.store
                .write(move |c| {
                    Box::pin(async move {
                        sqlx::query("DELETE FROM outbox WHERE seq=?")
                            .bind(seq)
                            .execute(&mut *c)
                            .await?;
                        sqlx::query(
                            "
UPDATE message_files SET delivered_at=COALESCE(delivered_at,?),expires_at=? WHERE
message_key=? AND NOT EXISTS(SELECT 1 FROM outbox WHERE message_key=?)
",
                        )
                        .bind(now())
                        .bind(now() + retention)
                        .bind(&message_key)
                        .bind(&message_key)
                        .execute(&mut *c)
                        .await?;
                        sqlx::query(
                            "
UPDATE messages SET delivered_at=COALESCE(delivered_at,?),expires_at=? WHERE id=? AND
NOT EXISTS(SELECT 1 FROM outbox WHERE message_key=?)
",
                        )
                        .bind(now())
                        .bind(now() + retention)
                        .bind(&message_key)
                        .bind(&message_key)
                        .execute(&mut *c)
                        .await?;
                        sqlx::query(
                            "
UPDATE message_payloads SET expires_at=? WHERE message_key=? AND expired=0 AND NOT
EXISTS(SELECT 1 FROM outbox WHERE message_key=?)
",
                        )
                        .bind(now() + retention)
                        .bind(&message_key)
                        .bind(&message_key)
                        .execute(&mut *c)
                        .await?;

                        if let Some(job) = backfill_id {
                            sqlx::query(
                                "UPDATE backfill_jobs SET delivered=delivered+1 WHERE id=?",
                            )
                            .bind(job)
                            .execute(&mut *c)
                            .await?;
                        }

                        Ok(())
                    })
                })
                .await?;
            tracing::debug!("webhook acknowledged and committed");
        } else {
            let attempts = row.try_get::<i64, _>("attempts")? + 1;
            let retryable = status.is_none_or(|s| s >= 500 || s == 408 || s == 429);
            let delay = response
                .as_ref()
                .ok()
                .and_then(|r| r.headers().get("retry-after"))
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.parse::<i64>().ok())
                .map(|s| s.clamp(1, 86400));
            let reason = status
                .map(|s| format!("http_{s}"))
                .unwrap_or_else(|| "network_error".into());
            self.fail_delivery(seq, attempts, reason, retryable, delay)
                .await?;
        }

        Ok(())
    }

    async fn fail_delivery(
        &self,
        seq: i64,
        attempts: i64,
        reason: String,
        retryable: bool,
        delay: Option<i64>,
    ) -> Result<(), Error> {
        let dead = !retryable || attempts >= self.config.delivery.max_attempts;
        let delay = delay.unwrap_or_else(|| backoff(attempts));
        tracing::warn!(
            delivery_id = seq,
            attempts,
            reason,
            dead,
            retry_delay_secs = delay,
            "webhook delivery failed"
        );
        self.store
            .write(move |c| {
                Box::pin(async move {
                    sqlx::query("UPDATE outbox SET state=?,attempts=?,next_attempt_at=?,last_error=? WHERE seq=?")
                        .bind(if dead { "dead" } else { "pending" })
                        .bind(attempts)
                        .bind(now() + delay)
                        .bind(reason)
                        .bind(seq)
                        .execute(c)
                        .await?;

                    Ok(())
                })
            })
            .await?;

        if dead {
            tracing::error!(
                delivery_id = seq,
                "webhook delivery dead; replay or discard required"
            );
        }

        Ok(())
    }

    /// Drains the current delivery batch before honoring cancellation.
    pub async fn run(self, cancel: CancellationToken) {
        loop {
            tokio::select! {
                biased;
                _ = cancel.cancelled() => break,
                _ = tokio::time::sleep(Duration::from_secs(1)) => {}
            }

            // Complete the whole batch, including durable acknowledgments.
            if let Err(error) = self.tick().await {
                tracing::error!(%error, "delivery tick failed");
            }
        }

        tracing::info!("delivery worker stopped");
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    #[test]
    fn signatures_bind_exact_bytes_and_timestamp() {
        let signature = signature("secret", 1000, b"{\"a\":1}").unwrap();
        assert!(verify_signature(
            "secret",
            1000,
            b"{\"a\":1}",
            &signature,
            1001,
            300
        ));
        assert!(!verify_signature(
            "secret",
            1000,
            b"{\"a\":2}",
            &signature,
            1001,
            300
        ));
        assert!(!verify_signature(
            "secret",
            1000,
            b"{\"a\":1}",
            &signature,
            1400,
            300
        ));
        assert!(!verify_signature(
            "wrong",
            1000,
            b"{\"a\":1}",
            &signature,
            1001,
            300
        ));
    }
}
