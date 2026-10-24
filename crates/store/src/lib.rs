use epistle_core::{Account, id, now};
use futures::future::BoxFuture;
use sqlx::{
    Connection, Row, SqliteConnection, SqlitePool,
    sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions},
};
use std::{path::Path, time::Duration};
use thiserror::Error;
use tokio::sync::{mpsc, oneshot};

#[derive(Debug, Error)]
pub enum Error {
    #[error("database operation failed")]
    Sql(#[from] sqlx::Error),
    #[error("migration failed")]
    Migration(#[from] sqlx::migrate::MigrateError),
    #[error("writer stopped")]
    Closed,
    #[error("stale process epoch")]
    Fenced,
    #[error("record not found")]
    NotFound,
    #[error("invalid stored data")]
    Json(#[from] serde_json::Error),
    #[error("conflict: {0}")]
    Conflict(&'static str),
}
type Job = Box<dyn for<'c> FnOnce(&'c mut SqliteConnection, i64) -> BoxFuture<'c, ()> + Send>;
#[derive(Clone)]
pub struct Store {
    pub reads: SqlitePool,
    sender: mpsc::Sender<Job>,
    pub epoch: i64,
}
impl Store {
    pub async fn open(path: &Path) -> Result<Self, Error> {
        let opts = SqliteConnectOptions::new()
            .filename(path)
            .create_if_missing(true)
            .foreign_keys(true)
            .journal_mode(SqliteJournalMode::Wal)
            .busy_timeout(Duration::from_secs(10));
        let mut conn = SqliteConnection::connect_with(&opts).await?;
        sqlx::migrate!("../../migrations").run(&mut conn).await?;
        let epoch: i64 = sqlx::query_scalar(
            "UPDATE service_epoch SET epoch=epoch+1 WHERE singleton=1 RETURNING epoch",
        )
        .fetch_one(&mut conn)
        .await?;
        let reads = SqlitePoolOptions::new()
            .max_connections(4)
            .connect_with(opts.read_only(true))
            .await?;
        let (sender, mut receiver) = mpsc::channel::<Job>(256);
        tokio::spawn(async move {
            while let Some(job) = receiver.recv().await {
                job(&mut conn, epoch).await;
            }
        });
        Ok(Self {
            reads,
            sender,
            epoch,
        })
    }
    pub async fn write<T, F>(&self, f: F) -> Result<T, Error>
    where
        T: Send + 'static,
        F: for<'c> FnOnce(&'c mut SqliteConnection) -> BoxFuture<'c, Result<T, Error>>
            + Send
            + 'static,
    {
        let (send, receive) = oneshot::channel();
        self.sender
            .send(Box::new(move |conn, epoch| {
                Box::pin(async move {
                    let result = async {
                        let mut tx = conn.begin().await?;
                        let actual: i64 =
                            sqlx::query_scalar("SELECT epoch FROM service_epoch WHERE singleton=1")
                                .fetch_one(&mut *tx)
                                .await?;
                        if actual != epoch {
                            return Err(Error::Fenced);
                        }
                        let value = f(&mut tx).await?;
                        tx.commit().await?;
                        Ok(value)
                    }
                    .await;
                    let _ = send.send(result);
                })
            }))
            .await
            .map_err(|_| Error::Closed)?;
        receive.await.map_err(|_| Error::Closed)?
    }
    pub async fn account(&self, account_id: &str) -> Result<Account, Error> {
        let r = sqlx::query("SELECT * FROM accounts WHERE id=?")
            .bind(account_id)
            .fetch_optional(&self.reads)
            .await?
            .ok_or(Error::NotFound)?;
        account_from_row(&r)
    }
    pub async fn accounts(&self) -> Result<Vec<Account>, Error> {
        sqlx::query("SELECT * FROM accounts")
            .fetch_all(&self.reads)
            .await?
            .iter()
            .map(account_from_row)
            .collect()
    }
    pub async fn status(
        &self,
        account_id: &str,
        status: &str,
        reason: Option<&str>,
        failures: i64,
    ) -> Result<(), Error> {
        let (a, s, r) = (
            account_id.to_owned(),
            status.to_owned(),
            reason.map(str::to_owned),
        );
        self.write(move |c| {
            Box::pin(async move { status_tx(c, &a, &s, r.as_deref(), failures).await })
        })
        .await
    }
    pub async fn worker_state(&self, account_id: &str, state: &str) -> Result<(), Error> {
        let (a, s) = (account_id.to_owned(), state.to_owned());
        self.write(move |c| {
            Box::pin(async move {
                sqlx::query("UPDATE accounts SET worker_state=? WHERE id=?")
                    .bind(s)
                    .bind(a)
                    .execute(c)
                    .await?;
                Ok(())
            })
        })
        .await
    }
}
fn account_from_row(r: &sqlx::sqlite::SqliteRow) -> Result<Account, Error> {
    Ok(Account {
        id: r.try_get("id")?,
        external_ref: r.try_get("external_ref")?,
        auth_kind: serde_json::from_str(&r.try_get::<String, _>("auth_kind")?)?,
        email: r.try_get("email")?,
        config: serde_json::from_str(&r.try_get::<String, _>("config")?)?,
        status: r.try_get("status")?,
        status_reason: r.try_get("status_reason")?,
        status_seq: r.try_get("status_seq")?,
        status_since: r.try_get("status_since")?,
        consecutive_failures: r.try_get("consecutive_failures")?,
        last_success_at: r.try_get("last_success_at")?,
        enabled: r.try_get("enabled")?,
        revision: r.try_get("revision")?,
    })
}

pub async fn status_tx(
    c: &mut SqliteConnection,
    a: &str,
    status: &str,
    reason: Option<&str>,
    failures: i64,
) -> Result<(), Error> {
    let r = sqlx::query(
        "SELECT status,status_reason,status_seq,consecutive_failures FROM accounts WHERE id=?",
    )
    .bind(a)
    .fetch_optional(&mut *c)
    .await?
    .ok_or(Error::NotFound)?;
    let prev: String = r.try_get("status")?;
    let seq: i64 = r.try_get("status_seq")?;
    if seq > 0
        && prev == status
        && r.try_get::<Option<String>, _>("status_reason")?.as_deref() == reason
        && r.try_get::<i64, _>("consecutive_failures")? == failures
    {
        return Ok(());
    }
    let seq = seq + 1;
    let t = now();
    sqlx::query("UPDATE accounts SET status=?,status_reason=?,status_seq=?,status_since=?,consecutive_failures=?,first_failure_at=CASE WHEN ?=0 THEN NULL ELSE COALESCE(first_failure_at,?) END,last_success_at=CASE WHEN ?='active' THEN ? ELSE last_success_at END WHERE id=?")
 .bind(status).bind(reason).bind(seq).bind(t).bind(failures).bind(failures).bind(t).bind(status).bind(t).bind(a).execute(&mut *c).await?;
    let retryable = matches!(status, "connecting" | "reconnecting" | "degraded");
    let action = match status {
        "needs_reauth" => Some("reauthenticate"),
        "error" => Some("check_provider_settings"),
        _ => None,
    };
    let payload = serde_json::json!({"id":id(),"kind":"account.status_changed","channel":"email","account_id":a,"status":status,"previous_status":prev,"status_seq":seq,"reason":reason,"detail":reason,"action_required":action,"retryable":retryable,"since":t,"consecutive_failures":failures});
    let body = serde_json::to_string(&payload)?;
    sqlx::query("INSERT INTO outbox(idempotency_key,message_key,account_id,kind,payload,size_bytes,created_at) VALUES(?,?,?,'account.status_changed',?,?,?)")
 .bind(format!("status:{a}:{seq}")).bind(format!("account:{a}")).bind(a).bind(&body).bind(body.len() as i64).bind(t).execute(&mut *c).await?;
    sqlx::query("INSERT INTO connection_events(id,account_id,seq,from_status,to_status,reason,detail,created_at) VALUES(?,?,?,?,?,?,?,?)")
 .bind(id()).bind(a).bind(seq).bind(prev).bind(status).bind(reason).bind(reason).bind(t).execute(c).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    async fn fixture() -> (tempfile::TempDir, Store) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("test.sqlite")).await.unwrap();
        store.write(|c| Box::pin(async move {
            sqlx::query("INSERT INTO accounts(id,external_ref,auth_kind,email,config,status_since,created_at) VALUES('a','ref','\"password\"','a@example.test','{}',0,0)").execute(c).await?; Ok(())
        })).await.unwrap();
        (dir, store)
    }
    #[tokio::test]
    async fn migrations_wal_atomic_rollback_and_epoch_fencing() {
        let (dir, store) = fixture().await;
        let mode: String = sqlx::query_scalar("PRAGMA journal_mode")
            .fetch_one(&store.reads)
            .await
            .unwrap();
        assert_eq!(mode, "wal");
        let outcome: Result<(), Error> = store
            .write(|c| {
                Box::pin(async move {
                    sqlx::query("UPDATE accounts SET external_ref='changed' WHERE id='a'")
                        .execute(c)
                        .await?;
                    Err(Error::Conflict("injected crash before commit"))
                })
            })
            .await;
        assert!(outcome.is_err());
        let value: String = sqlx::query_scalar("SELECT external_ref FROM accounts")
            .fetch_one(&store.reads)
            .await
            .unwrap();
        assert_eq!(value, "ref");
        let newer = Store::open(&dir.path().join("test.sqlite")).await.unwrap();
        assert_eq!(newer.epoch, store.epoch + 1);
        assert!(matches!(
            store.status("a", "active", None, 0).await,
            Err(Error::Fenced)
        ));
        newer.status("a", "active", None, 0).await.unwrap();
    }
    #[tokio::test]
    async fn transitions_are_atomic_edge_triggered_and_ordered() {
        let (_dir, store) = fixture().await;
        for (status, reason, failures) in [
            ("connecting", None, 0),
            ("active", None, 0),
            ("active", None, 0),
            ("reconnecting", Some("token_recycle"), 0),
            ("degraded", Some("server_unreachable"), 1),
            ("degraded", Some("server_unreachable"), 2),
            ("needs_reauth", Some("token_revoked"), 2),
        ] {
            store.status("a", status, reason, failures).await.unwrap();
        }
        let events: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM connection_events")
            .fetch_one(&store.reads)
            .await
            .unwrap();
        let outbox: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM outbox")
            .fetch_one(&store.reads)
            .await
            .unwrap();
        assert_eq!((events, outbox), (6, 6));
        let seq: i64 = sqlx::query_scalar("SELECT status_seq FROM accounts")
            .fetch_one(&store.reads)
            .await
            .unwrap();
        assert_eq!(seq, 6);
        let ready: i64=sqlx::query_scalar("SELECT COUNT(*) FROM outbox o WHERE NOT EXISTS(SELECT 1 FROM outbox e WHERE e.message_key=o.message_key AND e.seq<o.seq AND e.state='pending')").fetch_one(&store.reads).await.unwrap();
        assert_eq!(ready, 1);
    }
}
