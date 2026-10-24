//! Account supervision and durable email ingestion.

mod parse;
mod queue;
mod workers;
use epistle_auth::TokenProvider;
use epistle_core::{Account, Config, backoff, now};
use epistle_delivery::FileStore;
use epistle_imap::Connection;
use epistle_store::Store;

pub use parse::parse_message;
pub use queue::{enqueue, handoff};
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
    time::Duration,
};
use thiserror::Error;
use tokio_util::sync::CancellationToken;
use tracing::Instrument;

#[derive(Debug, Error)]
pub enum Error {
    #[error("database operation failed")]
    Store(#[from] epistle_store::Error),
    #[error("database query failed")]
    Sql(#[from] sqlx::Error),
    #[error("token acquisition failed")]
    Auth(#[from] epistle_auth::Error),
    #[error("IMAP failed")]
    Imap(#[from] epistle_imap::Error),
    #[error("file operation failed")]
    Files(#[from] epistle_delivery::Error),
    #[error("stored payload invalid")]
    Json(#[from] serde_json::Error),
    #[error("parser task failed")]
    Join(#[from] tokio::task::JoinError),
    #[error("planned token recycle")]
    Recycle,
}

/// Supervises account workers and their durable queues.
#[derive(Clone)]
pub struct Service {
    pub store: Store,
    pub tokens: TokenProvider,
    pub files: FileStore,
    pub config: Arc<Config>,
}

impl Service {
    /// Opens a session and returns its planned recycle deadline, not raw token expiry.
    pub async fn connect(&self, a: &Account) -> Result<(Connection, i64), Error> {
        let access = self.tokens.get_access_token(a, false).await?;
        let recycle_at = access.recycle_at(&a.id);

        match Connection::connect(a, access.secret, access.password, self.config.watchdog_secs)
            .await
        {
            Ok(c) => Ok((c, recycle_at)),
            Err(e) if e.auth && a.auth_kind != epistle_core::AuthKind::Password => {
                let access = self.tokens.get_access_token(a, true).await?;
                let recycle_at = access.recycle_at(&a.id);

                match Connection::connect(a, access.secret, false, self.config.watchdog_secs).await
                {
                    Ok(c) => Ok((c, recycle_at)),
                    Err(e) if e.auth => {
                        Err(epistle_auth::Error::Reauth("credentials_rejected").into())
                    }
                    Err(e) => Err(e.into()),
                }
            }
            Err(e) => Err(e.into()),
        }
    }

    /// Stops scheduling on cancellation and waits for account workers to drain.
    pub async fn run(self, cancel: CancellationToken) {
        let mut accounts: HashMap<String, (i64, CancellationToken, tokio::task::JoinHandle<()>)> =
            HashMap::new();

        loop {
            tokio::select! {
                biased;
                _ = cancel.cancelled() => break,
                _ = tokio::time::sleep(Duration::from_secs(1)) => {}
            }

            let all = match self.store.accounts().await {
                Ok(a) => a,
                Err(e) => {
                    tracing::error!(error = %e, "account enumeration failed");
                    continue;
                }
            };
            let mut remove = vec![];

            for (id, (revision, _, task)) in &accounts {
                if !all
                    .iter()
                    .any(|a| a.id == *id && a.enabled && a.revision == *revision)
                    || task.is_finished()
                {
                    remove.push(id.clone());
                }
            }

            let mut panicked = HashSet::new();

            for id in remove {
                if let Some((revision, stop, task)) = accounts.remove(&id) {
                    stop.cancel();

                    if task.await.is_err() {
                        panicked.insert(id.clone());
                        let _ = self
                            .store
                            .status_for_revision(&id, revision, "error", Some("worker_panicked"), 0)
                            .await;
                    }
                }
            }
            for a in all {
                if cancel.is_cancelled() {
                    break;
                }

                if !a.enabled
                    || panicked.contains(&a.id)
                    || accounts.contains_key(&a.id)
                    || a.status == "error"
                    || (a.status == "needs_reauth" && self.config.reauth_reminder_secs <= 0)
                {
                    continue;
                }

                let service = self.clone();
                let stop = cancel.child_token();
                let child = stop.clone();
                let account = a.clone();
                let span =
                    tracing::info_span!("account", account_id = %a.id, revision = a.revision);
                let task = tokio::spawn(
                    async move {
                        if account.status == "needs_reauth" {
                            service.remind(&account, &child).await;
                        } else {
                            service.supervise(account, child).await;
                        }
                    }
                    .instrument(span),
                );
                accounts.insert(a.id, (a.revision, stop, task));
            }
        }
        for (_, (_, stop, task)) in accounts {
            stop.cancel();
            let _ = task.await;
        }
        tracing::info!("account workers stopped");
    }

    /// Stops sibling workers on failure and drains every in-flight operation.
    async fn run_workers(&self, a: &Account, cancel: &CancellationToken) -> Result<(), Error> {
        let stop = cancel.child_token();
        let finish = |result: Result<(), Error>| {
            if result.is_err() {
                stop.cancel();
            }
            result
        };
        let (watch, fetch, commands) = tokio::join!(
            async { finish(self.watch(a, &stop).await) },
            async { finish(self.fetch_worker(a, &stop).await) },
            async { finish(self.command_worker(a, &stop).await) },
        );

        watch?;
        fetch?;
        commands
    }

    async fn supervise(self, a: Account, cancel: CancellationToken) {
        if cancel.is_cancelled() {
            return;
        }

        let mut failures = a.consecutive_failures;
        let mut first_failure = sqlx::query_scalar::<_, Option<i64>>(
            "SELECT first_failure_at FROM accounts WHERE id=?",
        )
        .bind(&a.id)
        .fetch_optional(&self.store.reads)
        .await
        .ok()
        .flatten()
        .flatten()
        .unwrap_or(0);
        let _ = self
            .store
            .status_for_revision(&a.id, a.revision, "connecting", None, failures)
            .await;

        loop {
            if cancel.is_cancelled() {
                return;
            }

            let result = self.run_workers(&a, &cancel).await;

            if cancel.is_cancelled() {
                return;
            }

            let Err(error) = result else { return };

            if matches!(error, Error::Recycle) {
                failures = 0;
                let _ = self
                    .store
                    .status_for_revision(
                        &a.id,
                        a.revision,
                        "reconnecting",
                        Some("token_recycle"),
                        0,
                    )
                    .await;
                continue;
            }
            if self
                .store
                .account(&a.id)
                .await
                .is_ok_and(|current| current.status == "active")
            {
                failures = 0;
                first_failure = 0;
            }
            failures += 1;

            if first_failure == 0 {
                first_failure = now();
            }

            let (status, reason, permanent) = match &error {
                Error::Auth(epistle_auth::Error::Reauth(reason)) => ("needs_reauth", *reason, true),
                Error::Auth(epistle_auth::Error::Unconfigured | epistle_auth::Error::Data) => {
                    ("error", "invalid_configuration", true)
                }
                Error::Auth(epistle_auth::Error::Crypto) => {
                    ("error", "credential_decryption_failed", true)
                }
                Error::Join(_) => ("error", "worker_panicked", true),
                Error::Imap(e) if e.auth && failures >= 3 && now() - first_failure >= 120 => {
                    ("needs_reauth", e.reason, true)
                }
                Error::Imap(e) if e.permanent => ("error", e.reason, true),
                Error::Imap(e) => ("degraded", e.reason, false),
                Error::Auth(_) => ("degraded", "provider_outage", false),
                _ => ("degraded", "internal_error", false),
            };

            if failures == 1 && !permanent {
                let _ = self
                    .store
                    .status_for_revision(
                        &a.id,
                        a.revision,
                        "reconnecting",
                        Some("connection_lost"),
                        failures,
                    )
                    .await;
            }

            let _ = self
                .store
                .status_for_revision(&a.id, a.revision, status, Some(reason), failures)
                .await;
            let _ = self.store.worker_state(&a.id, "backoff").await;
            tracing::warn!(account_id = %a.id, reason, failures, "account connection interrupted");

            if permanent {
                if status == "needs_reauth" && self.config.reauth_reminder_secs > 0 {
                    self.remind(&a, &cancel).await;
                }
                return;
            }

            let delay = if reason == "credentials_rejected" {
                60
            } else {
                backoff(failures)
            };
            tokio::select! {
                biased;
                _ = cancel.cancelled() => return,
                _ = tokio::time::sleep(Duration::from_secs(delay as u64)) => {}
            }
        }
    }

    async fn remind(&self, a: &Account, cancel: &CancellationToken) {
        if self.config.reauth_reminder_secs <= 0 {
            return;
        }
        loop {
            tokio::select! {
                _ = cancel.cancelled() => return,
                _ = tokio::time::sleep(Duration::from_secs(self.config.reauth_reminder_secs as u64)) => {}
            }

            let Ok(current) = self.store.account(&a.id).await else {
                return;
            };

            if !current.enabled
                || current.revision != a.revision
                || current.status != "needs_reauth"
            {
                return;
            }

            let _ = self
                .store
                .status_for_revision(
                    &a.id,
                    a.revision,
                    "needs_reauth",
                    current.status_reason.as_deref(),
                    current.consecutive_failures + 1,
                )
                .await;
        }
    }
}

#[cfg(test)]
mod recovery_tests;
