//! Gracefully drained send workers and conservative submission recovery.

use crate::{
    Error, Sender,
    queue::Claim,
    transport::{Failure, envelope},
};
use epistle_core::{backoff, now};
use std::time::Duration;
use tokio_util::sync::CancellationToken;

impl Sender {
    /// Runs bounded workers; shutdown drains the current SMTP result to storage.
    pub async fn run(self, cancel: CancellationToken) {
        let mut workers = tokio::task::JoinSet::new();

        for _ in 0..self.config.sending.workers {
            let sender = self.clone();
            let cancel = cancel.clone();
            workers.spawn(async move { sender.work(cancel).await });
        }

        while let Some(result) = workers.join_next().await {
            if !matches!(result, Ok(Ok(()))) {
                tracing::error!("send worker failed; stopping service for durable recovery");
                cancel.cancel();
            }
        }

        tracing::info!("send workers drained");
    }

    async fn work(&self, cancel: CancellationToken) -> Result<(), Error> {
        while !cancel.is_cancelled() {
            if let Some(claim) = self.claim().await? {
                self.process(claim, &cancel).await?;
                continue;
            }

            tokio::select! {
                biased;
                _ = cancel.cancelled() => break,
                _ = tokio::time::sleep(Duration::from_millis(250)) => {},
            }
        }

        Ok(())
    }

    pub(crate) async fn process(
        &self,
        claim: Claim,
        cancel: &CancellationToken,
    ) -> Result<(), Error> {
        let account = match self.store.account(&claim.account_id).await {
            Ok(account) => account,
            Err(epistle_store::Error::NotFound) => return Ok(()),
            Err(error) => return Err(error.into()),
        };

        if cancel.is_cancelled() || !account.enabled || account.revision != claim.revision {
            return self.defer(&claim).await;
        }

        let envelope = match envelope(&claim.envelope) {
            Ok(envelope) => envelope,
            Err(error) => return self.reject(&claim, error).await,
        };
        let mut connection = match self.connect(&account).await {
            Ok(connection) => connection,
            Err(error) => return self.reject(&claim, error).await,
        };

        if cancel.is_cancelled() || !self.begin_submission(&claim).await? {
            return self.defer(&claim).await;
        }

        // After this durable marker, a lost reply may mean SMTP accepted the message.
        let result =
            tokio::time::timeout(self.timeout(), connection.send(&envelope, &claim.message)).await;
        let (state, reason, next) = match result {
            Ok(Ok(response)) if response.has_code(250) => ("sent", None, 0),
            Ok(Err(error)) if error.is_transient() => {
                self.retry_outcome(claim.attempts, "smtp_temporary_rejection")
            }
            Ok(Err(error)) if error.is_permanent() || error.is_client() => {
                ("failed", Some("smtp_message_rejected"), 0)
            }
            _ => ("unknown", Some("smtp_acceptance_unknown"), 0),
        };

        // A failed QUIT must never erase an already observed acceptance.
        self.finish(&claim.id, state, reason, next).await?;
        tracing::info!(send_id = %claim.id, account_id = %claim.account_id, state, attempt = claim.attempts, reason, "SMTP submission recorded");

        Ok(())
    }

    async fn defer(&self, claim: &Claim) -> Result<(), Error> {
        self.finish(&claim.id, "pending", Some("account_changed_or_shutdown"), 0)
            .await
    }

    async fn reject(&self, claim: &Claim, failure: Failure) -> Result<(), Error> {
        let (state, reason, next) = if failure.retryable {
            self.retry_outcome(claim.attempts, failure.reason)
        } else {
            ("failed", Some(failure.reason), 0)
        };

        self.finish(&claim.id, state, reason, next).await?;
        tracing::warn!(send_id = %claim.id, state, reason, "SMTP preparation failed");

        Ok(())
    }

    fn retry_outcome(
        &self,
        attempts: i64,
        reason: &'static str,
    ) -> (&'static str, Option<&'static str>, i64) {
        if attempts >= self.config.sending.max_attempts {
            ("failed", Some(reason), 0)
        } else {
            ("pending", Some(reason), now() + backoff(attempts))
        }
    }
}
