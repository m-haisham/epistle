//! Transactional enqueue, claims and recovery for outbound submissions.

use crate::{Error, SendRequest, Sender};
use epistle_core::{SmtpConfig, hash, id, now};
use epistle_store::Error as StoreError;
use schemars::JsonSchema;
use serde::Serialize;

/// Submission status. `sent` means accepted by SMTP, not recipient delivery.
#[derive(Debug, Serialize, JsonSchema, sqlx::FromRow)]
pub struct SendJob {
    pub id: String,
    pub account_id: String,
    pub idempotency_key: String,
    pub message_id: String,
    pub state: String,
    pub attempts: i64,
    pub next_attempt: i64,
    pub last_error: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
    pub accepted_at: Option<i64>,
}

#[derive(sqlx::FromRow)]
pub(crate) struct Claim {
    pub id: String,
    pub account_id: String,
    pub envelope: String,
    pub message: Vec<u8>,
    pub attempts: i64,
    pub revision: i64,
}

impl Sender {
    /// Persists an immutable message or returns a matching idempotent submission.
    pub async fn enqueue(&self, account_id: &str, request: SendRequest) -> Result<SendJob, Error> {
        let request_hash = hash(&serde_json::to_vec(&request)?);
        let existing: Option<(String, String)> = sqlx::query_as(
            "SELECT id,request_hash FROM send_jobs WHERE account_id=? AND idempotency_key=?",
        )
        .bind(account_id)
        .bind(&request.idempotency_key)
        .fetch_optional(&self.store.reads)
        .await?;

        if let Some((id, previous)) = existing {
            check_hash(&previous, &request_hash)?;
            return self.job(&id).await;
        }

        let account = self.store.account(account_id).await?;
        if !account.enabled {
            return Err(StoreError::Conflict("account_disabled").into());
        }

        let smtp = SmtpConfig::for_account(&account)
            .ok_or(Error::Invalid("smtp_configuration_required"))?;
        smtp.validate(self.config.testing.allow_insecure_endpoints)
            .map_err(|_| Error::Invalid("invalid_smtp_configuration"))?;

        let prepared = request.prepare(&account.email, self.config.sending.max_message_bytes)?;
        let job_id = id();
        let result = self.store.write(move |c| Box::pin(async move {
            let previous: Option<(String, String)> = sqlx::query_as(
                "SELECT id,request_hash FROM send_jobs WHERE account_id=? AND idempotency_key=?",
            )
            .bind(&account.id).bind(&request.idempotency_key)
            .fetch_optional(&mut *c).await?;

            if let Some((id, previous)) = previous {
                check_hash(&previous, &request_hash)?;
                return Ok(id);
            }

            let current: Option<i64> = sqlx::query_scalar(
                "SELECT revision FROM accounts WHERE id=? AND enabled=1",
            )
            .bind(&account.id).fetch_optional(&mut *c).await?;

            if current != Some(account.revision) {
                return Err(StoreError::Conflict("account_changed"));
            }

            sqlx::query("INSERT INTO send_jobs(id,account_id,idempotency_key,request_hash,message_id,envelope,message,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)")
                .bind(&job_id).bind(&account.id).bind(request.idempotency_key)
                .bind(request_hash).bind(prepared.message_id).bind(prepared.envelope)
                .bind(prepared.message).bind(now()).bind(now()).execute(c).await?;

            Ok(job_id)
        })).await?;

        self.job(&result).await
    }

    /// Loads public submission metadata without message contents or recipients.
    pub async fn job(&self, id: &str) -> Result<SendJob, Error> {
        sqlx::query_as("SELECT * FROM send_jobs WHERE id=?")
            .bind(id)
            .fetch_optional(&self.store.reads)
            .await?
            .ok_or_else(|| StoreError::NotFound.into())
    }

    /// Requeues a terminal failure; unknown outcomes require duplicate consent.
    pub async fn retry(&self, id: &str, allow_duplicate: bool) -> Result<SendJob, Error> {
        let job_id = id.to_owned();
        self.store.write(move |c| Box::pin(async move {
            let state: Option<String> = sqlx::query_scalar("SELECT state FROM send_jobs WHERE id=?")
                .bind(&job_id).fetch_optional(&mut *c).await?;
            let state = state.ok_or(StoreError::NotFound)?;

            if state != "failed" && !(state == "unknown" && allow_duplicate) {
                return Err(StoreError::Conflict("retry_requires_failed_or_acknowledged_unknown"));
            }

            sqlx::query("UPDATE send_jobs SET state='pending',attempts=0,next_attempt=0,last_error=NULL,updated_at=? WHERE id=?")
                .bind(now()).bind(job_id).execute(c).await?;

            Ok(())
        })).await?;

        self.job(id).await
    }

    /// Cancels only a job that has not been claimed by a worker.
    pub async fn cancel(&self, id: &str) -> Result<SendJob, Error> {
        let job_id = id.to_owned();
        self.store
            .write(move |c| {
                Box::pin(async move {
                    let state: Option<String> =
                        sqlx::query_scalar("SELECT state FROM send_jobs WHERE id=?")
                            .bind(&job_id)
                            .fetch_optional(&mut *c)
                            .await?;
                    let state = state.ok_or(StoreError::NotFound)?;

                    if state != "pending" && state != "cancelled" {
                        return Err(StoreError::Conflict("send_already_started"));
                    }

                    sqlx::query("UPDATE send_jobs SET state='cancelled',updated_at=? WHERE id=?")
                        .bind(now())
                        .bind(job_id)
                        .execute(c)
                        .await?;

                    Ok(())
                })
            })
            .await?;

        self.job(id).await
    }

    /// Recovers safe claims and quarantines interrupted SMTP transactions.
    /// Run once at startup, before starting any sending workers.
    pub async fn recover(&self) -> Result<(), Error> {
        self.store.write(|c| Box::pin(async move {
            sqlx::query("UPDATE send_jobs SET state='pending',updated_at=? WHERE state='preparing'")
                .bind(now()).execute(&mut *c).await?;
            sqlx::query("UPDATE send_jobs SET state='unknown',last_error='interrupted_submission',updated_at=? WHERE state='sending'")
                .bind(now()).execute(c).await?;

            Ok(())
        })).await?;

        Ok(())
    }

    pub(crate) async fn claim(&self) -> Result<Option<Claim>, Error> {
        Ok(self.store.write(|c| Box::pin(async move {
            let claim: Option<Claim> = sqlx::query_as(
                "SELECT j.id,j.account_id,j.envelope,j.message,j.attempts+1 AS attempts,a.revision FROM send_jobs j JOIN accounts a ON a.id=j.account_id WHERE j.state='pending' AND j.next_attempt<=? AND a.enabled=1 AND NOT EXISTS(SELECT 1 FROM send_jobs active WHERE active.account_id=j.account_id AND active.state IN ('preparing','sending')) ORDER BY j.created_at,j.rowid LIMIT 1",
            )
            .bind(now()).fetch_optional(&mut *c).await?;

            if let Some(claim) = &claim {
                sqlx::query("UPDATE send_jobs SET state='preparing',attempts=attempts+1,updated_at=? WHERE id=?")
                    .bind(now()).bind(&claim.id).execute(c).await?;
            }

            Ok(claim)
        })).await?)
    }

    pub(crate) async fn begin_submission(&self, claim: &Claim) -> Result<bool, Error> {
        let (id, account_id, revision) =
            (claim.id.clone(), claim.account_id.clone(), claim.revision);
        Ok(self.store.write(move |c| Box::pin(async move {
            let result = sqlx::query("UPDATE send_jobs SET state='sending',updated_at=? WHERE id=? AND state='preparing' AND EXISTS(SELECT 1 FROM accounts WHERE id=? AND enabled=1 AND revision=?)")
                .bind(now()).bind(id).bind(account_id).bind(revision).execute(c).await?;

            Ok(result.rows_affected() == 1)
        })).await?)
    }

    pub(crate) async fn finish(
        &self,
        id: &str,
        state: &str,
        reason: Option<&str>,
        next: i64,
    ) -> Result<(), Error> {
        let (id, state, reason) = (id.to_owned(), state.to_owned(), reason.map(str::to_owned));
        self.store.write(move |c| Box::pin(async move {
            sqlx::query("UPDATE send_jobs SET state=?,last_error=?,next_attempt=?,updated_at=?,accepted_at=CASE WHEN ?='sent' THEN ? ELSE accepted_at END WHERE id=? AND state IN ('preparing','sending')")
                .bind(&state).bind(reason).bind(next).bind(now()).bind(state)
                .bind(now()).bind(id).execute(c).await?;

            Ok(())
        })).await?;

        Ok(())
    }
}

fn check_hash(previous: &str, requested: &str) -> Result<(), StoreError> {
    if previous != requested {
        return Err(StoreError::Conflict(
            "idempotency_key_reused_with_different_message",
        ));
    }

    Ok(())
}
