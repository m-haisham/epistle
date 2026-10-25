//! Authenticated outbound submission and endpoint configuration.

use super::{ApiError, AppState};
use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use epistle_core::{Account, SmtpConfig};
use epistle_send::{SendJob, SendRequest, Sender};
use schemars::JsonSchema;
use serde::Deserialize;

fn sender(state: AppState) -> Sender {
    Sender {
        store: state.store,
        tokens: state.tokens,
        config: state.config,
    }
}

impl From<epistle_send::Error> for ApiError {
    fn from(error: epistle_send::Error) -> Self {
        match error {
            epistle_send::Error::Invalid(reason) => Self::bad(reason),
            epistle_send::Error::Store(error) => error.into(),
            _ => Self::new(StatusCode::INTERNAL_SERVER_ERROR, "send_storage_error"),
        }
    }
}

/// Queues an immutable email with a caller-supplied idempotency key.
pub(super) async fn enqueue(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(request): Json<SendRequest>,
) -> Result<(StatusCode, Json<SendJob>), ApiError> {
    Ok((
        StatusCode::ACCEPTED,
        Json(sender(state).enqueue(&id, request).await?),
    ))
}

/// Returns SMTP submission status without exposing message contents.
pub(super) async fn status(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<SendJob>, ApiError> {
    Ok(Json(sender(state).job(&id).await?))
}

/// Cancels a pending submission before a worker claims it.
pub(super) async fn cancel(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<SendJob>, ApiError> {
    Ok(Json(sender(state).cancel(&id).await?))
}

/// Explicit acknowledgment that retrying an unknown outcome may send a duplicate.
#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct RetryRequest {
    #[serde(default)]
    allow_duplicate: bool,
}

pub(super) async fn retry(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(request): Json<RetryRequest>,
) -> Result<(StatusCode, Json<SendJob>), ApiError> {
    Ok((
        StatusCode::ACCEPTED,
        Json(sender(state).retry(&id, request.allow_duplicate).await?),
    ))
}

/// Sets an SMTP endpoint; credentials continue to come from the account.
pub(super) async fn configure(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(smtp): Json<SmtpConfig>,
) -> Result<Json<Account>, ApiError> {
    smtp.validate(state.config.testing.allow_insecure_endpoints)
        .map_err(|e| ApiError::bad(e.to_string()))?;

    let account_id = id.clone();
    state
        .store
        .write(move |c| {
            Box::pin(async move {
                let config: Option<String> =
                    sqlx::query_scalar("SELECT config FROM accounts WHERE id=?")
                        .bind(&account_id)
                        .fetch_optional(&mut *c)
                        .await?;
                let mut config: epistle_core::AccountConfig =
                    serde_json::from_str(&config.ok_or(epistle_store::Error::NotFound)?)?;
                config.smtp = Some(smtp);

                sqlx::query("UPDATE accounts SET config=?,revision=revision+1 WHERE id=?")
                    .bind(serde_json::to_string(&config)?)
                    .bind(account_id)
                    .execute(c)
                    .await?;

                Ok(())
            })
        })
        .await?;

    Ok(Json(state.store.account(&id).await?))
}
