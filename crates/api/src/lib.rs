//! Authenticated HTTP operations and generated API documentation.

use aide::{
    OperationOutput,
    axum::{
        ApiRouter,
        routing::{delete, get, post},
    },
    openapi::{Info, OpenApi},
};
use axum::{
    Extension, Json,
    body::Body,
    extract::{Path, Query, Request, State},
    http::{HeaderMap, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
};
use epistle_auth::{Credentials, TokenProvider};
use epistle_core::{Account, AccountConfig, AuthKind, Config, Message, id, now};
use epistle_store::Store;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::Row;
use std::{
    sync::Arc,
    time::{Duration, Instant},
};
use subtle::ConstantTimeEq;
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncSeekExt};
use tokio_util::io::ReaderStream;
use tracing::Instrument;

/// Shared services used by HTTP handlers.
#[derive(Clone)]
pub struct AppState {
    pub store: Store,
    pub tokens: TokenProvider,
    pub config: Arc<Config>,
}

/// Sanitized API error response.
#[derive(Debug, Serialize, JsonSchema)]
pub struct ErrorBody {
    pub error: String,
}

/// HTTP status and public error code.
#[derive(Debug, Error)]
#[error("{message}")]
pub struct ApiError {
    status: StatusCode,
    message: String,
}

impl ApiError {
    fn new(status: StatusCode, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
        }
    }

    fn bad(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, message)
    }

    fn not_found() -> Self {
        Self::new(StatusCode::NOT_FOUND, "not_found")
    }

    fn gone() -> Self {
        Self::new(StatusCode::GONE, "expired")
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(ErrorBody {
                error: self.message,
            }),
        )
            .into_response()
    }
}

impl OperationOutput for ApiError {
    type Inner = ErrorBody;
    fn inferred_responses(
        ctx: &mut aide::generate::GenContext,
        operation: &mut aide::openapi::Operation,
    ) -> Vec<(Option<u16>, aide::openapi::Response)> {
        let responses = <Json<ErrorBody> as OperationOutput>::inferred_responses(ctx, operation);
        let Some((_, response)) = responses.into_iter().next() else {
            return vec![];
        };
        [400, 401, 404, 409, 410, 416, 500]
            .into_iter()
            .map(|code| (Some(code), response.clone()))
            .collect()
    }
}

impl From<epistle_store::Error> for ApiError {
    fn from(e: epistle_store::Error) -> Self {
        match e {
            epistle_store::Error::NotFound => Self::not_found(),
            epistle_store::Error::Conflict(m) => Self::new(StatusCode::CONFLICT, m),
            epistle_store::Error::Sql(ref err)
                if err
                    .as_database_error()
                    .is_some_and(|e| e.is_unique_violation()) =>
            {
                Self::new(StatusCode::CONFLICT, "already_exists")
            }
            _ => Self::new(StatusCode::INTERNAL_SERVER_ERROR, "storage_error"),
        }
    }
}

impl From<sqlx::Error> for ApiError {
    fn from(_: sqlx::Error) -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, "storage_error")
    }
}

impl From<epistle_auth::Error> for ApiError {
    fn from(e: epistle_auth::Error) -> Self {
        match e {
            epistle_auth::Error::State => Self::bad("invalid_or_expired_state"),
            epistle_auth::Error::Unconfigured => Self::bad("oauth_provider_not_configured"),
            epistle_auth::Error::Reauth(reason) => Self::bad(reason),
            _ => Self::new(StatusCode::INTERNAL_SERVER_ERROR, "credential_error"),
        }
    }
}

impl From<serde_json::Error> for ApiError {
    fn from(_: serde_json::Error) -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, "payload_error")
    }
}

impl From<std::io::Error> for ApiError {
    fn from(_: std::io::Error) -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, "file_error")
    }
}

/// Builds authenticated operations, OpenAPI and the Scalar reference.
pub fn router(state: AppState) -> axum::Router {
    aide::generate::infer_responses(true);
    let mut api = OpenApi {
        info: Info {
            title: "Epistle Email API".into(),
            version: env!("CARGO_PKG_VERSION").into(),
            description: Some("Transport-neutral single-tenant email API. Authenticate with Authorization: Bearer <API_KEY>. Webhook signatures use HMAC-SHA256 over timestamp + '.' + exact request bytes.".into()),
            ..Default::default()
        },
        ..Default::default()
    };
    let protected = ApiRouter::new()
        .api_route("/email/accounts", post(create_account).get(list_accounts))
        .api_route(
            "/email/accounts/{id}",
            get(get_account).delete(remove_account).patch(set_enabled),
        )
        .api_route("/email/accounts/{id}/credentials", post(update_credentials))
        .api_route("/email/accounts/{id}/backfills", post(create_backfill))
        .api_route("/email/messages/{id}", get(get_message))
        .api_route("/email/messages/{id}/files/{file_id}", get(download))
        .api_route("/email/messages/{id}/read", post(mark_read))
        .api_route("/commands/{id}", get(get_command))
        .api_route("/backfills/{id}", get(get_backfill).delete(cancel_backfill))
        .api_route("/outbox", get(list_outbox))
        .api_route("/outbox/{id}/replay", post(replay))
        .api_route("/outbox/{id}", delete(discard))
        .api_route("/health", get(health))
        .route_layer(middleware::from_fn_with_state(state.clone(), authenticate));
    let router = protected
        .merge(ApiRouter::new().api_route("/oauth/callback", get(callback)))
        .finish_api(&mut api);
    // Document security on every operation except the provider callback.
    let mut document = serde_json::to_value(api).unwrap_or_default();

    if let Some(root) = document.as_object_mut() {
        let components = root.entry("components").or_insert_with(|| json!({}));

        if let Some(components) = components.as_object_mut() {
            components.insert(
                "securitySchemes".into(),
                json!({"apiKey":{"type":"http","scheme":"bearer"}}),
            );
        }
    }
    if let Some(paths) = document.get_mut("paths").and_then(Value::as_object_mut) {
        for (path, item) in paths {
            if path == "/oauth/callback" {
                continue;
            }
            if let Some(ops) = item.as_object_mut() {
                for (method, op) in ops {
                    if ["get", "post", "delete", "patch"].contains(&method.as_str())
                        && let Some(op) = op.as_object_mut()
                    {
                        op.insert("security".into(), json!([{"apiKey":[]}]));
                    }
                }
            }
        }
    }
    // StatusCode is dynamic at runtime; document the concrete success codes used here.
    for (path, method, code) in [
        ("/email/accounts", "post", "201"),
        ("/email/accounts/{id}/backfills", "post", "202"),
        ("/email/messages/{id}/read", "post", "202"),
        ("/outbox/{id}/replay", "post", "202"),
        ("/email/accounts/{id}", "delete", "204"),
        ("/backfills/{id}", "delete", "204"),
        ("/outbox/{id}", "delete", "204"),
    ] {
        if let Some(responses) = document
            .get_mut("paths")
            .and_then(|p| p.get_mut(path))
            .and_then(|p| p.get_mut(method))
            .and_then(|p| p.get_mut("responses"))
            .and_then(Value::as_object_mut)
        {
            let success = responses
                .remove("200")
                .unwrap_or_else(|| json!({"description":"Success"}));
            responses.insert(code.into(), success);
        }
    }
    if let Some(operation) = document
        .get_mut("paths")
        .and_then(|p| p.get_mut("/email/messages/{id}/files/{file_id}"))
        .and_then(|p| p.get_mut("get"))
        .and_then(Value::as_object_mut)
    {
        let responses = operation.entry("responses").or_insert_with(|| json!({}));

        if let Some(responses) = responses.as_object_mut() {
            let binary = json!({"description":"File bytes","content":{"application/octet-stream":{"schema":{"type":"string","format":"binary"}}},"headers":{"ETag":{"schema":{"type":"string"}},"Content-Length":{"schema":{"type":"integer"}},"Accept-Ranges":{"schema":{"type":"string"}}}});
            responses.insert("200".into(), binary.clone());
            responses.insert("206".into(), binary);
            responses.insert("304".into(), json!({"description":"Not modified"}));
        }
    }
    router
        .route("/openapi.json", axum::routing::get(openapi))
        .route("/scalar", axum::routing::get(scalar))
        .layer(Extension(Arc::new(document)))
        .layer(axum::extract::DefaultBodyLimit::max(2 * 1024 * 1024))
        .layer(middleware::from_fn(trace_request))
        .with_state(state)
}

/// Records route templates and timing without URLs, headers or request bodies.
async fn trace_request(request: Request, next: Next) -> Response {
    let route = request
        .extensions()
        .get::<axum::extract::MatchedPath>()
        .map(|path| path.as_str())
        .unwrap_or("unmatched");
    let span =
        tracing::info_span!("http_request", request_id = %id(), method = %request.method(), route);

    async move {
        let started = Instant::now();

        let response = next.run(request).await;
        tracing::info!(
            status = response.status().as_u16(),
            elapsed_ms = started.elapsed().as_millis() as u64,
            "request completed"
        );
        response
    }
    .instrument(span)
    .await
}

async fn openapi(Extension(api): Extension<Arc<Value>>) -> Json<Value> {
    Json((*api).clone())
}

async fn scalar() -> axum::response::Html<&'static str> {
    axum::response::Html(include_str!("scalar.html"))
}

async fn authenticate(State(s): State<AppState>, request: Request, next: Next) -> Response {
    let key = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .unwrap_or("");
    let got = Sha256::digest(key.as_bytes());
    let expected = Sha256::digest(s.config.api_key.as_bytes());

    if !bool::from(got.as_slice().ct_eq(expected.as_slice())) {
        return ApiError::new(StatusCode::UNAUTHORIZED, "unauthorized").into_response();
    }
    next.run(request).await
}

#[derive(Deserialize, JsonSchema, Default)]
#[serde(default, deny_unknown_fields)]
pub struct CredentialInput {
    password: Option<String>,
    refresh_token: Option<String>,
    client_email: Option<String>,
    private_key: Option<String>,
}

impl From<CredentialInput> for Credentials {
    fn from(c: CredentialInput) -> Self {
        Self {
            password: c.password,
            refresh_token: c.refresh_token,
            client_email: c.client_email,
            private_key: c.private_key,
            ..Default::default()
        }
    }
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CreateAccount {
    external_ref: String,
    email: String,
    auth_kind: AuthKind,
    #[serde(default)]
    config: AccountConfig,
    #[serde(default)]
    credentials: CredentialInput,
}

#[derive(Serialize, JsonSchema)]
pub struct AccountCreated {
    account: Account,
    redirect_url: Option<String>,
}

fn validate_credentials(kind: AuthKind, c: &Credentials) -> Result<(), ApiError> {
    match kind {
        AuthKind::Password if c.password.as_ref().is_none_or(|p| p.is_empty()) => {
            Err(ApiError::bad("password_required"))
        }
        AuthKind::GoogleServiceAccount
            if c.client_email.as_ref().is_none_or(|v| v.is_empty())
                || c.private_key.as_ref().is_none_or(|v| v.is_empty()) =>
        {
            Err(ApiError::bad("service_account_key_required"))
        }
        _ => Ok(()),
    }
}

async fn create_account(
    State(s): State<AppState>,
    Json(mut body): Json<CreateAccount>,
) -> Result<(StatusCode, Json<AccountCreated>), ApiError> {
    if body.external_ref.is_empty()
        || body.external_ref.len() > 255
        || !body.email.contains('@')
        || body.email.chars().any(char::is_control)
    {
        return Err(ApiError::bad("invalid_account"));
    }
    body.config
        .normalize(body.auth_kind, s.config.allow_insecure)
        .map_err(|e| ApiError::bad(e.to_string()))?;
    let credentials = zeroize::Zeroizing::new(Credentials::from(body.credentials));
    validate_credentials(body.auth_kind, &credentials)?;
    s.tokens.ensure_configured(body.auth_kind)?;
    let account = id();
    let sealed = s.tokens.encrypt_credentials(&account, &credentials)?;
    let a = account.clone();
    let kind = serde_json::to_string(&body.auth_kind)?;
    let cfg = serde_json::to_string(&body.config)?;
    let oauth = body.auth_kind.oauth() && credentials.refresh_token.is_none();
    s.store
        .write(move |c| {
            Box::pin(async move {
                sqlx::query(
                    "
INSERT INTO accounts(id,external_ref,auth_kind,email,config,status_since,created_at)
VALUES(?,?,?,?,?,?,?)
",
                )
                .bind(&a)
                .bind(body.external_ref)
                .bind(kind)
                .bind(body.email)
                .bind(cfg)
                .bind(now())
                .bind(now())
                .execute(&mut *c)
                .await?;
                sqlx::query(
                    "INSERT INTO credentials(account_id,ciphertext,updated_at) VALUES(?,?,?)",
                )
                .bind(&a)
                .bind(sealed)
                .bind(now())
                .execute(&mut *c)
                .await?;
                epistle_store::status_tx(
                    c,
                    &a,
                    if oauth { "needs_reauth" } else { "connecting" },
                    if oauth {
                        Some("consent_required")
                    } else {
                        None
                    },
                    0,
                )
                .await
            })
        })
        .await?;
    let a = s.store.account(&account).await?;
    let redirect_url = if oauth {
        Some(s.tokens.authorization_url(&a).await?)
    } else {
        None
    };

    Ok((
        StatusCode::CREATED,
        Json(AccountCreated {
            account: a,
            redirect_url,
        }),
    ))
}

async fn list_accounts(State(s): State<AppState>) -> Result<Json<Vec<Account>>, ApiError> {
    Ok(Json(s.store.accounts().await?))
}

async fn get_account(
    State(s): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<Account>, ApiError> {
    Ok(Json(s.store.account(&id).await?))
}

async fn update_credentials(
    State(s): State<AppState>,
    Path(id): Path<String>,
    Json(input): Json<CredentialInput>,
) -> Result<Json<AccountCreated>, ApiError> {
    let a = s.store.account(&id).await?;
    let credentials = zeroize::Zeroizing::new(Credentials::from(input));
    let oauth = a.auth_kind.oauth() && credentials.refresh_token.is_none();
    validate_credentials(a.auth_kind, &credentials)?;
    let _guard = s.tokens.lock(&id).await;
    let sealed = s.tokens.encrypt_credentials(&id, &credentials)?;
    let aid = id.clone();
    s.store
        .write(move |c| {
            Box::pin(async move {
                sqlx::query("
UPDATE credentials SET ciphertext=?,access_expires_at=NULL,refresh_expires_at=NULL,scopes='[]',updated_at=?
WHERE account_id=?
")
                    .bind(sealed)
                    .bind(now())
                    .bind(&aid)
                    .execute(&mut *c)
                    .await?;
                sqlx::query("UPDATE accounts SET revision=revision+1,enabled=1 WHERE id=?")
                    .bind(&aid)
                    .execute(&mut *c)
                    .await?;
                sqlx::query("DELETE FROM oauth_states WHERE account_id=?")
                    .bind(&aid)
                    .execute(&mut *c)
                    .await?;
                epistle_store::status_tx(
                    c,
                    &aid,
                    if oauth { "needs_reauth" } else { "connecting" },
                    if oauth {
                        Some("consent_required")
                    } else {
                        None
                    },
                    0,
                )
                .await
            })
        })
        .await?;
    let a = s.store.account(&id).await?;
    let redirect_url = if oauth {
        Some(s.tokens.authorization_url(&a).await?)
    } else {
        None
    };

    Ok(Json(AccountCreated {
        account: a,
        redirect_url,
    }))
}

#[derive(Deserialize, JsonSchema)]
struct Enabled {
    enabled: bool,
}

async fn set_enabled(
    State(s): State<AppState>,
    Path(id): Path<String>,
    Json(input): Json<Enabled>,
) -> Result<Json<Account>, ApiError> {
    let aid = id.clone();
    s.store
        .write(move |c| {
            Box::pin(async move {
                sqlx::query("UPDATE accounts SET enabled=?,revision=revision+1 WHERE id=?")
                    .bind(input.enabled)
                    .bind(&aid)
                    .execute(&mut *c)
                    .await?;
                epistle_store::status_tx(
                    c,
                    &aid,
                    if input.enabled {
                        "connecting"
                    } else {
                        "disabled"
                    },
                    None,
                    0,
                )
                .await
            })
        })
        .await?;

    Ok(Json(s.store.account(&id).await?))
}

async fn remove_account(
    State(s): State<AppState>,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError> {
    s.store.account(&id).await?;
    let mids: Vec<String> = sqlx::query_scalar("SELECT id FROM messages WHERE account_id=?")
        .bind(&id)
        .fetch_all(&s.store.reads)
        .await?;
    s.store
        .write(move |c| {
            Box::pin(async move {
                sqlx::query("DELETE FROM accounts WHERE id=?")
                    .bind(id)
                    .execute(c)
                    .await?;

                Ok(())
            })
        })
        .await?;

    for mid in mids {
        let path = s.config.data_dir.join("files").join(mid);

        match tokio::fs::remove_dir_all(path).await {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
    }

    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize, JsonSchema)]
struct Callback {
    state: String,
    code: Option<String>,
    error: Option<String>,
}

#[derive(Serialize, JsonSchema)]
struct CallbackResult {
    account_id: String,
    status: String,
}

async fn callback(
    State(s): State<AppState>,
    Query(q): Query<Callback>,
) -> Result<Json<CallbackResult>, ApiError> {
    if q.error.is_some() {
        return Err(ApiError::bad("authorization_denied"));
    }

    let account = s
        .tokens
        .callback(
            &q.state,
            q.code
                .as_deref()
                .ok_or_else(|| ApiError::bad("code_required"))?,
        )
        .await?;

    Ok(Json(CallbackResult {
        account_id: account,
        status: "connecting".into(),
    }))
}

async fn get_message(
    State(s): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<Message>, ApiError> {
    let row = sqlx::query("SELECT payload_path,expired,expires_at FROM messages WHERE id=?")
        .bind(id)
        .fetch_optional(&s.store.reads)
        .await?
        .ok_or_else(ApiError::not_found)?;

    if row.try_get::<bool, _>("expired")?
        || row
            .try_get::<Option<i64>, _>("expires_at")?
            .is_some_and(|t| t <= now())
    {
        return Err(ApiError::gone());
    }

    let bytes = tokio::fs::read(row.try_get::<String, _>("payload_path")?).await?;
    let v: Value = serde_json::from_slice(&bytes)?;

    Ok(Json(serde_json::from_value(
        v.get("message").cloned().ok_or_else(ApiError::not_found)?,
    )?))
}

#[derive(Deserialize, JsonSchema)]
struct ReadInput {
    read: bool,
}

#[derive(Serialize, JsonSchema)]
struct CommandCreated {
    command_id: String,
}

async fn mark_read(
    State(s): State<AppState>,
    Path(mid): Path<String>,
    Json(body): Json<ReadInput>,
) -> Result<(StatusCode, Json<CommandCreated>), ApiError> {
    let command_id = id();
    let cid = command_id.clone();
    s.store
        .write(move |c| {
            Box::pin(async move {
                let account: Option<String> =
                    sqlx::query_scalar("SELECT account_id FROM message_index WHERE message_key=?")
                        .bind(&mid)
                        .fetch_optional(&mut *c)
                        .await?;
                let account = account.ok_or(epistle_store::Error::NotFound)?;
                sqlx::query(
                    "
INSERT INTO commands(id,account_id,message_key,kind,read_value,created_at)
VALUES(?,?,?,'mark_read',?,?)
",
                )
                .bind(cid)
                .bind(account)
                .bind(mid)
                .bind(body.read)
                .bind(now())
                .execute(c)
                .await?;

                Ok(())
            })
        })
        .await?;

    Ok((StatusCode::ACCEPTED, Json(CommandCreated { command_id })))
}

#[derive(Deserialize, JsonSchema, Default)]
struct Wait {
    wait: Option<String>,
}

#[derive(Serialize, JsonSchema)]
struct CommandStatus {
    id: String,
    state: String,
    attempts: i64,
    last_error: Option<String>,
    completed_at: Option<i64>,
}

async fn get_command(
    State(s): State<AppState>,
    Path(id): Path<String>,
    Query(q): Query<Wait>,
) -> Result<Json<CommandStatus>, ApiError> {
    let wait = if let Some(w) = q.wait {
        w.strip_suffix('s')
            .and_then(|w| w.parse::<u64>().ok())
            .filter(|n| *n <= 30)
            .ok_or_else(|| ApiError::bad("wait must be between 0s and 30s"))?
    } else {
        0
    };
    let deadline = Instant::now() + Duration::from_secs(wait);

    loop {
        let r = sqlx::query("SELECT * FROM commands WHERE id=?")
            .bind(&id)
            .fetch_optional(&s.store.reads)
            .await?
            .ok_or_else(ApiError::not_found)?;
        let status = CommandStatus {
            id: id.clone(),
            state: r.try_get("state")?,
            attempts: r.try_get("attempts")?,
            last_error: r.try_get("last_error")?,
            completed_at: r.try_get("completed_at")?,
        };

        if status.state != "pending" || Instant::now() >= deadline {
            return Ok(Json(status));
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct BackfillInput {
    since: chrono::DateTime<chrono::Utc>,
    until: Option<chrono::DateTime<chrono::Utc>>,
    folders: Option<Vec<String>>,
    #[serde(default)]
    unread_only: bool,
    #[serde(default)]
    redeliver: bool,
}

#[derive(Serialize, JsonSchema)]
struct BackfillCreated {
    backfill_id: String,
}

async fn create_backfill(
    State(s): State<AppState>,
    Path(account): Path<String>,
    Json(input): Json<BackfillInput>,
) -> Result<(StatusCode, Json<BackfillCreated>), ApiError> {
    s.store.account(&account).await?;

    if input.until.is_some_and(|u| u <= input.since)
        || input.folders.as_ref().is_some_and(|f| {
            f.is_empty()
                || f.len() > 32
                || f.iter()
                    .any(|v| v.is_empty() || v.chars().any(char::is_control))
        })
    {
        return Err(ApiError::bad("invalid_backfill_range_or_folders"));
    }

    let job = id();
    let j = job.clone();
    s.store
        .write(move |c| {
            Box::pin(async move {
                sqlx::query(
                    "
INSERT INTO
backfill_jobs(id,account_id,since,until,folders_json,unread_only,redeliver,created_at)
VALUES(?,?,?,?,?,?,?,?)
",
                )
                .bind(j)
                .bind(account)
                .bind(input.since.timestamp())
                .bind(input.until.map(|u| u.timestamp()))
                .bind(
                    input
                        .folders
                        .map(|f| serde_json::to_string(&f))
                        .transpose()?,
                )
                .bind(input.unread_only)
                .bind(input.redeliver)
                .bind(now())
                .execute(c)
                .await?;

                Ok(())
            })
        })
        .await?;

    Ok((
        StatusCode::ACCEPTED,
        Json(BackfillCreated { backfill_id: job }),
    ))
}

#[derive(Serialize, JsonSchema)]
struct BackfillStatus {
    id: String,
    state: String,
    matched: i64,
    enqueued: i64,
    delivered: i64,
    last_error: Option<String>,
}

async fn get_backfill(
    State(s): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<BackfillStatus>, ApiError> {
    let r = sqlx::query("SELECT * FROM backfill_jobs WHERE id=?")
        .bind(&id)
        .fetch_optional(&s.store.reads)
        .await?
        .ok_or_else(ApiError::not_found)?;

    Ok(Json(BackfillStatus {
        id,
        state: r.try_get("state")?,
        matched: r.try_get("matched")?,
        enqueued: r.try_get("enqueued")?,
        delivered: r.try_get("delivered")?,
        last_error: r.try_get("last_error")?,
    }))
}

async fn cancel_backfill(
    State(s): State<AppState>,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError> {
    s.store
        .write(move |c| {
            Box::pin(async move {
                let changed = sqlx::query(
                    "UPDATE backfill_jobs SET state='cancelled',completed_at=? WHERE id=?",
                )
                .bind(now())
                .bind(&id)
                .execute(&mut *c)
                .await?
                .rows_affected();

                if changed == 0 {
                    return Err(epistle_store::Error::NotFound);
                }
                sqlx::query("DELETE FROM fetch_queue WHERE backfill_id=? AND state='pending'")
                    .bind(id)
                    .execute(c)
                    .await?;

                Ok(())
            })
        })
        .await?;

    Ok(StatusCode::NO_CONTENT)
}

#[derive(Serialize, JsonSchema)]
struct OutboxItem {
    id: i64,
    kind: String,
    state: String,
    attempts: i64,
    last_error: Option<String>,
    created_at: i64,
}

async fn list_outbox(State(s): State<AppState>) -> Result<Json<Vec<OutboxItem>>, ApiError> {
    let rows = sqlx::query("SELECT * FROM outbox ORDER BY seq LIMIT 500")
        .fetch_all(&s.store.reads)
        .await?;

    Ok(Json(
        rows.into_iter()
            .map(|r| {
                Ok(OutboxItem {
                    id: r.try_get("seq")?,
                    kind: r.try_get("kind")?,
                    state: r.try_get("state")?,
                    attempts: r.try_get("attempts")?,
                    last_error: r.try_get("last_error")?,
                    created_at: r.try_get("created_at")?,
                })
            })
            .collect::<Result<Vec<_>, sqlx::Error>>()?,
    ))
}

async fn replay(State(s): State<AppState>, Path(id): Path<i64>) -> Result<StatusCode, ApiError> {
    s.store
        .write(move |c| {
            Box::pin(async move {
                let changed = sqlx::query(
                    "
UPDATE outbox SET state='pending',attempts=0,next_attempt_at=0,last_error=NULL WHERE
seq=? AND state='dead'
",
                )
                .bind(id)
                .execute(c)
                .await?
                .rows_affected();

                if changed == 0 {
                    return Err(epistle_store::Error::Conflict("delivery_not_dead"));
                }

                Ok(())
            })
        })
        .await?;

    Ok(StatusCode::ACCEPTED)
}

async fn discard(State(s): State<AppState>, Path(id): Path<i64>) -> Result<StatusCode, ApiError> {
    let retention = s.config.file_retention_secs;
    s.store
        .write(move |c| {
            Box::pin(async move {
                let key: Option<String> = sqlx::query_scalar(
                    "DELETE FROM outbox WHERE seq=? AND state='dead' RETURNING message_key",
                )
                .bind(id)
                .fetch_optional(&mut *c)
                .await?;
                let key = key.ok_or(epistle_store::Error::Conflict("delivery_not_dead"))?;
                sqlx::query(
                    "
UPDATE message_files SET expires_at=? WHERE message_key=? AND NOT EXISTS(SELECT 1 FROM
outbox WHERE message_key=?)
",
                )
                .bind(now() + retention)
                .bind(&key)
                .bind(&key)
                .execute(&mut *c)
                .await?;
                sqlx::query(
                    "
UPDATE message_payloads SET expires_at=? WHERE message_key=? AND NOT EXISTS(SELECT 1
FROM outbox WHERE message_key=?)
",
                )
                .bind(now() + retention)
                .bind(&key)
                .bind(&key)
                .execute(&mut *c)
                .await?;
                sqlx::query(
                    "
UPDATE messages SET expires_at=? WHERE id=? AND NOT EXISTS(SELECT 1 FROM outbox WHERE
message_key=?)
",
                )
                .bind(now() + retention)
                .bind(&key)
                .bind(key)
                .execute(c)
                .await?;

                Ok(())
            })
        })
        .await?;

    Ok(StatusCode::NO_CONTENT)
}

#[derive(Serialize, JsonSchema)]
struct FolderError {
    id: String,
    reason: String,
}

#[derive(Serialize, JsonSchema)]
struct AccountHealth {
    id: String,
    status: String,
    last_success_at: Option<i64>,
    lag_seconds: i64,
    /// Provider-reported Unix deadline; null means unknown.
    refresh_token_expires_at: Option<i64>,
    folder_errors: Vec<FolderError>,
}

#[derive(Serialize, JsonSchema)]
struct HealthResponse {
    status: String,
    accounts: Vec<AccountHealth>,
    outbox_depth: i64,
    oldest_pending_age_seconds: Option<i64>,
    dead_deliveries: i64,
    dead_fetches: i64,
}

async fn health(State(s): State<AppState>) -> Result<Json<HealthResponse>, ApiError> {
    let r = sqlx::query(
        "
SELECT COUNT(*) AS depth,MIN(CASE WHEN state='pending' THEN created_at END) AS
oldest,SUM(CASE WHEN state='dead' THEN 1 ELSE 0 END) AS dead FROM outbox
",
    )
    .fetch_one(&s.store.reads)
    .await?;
    let accounts = s.store.accounts().await?;
    let mut account_health = vec![];

    for a in accounts {
        let oldest: Option<i64> = sqlx::query_scalar(
            "SELECT MIN(created_at) FROM fetch_queue WHERE account_id=? AND state='pending'",
        )
        .bind(&a.id)
        .fetch_one(&s.store.reads)
        .await?;
        let refresh_expires_at = sqlx::query_scalar::<_, Option<i64>>(
            "SELECT refresh_expires_at FROM credentials WHERE account_id=?",
        )
        .bind(&a.id)
        .fetch_optional(&s.store.reads)
        .await?
        .flatten();
        let folder_errors: Vec<(String, String)> = sqlx::query_as("SELECT id,last_error FROM folders WHERE account_id=? AND last_error IS NOT NULL ORDER BY id")
            .bind(&a.id)
            .fetch_all(&s.store.reads)
            .await?;
        account_health.push(AccountHealth {
            id: a.id,
            status: a.status,
            last_success_at: a.last_success_at,
            lag_seconds: oldest.map(|t| now() - t).unwrap_or(0),
            refresh_token_expires_at: refresh_expires_at,
            folder_errors: folder_errors
                .into_iter()
                .map(|(id, reason)| FolderError { id, reason })
                .collect(),
        });
    }

    let dead_fetch: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM fetch_queue WHERE state='dead'")
        .fetch_one(&s.store.reads)
        .await?;

    Ok(Json(HealthResponse {
        status: "ok".into(),
        accounts: account_health,
        outbox_depth: r.try_get("depth")?,
        oldest_pending_age_seconds: r.try_get::<Option<i64>, _>("oldest")?.map(|t| now() - t),
        dead_deliveries: r.try_get::<Option<i64>, _>("dead")?.unwrap_or(0),
        dead_fetches: dead_fetch,
    }))
}

pub fn byte_range(value: &str, size: u64) -> Result<(u64, u64), ApiError> {
    let range = value
        .strip_prefix("bytes=")
        .ok_or_else(|| ApiError::new(StatusCode::RANGE_NOT_SATISFIABLE, "invalid_range"))?;
    let (start, end) = range
        .split_once('-')
        .ok_or_else(|| ApiError::new(StatusCode::RANGE_NOT_SATISFIABLE, "invalid_range"))?;
    let invalid = || ApiError::new(StatusCode::RANGE_NOT_SATISFIABLE, "invalid_range");

    if size == 0 || range.contains(',') {
        return Err(invalid());
    }
    if start.is_empty() {
        let n = end.parse::<u64>().map_err(|_| invalid())?;

        if n == 0 {
            return Err(invalid());
        }
        return Ok((size.saturating_sub(n), size - 1));
    }

    let start = start.parse::<u64>().map_err(|_| invalid())?;
    let end = if end.is_empty() {
        size - 1
    } else {
        end.parse::<u64>().map_err(|_| invalid())?.min(size - 1)
    };

    if start >= size || end < start {
        return Err(invalid());
    }

    Ok((start, end))
}

async fn download(
    State(s): State<AppState>,
    Path((mid, fid)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let r = sqlx::query("SELECT * FROM message_files WHERE message_key=? AND file_id=?")
        .bind(mid)
        .bind(fid)
        .fetch_optional(&s.store.reads)
        .await?
        .ok_or_else(ApiError::not_found)?;

    if r.try_get::<bool, _>("expired")?
        || r.try_get::<Option<i64>, _>("expires_at")?
            .is_some_and(|t| t <= now())
    {
        return Err(ApiError::gone());
    }

    let etag = format!("\"{}\"", r.try_get::<String, _>("sha256")?);

    if headers
        .get(header::IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v == etag || v == "*")
    {
        return Ok((StatusCode::NOT_MODIFIED, [(header::ETAG, etag)]).into_response());
    }

    let size = r.try_get::<i64, _>("size")? as u64;
    let mut file = tokio::fs::File::open(r.try_get::<String, _>("path")?).await?;
    let requested = headers
        .get(header::RANGE)
        .and_then(|v| v.to_str().ok())
        .filter(|_| {
            headers
                .get(header::IF_RANGE)
                .is_none_or(|v| v.to_str().ok() == Some(&etag))
        });
    let mut response = Response::builder();
    let (start, length) = if let Some(range) = requested {
        match byte_range(range, size) {
            Ok((start, end)) => {
                response = response
                    .status(StatusCode::PARTIAL_CONTENT)
                    .header(header::CONTENT_RANGE, format!("bytes {start}-{end}/{size}"));
                (start, end - start + 1)
            }
            Err(_) => {
                return Ok((
                    StatusCode::RANGE_NOT_SATISFIABLE,
                    [(header::CONTENT_RANGE, format!("bytes */{size}"))],
                )
                    .into_response());
            }
        }
    } else {
        (0, size)
    };
    file.seek(std::io::SeekFrom::Start(start)).await?;
    let filename: String = r.try_get("filename")?;
    let safe: String = filename
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || " ._-".contains(c) {
                c
            } else {
                '_'
            }
        })
        .collect();
    let mime: String = r.try_get("content_type")?;
    let mime = if mime.chars().any(char::is_control) {
        "application/octet-stream"
    } else {
        &mime
    };
    response
        .header(header::CONTENT_LENGTH, length)
        .header(header::CONTENT_TYPE, mime)
        .header(header::ETAG, etag)
        .header(header::ACCEPT_RANGES, "bytes")
        .header(
            header::CONTENT_DISPOSITION,
            format!("attachment; filename=\"{safe}\""),
        )
        .header(header::CACHE_CONTROL, "private, no-store")
        .header("x-content-type-options", "nosniff")
        .body(Body::from_stream(ReaderStream::new(file.take(length))))
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "invalid_file_headers"))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    #[test]
    fn range_download_boundaries() {
        assert_eq!(byte_range("bytes=0-0", 10).unwrap(), (0, 0));
        assert_eq!(byte_range("bytes=2-", 10).unwrap(), (2, 9));
        assert_eq!(byte_range("bytes=-3", 10).unwrap(), (7, 9));
        assert_eq!(byte_range("bytes=-999", 10).unwrap(), (0, 9));
        assert_eq!(byte_range("bytes=0-999", 10).unwrap(), (0, 9));

        for value in [
            "bytes=10-",
            "bytes=9-8",
            "bytes=-0",
            "bytes=0-1,3-5",
            "bytes=x-2",
            "bytes=18446744073709551616-",
        ] {
            assert!(byte_range(value, 10).is_err());
        }
        assert!(byte_range("bytes=0-", 0).is_err());
    }
}

#[cfg(test)]
#[path = "../../../tests/support/mod.rs"]
mod support;

#[cfg(test)]
mod reference_tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use tower::ServiceExt;
    #[tokio::test]
    async fn scalar_and_openapi_are_public_but_operations_require_bearer_authentication() {
        let dir = tempfile::tempdir().unwrap();
        let config = Arc::new(support::config(dir.path()));
        let store = Store::open(&dir.path().join("db.sqlite")).await.unwrap();
        let app = router(AppState {
            tokens: TokenProvider::new(store.clone(), config.clone()).unwrap(),
            store,
            config: config.clone(),
        });

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/scalar")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert!(
            response
                .headers()
                .get(header::CONTENT_TYPE)
                .unwrap()
                .to_str()
                .unwrap()
                .starts_with("text/html")
        );
        let html = String::from_utf8(
            axum::body::to_bytes(response.into_body(), 16384)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        assert!(html.contains("url: '/openapi.json'"));
        assert!(html.contains("Scalar.createApiReference"));
        assert!(!html.contains(&config.api_key));

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/openapi.json")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let schema: Value = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), 1_048_576)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            schema.pointer("/paths/~1health/get/security"),
            Some(&json!([{"apiKey":[]}]))
        );
        assert!(
            schema
                .pointer("/components/schemas/HealthResponse/properties/dead_fetches")
                .is_some()
        );
        assert!(
            schema
                .pointer("/components/schemas/AccountHealth/properties/folder_errors")
                .is_some()
        );
        assert!(
            schema
                .pointer("/paths/~1oauth~1callback/get/security")
                .is_none()
        );

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .header(header::AUTHORIZATION, format!("Bearer {}", config.api_key))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }
}
