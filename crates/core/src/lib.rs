//! Shared configuration, identifiers and mail data types.

use chrono::Utc;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{net::SocketAddr, path::PathBuf};
use thiserror::Error;

/// Returns the current Unix timestamp in seconds.
pub fn now() -> i64 {
    Utc::now().timestamp()
}

/// Creates an opaque identifier.
pub fn id() -> String {
    uuid::Uuid::new_v4().to_string()
}

/// Returns a hexadecimal SHA-256 digest.
pub fn hash(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// Returns a capped, jittered retry delay in seconds.
pub fn backoff(attempt: i64) -> i64 {
    (5_i64.saturating_mul(2_i64.saturating_pow(attempt.clamp(0, 10) as u32))).min(3600)
        + i64::from(rand::random::<u8>() % 10)
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid configuration: {0}")]
    Config(String),
}

/// Supported account authentication strategies.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AuthKind {
    Password,
    GoogleOauth,
    MicrosoftOauth,
    GoogleServiceAccount,
}

impl AuthKind {
    /// Reports whether this strategy uses user OAuth consent.
    pub fn oauth(self) -> bool {
        matches!(self, Self::GoogleOauth | Self::MicrosoftOauth)
    }
}

/// IMAP connection and initial synchronization settings.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct AccountConfig {
    pub host: String,
    pub port: u16,
    pub tls: bool,
    pub folders: Vec<String>,
    pub initial_sync_days: u32,
    pub tenant: String,
}

impl Default for AccountConfig {
    fn default() -> Self {
        Self {
            host: String::new(),
            port: 993,
            tls: true,
            folders: vec![],
            initial_sync_days: 7,
            tenant: "common".into(),
        }
    }
}

impl AccountConfig {
    /// Applies provider defaults and validates connection settings.
    pub fn normalize(&mut self, kind: AuthKind, allow_insecure: bool) -> Result<(), Error> {
        if self.host.is_empty() {
            self.host = match kind {
                AuthKind::GoogleOauth | AuthKind::GoogleServiceAccount => "imap.gmail.com",
                AuthKind::MicrosoftOauth => "outlook.office365.com",
                _ => return Err(Error::Config("host is required".into())),
            }
            .into();
        }
        if !self.tls && !allow_insecure {
            return Err(Error::Config(
                "plaintext IMAP requires ALLOW_INSECURE_TEST_ENDPOINTS=true".into(),
            ));
        }
        if self.port == 0
            || self.host.chars().any(char::is_control)
            || !self
                .tenant
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
        {
            return Err(Error::Config("invalid IMAP host, port or tenant".into()));
        }
        if self.folders.len() > 32
            || self
                .folders
                .iter()
                .any(|f| f.is_empty() || f.chars().any(char::is_control))
        {
            return Err(Error::Config("invalid folders".into()));
        }

        Ok(())
    }
}

/// Persisted account state and configuration revision.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct Account {
    pub id: String,
    pub external_ref: String,
    pub auth_kind: AuthKind,
    pub email: String,
    pub config: AccountConfig,
    pub status: String,
    pub status_reason: Option<String>,
    pub status_seq: i64,
    pub status_since: i64,
    pub consecutive_failures: i64,
    pub last_success_at: Option<i64>,
    pub enabled: bool,
    pub revision: i64,
}

/// Public metadata for a retained message file.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct FileManifest {
    pub id: String,
    pub role: String,
    pub filename: String,
    pub content_type: String,
    pub size: i64,
    pub sha256: String,
    pub content_id: Option<String>,
    #[serde(default)]
    pub content_disposition: Option<String>,
    #[serde(default)]
    pub content_description: Option<String>,
    #[serde(default)]
    pub content_location: Option<String>,
}

/// Normalized email delivered to webhook consumers.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct Message {
    pub id: String,
    pub account_id: String,
    pub origin: String,
    pub backfill_id: Option<String>,
    pub envelope: serde_json::Value,
    pub headers: serde_json::Value,
    pub flags: Vec<String>,
    pub thread_id: Option<String>,
    pub labels: Vec<String>,
    pub text: Option<String>,
    pub html: Option<String>,
    pub parse_error: bool,
    pub files: Vec<FileManifest>,
}

/// Mailbox location and identity used to recover moved messages.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Pointer {
    pub account_id: String,
    pub folder_id: String,
    pub folder: String,
    pub uidvalidity: i64,
    pub uid: i64,
    pub rfc_message_id: Option<String>,
    pub gmail_id: Option<String>,
    pub thread_id: Option<String>,
    pub labels: Vec<String>,
    pub flags: Vec<String>,
    pub size: i64,
    pub internal_date: i64,
}

impl Pointer {
    /// Returns the provider identity used for deduplication.
    pub fn identity(&self) -> String {
        self.gmail_id
            .as_ref()
            .map(|s| format!("gmail:{s}"))
            .or_else(|| self.rfc_message_id.as_ref().map(|s| format!("rfc:{s}")))
            .unwrap_or_else(|| format!("{}:{}:{}", self.folder_id, self.uidvalidity, self.uid))
    }

    /// Returns the stable location key for this pointer.
    pub fn key(&self) -> String {
        format!(
            "email:{}:{}:{}:{}",
            self.account_id, self.folder_id, self.uidvalidity, self.uid
        )
    }
}

/// Validated service configuration loaded from defaults, TOML and environment.
#[derive(Clone, Deserialize)]
pub struct Config {
    pub data_dir: PathBuf,
    #[serde(rename = "bind_addr")]
    pub bind: SocketAddr,
    pub api_key: String,
    pub master_key: String,
    pub webhook_url: String,
    pub webhook_secret: String,
    pub public_url: String,
    pub file_retention_secs: i64,
    pub inline_body_cap: usize,
    pub index_retention_secs: i64,
    pub reconcile_secs: u64,
    pub watchdog_secs: u64,
    pub fetch_batch_count: usize,
    pub fetch_batch_bytes: i64,
    pub max_attempts: i64,
    #[serde(rename = "allow_insecure_test_endpoints")]
    pub allow_insecure: bool,
    pub disk_reserve_bytes: u64,
    pub reauth_reminder_secs: i64,
    pub google_client_id: String,
    pub google_client_secret: String,
    pub microsoft_client_id: String,
    pub microsoft_client_secret: String,
    pub token_endpoint_override: Option<String>,
}

impl Config {
    /// Loads and validates defaults, optional TOML and environment settings.
    pub fn from_env() -> Result<Self, Error> {
        let settings = config::Config::builder()
            .set_default("data_dir", "./data")
            .map_err(cfg)?
            .set_default("bind_addr", "127.0.0.1:8080")
            .map_err(cfg)?
            .set_default("api_key", "")
            .map_err(cfg)?
            .set_default("master_key", "")
            .map_err(cfg)?
            .set_default("webhook_url", "")
            .map_err(cfg)?
            .set_default("webhook_secret", "")
            .map_err(cfg)?
            .set_default("public_url", "http://localhost:8080")
            .map_err(cfg)?
            .set_default("file_retention_secs", 7200)
            .map_err(cfg)?
            .set_default("inline_body_cap", 262144)
            .map_err(cfg)?
            .set_default("index_retention_secs", 2592000)
            .map_err(cfg)?
            .set_default("reconcile_secs", 180)
            .map_err(cfg)?
            .set_default("watchdog_secs", 60)
            .map_err(cfg)?
            .set_default("fetch_batch_count", 50)
            .map_err(cfg)?
            .set_default("fetch_batch_bytes", 26214400)
            .map_err(cfg)?
            .set_default("max_attempts", 12)
            .map_err(cfg)?
            .set_default("allow_insecure_test_endpoints", false)
            .map_err(cfg)?
            .set_default("disk_reserve_bytes", 268435456)
            .map_err(cfg)?
            .set_default("reauth_reminder_secs", 0)
            .map_err(cfg)?
            .set_default("google_client_id", "")
            .map_err(cfg)?
            .set_default("google_client_secret", "")
            .map_err(cfg)?
            .set_default("microsoft_client_id", "")
            .map_err(cfg)?
            .set_default("microsoft_client_secret", "")
            .map_err(cfg)?
            .add_source(config::File::with_name("epistle").required(false))
            .add_source(config::Environment::default().try_parsing(false))
            .build()
            .map_err(cfg)?;
        let c: Self = settings.try_deserialize().map_err(cfg)?;

        if c.api_key.len() < 32 || c.webhook_secret.len() < 32 || c.master_key.len() != 64 {
            return Err(Error::Config("API_KEY and WEBHOOK_SECRET need at least 32 characters; MASTER_KEY must be 64 hex characters".into()));
        }
        if c.file_retention_secs < 1
            || c.index_retention_secs < 1
            || c.reconcile_secs == 0
            || c.watchdog_secs == 0
            || c.max_attempts < 1
            || c.fetch_batch_count == 0
            || c.fetch_batch_bytes < 1
        {
            return Err(Error::Config(
                "limits and intervals must be positive".into(),
            ));
        }
        if !c.webhook_url.starts_with("https://")
            && !(c.allow_insecure && c.webhook_url.starts_with("http://"))
        {
            return Err(Error::Config("WEBHOOK_URL must use HTTPS".into()));
        }
        if c.token_endpoint_override.is_some() && !c.allow_insecure {
            return Err(Error::Config("token override is test-only".into()));
        }

        Ok(c)
    }
}

fn cfg(_: config::ConfigError) -> Error {
    Error::Config(
        "could not load configuration; check epistle.toml and environment variable types".into(),
    )
}
