//! Shared configuration, identifiers and mail data types.

use chrono::Utc;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub mod config;
pub use config::Config;

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
                "plaintext IMAP requires EPISTLE_TESTING__ALLOW_INSECURE_ENDPOINTS=true".into(),
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
