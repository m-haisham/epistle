//! Typed application settings with file and environment overrides.

use crate::Error;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    net::SocketAddr,
    path::{Path, PathBuf},
};

/// Application settings grouped by subsystem.
#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub server: ServerConfig,
    pub storage: StorageConfig,
    pub mail: MailConfig,
    pub delivery: DeliveryConfig,
    pub sending: SendingConfig,
    pub auth: AuthConfig,
    pub testing: TestingConfig,
}

/// HTTP listener, public callback origin and API authentication.
#[derive(Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct ServerConfig {
    pub bind_addr: SocketAddr,
    pub public_url: String,
    pub api_key: String,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind_addr: ([127, 0, 0, 1], 8080).into(),
            public_url: "http://localhost:8080".into(),
            api_key: String::new(),
        }
    }
}

/// Persistent data location and retention limits.
#[derive(Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct StorageConfig {
    pub data_dir: PathBuf,
    pub file_retention_secs: i64,
    pub index_retention_secs: i64,
    pub disk_reserve_bytes: u64,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            data_dir: "./data".into(),
            file_retention_secs: 7_200,
            index_retention_secs: 2_592_000,
            disk_reserve_bytes: 268_435_456,
        }
    }
}

/// Mailbox reconciliation, network watchdogs and parsing limits.
#[derive(Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct MailConfig {
    pub reconcile_secs: u64,
    pub watchdog_secs: u64,
    pub inline_body_cap: usize,
    pub fetch: FetchConfig,
}

impl Default for MailConfig {
    fn default() -> Self {
        Self {
            reconcile_secs: 180,
            watchdog_secs: 60,
            inline_body_cap: 262_144,
            fetch: FetchConfig::default(),
        }
    }
}

/// Limits for each fetch batch.
#[derive(Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct FetchConfig {
    pub batch_count: usize,
    pub batch_bytes: i64,
}

impl Default for FetchConfig {
    fn default() -> Self {
        Self {
            batch_count: 50,
            batch_bytes: 26_214_400,
        }
    }
}

/// Webhook destination, signing secret and retry budget.
#[derive(Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct DeliveryConfig {
    pub webhook_url: String,
    pub webhook_secret: String,
    pub max_attempts: i64,
}

impl Default for DeliveryConfig {
    fn default() -> Self {
        Self {
            webhook_url: String::new(),
            webhook_secret: String::new(),
            max_attempts: 12,
        }
    }
}

/// Outbound SMTP concurrency, retry budget and size limits.
#[derive(Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct SendingConfig {
    pub workers: usize,
    pub timeout_secs: u64,
    pub max_attempts: i64,
    pub max_message_bytes: usize,
}

impl Default for SendingConfig {
    fn default() -> Self {
        Self {
            workers: 4,
            timeout_secs: 60,
            max_attempts: 12,
            max_message_bytes: 1_048_576,
        }
    }
}

/// Credential encryption, provider clients and reauthorization reminders.
#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct AuthConfig {
    pub master_key: String,
    pub reauth_reminder_secs: i64,
    pub google: OAuthClientConfig,
    pub microsoft: OAuthClientConfig,
}

/// Confidential OAuth application credentials.
#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct OAuthClientConfig {
    pub client_id: String,
    pub client_secret: String,
}

/// Explicit opt-ins for local protocol fixtures.
#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct TestingConfig {
    pub allow_insecure_endpoints: bool,
    pub token_endpoint_override: Option<String>,
}

impl Config {
    /// Loads defaults, optional `epistle.toml`, then environment overrides.
    pub fn from_env() -> Result<Self, Error> {
        let environment = std::env::vars_os()
            .filter_map(|(key, value)| Some((key.into_string().ok()?, value.into_string().ok()?)))
            .collect();

        Self::from_sources(Path::new("epistle.toml"), environment)
    }

    fn from_sources(path: &Path, variables: HashMap<String, String>) -> Result<Self, Error> {
        let file = config::Config::builder()
            .add_source(config::File::from(path).required(false))
            .build()
            .map_err(config_error)?;
        let file = normalize_legacy_file(file)?;

        let legacy = LEGACY_KEYS
            .iter()
            .filter_map(|(old, new)| {
                variables
                    .get(&old.to_ascii_uppercase())
                    .map(|value| (environment_key(new), value.clone()))
            })
            .collect();

        let settings = config::Config::builder()
            .add_source(config::Config::try_from(&Self::default()).map_err(config_error)?)
            .add_source(file)
            .add_source(environment(legacy))
            .add_source(environment(variables))
            .build()
            .map_err(config_error)?;

        let settings: Self = settings.try_deserialize().map_err(config_error)?;
        settings.validate()?;

        Ok(settings)
    }

    fn validate(&self) -> Result<(), Error> {
        if self.server.api_key.len() < 32 || self.delivery.webhook_secret.len() < 32 {
            return Err(Error::Config(
                "server.api_key and delivery.webhook_secret need at least 32 characters".into(),
            ));
        }

        if self.auth.master_key.len() != 64
            || !self.auth.master_key.bytes().all(|b| b.is_ascii_hexdigit())
        {
            return Err(Error::Config(
                "auth.master_key must encode 32 bytes as 64 hex characters".into(),
            ));
        }

        if self.storage.file_retention_secs < 1
            || self.storage.index_retention_secs < 1
            || self.mail.reconcile_secs == 0
            || self.mail.watchdog_secs == 0
            || self.sending.workers == 0
            || self.sending.workers > 32
            || self.sending.timeout_secs == 0
            || self.sending.max_attempts < 1
            || self.sending.max_message_bytes == 0
            || self.delivery.max_attempts < 1
            || self.mail.fetch.batch_count == 0
            || self.mail.fetch.batch_bytes < 1
        {
            return Err(Error::Config(
                "limits and intervals must be positive".into(),
            ));
        }

        if !self.delivery.webhook_url.starts_with("https://")
            && !(self.testing.allow_insecure_endpoints
                && self.delivery.webhook_url.starts_with("http://"))
        {
            return Err(Error::Config("delivery.webhook_url must use HTTPS".into()));
        }

        if self.testing.token_endpoint_override.is_some() && !self.testing.allow_insecure_endpoints
        {
            return Err(Error::Config(
                "testing.token_endpoint_override requires testing.allow_insecure_endpoints".into(),
            ));
        }

        Ok(())
    }
}

fn environment(source: HashMap<String, String>) -> config::Environment {
    config::Environment::with_prefix("EPISTLE")
        .prefix_separator("_")
        .separator("__")
        // Preserve digit-only secrets and leading zeros; deserialize by field type.
        .try_parsing(false)
        .source(Some(source))
}

fn environment_key(path: &str) -> String {
    format!("EPISTLE_{}", path.replace('.', "__").to_ascii_uppercase())
}

/// Translates old file keys before merging; an explicit nested value wins.
fn normalize_legacy_file(file: config::Config) -> Result<config::Config, Error> {
    let mut document: serde_json::Value = file.try_deserialize().map_err(config_error)?;

    for (old, path) in LEGACY_KEYS {
        if let Some(value) = document.as_object_mut().and_then(|root| root.remove(*old)) {
            insert_missing(&mut document, path, value)?;
        }
    }

    config::Config::try_from(&document).map_err(config_error)
}

fn insert_missing(
    root: &mut serde_json::Value,
    path: &str,
    value: serde_json::Value,
) -> Result<(), Error> {
    let object = root
        .as_object_mut()
        .ok_or_else(|| Error::Config("configuration sections must be tables".into()))?;

    if let Some((section, rest)) = path.split_once('.') {
        let child = object
            .entry(section)
            .or_insert_with(|| serde_json::json!({}));
        insert_missing(child, rest, value)
    } else {
        object.entry(path).or_insert(value);

        Ok(())
    }
}

fn config_error(_: config::ConfigError) -> Error {
    // Deserializer errors can include the rejected value, including secrets.
    Error::Config("could not load configuration; check section names, keys and value types".into())
}

// Compatibility is limited to the previously supported application keys.
const LEGACY_KEYS: &[(&str, &str)] = &[
    ("data_dir", "storage.data_dir"),
    ("bind_addr", "server.bind_addr"),
    ("api_key", "server.api_key"),
    ("master_key", "auth.master_key"),
    ("webhook_url", "delivery.webhook_url"),
    ("webhook_secret", "delivery.webhook_secret"),
    ("public_url", "server.public_url"),
    ("file_retention_secs", "storage.file_retention_secs"),
    ("inline_body_cap", "mail.inline_body_cap"),
    ("index_retention_secs", "storage.index_retention_secs"),
    ("reconcile_secs", "mail.reconcile_secs"),
    ("watchdog_secs", "mail.watchdog_secs"),
    ("fetch_batch_count", "mail.fetch.batch_count"),
    ("fetch_batch_bytes", "mail.fetch.batch_bytes"),
    ("max_attempts", "delivery.max_attempts"),
    (
        "allow_insecure_test_endpoints",
        "testing.allow_insecure_endpoints",
    ),
    ("disk_reserve_bytes", "storage.disk_reserve_bytes"),
    ("reauth_reminder_secs", "auth.reauth_reminder_secs"),
    ("google_client_id", "auth.google.client_id"),
    ("google_client_secret", "auth.google.client_secret"),
    ("microsoft_client_id", "auth.microsoft.client_id"),
    ("microsoft_client_secret", "auth.microsoft.client_secret"),
    ("token_endpoint_override", "testing.token_endpoint_override"),
];

#[cfg(test)]
mod tests;
