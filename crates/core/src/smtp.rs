//! SMTP settings shared by account registration and sending.

use crate::{Account, AuthKind, Error};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Required connection security; plaintext is restricted to test fixtures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SmtpSecurity {
    Tls,
    Starttls,
    Plain,
}

/// SMTP endpoint using the account's existing identity and credentials.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SmtpConfig {
    pub host: String,
    pub port: u16,
    pub security: SmtpSecurity,
}

impl SmtpConfig {
    /// Rejects malformed endpoints and insecure production connections.
    pub fn validate(&self, allow_insecure: bool) -> Result<(), Error> {
        if self.host.is_empty()
            || self
                .host
                .chars()
                .any(|c| c.is_whitespace() || c.is_control())
            || self.host.contains('/')
            || self.port == 0
        {
            return Err(Error::Config("invalid SMTP host or port".into()));
        }

        if self.security == SmtpSecurity::Plain && !allow_insecure {
            return Err(Error::Config(
                "plaintext SMTP is restricted to testing".into(),
            ));
        }

        Ok(())
    }

    /// Resolves explicit settings or provider defaults for existing accounts.
    pub fn for_account(account: &Account) -> Option<Self> {
        if let Some(config) = &account.config.smtp {
            return Some(config.clone());
        }

        let (host, port, security) = match account.auth_kind {
            AuthKind::Password => return None,
            AuthKind::GoogleOauth | AuthKind::GoogleServiceAccount => {
                ("smtp.gmail.com", 465, SmtpSecurity::Tls)
            }
            AuthKind::MicrosoftOauth => {
                let host = if account.config.tenant == "consumers" {
                    "smtp-mail.outlook.com"
                } else {
                    "smtp.office365.com"
                };

                (host, 587, SmtpSecurity::Starttls)
            }
        };

        Some(Self {
            host: host.into(),
            port,
            security,
        })
    }
}
