//! Bounded SMTP connection and authentication before the submission boundary.

use crate::{Sender, compose::Envelope};
use epistle_core::{Account, AuthKind, SmtpConfig, SmtpSecurity};
use lettre::transport::smtp::{
    authentication::{Credentials, Mechanism},
    client::{AsyncSmtpConnection, TlsParameters},
    extension::ClientId,
};
use secrecy::ExposeSecret;
use std::time::Duration;

pub(crate) struct Failure {
    pub reason: &'static str,
    pub retryable: bool,
}

impl Failure {
    pub(crate) fn permanent(reason: &'static str) -> Self {
        Self {
            reason,
            retryable: false,
        }
    }

    fn temporary(reason: &'static str) -> Self {
        Self {
            reason,
            retryable: true,
        }
    }
}

impl Sender {
    pub(crate) fn timeout(&self) -> Duration {
        Duration::from_secs(self.config.sending.timeout_secs)
    }

    pub(crate) async fn connect(&self, account: &Account) -> Result<AsyncSmtpConnection, Failure> {
        let smtp = SmtpConfig::for_account(account)
            .ok_or_else(|| Failure::permanent("smtp_configuration_required"))?;
        smtp.validate(self.config.testing.allow_insecure_endpoints)
            .map_err(|_| Failure::permanent("invalid_smtp_configuration"))?;

        for force in [false, true] {
            // Refreshes persist replacement credentials before returning. Never cancel them.
            let access = self
                .tokens
                .get_access_token(account, force)
                .await
                .map_err(auth_failure)?;
            self.check_scope(account).await?;

            let mut connection = tokio::time::timeout(self.timeout(), self.open_connection(&smtp))
                .await
                .map_err(|_| Failure::temporary("smtp_connect_timeout"))??;
            let credentials =
                Credentials::new(account.email.clone(), access.secret.expose_secret().into());
            let mechanisms = if access.password {
                vec![Mechanism::Plain, Mechanism::Login]
            } else {
                vec![Mechanism::Xoauth2]
            };

            let result =
                tokio::time::timeout(self.timeout(), connection.auth(&mechanisms, &credentials))
                    .await
                    .map_err(|_| Failure::temporary("smtp_auth_timeout"))?;

            match result {
                Ok(response) if response.has_code(235) => return Ok(connection),
                Err(error) if error.is_permanent() && !access.password && !force => continue,
                Err(error) => return Err(smtp_failure(&error, "smtp_auth_rejected")),
                Ok(_) => return Err(Failure::permanent("smtp_auth_incomplete")),
            }
        }

        Err(Failure::permanent("smtp_auth_rejected"))
    }

    async fn check_scope(&self, account: &Account) -> Result<(), Failure> {
        if account.auth_kind != AuthKind::MicrosoftOauth {
            return Ok(());
        }

        let credentials = self.tokens.load(&account.id).await.map_err(auth_failure)?;
        if !credentials.scopes.is_empty()
            && !credentials
                .scopes
                .iter()
                .any(|s| s.eq_ignore_ascii_case("https://outlook.office.com/SMTP.Send"))
        {
            return Err(Failure::permanent("smtp_scope_missing_reauthorize"));
        }

        Ok(())
    }

    async fn open_connection(&self, smtp: &SmtpConfig) -> Result<AsyncSmtpConnection, Failure> {
        let hello = ClientId::Domain("epistle.local".into());
        let tls = || {
            TlsParameters::new(smtp.host.clone())
                .map_err(|_| Failure::permanent("smtp_tls_configuration"))
        };
        let implicit_tls = if smtp.security == SmtpSecurity::Tls {
            Some(tls()?)
        } else {
            None
        };

        let mut connection = AsyncSmtpConnection::connect_tokio1(
            (smtp.host.as_str(), smtp.port),
            Some(self.timeout()),
            &hello,
            implicit_tls,
            None,
        )
        .await
        .map_err(|e| smtp_failure(&e, "smtp_connect_failed"))?;

        if smtp.security == SmtpSecurity::Starttls {
            if !connection.can_starttls() {
                return Err(Failure::permanent("smtp_starttls_required"));
            }

            connection
                .starttls(tls()?, &hello)
                .await
                .map_err(|e| smtp_failure(&e, "smtp_tls_failed"))?;
        }

        Ok(connection)
    }
}

pub(crate) fn envelope(encoded: &str) -> Result<lettre::address::Envelope, Failure> {
    let envelope: Envelope =
        serde_json::from_str(encoded).map_err(|_| Failure::permanent("invalid_stored_message"))?;
    let from = envelope
        .from
        .parse()
        .map_err(|_| Failure::permanent("invalid_stored_message"))?;
    let to = envelope
        .to
        .iter()
        .map(|a| a.parse())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| Failure::permanent("invalid_stored_message"))?;

    lettre::address::Envelope::new(Some(from), to)
        .map_err(|_| Failure::permanent("invalid_stored_message"))
}

fn auth_failure(error: epistle_auth::Error) -> Failure {
    match error {
        epistle_auth::Error::Reauth(reason) => Failure::permanent(reason),
        epistle_auth::Error::Unconfigured => Failure::permanent("oauth_provider_not_configured"),
        _ => Failure::temporary("credential_unavailable"),
    }
}

fn smtp_failure(error: &lettre::transport::smtp::Error, reason: &'static str) -> Failure {
    Failure {
        reason,
        retryable: !error.is_permanent() && !error.is_client(),
    }
}
