use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chacha20poly1305::{
    ChaCha20Poly1305, KeyInit,
    aead::{Aead, Payload},
};
use epistle_core::{Account, AuthKind, Config, hash, now};
use epistle_store::Store;
use hmac::{Hmac, Mac};
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::Row;
use std::{collections::HashMap, sync::Arc, time::Duration};
use thiserror::Error;
use tokio::sync::Mutex;
use zeroize::{Zeroize, Zeroizing};
#[derive(Debug, Error)]
pub enum Error {
    #[error("credential storage failed")]
    Store(#[from] epistle_store::Error),
    #[error("credential query failed")]
    Sql(#[from] sqlx::Error),
    #[error("credential encryption failed")]
    Crypto,
    #[error("invalid credential data")]
    Data,
    #[error("reauthentication required: {0}")]
    Reauth(&'static str),
    #[error("token provider temporarily unavailable")]
    Temporary,
    #[error("OAuth provider is not configured")]
    Unconfigured,
    #[error("invalid or expired OAuth state")]
    State,
}
// Intentionally no Debug: credentials must never appear in traces.
#[derive(Default, Clone, Serialize, Deserialize, Zeroize)]
#[serde(default, deny_unknown_fields)]
pub struct Credentials {
    pub password: Option<String>,
    pub refresh_token: Option<String>,
    pub access_token: Option<String>,
    pub access_expires_at: Option<i64>,
    pub access_issued_at: Option<i64>,
    pub scopes: Vec<String>,
    pub client_email: Option<String>,
    pub private_key: Option<String>,
}
#[derive(Serialize, Deserialize)]
struct Envelope {
    key_id: String,
    wrapped_key: Vec<u8>,
    wrap_nonce: [u8; 12],
    nonce: [u8; 12],
    ciphertext: Vec<u8>,
}
#[derive(Clone)]
pub struct Vault {
    master: Arc<Zeroizing<[u8; 32]>>,
}
impl Vault {
    pub fn new(key: &str) -> Result<Self, Error> {
        let bytes = Zeroizing::new(hex::decode(key).map_err(|_| Error::Crypto)?);
        let key: [u8; 32] = bytes.as_slice().try_into().map_err(|_| Error::Crypto)?;
        Ok(Self {
            master: Arc::new(Zeroizing::new(key)),
        })
    }
    pub fn seal(&self, account: &str, plaintext: &[u8]) -> Result<String, Error> {
        let key = Zeroizing::new(rand::random::<[u8; 32]>());
        let nonce = rand::random::<[u8; 12]>();
        let wrap_nonce = rand::random::<[u8; 12]>();
        let cipher = ChaCha20Poly1305::new_from_slice(key.as_ref()).map_err(|_| Error::Crypto)?;
        let ciphertext = cipher
            .encrypt(
                (&nonce).into(),
                Payload {
                    msg: plaintext,
                    aad: account.as_bytes(),
                },
            )
            .map_err(|_| Error::Crypto)?;
        let master = ChaCha20Poly1305::new_from_slice(self.master.as_ref().as_ref())
            .map_err(|_| Error::Crypto)?;
        let wrapped_key = master
            .encrypt(
                (&wrap_nonce).into(),
                Payload {
                    msg: key.as_ref(),
                    aad: account.as_bytes(),
                },
            )
            .map_err(|_| Error::Crypto)?;
        serde_json::to_string(&Envelope {
            key_id: "env-v1".into(),
            wrapped_key,
            wrap_nonce,
            nonce,
            ciphertext,
        })
        .map_err(|_| Error::Data)
    }
    pub fn open(&self, account: &str, sealed: &str) -> Result<Zeroizing<Vec<u8>>, Error> {
        let e: Envelope = serde_json::from_str(sealed).map_err(|_| Error::Crypto)?;
        let master = ChaCha20Poly1305::new_from_slice(self.master.as_ref().as_ref())
            .map_err(|_| Error::Crypto)?;
        let key = Zeroizing::new(
            master
                .decrypt(
                    (&e.wrap_nonce).into(),
                    Payload {
                        msg: &e.wrapped_key,
                        aad: account.as_bytes(),
                    },
                )
                .map_err(|_| Error::Crypto)?,
        );
        let cipher = ChaCha20Poly1305::new_from_slice(&key).map_err(|_| Error::Crypto)?;
        Ok(Zeroizing::new(
            cipher
                .decrypt(
                    (&e.nonce).into(),
                    Payload {
                        msg: &e.ciphertext,
                        aad: account.as_bytes(),
                    },
                )
                .map_err(|_| Error::Crypto)?,
        ))
    }
}
#[derive(Clone)]
pub struct TokenProvider {
    pub store: Store,
    pub vault: Vault,
    config: Arc<Config>,
    client: reqwest::Client,
    locks: Arc<Mutex<HashMap<String, Arc<Mutex<()>>>>>,
}
pub struct Access {
    pub secret: SecretString,
    pub expires_at: i64,
    pub refresh_at: i64,
    pub password: bool,
}
impl Access {
    /// Recycle only once the cached token is refreshable. Short-lived tokens need
    /// a proportionally smaller margin or they cause an immediate reconnect loop.
    pub fn recycle_at(&self, account_id: &str) -> i64 {
        if self.password {
            return i64::MAX;
        }
        let jitter = i64::from(account_id.bytes().next().unwrap_or(0) % 30);
        (self.expires_at - 60 - jitter).max(self.refresh_at)
    }
}
impl Credentials {
    fn refresh_at(&self) -> i64 {
        let expiry = self.access_expires_at.unwrap_or(0);
        // Older encrypted records have no issuance time; retain their 5-minute margin.
        let margin = self.access_issued_at.map_or(300, |issued| {
            (expiry.saturating_sub(issued) / 10).clamp(1, 300)
        });
        expiry.saturating_sub(margin)
    }
}
#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    refresh_token: Option<String>,
    expires_in: Option<i64>,
    scope: Option<String>,
}
impl TokenProvider {
    pub fn new(store: Store, config: Arc<Config>) -> Result<Self, Error> {
        let vault = Vault::new(&config.master_key)?;
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|_| Error::Temporary)?;
        Ok(Self {
            store,
            vault,
            config,
            client,
            locks: Default::default(),
        })
    }
    pub async fn lock(&self, a: &str) -> tokio::sync::OwnedMutexGuard<()> {
        self.locks
            .lock()
            .await
            .entry(a.into())
            .or_default()
            .clone()
            .lock_owned()
            .await
    }
    pub async fn load(&self, a: &str) -> Result<Zeroizing<Credentials>, Error> {
        let sealed: Option<String> =
            sqlx::query_scalar("SELECT ciphertext FROM credentials WHERE account_id=?")
                .bind(a)
                .fetch_optional(&self.store.reads)
                .await?;
        let bytes = self
            .vault
            .open(a, &sealed.ok_or(Error::Reauth("credentials_rejected"))?)?;
        serde_json::from_slice(&bytes)
            .map(Zeroizing::new)
            .map_err(|_| Error::Data)
    }
    pub fn encrypt_credentials(&self, a: &str, c: &Credentials) -> Result<String, Error> {
        self.vault.seal(
            a,
            &Zeroizing::new(serde_json::to_vec(c).map_err(|_| Error::Data)?),
        )
    }
    pub async fn save(&self, a: &str, c: &Credentials) -> Result<(), Error> {
        let sealed = self.encrypt_credentials(a, c)?;
        let a = a.to_owned();
        let exp = c.access_expires_at;
        let scopes = serde_json::to_string(&c.scopes).map_err(|_| Error::Data)?;
        self.store.write(move |db|Box::pin(async move { sqlx::query("
INSERT INTO credentials(account_id,ciphertext,access_expires_at,scopes,updated_at)
VALUES(?,?,?,?,?) ON CONFLICT(account_id) DO UPDATE SET
ciphertext=excluded.ciphertext,access_expires_at=excluded.access_expires_at,scopes=excluded.scopes,updated_at=excluded.updated_at
")
   .bind(a).bind(sealed).bind(exp).bind(scopes).bind(now()).execute(db).await?;
 Ok(()) })).await?;
        Ok(())
    }
    pub async fn get_access_token(&self, a: &Account, force: bool) -> Result<Access, Error> {
        let _guard = self.lock(&a.id).await;
        let mut c = self.load(&a.id).await?;
        if a.auth_kind == AuthKind::Password {
            return Ok(Access {
                secret: c
                    .password
                    .clone()
                    .ok_or(Error::Reauth("credentials_rejected"))?
                    .into(),
                expires_at: i64::MAX,
                refresh_at: i64::MAX,
                password: true,
            });
        }
        if !force
            && c.refresh_at() > now()
            && let Some(token) = &c.access_token
        {
            return Ok(Access {
                secret: token.clone().into(),
                expires_at: c.access_expires_at.unwrap_or(0),
                refresh_at: c.refresh_at(),
                password: false,
            });
        }
        let endpoint = self.endpoint(a);
        let form = if a.auth_kind == AuthKind::GoogleServiceAccount {
            #[derive(Serialize)]
            struct Claims<'a> {
                iss: &'a str,
                sub: &'a str,
                aud: &'a str,
                scope: &'a str,
                iat: i64,
                exp: i64,
            }
            let claims = Claims {
                iss: c.client_email.as_deref().ok_or(Error::Data)?,
                sub: &a.email,
                aud: &endpoint,
                scope: "https://mail.google.com/",
                iat: now(),
                exp: now() + 3600,
            };
            let key = jsonwebtoken::EncodingKey::from_rsa_pem(
                c.private_key.as_deref().ok_or(Error::Data)?.as_bytes(),
            )
            .map_err(|_| Error::Data)?;
            let jwt = jsonwebtoken::encode(
                &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256),
                &claims,
                &key,
            )
            .map_err(|_| Error::Data)?;
            vec![
                (
                    "grant_type",
                    "urn:ietf:params:oauth:grant-type:jwt-bearer".to_owned(),
                ),
                ("assertion", jwt),
            ]
        } else {
            let (client, secret) = self.client_credentials(a.auth_kind)?;
            vec![
                ("grant_type", "refresh_token".into()),
                (
                    "refresh_token",
                    c.refresh_token
                        .clone()
                        .ok_or(Error::Reauth("token_revoked"))?,
                ),
                ("client_id", client),
                ("client_secret", secret),
            ]
        };
        let response = self.exchange(&endpoint, &form).await?;
        self.apply_response(a, &mut c, response, false)?;
        self.save(&a.id, &c).await?;
        // A rotated refresh token is durable before the access token leaves this function.
        Ok(Access {
            secret: c.access_token.clone().ok_or(Error::Data)?.into(),
            expires_at: c.access_expires_at.ok_or(Error::Data)?,
            refresh_at: c.refresh_at(),
            password: false,
        })
    }
    fn endpoint(&self, a: &Account) -> String {
        self.config
            .token_endpoint_override
            .clone()
            .unwrap_or_else(|| {
                if a.auth_kind == AuthKind::MicrosoftOauth {
                    format!(
                        "https://login.microsoftonline.com/{}/oauth2/v2.0/token",
                        a.config.tenant
                    )
                } else {
                    "https://oauth2.googleapis.com/token".into()
                }
            })
    }
    pub fn ensure_configured(&self, kind: AuthKind) -> Result<(), Error> {
        if kind.oauth() {
            self.client_credentials(kind)?;
        }
        Ok(())
    }
    fn client_credentials(&self, kind: AuthKind) -> Result<(String, String), Error> {
        let (id, secret) = if kind == AuthKind::MicrosoftOauth {
            (
                &self.config.microsoft_client_id,
                &self.config.microsoft_client_secret,
            )
        } else {
            (
                &self.config.google_client_id,
                &self.config.google_client_secret,
            )
        };
        if id.is_empty() {
            return Err(Error::Unconfigured);
        }
        Ok((id.clone(), secret.clone()))
    }
    async fn exchange(&self, url: &str, form: &[(&str, String)]) -> Result<TokenResponse, Error> {
        let response = self
            .client
            .post(url)
            .form(form)
            .send()
            .await
            .map_err(|_| Error::Temporary)?;
        let status = response.status();
        if status.is_server_error() || status.as_u16() == 429 {
            return Err(Error::Temporary);
        }
        if !status.is_success() {
            let body: serde_json::Value = response.json().await.map_err(|_| Error::Temporary)?;
            return Err(match body.get("error").and_then(|e| e.as_str()) {
                Some("invalid_grant") => Error::Reauth("token_revoked"),
                Some("interaction_required" | "consent_required") => {
                    Error::Reauth("consent_required")
                }
                Some("invalid_scope") => Error::Reauth("scope_missing"),
                _ => Error::Reauth("credentials_rejected"),
            });
        }
        response.json().await.map_err(|_| Error::Data)
    }
    fn apply_response(
        &self,
        a: &Account,
        c: &mut Credentials,
        r: TokenResponse,
        require_scope: bool,
    ) -> Result<(), Error> {
        if r.access_token.is_empty() {
            return Err(Error::Data);
        }
        if let Some(scope) = r.scope {
            c.scopes = scope.split_whitespace().map(str::to_owned).collect();
        }
        let required = if a.auth_kind == AuthKind::MicrosoftOauth {
            "https://outlook.office.com/IMAP.AccessAsUser.All"
        } else {
            "https://mail.google.com/"
        };
        if (require_scope || !c.scopes.is_empty())
            && !c.scopes.iter().any(|s| s.eq_ignore_ascii_case(required))
        {
            return Err(Error::Reauth("scope_missing"));
        }
        c.access_token = Some(r.access_token);
        let issued = now();
        c.access_issued_at = Some(issued);
        c.access_expires_at = Some(issued + r.expires_in.unwrap_or(3600).clamp(1, 86400));
        if let Some(token) = r.refresh_token {
            c.refresh_token = Some(token);
        }
        Ok(())
    }
    pub async fn authorization_url(&self, a: &Account) -> Result<String, Error> {
        let (client, _) = self.client_credentials(a.auth_kind)?;
        let nonce = URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>());
        let unsigned = format!("{}.{}.{}", a.id, now() + 600, nonce);
        let mut mac =
            <Hmac<Sha256> as hmac::KeyInit>::new_from_slice(self.config.webhook_secret.as_bytes())
                .map_err(|_| Error::Crypto)?;
        mac.update(unsigned.as_bytes());
        let state = format!(
            "{unsigned}.{}",
            URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
        );
        let verifier = URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>());
        let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
        let encrypted = self.vault.seal(&a.id, verifier.as_bytes())?;
        let state_hash = hash(state.as_bytes());
        let account = a.id.clone();
        let revision = a.revision;
        self.store
            .write(move |c| {
                Box::pin(async move {
                    sqlx::query("DELETE FROM oauth_states WHERE account_id=? OR expires_at<?")
                        .bind(&account)
                        .bind(now())
                        .execute(&mut *c)
                        .await?;
                    sqlx::query(
                        "
INSERT INTO oauth_states(state_hash,account_id,encrypted_verifier,expires_at,revision)
VALUES(?,?,?,?,?)
",
                    )
                    .bind(state_hash)
                    .bind(account)
                    .bind(encrypted)
                    .bind(now() + 600)
                    .bind(revision)
                    .execute(c)
                    .await?;
                    Ok(())
                })
            })
            .await?;
        let base = if a.auth_kind == AuthKind::MicrosoftOauth {
            format!(
                "https://login.microsoftonline.com/{}/oauth2/v2.0/authorize",
                a.config.tenant
            )
        } else {
            "https://accounts.google.com/o/oauth2/v2/auth".into()
        };
        let mut url = url::Url::parse(&base).map_err(|_| Error::Data)?;
        let scope = if a.auth_kind == AuthKind::MicrosoftOauth {
            "offline_access https://outlook.office.com/IMAP.AccessAsUser.All https://outlook.office.com/SMTP.Send"
        } else {
            "https://mail.google.com/"
        };
        url.query_pairs_mut().extend_pairs([
            ("client_id", client.as_str()),
            (
                "redirect_uri",
                &format!(
                    "{}/oauth/callback",
                    self.config.public_url.trim_end_matches('/')
                ),
            ),
            ("response_type", "code"),
            ("scope", scope),
            ("state", &state),
            ("code_challenge", &challenge),
            ("code_challenge_method", "S256"),
            ("access_type", "offline"),
            ("prompt", "consent"),
            ("login_hint", &a.email),
        ]);
        Ok(url.into())
    }
    pub async fn callback(&self, state: &str, code: &str) -> Result<String, Error> {
        let (unsigned, signature) = state.rsplit_once('.').ok_or(Error::State)?;
        let mut mac =
            <Hmac<Sha256> as hmac::KeyInit>::new_from_slice(self.config.webhook_secret.as_bytes())
                .map_err(|_| Error::Crypto)?;
        mac.update(unsigned.as_bytes());
        mac.verify_slice(
            &URL_SAFE_NO_PAD
                .decode(signature)
                .map_err(|_| Error::State)?,
        )
        .map_err(|_| Error::State)?;
        let state_hash = hash(state.as_bytes());
        let row = self
            .store
            .write(move |c| {
                Box::pin(async move {
                    Ok(sqlx::query(
                        "
DELETE FROM oauth_states WHERE state_hash=? AND expires_at>? RETURNING
account_id,encrypted_verifier,revision
",
                    )
                    .bind(state_hash)
                    .bind(now())
                    .fetch_optional(c)
                    .await?)
                })
            })
            .await?
            .ok_or(Error::State)?;
        let account_id: String = row.try_get("account_id")?;
        let _guard = self.lock(&account_id).await;
        let a = self.store.account(&account_id).await?;
        if a.revision != row.try_get::<i64, _>("revision")? {
            return Err(Error::State);
        }
        let verifier = self
            .vault
            .open(&a.id, &row.try_get::<String, _>("encrypted_verifier")?)?;
        let (client, secret) = self.client_credentials(a.auth_kind)?;
        let form = vec![
            ("grant_type", "authorization_code".into()),
            ("code", code.into()),
            ("client_id", client),
            ("client_secret", secret),
            (
                "redirect_uri",
                format!(
                    "{}/oauth/callback",
                    self.config.public_url.trim_end_matches('/')
                ),
            ),
            (
                "code_verifier",
                String::from_utf8(verifier.to_vec()).map_err(|_| Error::Data)?,
            ),
        ];
        let r = self.exchange(&self.endpoint(&a), &form).await?;
        let mut c = self.load(&a.id).await?;
        self.apply_response(&a, &mut c, r, true)?;
        self.save(&a.id, &c).await?;
        let id = a.id.clone();
        self.store
            .write(move |db| {
                Box::pin(async move {
                    sqlx::query("UPDATE accounts SET revision=revision+1,enabled=1 WHERE id=?")
                        .bind(&id)
                        .execute(&mut *db)
                        .await?;
                    epistle_store::status_tx(db, &id, "connecting", None, 0).await
                })
            })
            .await?;
        Ok(a.id)
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )]
    use super::*;
    #[test]
    fn short_lived_tokens_have_a_reusable_window_and_legacy_records_keep_their_margin() {
        let mut c = Credentials {
            access_issued_at: Some(1000),
            access_expires_at: Some(1012),
            ..Default::default()
        };
        assert_eq!(c.refresh_at(), 1011);
        let access = Access {
            secret: "test".into(),
            expires_at: 1012,
            refresh_at: c.refresh_at(),
            password: false,
        };
        for id in ["a", "z", "0"] {
            assert_eq!(access.recycle_at(id), 1011);
        }
        c.access_expires_at = Some(4600);
        assert_eq!(c.refresh_at(), 4300);
        c.access_issued_at = None;
        assert_eq!(c.refresh_at(), 4300);
    }
    #[test]
    fn envelope_encryption_binds_account_and_detects_tampering() {
        let vault = Vault::new(&"01".repeat(32)).unwrap();
        let sealed = vault.seal("account-a", b"refresh-token-secret").unwrap();
        assert!(!sealed.contains("refresh-token-secret"));
        assert_eq!(
            &**vault.open("account-a", &sealed).unwrap(),
            b"refresh-token-secret"
        );
        assert!(vault.open("account-b", &sealed).is_err());
        assert!(
            Vault::new(&"02".repeat(32))
                .unwrap()
                .open("account-a", &sealed)
                .is_err()
        );
        let mut value: serde_json::Value = serde_json::from_str(&sealed).unwrap();
        value["ciphertext"] = serde_json::json!([0, 1, 2]);
        assert!(vault.open("account-a", &value.to_string()).is_err());
        assert_ne!(
            sealed,
            vault.seal("account-a", b"refresh-token-secret").unwrap()
        );
    }
}
