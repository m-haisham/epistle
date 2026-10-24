use epistle_core::{Account, Pointer};
use futures::TryStreamExt;
use secrecy::{ExposeSecret, SecretString};
use std::{fmt::Debug, sync::Arc, time::Duration};
use thiserror::Error;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpStream,
    time::timeout,
};
use tokio_rustls::{
    TlsConnector,
    rustls::{ClientConfig, RootCertStore, pki_types::ServerName},
};
#[derive(Debug, Error, Clone)]
#[error("IMAP operation failed: {reason}")]
pub struct Error {
    pub reason: &'static str,
    pub permanent: bool,
    pub auth: bool,
}
impl Error {
    fn transient(reason: &'static str) -> Self {
        Self {
            reason,
            permanent: false,
            auth: false,
        }
    }
}
impl From<async_imap::error::Error> for Error {
    fn from(e: async_imap::error::Error) -> Self {
        // Interpret only allow-listed provider response codes; never retain raw server text.
        match e {
            async_imap::error::Error::No(s) | async_imap::error::Error::Bad(s) => {
                let u = s.to_ascii_uppercase();
                if u.contains("AUTHENTICATIONFAILED") {
                    Self {
                        reason: "credentials_rejected",
                        permanent: false,
                        auth: true,
                    }
                } else if u.contains("[UNAVAILABLE]") {
                    Self::transient("provider_outage")
                } else if u.contains("[LIMIT]") || u.contains("[OVERQUOTA]") {
                    Self::transient("rate_limited")
                } else if u.contains("[NONEXISTENT]") {
                    Self {
                        reason: "mailbox_missing",
                        permanent: true,
                        auth: false,
                    }
                } else if u.contains("[ALERT]") && (u.contains("WEBALERT") || u.contains("LOGIN")) {
                    Self {
                        reason: "account_locked",
                        permanent: true,
                        auth: false,
                    }
                } else if u.contains("IMAP") && u.contains("DISABLED") {
                    Self {
                        reason: "imap_disabled",
                        permanent: true,
                        auth: false,
                    }
                } else {
                    Self::transient("provider_outage")
                }
            }
            async_imap::error::Error::Validate(_) => Self {
                reason: "invalid_configuration",
                permanent: true,
                auth: false,
            },
            _ => Self::transient("connection_lost"),
        }
    }
}
trait Io: AsyncRead + AsyncWrite + Unpin + Send + Debug {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send + Debug> Io for T {}
type Session = async_imap::Session<Box<dyn Io>>;
pub struct Connection {
    session: Session,
    pub gmail: bool,
    pub idle_supported: bool,
    timeout: Duration,
}
struct Xoauth {
    email: String,
    token: SecretString,
    sent: bool,
}
impl async_imap::Authenticator for Xoauth {
    type Response = String;
    fn process(&mut self, _: &[u8]) -> String {
        if self.sent {
            return String::new();
        } // RFC 7628 error challenges require an empty acknowledgement.
        self.sent = true;
        format!(
            "user={}\x01auth=Bearer {}\x01\x01",
            self.email,
            self.token.expose_secret()
        )
    }
}
async fn bounded<T>(
    duration: Duration,
    f: impl std::future::Future<Output = Result<T, async_imap::error::Error>>,
) -> Result<T, Error> {
    timeout(duration, f)
        .await
        .map_err(|_| Error::transient("connection_lost"))?
        .map_err(Into::into)
}
impl Connection {
    pub async fn connect(
        a: &Account,
        secret: SecretString,
        password: bool,
        watchdog_secs: u64,
    ) -> Result<Self, Error> {
        let duration = Duration::from_secs(watchdog_secs);
        timeout(duration, async {
            let tcp = TcpStream::connect((&*a.config.host, a.config.port))
                .await
                .map_err(|_| Error::transient("server_unreachable"))?;
            let stream: Box<dyn Io> = if a.config.tls {
                let roots =
                    RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
                let cfg = ClientConfig::builder()
                    .with_root_certificates(roots)
                    .with_no_client_auth();
                let name = ServerName::try_from(a.config.host.clone())
                    .map_err(|_| Error::transient("tls_error"))?;
                Box::new(
                    TlsConnector::from(Arc::new(cfg))
                        .connect(name, tcp)
                        .await
                        .map_err(|_| Error::transient("tls_error"))?,
                )
            } else {
                Box::new(tcp)
            };
            let mut client = async_imap::Client::new(stream);
            client
                .read_response()
                .await
                .map_err(|_| Error::transient("connection_lost"))?
                .ok_or(Error::transient("connection_lost"))?;
            let mut session = if password {
                client.login(&a.email, secret.expose_secret()).await
            } else {
                client
                    .authenticate(
                        "XOAUTH2",
                        Xoauth {
                            email: a.email.clone(),
                            token: secret,
                            sent: false,
                        },
                    )
                    .await
            }
            .map_err(|(e, _)| {
                let mut classified = Error::from(e);
                if classified.reason == "provider_outage" {
                    classified.auth = true;
                    classified.reason = "credentials_rejected";
                }
                classified
            })?;
            let caps = session.capabilities().await.map_err(Error::from)?;
            if caps.has_str("ENABLE") && caps.has_str("CONDSTORE") {
                session
                    .run_command_and_check_ok("ENABLE CONDSTORE")
                    .await
                    .map_err(Error::from)?;
            }
            Ok(Self {
                gmail: caps.has_str("X-GM-EXT-1"),
                idle_supported: caps.has_str("IDLE"),
                session,
                timeout: duration,
            })
        })
        .await
        .map_err(|_| Error::transient("server_unreachable"))?
    }
    pub async fn folders(&mut self, a: &Account) -> Result<Vec<String>, Error> {
        if !a.config.folders.is_empty() {
            return Ok(a.config.folders.clone());
        }
        let names = bounded(self.timeout, async {
            self.session
                .list(None, Some("*"))
                .await?
                .try_collect::<Vec<_>>()
                .await
        })
        .await?;
        if self.gmail {
            if let Some(all) = names.iter().find(|n| {
                n.attributes()
                    .iter()
                    .any(|a| format!("{a:?}").eq_ignore_ascii_case("All"))
                    || n.name().ends_with("/All Mail")
            }) {
                return Ok(vec![all.name().into()]);
            }
            return Ok(vec!["[Gmail]/All Mail".into()]);
        }
        let mut result = vec!["INBOX".into()];
        if let Some(sent) = names.iter().find(|n| {
            n.attributes()
                .iter()
                .any(|a| format!("{a:?}").eq_ignore_ascii_case("Sent"))
                || matches!(n.name(), "Sent" | "Sent Items" | "Sent Messages")
        }) {
            result.push(sent.name().into());
        }
        Ok(result)
    }
    pub async fn examine(&mut self, folder: &str) -> Result<async_imap::types::Mailbox, Error> {
        bounded(self.timeout, self.session.examine(folder)).await
    }
    pub async fn search(&mut self, query: &str) -> Result<Vec<u32>, Error> {
        let mut ids: Vec<_> = bounded(self.timeout, self.session.uid_search(query))
            .await?
            .into_iter()
            .collect();
        ids.sort_unstable();
        Ok(ids)
    }
    pub async fn metadata(
        &mut self,
        a: &Account,
        folder_id: &str,
        folder: &str,
        validity: i64,
        ids: &str,
    ) -> Result<Vec<Pointer>, Error> {
        let query = if self.gmail {
            "(UID FLAGS RFC822.SIZE INTERNALDATE ENVELOPE X-GM-MSGID X-GM-LABELS)"
        } else {
            "(UID FLAGS RFC822.SIZE INTERNALDATE ENVELOPE)"
        };
        let fetched = bounded(self.timeout, async {
            self.session
                .uid_fetch(ids, query)
                .await?
                .try_collect::<Vec<_>>()
                .await
        })
        .await?;
        let mut items = vec![];
        for f in fetched {
            let Some(uid) = f.uid else { continue };
            let thread_id = if self.gmail {
                self.thread_id(uid).await?
            } else {
                None
            };
            items.push(Pointer {
                account_id: a.id.clone(),
                folder_id: folder_id.into(),
                folder: folder.into(),
                uidvalidity: validity,
                uid: i64::from(uid),
                rfc_message_id: f
                    .envelope()
                    .and_then(|e| e.message_id.as_ref())
                    .map(|s| String::from_utf8_lossy(s).into_owned()),
                gmail_id: f.gmail_msg_id().map(ToString::to_string),
                thread_id,
                labels: f
                    .gmail_labels()
                    .map(|x| x.iter().map(ToString::to_string).collect())
                    .unwrap_or_default(),
                flags: f.flags().map(flag_string).collect(),
                size: i64::from(f.size.unwrap_or(0)),
                internal_date: f.internal_date().map(|d| d.timestamp()).unwrap_or(0),
            });
        }
        Ok(items)
    }
    async fn thread_id(&mut self, uid: u32) -> Result<Option<String>, Error> {
        use imap_proto::{AttributeValue, Response, Status};
        timeout(self.timeout, async {
            let tag = self
                .session
                .run_command(format!("UID FETCH {uid} (X-GM-THRID)"))
                .await
                .map_err(Error::from)?;
            let mut thread = None;
            loop {
                let r = self
                    .session
                    .read_response()
                    .await
                    .map_err(|_| Error::transient("connection_lost"))?
                    .ok_or(Error::transient("connection_lost"))?;
                match r.parsed() {
                    Response::Fetch(_, attrs) => {
                        for attr in attrs {
                            if let AttributeValue::GmailThrId(t) = attr {
                                thread = Some(t.to_string());
                            }
                        }
                    }
                    Response::Done {
                        tag: got, status, ..
                    } if *got == tag => {
                        return if *status == Status::Ok {
                            Ok(thread)
                        } else {
                            Err(Error::transient("provider_outage"))
                        };
                    }
                    _ => {}
                }
            }
        })
        .await
        .map_err(|_| Error::transient("connection_lost"))?
    }
    pub async fn resolve(&mut self, p: &Pointer, write: bool) -> Result<Option<Pointer>, Error> {
        let mailbox = if write {
            bounded(self.timeout, self.session.select(&p.folder)).await?
        } else {
            self.examine(&p.folder).await?
        };
        let validity = i64::from(mailbox.uid_validity.ok_or(Error {
            reason: "uidvalidity_missing",
            permanent: true,
            auth: false,
        })?);
        let mut resolved = p.clone();
        if validity != p.uidvalidity {
            let Some(mid) = p.rfc_message_id.as_ref() else {
                return Ok(None);
            };
            let ids = self
                .search(&format!("HEADER Message-ID {}", quote(mid)?))
                .await?;
            let Some(uid) = ids.first() else {
                return Ok(None);
            };
            resolved.uid = i64::from(*uid);
            resolved.uidvalidity = validity;
        }
        Ok(Some(resolved))
    }
    pub async fn fetch(&mut self, p: &Pointer) -> Result<Option<(Pointer, Vec<u8>)>, Error> {
        let Some(p) = self.resolve(p, false).await? else {
            return Ok(None);
        };
        let fetched = bounded(self.timeout, async {
            self.session
                .uid_fetch(p.uid.to_string(), "(UID BODY.PEEK[])")
                .await?
                .try_collect::<Vec<_>>()
                .await
        })
        .await?;
        Ok(fetched
            .into_iter()
            .find(|f| f.uid.map(i64::from) == Some(p.uid))
            .and_then(|f| f.body().map(|b| (p, b.to_vec()))))
    }
    pub async fn mark_read(&mut self, p: &Pointer, read: bool) -> Result<Option<Pointer>, Error> {
        let Some(p) = self.resolve(p, true).await? else {
            return Ok(None);
        };
        if self.search(&format!("UID {}", p.uid)).await?.is_empty() {
            return Ok(None);
        }
        let cmd = if read {
            "+FLAGS.SILENT (\\Seen)"
        } else {
            "-FLAGS.SILENT (\\Seen)"
        };
        bounded(self.timeout, async {
            self.session
                .uid_store(p.uid.to_string(), cmd)
                .await?
                .try_collect::<Vec<_>>()
                .await
        })
        .await?;
        Ok(Some(p))
    }
    pub async fn idle(self, seconds: u64) -> Result<Self, Error> {
        if !self.idle_supported {
            tokio::time::sleep(Duration::from_secs(seconds)).await;
            return Ok(self);
        }
        let Self {
            session,
            gmail,
            idle_supported,
            timeout: duration,
        } = self;
        let mut handle = session.idle();
        bounded(duration, handle.init()).await?;
        {
            let (wait, _stop) = handle.wait_with_timeout(Duration::from_secs(seconds.min(1200)));
            // Outer timer is absolute: unsolicited keepalives must not postpone reconciliation forever.
            if let Ok(result) = timeout(Duration::from_secs(seconds.min(1200)), wait).await {
                result.map_err(Error::from)?;
            }
        }
        let session = bounded(duration, handle.done()).await?;
        Ok(Self {
            session,
            gmail,
            idle_supported,
            timeout: duration,
        })
    }
    pub async fn logout(mut self) {
        let _ = bounded(self.timeout, self.session.logout()).await;
    }
}
pub fn quote(s: &str) -> Result<String, Error> {
    if s.chars().any(char::is_control) {
        return Err(Error {
            reason: "invalid_message_id",
            permanent: true,
            auth: false,
        });
    }
    Ok(format!(
        "\"{}\"",
        s.replace('\\', "\\\\").replace('"', "\\\"")
    ))
}

fn flag_string(f: async_imap::types::Flag<'_>) -> String {
    use async_imap::types::Flag;
    match f {
        Flag::Custom(s) => s.into_owned(),
        Flag::MayCreate => "\\*".into(),
        other => format!("\\{other:?}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn xoauth_error_challenge_is_acknowledged_without_repeating_secret() {
        use async_imap::Authenticator;
        let mut auth = Xoauth {
            email: "a@example.test".into(),
            token: "secret-token".into(),
            sent: false,
        };
        assert!(auth.process(b"").contains("auth=Bearer secret-token"));
        assert_eq!(auth.process(br#"{"status":"401"}"#), "");
    }
    #[test]
    fn provider_error_text_does_not_escape_and_search_is_quoted() {
        let e = Error::from(async_imap::error::Error::No(
            "[AUTHENTICATIONFAILED] secret-token".into(),
        ));
        assert!(e.auth);
        assert!(!e.to_string().contains("secret-token"));
        assert!(quote("bad\r\nUID STORE 1 +FLAGS (\\Seen)").is_err());
        assert_eq!(
            quote("<a\"b@example.test>").ok().as_deref(),
            Some("\"<a\\\"b@example.test>\"")
        );
    }
}
