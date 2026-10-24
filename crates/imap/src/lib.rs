use epistle_core::{Account, Pointer};
use imap_proto::{AttributeValue, MailboxDatum, Response, Status};
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
                } else if u.contains("[NONEXISTENT]")
                    // Older Dovecot IMAP4rev1 responses omit NONEXISTENT.
                    || u.contains("MAILBOX DOESN'T EXIST:")
                {
                    Self {
                        reason: "mailbox_missing",
                        permanent: true,
                        auth: false,
                    }
                } else if (u.contains("[ALERT]") || u.contains("CODE: SOME(ALERT)"))
                    && (u.contains("WEBALERT") || u.contains("LOGIN"))
                {
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
            // Every IMAP server sends an initial greeting, including Gmail and
            // Exchange. Client::new does not consume it (Hark did this for Gmail).
            let greeting = client
                .read_response()
                .await
                .map_err(|_| Error::transient("connection_lost"))?
                .ok_or(Error::transient("connection_lost"))?;
            match greeting.parsed() {
                imap_proto::Response::Data {
                    status: imap_proto::Status::Ok,
                    ..
                } => {}
                imap_proto::Response::Data {
                    status: imap_proto::Status::Bye,
                    ..
                } => {
                    return Err(Error::transient("provider_outage"));
                }
                imap_proto::Response::Data {
                    status: imap_proto::Status::PreAuth,
                    ..
                } => {
                    // async-imap has no public Client -> preauthenticated Session
                    // conversion. Refuse this unsupported mode without sending credentials.
                    return Err(Error {
                        reason: "preauthenticated_connection_unsupported",
                        permanent: true,
                        auth: false,
                    });
                }
                _ => return Err(Error::transient("invalid_greeting")),
            }
            let session = if password {
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
                let explicit_outage = matches!(&e,
                    async_imap::error::Error::No(s) | async_imap::error::Error::Bad(s)
                    if s.to_ascii_uppercase().contains("[UNAVAILABLE]"));
                let mut classified = Error::from(e);
                if classified.reason == "provider_outage" && !explicit_outage {
                    classified.auth = true;
                    classified.reason = "credentials_rejected";
                }
                classified
            })?;
            let mut connection = Self {
                session,
                gmail: false,
                idle_supported: false,
                timeout: duration,
            };
            let caps = connection.checked("CAPABILITY".into()).await?;
            let has = |name: &str| {
                caps.capabilities
                    .iter()
                    .any(|c| c.eq_ignore_ascii_case(name))
            };
            connection.gmail = has("X-GM-EXT-1");
            connection.idle_supported = has("IDLE");
            if has("ENABLE") && has("CONDSTORE") {
                connection.checked("ENABLE CONDSTORE".into()).await?;
            }
            Ok(connection)
        })
        .await
        .map_err(|_| Error::transient("server_unreachable"))?
    }
    pub async fn folders(&mut self, a: &Account) -> Result<Vec<String>, Error> {
        if !a.config.folders.is_empty() {
            return Ok(a.config.folders.clone());
        }
        let names = self.checked("LIST \"\" \"*\"".into()).await?.mailboxes;
        if self.gmail {
            if let Some(all) = names.iter().find(|n| {
                n.name_attributes
                    .iter()
                    .any(|a| format!("{a:?}").eq_ignore_ascii_case("All"))
                    || n.name.as_ref().ends_with("/All Mail")
            }) {
                return Ok(vec![all.name.as_ref().into()]);
            }
            return Ok(vec!["[Gmail]/All Mail".into()]);
        }
        let mut result = vec!["INBOX".into()];
        if let Some(sent) = names.iter().find(|n| {
            n.name_attributes
                .iter()
                .any(|a| format!("{a:?}").eq_ignore_ascii_case("Sent"))
                || matches!(n.name.as_ref(), "Sent" | "Sent Items" | "Sent Messages")
        }) {
            result.push(sent.name.as_ref().into());
        }
        Ok(result)
    }
    pub async fn examine(&mut self, folder: &str) -> Result<async_imap::types::Mailbox, Error> {
        bounded(self.timeout, self.session.examine(folder)).await
    }
    pub async fn search(&mut self, query: &str) -> Result<Vec<u32>, Error> {
        let mut ids = self.checked(format!("UID SEARCH {query}")).await?.ids;
        ids.sort_unstable();
        ids.dedup();
        Ok(ids)
    }
    /// Unlike async-imap's streaming helpers, check the tagged completion before
    /// exposing partial data. A rejected command must never advance a cursor or
    /// become a successful STORE / an empty successful FETCH.
    async fn checked(&mut self, command: String) -> Result<Checked, Error> {
        timeout(self.timeout, async {
            let tag = self
                .session
                .run_command(command)
                .await
                .map_err(Error::from)?;
            let mut responses = Checked::default();
            loop {
                let response = self
                    .session
                    .read_response()
                    .await
                    .map_err(|_| Error::transient("connection_lost"))?
                    .ok_or_else(|| Error::transient("connection_lost"))?;
                match response.parsed() {
                    Response::Done {
                        tag: got,
                        status,
                        outcome,
                    } if *got == tag => {
                        return if *status == Status::Ok {
                            Ok(responses)
                        } else {
                            Err(Error::from(async_imap::error::Error::No(format!(
                                "{outcome:?}"
                            ))))
                        };
                    }
                    Response::Data {
                        status: Status::Bye,
                        ..
                    } => return Err(Error::transient("connection_lost")),
                    Response::Fetch(_, attrs) => {
                        responses.fetches.push(Fetched::from(attrs.as_slice()))
                    }
                    Response::MailboxData(MailboxDatum::Search(ids)) => {
                        responses.ids.extend(ids.iter().copied())
                    }
                    Response::MailboxData(MailboxDatum::List(data)) => {
                        responses.mailboxes.push(data.clone().into_owned())
                    }
                    Response::Capabilities(caps) => {
                        responses.capabilities.extend(caps.iter().filter_map(|c| {
                            if let imap_proto::Capability::Atom(atom) = c {
                                Some(atom.to_string())
                            } else {
                                None
                            }
                        }))
                    }
                    _ => {}
                }
            }
        })
        .await
        .map_err(|_| Error::transient("connection_lost"))?
    }
    async fn fetch_data(&mut self, ids: &str, query: &str) -> Result<Vec<Fetched>, Error> {
        Ok(self
            .checked(format!("UID FETCH {ids} {query}"))
            .await?
            .fetches
            .into_iter()
            .filter(|f| f.uid.is_some_and(|uid| requested_uid(ids, uid)))
            .collect())
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
            "(UID FLAGS RFC822.SIZE INTERNALDATE ENVELOPE X-GM-MSGID X-GM-THRID X-GM-LABELS)"
        } else {
            "(UID FLAGS RFC822.SIZE INTERNALDATE ENVELOPE)"
        };
        let fetched = self.fetch_data(ids, query).await?;
        Ok(fetched
            .into_iter()
            // Unsolicited FLAGS/MODSEQ updates are not discovery records, even
            // when they happen to name one of the requested UIDs.
            .filter(|f| f.has_envelope)
            .filter_map(|f| {
                Some(Pointer {
                    account_id: a.id.clone(),
                    folder_id: folder_id.into(),
                    folder: folder.into(),
                    uidvalidity: validity,
                    uid: i64::from(f.uid?),
                    rfc_message_id: f.message_id,
                    gmail_id: f.gmail_id,
                    thread_id: f.thread_id,
                    labels: f.labels,
                    flags: f.flags,
                    size: f.size,
                    internal_date: f.internal_date,
                })
            })
            .collect())
    }
    pub async fn resolve(&mut self, p: &Pointer, write: bool) -> Result<Option<Pointer>, Error> {
        let mailbox = if write {
            bounded(self.timeout, self.session.select(&p.folder)).await
        } else {
            self.examine(&p.folder).await
        };
        let mailbox = match mailbox {
            Ok(mailbox) => mailbox,
            Err(e) if e.reason == "mailbox_missing" => return Ok(None),
            Err(e) => return Err(e),
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
            // IMAP HEADER searches are substring matches. Never FETCH/STORE a
            // different message just because its Message-ID contains this one.
            let mut exact = None;
            for chunk in ids.chunks(500) {
                let set = chunk
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(",");
                let candidates = self.fetch_data(&set, "(UID ENVELOPE)").await?;
                exact = candidates
                    .iter()
                    .find(|f| f.message_id.as_deref() == Some(mid.as_str()))
                    .and_then(|f| f.uid);
                if exact.is_some() {
                    break;
                }
            }
            let Some(uid) = exact else { return Ok(None) };
            resolved.uid = i64::from(uid);
            resolved.uidvalidity = validity;
        }
        Ok(Some(resolved))
    }
    pub async fn fetch(&mut self, p: &Pointer) -> Result<Option<(Pointer, Vec<u8>)>, Error> {
        let Some(p) = self.resolve(p, false).await? else {
            return Ok(None);
        };
        let fetched = self
            .fetch_data(&p.uid.to_string(), "(UID BODY.PEEK[])")
            .await?;
        Ok(fetched
            .into_iter()
            .find(|f| f.uid.map(i64::from) == Some(p.uid))
            .and_then(|f| f.body.map(|b| (p, b))))
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
        self.checked(format!("UID STORE {} {cmd}", p.uid)).await?;
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

#[derive(Default)]
struct Checked {
    fetches: Vec<Fetched>,
    ids: Vec<u32>,
    mailboxes: Vec<imap_proto::MailboxListData<'static>>,
    capabilities: Vec<String>,
}
#[derive(Default)]
struct Fetched {
    uid: Option<u32>,
    size: i64,
    internal_date: i64,
    message_id: Option<String>,
    has_envelope: bool,
    gmail_id: Option<String>,
    thread_id: Option<String>,
    labels: Vec<String>,
    flags: Vec<String>,
    body: Option<Vec<u8>>,
}
impl From<&[AttributeValue<'_>]> for Fetched {
    fn from(attrs: &[AttributeValue<'_>]) -> Self {
        let mut result = Self::default();
        for attr in attrs {
            match attr {
                AttributeValue::Uid(uid) => result.uid = Some(*uid),
                AttributeValue::Rfc822Size(size) => result.size = i64::from(*size),
                AttributeValue::InternalDate(date) => {
                    result.internal_date =
                        chrono::DateTime::parse_from_str(date, "%d-%b-%Y %H:%M:%S %z")
                            .map(|d| d.timestamp())
                            .unwrap_or(0)
                }
                AttributeValue::Envelope(e) => {
                    result.has_envelope = true;
                    result.message_id = e
                        .message_id
                        .as_ref()
                        .map(|m| String::from_utf8_lossy(m).into_owned())
                }
                AttributeValue::GmailMsgId(id) => result.gmail_id = Some(id.to_string()),
                AttributeValue::GmailThrId(id) => result.thread_id = Some(id.to_string()),
                AttributeValue::GmailLabels(labels) => {
                    result.labels = labels.iter().map(ToString::to_string).collect()
                }
                AttributeValue::Flags(flags) => {
                    result.flags = flags.iter().map(ToString::to_string).collect()
                }
                AttributeValue::BodySection {
                    section: None,
                    data: Some(body),
                    ..
                }
                | AttributeValue::Rfc822(Some(body)) => result.body = Some(body.to_vec()),
                _ => {}
            }
        }
        result
    }
}

fn requested_uid(set: &str, uid: u32) -> bool {
    let bound = |value: &str| {
        if value == "*" {
            Some(u32::MAX)
        } else {
            value.parse::<u32>().ok()
        }
    };
    set.split(',').any(|part| {
        if let Some((a, b)) = part.split_once(':') {
            match (bound(a), bound(b)) {
                (Some(a), Some(b)) => (a.min(b)..=a.max(b)).contains(&uid),
                _ => false,
            }
        } else {
            bound(part) == Some(uid)
        }
    })
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
