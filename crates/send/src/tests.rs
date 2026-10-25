//! Synthetic SMTP and OAuth regressions for submission boundaries.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "../../../tests/support/mod.rs"]
mod support;

use super::*;
use epistle_auth::Credentials;
use epistle_core::{AuthKind, SmtpConfig, SmtpSecurity, now};
use std::{
    sync::{
        Arc,
        atomic::{AtomicU8, AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::TcpListener,
    sync::{Mutex, Notify},
};
use tokio_util::sync::CancellationToken;

#[derive(Default)]
struct Smtp {
    port: u16,
    mode: AtomicU8,
    messages: Mutex<Vec<Vec<u8>>>,
    recipients: Mutex<Vec<String>>,
    auth: Mutex<Vec<String>>,
    entered: Notify,
    release: Notify,
}

impl Smtp {
    async fn start() -> Arc<Self> {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let smtp = Arc::new(Self {
            port: listener.local_addr().unwrap().port(),
            ..Default::default()
        });
        let server = smtp.clone();

        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let smtp = server.clone();
                tokio::spawn(async move { smtp.session(stream).await });
            }
        });

        smtp
    }

    async fn session(&self, stream: tokio::net::TcpStream) {
        let (read, mut write) = stream.into_split();
        let mut read = BufReader::new(read);
        write.write_all(b"220 fixture ESMTP\r\n").await.unwrap();

        loop {
            let mut line = String::new();
            if read.read_line(&mut line).await.unwrap_or(0) == 0 {
                return;
            }

            let mode = self.mode.load(Ordering::SeqCst);
            let response = if line.starts_with("EHLO") {
                "250-fixture\r\n250-8BITMIME\r\n250 AUTH PLAIN LOGIN XOAUTH2\r\n"
            } else if line.starts_with("AUTH") {
                self.auth.lock().await.push(line.clone());
                if mode == 5 && self.auth.lock().await.len() == 1 {
                    "535 rejected\r\n"
                } else {
                    "235 authenticated\r\n"
                }
            } else if line.starts_with("MAIL") {
                if mode == 1 {
                    "450 try later\r\n"
                } else {
                    "250 sender\r\n"
                }
            } else if line.starts_with("RCPT") {
                self.recipients.lock().await.push(line.clone());
                if mode == 2 && line.contains("reject@") {
                    "550 no recipient\r\n"
                } else {
                    "250 recipient\r\n"
                }
            } else if line.starts_with("DATA") {
                write.write_all(b"354 content\r\n").await.unwrap();
                let mut message = Vec::new();

                loop {
                    let mut part = Vec::new();
                    if read.read_until(b'\n', &mut part).await.unwrap_or(0) == 0 {
                        return;
                    }
                    if part == b".\r\n" {
                        break;
                    }
                    message.extend(part);
                }

                self.messages.lock().await.push(message);
                self.entered.notify_one();
                if mode == 3 {
                    return;
                }
                if mode == 4 {
                    self.release.notified().await;
                }

                if mode == 6 {
                    "450 content rejected\r\n"
                } else {
                    "250 accepted\r\n"
                }
            } else if line.starts_with("QUIT") {
                let _ = write.write_all(b"221 bye\r\n").await;
                return;
            } else {
                "500 unknown command\r\n"
            };

            if write.write_all(response.as_bytes()).await.is_err() {
                return;
            }
        }
    }
}

fn request(key: &str) -> SendRequest {
    serde_json::from_value(serde_json::json!({
        "idempotency_key":key, "to":["Recipient <to@example.test>"],
        "cc":["cc@example.test"], "bcc":["hidden@example.test"],
        "subject":"Hello ✓", "text":"Text body", "html":"<p>HTML body</p>",
        "in_reply_to":"<original@example.test>", "references":["<original@example.test>"],
        "attachments":[{"filename":"hello.txt", "content_type":"text/plain", "content_base64":"aGVsbG8="}]
    })).unwrap()
}

async fn fixture(smtp: &Smtp, kind: AuthKind) -> (tempfile::TempDir, Sender) {
    let dir = tempfile::tempdir().unwrap();
    let config = Arc::new(support::config(dir.path()));
    let store = Store::open(&dir.path().join("test.sqlite")).await.unwrap();
    let mut account = support::account(&store, kind).await;
    account.config.smtp = Some(SmtpConfig {
        host: "127.0.0.1".into(),
        port: smtp.port,
        security: SmtpSecurity::Plain,
    });
    let encoded = serde_json::to_string(&account.config).unwrap();

    store
        .write(move |c| {
            Box::pin(async move {
                sqlx::query("UPDATE accounts SET config=? WHERE id='a'")
                    .bind(encoded)
                    .execute(c)
                    .await?;
                Ok(())
            })
        })
        .await
        .unwrap();

    let tokens = TokenProvider::new(store.clone(), config.clone()).unwrap();
    tokens
        .save(
            "a",
            &Credentials {
                password: Some("test-password".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    (
        dir,
        Sender {
            store,
            tokens,
            config,
        },
    )
}

async fn wait_state(sender: &Sender, id: &str, state: &str) -> SendJob {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let job = sender.job(id).await.unwrap();
            if job.state == state {
                return job;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap()
}

async fn attempt(sender: &Sender) {
    let claim = sender.claim().await.unwrap().unwrap();
    sender
        .process(claim, &CancellationToken::new())
        .await
        .unwrap();
}

#[tokio::test]
async fn mime_envelope_idempotency_and_sent_status() {
    let smtp = Smtp::start().await;
    let (_dir, sender) = fixture(&smtp, AuthKind::Password).await;
    let (one, two) = tokio::join!(
        sender.enqueue("a", request("same")),
        sender.enqueue("a", request("same"))
    );
    let one = one.unwrap();
    assert_eq!(one.id, two.unwrap().id);

    let mut changed = request("same");
    changed.subject = "Different".into();
    assert!(matches!(
        sender.enqueue("a", changed).await,
        Err(Error::Store(epistle_store::Error::Conflict(_)))
    ));

    attempt(&sender).await;
    let job = sender.job(&one.id).await.unwrap();
    assert_eq!(job.state, "sent");
    assert!(job.accepted_at.is_some());
    assert!(sender.retry(&job.id, true).await.is_err());
    assert!(sender.cancel(&job.id).await.is_err());

    let messages = smtp.messages.lock().await;
    assert_eq!(messages.len(), 1);
    let bytes = messages.first().unwrap();
    let parsed = mail_parser::MessageParser::default().parse(bytes).unwrap();
    assert_eq!(parsed.subject(), Some("Hello ✓"));
    assert_eq!(
        parsed.message_id(),
        Some(job.message_id.trim_matches(['<', '>']))
    );
    assert_eq!(parsed.body_text(0).unwrap().trim(), "Text body");
    assert!(parsed.body_html(0).unwrap().contains("HTML body"));
    assert_eq!(
        parsed.attachments().next().unwrap().decoded().as_ref(),
        b"hello"
    );
    assert!(!String::from_utf8_lossy(bytes).contains("hidden@example.test"));
    assert!(
        smtp.recipients
            .lock()
            .await
            .iter()
            .any(|r| r.contains("hidden@example.test"))
    );
    assert!(
        smtp.auth
            .lock()
            .await
            .first()
            .unwrap()
            .starts_with("AUTH PLAIN")
    );
}

#[tokio::test]
async fn validation_rejects_headers_sizes_and_unconfigured_smtp() {
    let smtp = Smtp::start().await;
    let (_dir, sender) = fixture(&smtp, AuthKind::Password).await;
    for bad in ["hello\r\nBcc: victim@example.test", "hello\u{0}"] {
        let mut message = request("invalid");
        message.subject = bad.into();
        assert!(sender.enqueue("a", message).await.is_err());
    }

    let mut empty = request("empty");
    empty.to.clear();
    empty.cc.clear();
    empty.bcc.clear();
    assert!(sender.enqueue("a", empty).await.is_err());
    assert!(request("oversized").prepare("a@example.test", 10).is_err());

    sender
        .store
        .write(|c| {
            Box::pin(async move {
                sqlx::query("UPDATE accounts SET config='{}' WHERE id='a'")
                    .execute(c)
                    .await?;
                Ok(())
            })
        })
        .await
        .unwrap();
    assert!(matches!(
        sender.enqueue("a", request("no-smtp")).await,
        Err(Error::Invalid("smtp_configuration_required"))
    ));
}

#[tokio::test]
async fn known_rejections_retry_without_partial_recipient_delivery() {
    let smtp = Smtp::start().await;
    let (_dir, sender) = fixture(&smtp, AuthKind::Password).await;
    let job = sender.enqueue("a", request("temporary")).await.unwrap();
    smtp.mode.store(1, Ordering::SeqCst);
    attempt(&sender).await;

    let pending = sender.job(&job.id).await.unwrap();
    assert_eq!(pending.state, "pending");
    assert!(pending.next_attempt > now());
    assert!(smtp.messages.lock().await.is_empty());

    let mut request = request("partial");
    request.to.push("reject@example.test".into());
    let failed = sender.enqueue("a", request).await.unwrap();
    smtp.mode.store(2, Ordering::SeqCst);
    attempt(&sender).await;
    assert_eq!(sender.job(&failed.id).await.unwrap().state, "failed");
    assert!(smtp.messages.lock().await.is_empty());

    smtp.mode.store(0, Ordering::SeqCst);
    sender.retry(&failed.id, false).await.unwrap();
    attempt(&sender).await;
    assert_eq!(sender.job(&failed.id).await.unwrap().state, "sent");
}

#[tokio::test]
async fn lost_acceptance_is_unknown_and_never_automatically_replayed() {
    let smtp = Smtp::start().await;
    smtp.mode.store(3, Ordering::SeqCst);
    let (_dir, sender) = fixture(&smtp, AuthKind::Password).await;
    let job = sender.enqueue("a", request("lost-reply")).await.unwrap();
    attempt(&sender).await;

    assert_eq!(sender.job(&job.id).await.unwrap().state, "unknown");
    assert!(sender.claim().await.unwrap().is_none());
    assert!(sender.retry(&job.id, false).await.is_err());
    assert_eq!(smtp.messages.lock().await.len(), 1);

    smtp.mode.store(0, Ordering::SeqCst);
    sender.retry(&job.id, true).await.unwrap();
    attempt(&sender).await;
    assert_eq!(sender.job(&job.id).await.unwrap().state, "sent");
    let messages = smtp.messages.lock().await;
    assert_eq!(messages.len(), 2);
    assert_eq!(messages.first(), messages.last());
}

#[tokio::test]
async fn restart_recovers_preparation_but_quarantines_submission() {
    let smtp = Smtp::start().await;
    let (dir, sender) = fixture(&smtp, AuthKind::Password).await;
    let prepared = sender.enqueue("a", request("preparation")).await.unwrap();
    sender.claim().await.unwrap().unwrap();
    sender.store.close().await.unwrap();

    let store = Store::open(&dir.path().join("test.sqlite")).await.unwrap();
    let sender = Sender {
        tokens: TokenProvider::new(store.clone(), sender.config.clone()).unwrap(),
        store,
        config: sender.config,
    };
    sender.recover().await.unwrap();
    assert_eq!(sender.job(&prepared.id).await.unwrap().state, "pending");

    let claim = sender.claim().await.unwrap().unwrap();
    assert!(sender.begin_submission(&claim).await.unwrap());
    sender.recover().await.unwrap();
    assert_eq!(sender.job(&prepared.id).await.unwrap().state, "unknown");
    assert!(sender.claim().await.unwrap().is_none());
}

#[tokio::test]
async fn revision_fence_disable_cancel_and_one_claim_per_account() {
    let smtp = Smtp::start().await;
    let (_dir, sender) = fixture(&smtp, AuthKind::Password).await;
    let first = sender.enqueue("a", request("first")).await.unwrap();
    let second = sender.enqueue("a", request("second")).await.unwrap();
    let claim = sender.claim().await.unwrap().unwrap();
    assert!(sender.claim().await.unwrap().is_none());
    assert!(sender.cancel(&first.id).await.is_err());
    assert_eq!(sender.cancel(&second.id).await.unwrap().state, "cancelled");

    sender
        .store
        .write(|c| {
            Box::pin(async move {
                sqlx::query(
                    "
UPDATE accounts SET revision=revision+1, enabled=0 WHERE id='a'
",
                )
                .execute(c)
                .await?;
                Ok(())
            })
        })
        .await
        .unwrap();
    assert!(!sender.begin_submission(&claim).await.unwrap());
    sender
        .process(claim, &CancellationToken::new())
        .await
        .unwrap();
    assert!(sender.claim().await.unwrap().is_none());
    assert!(sender.enqueue("a", request("disabled")).await.is_err());
    assert!(smtp.messages.lock().await.is_empty());
}

#[tokio::test]
async fn shutdown_drains_smtp_acceptance_and_leaves_pending_durable() {
    let smtp = Smtp::start().await;
    smtp.mode.store(4, Ordering::SeqCst);
    let (_dir, sender) = fixture(&smtp, AuthKind::Password).await;
    let first = sender.enqueue("a", request("drain")).await.unwrap();
    let second = sender.enqueue("a", request("later")).await.unwrap();
    let cancel = CancellationToken::new();
    let task = tokio::spawn(sender.clone().run(cancel.clone()));
    tokio::time::timeout(Duration::from_secs(5), smtp.entered.notified())
        .await
        .unwrap();

    cancel.cancel();
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(!task.is_finished());
    smtp.release.notify_one();
    tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(sender.job(&first.id).await.unwrap().state, "sent");
    assert_eq!(sender.job(&second.id).await.unwrap().state, "pending");
}

#[tokio::test]
async fn required_starttls_never_authenticates_without_encryption() {
    let smtp = Smtp::start().await;
    let (_dir, sender) = fixture(&smtp, AuthKind::Password).await;
    let mut account = sender.store.account("a").await.unwrap();
    account.config.smtp.as_mut().unwrap().security = SmtpSecurity::Starttls;
    let result = sender.connect(&account).await;
    assert!(matches!(
        result,
        Err(transport::Failure {
            reason: "smtp_starttls_required",
            ..
        })
    ));
    assert!(smtp.auth.lock().await.is_empty());
}

#[tokio::test]
async fn oauth_rejection_refreshes_once_and_persists_rotated_credentials() {
    let smtp = Smtp::start().await;
    smtp.mode.store(5, Ordering::SeqCst);
    let (_dir, mut sender) = fixture(&smtp, AuthKind::GoogleOauth).await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let count = Arc::new(AtomicUsize::new(0));
    let calls = count.clone();
    let app = axum::Router::new().route("/token", axum::routing::post(move || {
        calls.fetch_add(1, Ordering::SeqCst);
        async { axum::Json(serde_json::json!({"access_token":"new-access","refresh_token":"rotated-refresh","expires_in":3600,"scope":"https://mail.google.com/"})) }
    }));
    let mut config = (*sender.config).clone();
    config.testing.token_endpoint_override =
        Some(format!("http://{}/token", listener.local_addr().unwrap()));
    sender.config = Arc::new(config);
    sender.tokens = TokenProvider::new(sender.store.clone(), sender.config.clone()).unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    sender
        .tokens
        .save(
            "a",
            &Credentials {
                access_token: Some("old-access".into()),
                access_expires_at: Some(now() + 3600),
                access_issued_at: Some(now()),
                refresh_token: Some("old-refresh".into()),
                scopes: vec!["https://mail.google.com/".into()],
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let job = sender.enqueue("a", request("oauth")).await.unwrap();
    attempt(&sender).await;
    assert_eq!(sender.job(&job.id).await.unwrap().state, "sent");
    assert_eq!(count.load(Ordering::SeqCst), 1);
    assert_eq!(
        sender
            .tokens
            .load("a")
            .await
            .unwrap()
            .refresh_token
            .as_deref(),
        Some("rotated-refresh")
    );
    assert_eq!(smtp.auth.lock().await.len(), 2);
    assert!(
        smtp.auth
            .lock()
            .await
            .iter()
            .all(|line| line.starts_with("AUTH XOAUTH2"))
    );
}

#[tokio::test]
async fn microsoft_missing_smtp_scope_fails_without_network_submission() {
    let smtp = Smtp::start().await;
    let (_dir, sender) = fixture(&smtp, AuthKind::MicrosoftOauth).await;
    sender
        .tokens
        .save(
            "a",
            &Credentials {
                access_token: Some("access".into()),
                access_expires_at: Some(now() + 3600),
                access_issued_at: Some(now()),
                refresh_token: Some("refresh".into()),
                scopes: vec!["https://outlook.office.com/IMAP.AccessAsUser.All".into()],
                ..Default::default()
            },
        )
        .await
        .unwrap();

    let job = sender.enqueue("a", request("missing-scope")).await.unwrap();
    let cancel = CancellationToken::new();
    let task = tokio::spawn(sender.clone().run(cancel.clone()));
    let failed = wait_state(&sender, &job.id, "failed").await;
    cancel.cancel();
    task.await.unwrap();

    assert_eq!(
        failed.last_error.as_deref(),
        Some("smtp_scope_missing_reauthorize")
    );
    assert!(smtp.auth.lock().await.is_empty());
}

#[tokio::test]
async fn submission_timeout_is_unknown_and_retry_budget_stops_known_rejections() {
    let smtp = Smtp::start().await;
    let (_dir, mut sender) = fixture(&smtp, AuthKind::Password).await;
    let mut config = (*sender.config).clone();
    config.sending.timeout_secs = 1;
    config.sending.max_attempts = 1;
    sender.config = Arc::new(config);

    smtp.mode.store(4, Ordering::SeqCst);
    let timed_out = sender.enqueue("a", request("timeout")).await.unwrap();
    attempt(&sender).await;
    assert_eq!(sender.job(&timed_out.id).await.unwrap().state, "unknown");
    smtp.release.notify_one();

    smtp.mode.store(6, Ordering::SeqCst);
    let rejected = sender.enqueue("a", request("rejected-data")).await.unwrap();
    attempt(&sender).await;
    let job = sender.job(&rejected.id).await.unwrap();
    assert_eq!(job.state, "failed");
    assert_eq!(job.last_error.as_deref(), Some("smtp_temporary_rejection"));
    assert!(sender.claim().await.unwrap().is_none());
}

#[tokio::test]
async fn smtp_provider_defaults_and_plaintext_validation() {
    let smtp = Smtp::start().await;
    let (_dir, sender) = fixture(&smtp, AuthKind::Password).await;
    let mut account = sender.store.account("a").await.unwrap();
    let explicit = account.config.smtp.take().unwrap();
    assert!(explicit.validate(false).is_err());
    assert!(SmtpConfig::for_account(&account).is_none());

    for kind in [AuthKind::GoogleOauth, AuthKind::GoogleServiceAccount] {
        account.auth_kind = kind;
        let settings = SmtpConfig::for_account(&account).unwrap();
        assert_eq!(
            (settings.host.as_str(), settings.port, settings.security),
            ("smtp.gmail.com", 465, SmtpSecurity::Tls)
        );
    }

    account.auth_kind = AuthKind::MicrosoftOauth;
    let settings = SmtpConfig::for_account(&account).unwrap();
    assert_eq!(
        (settings.host.as_str(), settings.port, settings.security),
        ("smtp.office365.com", 587, SmtpSecurity::Starttls)
    );
    account.config.tenant = "consumers".into();
    assert_eq!(
        SmtpConfig::for_account(&account).unwrap().host,
        "smtp-mail.outlook.com"
    );
}

#[tokio::test]
async fn implicit_tls_never_falls_back_to_plaintext() {
    let smtp = Smtp::start().await;
    let (_dir, sender) = fixture(&smtp, AuthKind::Password).await;
    let mut account = sender.store.account("a").await.unwrap();
    account.config.smtp.as_mut().unwrap().security = SmtpSecurity::Tls;

    assert!(sender.connect(&account).await.is_err());
    assert!(smtp.auth.lock().await.is_empty());
}

#[tokio::test]
async fn worker_storage_failure_returns_without_signalling_normal_shutdown() {
    let smtp = Smtp::start().await;
    let (_dir, sender) = fixture(&smtp, AuthKind::Password).await;
    let cancel = CancellationToken::new();
    sender.store.close().await.unwrap();

    tokio::time::timeout(Duration::from_secs(5), sender.run(cancel.clone()))
        .await
        .unwrap();
    // The server observes worker completion as a fatal error, not a clean HTTP stop.
    assert!(!cancel.is_cancelled());
}
