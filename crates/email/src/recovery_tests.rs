//! Account outage, restart and shutdown regressions.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#[path = "../../../tests/support/mod.rs"]
mod support;
use super::*;
use epistle_auth::Credentials;
use epistle_core::{AuthKind, Pointer};
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

#[tokio::test]
async fn repeated_provider_outages_preserve_fetches_and_commands_until_restart_recovery() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&dir.path().join("db.sqlite")).await.unwrap();
    let mut account = support::account(&store, AuthKind::Password).await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    account.config.host = "127.0.0.1".into();
    account.config.port = listener.local_addr().unwrap().port();
    account.config.tls = false;
    let failing = Arc::new(AtomicBool::new(true));
    let fail = failing.clone();
    let server = tokio::spawn(async move {
        loop {
            let (mut socket, _) = listener.accept().await.unwrap();
            let fail = fail.clone();
            tokio::spawn(async move {
                socket.write_all(b"* OK ready\r\n").await.unwrap();
                let mut io = BufReader::new(socket);

                loop {
                    let mut line = String::new();

                    if io.read_line(&mut line).await.unwrap() == 0 {
                        break;
                    }

                    let tag = line.split_whitespace().next().unwrap();

                    let response = if line.contains(" CAPABILITY") {
                        format!("* CAPABILITY IMAP4rev1\r\n{tag} OK capabilities\r\n")
                    } else if line.contains(" EXAMINE ") || line.contains(" SELECT ") {
                        format!("* 1 EXISTS\r\n* OK [UIDVALIDITY 1] epoch\r\n{tag} OK selected\r\n")
                    } else if line.contains("UID SEARCH") {
                        format!("* SEARCH 1\r\n{tag} OK search\r\n")
                    } else if line.contains("UID FETCH") || line.contains("UID STORE") {
                        if fail.load(Ordering::SeqCst) {
                            format!("{tag} NO [UNAVAILABLE] maintenance\r\n")
                        } else if line.contains("UID FETCH") {
                            let raw = "Subject: recovered\r\n\r\nbody";
                            format!(
                                "* 1 FETCH (UID 1 BODY[] {{{}}}\r\n{raw})\r\n{tag} OK fetched\r\n",
                                raw.len()
                            )
                        } else {
                            format!("{tag} OK stored\r\n")
                        }
                    } else {
                        format!("{tag} OK done\r\n")
                    };

                    if io.get_mut().write_all(response.as_bytes()).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    let pointer = Pointer {
        account_id: "a".into(),
        folder_id: "f".into(),
        folder: "INBOX".into(),
        uidvalidity: 1,
        uid: 1,
        rfc_message_id: Some("<a@example.test>".into()),
        gmail_id: None,
        thread_id: None,
        labels: vec![],
        flags: vec![],
        size: 1,
        internal_date: now(),
    };
    store
        .write(move |c| {
            Box::pin(async move {
                sqlx::query("INSERT INTO folders(id,account_id,name,uidvalidity) VALUES('f','a','INBOX',1)").execute(&mut *c).await?;
                enqueue(c, &pointer, "live", None, false).await?;
                sqlx::query("INSERT INTO commands(id,account_id,message_key,kind,read_value,created_at) SELECT 'cmd','a',message_key,'mark_read',1,0 FROM fetch_queue").execute(&mut *c).await?;
                epistle_store::status_tx(c, "a", "active", None, 0).await
            })
        })
        .await
        .unwrap();
    let config = Arc::new(support::config(dir.path()));
    let tokens = TokenProvider::new(store.clone(), config.clone()).unwrap();
    tokens
        .save(
            "a",
            &Credentials {
                password: Some("test".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let service = Service {
        store: store.clone(),
        tokens,
        files: FileStore::new(dir.path()),
        config: config.clone(),
    };

    for _ in 0..=config.max_attempts {
        assert_eq!(store.account("a").await.unwrap().status, "active");
        assert_eq!(store.account("a").await.unwrap().revision, account.revision);
        assert!(matches!(
            tokio::time::timeout(
                Duration::from_secs(3),
                service.fetch_worker(&account, &CancellationToken::new())
            )
            .await
            .unwrap(),
            Err(Error::Imap(_))
        ));
        assert!(matches!(
            tokio::time::timeout(
                Duration::from_secs(3),
                service.command_worker(&account, &CancellationToken::new())
            )
            .await
            .unwrap(),
            Err(Error::Imap(_))
        ));
    }
    for query in [
        "SELECT state,attempts,next_attempt_at FROM fetch_queue",
        "SELECT state,attempts,next_attempt_at FROM commands",
    ] {
        let (state, attempts, next): (String, i64, i64) =
            sqlx::query_as(query).fetch_one(&store.reads).await.unwrap();
        assert_eq!((state, attempts, next), ("pending".into(), 0, 0));
    }
    // A fresh writer epoch resumes the very same queued work after the outage.
    drop(service);
    let store = Store::open(&dir.path().join("db.sqlite")).await.unwrap();
    let service = Service {
        tokens: TokenProvider::new(store.clone(), config.clone()).unwrap(),
        store: store.clone(),
        files: FileStore::new(dir.path()),
        config,
    };
    failing.store(false, Ordering::SeqCst);
    let worker = service.clone();
    let a = account.clone();
    let fetch =
        tokio::spawn(async move { worker.fetch_worker(&a, &CancellationToken::new()).await });
    let command = tokio::spawn(async move {
        service
            .command_worker(&account, &CancellationToken::new())
            .await
    });
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let pending: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM fetch_queue")
                .fetch_one(&store.reads)
                .await
                .unwrap();
            let state: String = sqlx::query_scalar("SELECT state FROM commands")
                .fetch_one(&store.reads)
                .await
                .unwrap();

            if pending == 0 && state == "done" {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    let messages: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM outbox WHERE kind='email.message.received'")
            .fetch_one(&store.reads)
            .await
            .unwrap();
    assert_eq!(messages, 1);
    fetch.abort();
    command.abort();
    server.abort();
}

#[tokio::test]
async fn restart_resumes_opt_in_reauth_reminders_without_reconnecting() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&dir.path().join("db.sqlite")).await.unwrap();
    support::account(&store, AuthKind::MicrosoftOauth).await;
    store
        .status("a", "needs_reauth", Some("token_revoked"), 3)
        .await
        .unwrap();
    drop(store);
    let store = Store::open(&dir.path().join("db.sqlite")).await.unwrap();
    let mut config = support::config(dir.path());
    config.reauth_reminder_secs = 1;
    let config = Arc::new(config);
    let service = Service {
        tokens: TokenProvider::new(store.clone(), config.clone()).unwrap(),
        store: store.clone(),
        files: FileStore::new(dir.path()),
        config,
    };
    let stop = CancellationToken::new();
    let task = tokio::spawn(service.run(stop.clone()));
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let account = store.account("a").await.unwrap();
            assert_eq!(account.status, "needs_reauth");
            assert_eq!(account.status_reason.as_deref(), Some("token_revoked"));

            if account.status_seq == 2 {
                assert_eq!(account.consecutive_failures, 4);
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    stop.cancel();
    task.await.unwrap();
}

#[tokio::test]
async fn restart_keeps_password_failure_count_and_elapsed_window() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&dir.path().join("db.sqlite")).await.unwrap();
    support::account(&store, AuthKind::Password).await;
    store
        .status("a", "degraded", Some("credentials_rejected"), 3)
        .await
        .unwrap();
    store
        .write(|c| {
            Box::pin(async move {
                sqlx::query("UPDATE accounts SET first_failure_at=? WHERE id='a'")
                    .bind(now() - 180)
                    .execute(c)
                    .await?;

                Ok(())
            })
        })
        .await
        .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut a = store.account("a").await.unwrap();
    a.config.host = "127.0.0.1".into();
    a.config.port = listener.local_addr().unwrap().port();
    a.config.tls = false;
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        socket.write_all(b"* OK ready\r\n").await.unwrap();
        let mut io = BufReader::new(socket);
        let mut line = String::new();
        io.read_line(&mut line).await.unwrap();
        let tag = line.split_whitespace().next().unwrap();
        io.get_mut()
            .write_all(format!("{tag} NO [AUTHENTICATIONFAILED] rejected\r\n").as_bytes())
            .await
            .unwrap();
    });
    let config = Arc::new(support::config(dir.path()));
    let tokens = TokenProvider::new(store.clone(), config.clone()).unwrap();
    tokens
        .save(
            "a",
            &Credentials {
                password: Some("invalid".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let service = Service {
        tokens,
        store: store.clone(),
        files: FileStore::new(dir.path()),
        config,
    };
    tokio::time::timeout(
        Duration::from_secs(3),
        service.supervise(a, CancellationToken::new()),
    )
    .await
    .unwrap();
    let a = store.account("a").await.unwrap();
    assert_eq!(a.status, "needs_reauth");
    assert_eq!(a.consecutive_failures, 4);
    server.await.unwrap();
}

#[tokio::test]
async fn graceful_workers_finish_current_item_and_leave_the_rest_pending() {
    for commands in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("db.sqlite")).await.unwrap();
        let mut account = support::account(&store, AuthKind::Password).await;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (started, entered) = tokio::sync::oneshot::channel();
        let (release, gate) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            socket.write_all(b"* OK ready\r\n").await.unwrap();
            let mut io = BufReader::new(socket);
            let mut barrier = Some((started, gate));

            loop {
                let mut line = String::new();

                if io.read_line(&mut line).await.unwrap() == 0 {
                    break;
                }

                let tag = line.split_whitespace().next().unwrap();

                let response = if line.contains(" CAPABILITY") {
                    format!("* CAPABILITY IMAP4rev1\r\n{tag} OK capabilities\r\n")
                } else if line.contains(" EXAMINE ") || line.contains(" SELECT ") {
                    format!("* 2 EXISTS\r\n* OK [UIDVALIDITY 1] epoch\r\n{tag} OK selected\r\n")
                } else if line.contains("UID SEARCH") {
                    format!("* SEARCH 1 2\r\n{tag} OK search\r\n")
                } else if line.contains("UID FETCH") || line.contains("UID STORE") {
                    let (started, gate) = barrier.take().expect("only the first item may run");
                    started.send(()).unwrap();
                    gate.await.unwrap();

                    if commands {
                        format!("{tag} OK stored\r\n")
                    } else {
                        let raw = "Subject: drained\r\n\r\nbody";
                        let uid = line.split_whitespace().nth(3).unwrap();
                        format!(
                            "* 1 FETCH (UID {uid} BODY[] {{{}}}\r\n{raw})\r\n{tag} OK fetched\r\n",
                            raw.len()
                        )
                    }
                } else if line.contains(" LOGOUT") {
                    io.get_mut()
                        .write_all(format!("* BYE closing\r\n{tag} OK logout\r\n").as_bytes())
                        .await
                        .unwrap();
                    break;
                } else {
                    format!("{tag} OK done\r\n")
                };
                io.get_mut().write_all(response.as_bytes()).await.unwrap();
            }
        });
        store.write(move |c| Box::pin(async move {
            sqlx::query("INSERT INTO folders(id,account_id,name,uidvalidity) VALUES('f','a','INBOX',1)").execute(&mut *c).await?;

            for uid in [1, 2] {
                let pointer = Pointer {
                    account_id: "a".into(), folder_id: "f".into(), folder: "INBOX".into(),
                    uidvalidity: 1, uid, rfc_message_id: Some(format!("<{uid}@example.test>")),
                    gmail_id: None, thread_id: None, labels: vec![], flags: vec![], size: 1, internal_date: now(),
                };
                enqueue(c, &pointer, "live", None, false).await?;
            }
            sqlx::query("INSERT INTO commands(id,account_id,message_key,kind,read_value,created_at) SELECT id,'a',message_key,'mark_read',1,0 FROM fetch_queue ORDER BY rowid").execute(&mut *c).await?;
            epistle_store::status_tx(c, "a", "active", None, 0).await
        })).await.unwrap();
        account.config.host = address.ip().to_string();
        account.config.port = address.port();
        account.config.tls = false;
        let config = Arc::new(support::config(dir.path()));
        let tokens = TokenProvider::new(store.clone(), config.clone()).unwrap();
        tokens
            .save(
                "a",
                &Credentials {
                    password: Some("test".into()),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        let service = Service {
            store: store.clone(),
            tokens,
            files: FileStore::new(dir.path()),
            config,
        };
        let stop = CancellationToken::new();
        let cancel = stop.clone();
        let worker = tokio::spawn(async move {
            if commands {
                service.command_worker(&account, &cancel).await
            } else {
                service.fetch_worker(&account, &cancel).await
            }
        });
        tokio::time::timeout(Duration::from_secs(5), entered)
            .await
            .unwrap()
            .unwrap();
        stop.cancel();
        assert!(!worker.is_finished());
        release.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(5), worker)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        server.await.unwrap();

        let pending: i64 = sqlx::query_scalar(if commands {
            "SELECT COUNT(*) FROM commands WHERE state='pending'"
        } else {
            "SELECT COUNT(*) FROM fetch_queue WHERE state='pending'"
        })
        .fetch_one(&store.reads)
        .await
        .unwrap();
        assert_eq!(pending, 1);
        let completed: i64 = sqlx::query_scalar(if commands {
            "SELECT COUNT(*) FROM commands WHERE state='done'"
        } else {
            "SELECT COUNT(*) FROM messages"
        })
        .fetch_one(&store.reads)
        .await
        .unwrap();
        assert_eq!(completed, 1);
        store.close().await.unwrap();
    }
}
