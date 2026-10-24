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
    store.write(move |c| Box::pin(async move {
        sqlx::query("INSERT INTO folders(id,account_id,name,uidvalidity) VALUES('f','a','INBOX',1)").execute(&mut *c).await?;
        enqueue(c, &pointer, "live", None, false).await?;
        sqlx::query("INSERT INTO commands(id,account_id,message_key,kind,read_value,created_at) SELECT 'cmd','a',message_key,'mark_read',1,0 FROM fetch_queue").execute(&mut *c).await?;
        epistle_store::status_tx(c, "a", "active", None, 0).await
    })).await.unwrap();
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
            tokio::time::timeout(Duration::from_secs(3), service.fetch_worker(&account))
                .await
                .unwrap(),
            Err(Error::Imap(_))
        ));
        assert!(matches!(
            tokio::time::timeout(Duration::from_secs(3), service.command_worker(&account))
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
    let fetch = tokio::spawn(async move { worker.fetch_worker(&a).await });
    let command = tokio::spawn(async move { service.command_worker(&account).await });
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
