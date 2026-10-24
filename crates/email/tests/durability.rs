#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#[path = "../../../tests/support/mod.rs"]
mod support;
use epistle_core::{AuthKind, Pointer};
use epistle_delivery::{Delivery, FileStore};
use epistle_email::{enqueue, handoff, parse_message};
use epistle_store::{Error, Store};
use std::sync::{
    Arc,
    atomic::{AtomicU16, Ordering},
};
fn pointer() -> Pointer {
    Pointer {
        account_id: "a".into(),
        folder_id: "f".into(),
        folder: "INBOX".into(),
        uidvalidity: 1,
        uid: 1,
        rfc_message_id: Some("<message@example.test>".into()),
        gmail_id: None,
        thread_id: None,
        labels: vec![],
        flags: vec![],
        size: 100,
        internal_date: epistle_core::now(),
    }
}
async fn fixture() -> (tempfile::TempDir, Store, FileStore) {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&dir.path().join("db.sqlite")).await.unwrap();
    support::account(&store, AuthKind::Password).await;
    store
        .write(|c| {
            Box::pin(async move {
                sqlx::query(
                    "INSERT INTO folders(id,account_id,name,uidvalidity) VALUES('f','a','INBOX',1)",
                )
                .execute(c)
                .await?;
                Ok(())
            })
        })
        .await
        .unwrap();
    let files = FileStore::new(dir.path());
    (dir, store, files)
}
async fn discover(store: &Store, redeliver: bool) {
    store
        .write(move |c| {
            Box::pin(async move {
                enqueue(c, &pointer(), "live", None, redeliver).await?;
                sqlx::query("UPDATE folders SET cursor_uid=1 WHERE id='f'")
                    .execute(c)
                    .await?;
                Ok(())
            })
        })
        .await
        .unwrap();
}
async fn prepare(store: &Store, files: &FileStore) -> (String, epistle_delivery::Prepared) {
    use sqlx::Row;
    let row = sqlx::query("SELECT id,message_key,idempotency_key FROM fetch_queue LIMIT 1")
        .fetch_one(&store.reads)
        .await
        .unwrap();
    let (message, drafts) = parse_message(
        row.try_get("message_key").unwrap(),
        &pointer(),
        b"Subject: Test\r\n\r\nbody".to_vec(),
        "live".into(),
        None,
        256,
    );
    (
        row.try_get("id").unwrap(),
        files
            .prepare(message, drafts, row.try_get("idempotency_key").unwrap())
            .await
            .unwrap(),
    )
}
async fn count(store: &Store, table: &str) -> i64 {
    sqlx::query_scalar(match table {
        "fetch_queue" => "SELECT COUNT(*) FROM fetch_queue",
        "seen" => "SELECT COUNT(*) FROM seen",
        "messages" => "SELECT COUNT(*) FROM messages",
        "message_files" => "SELECT COUNT(*) FROM message_files",
        "outbox" => "SELECT COUNT(*) FROM outbox",
        "message_payloads" => "SELECT COUNT(*) FROM message_payloads",
        "message_index" => "SELECT COUNT(*) FROM message_index",
        _ => panic!("unknown test table"),
    })
    .fetch_one(&store.reads)
    .await
    .unwrap()
}
#[tokio::test]
async fn crash_boundaries_preserve_stub_and_remove_orphan_files() {
    let (dir, store, files) = fixture().await;
    let failure: Result<(), Error> = store
        .write(|c| {
            Box::pin(async move {
                enqueue(c, &pointer(), "live", None, false).await?;
                sqlx::query("UPDATE folders SET cursor_uid=1")
                    .execute(c)
                    .await?;
                Err(Error::Conflict("crash after stub insert"))
            })
        })
        .await;
    assert!(failure.is_err());
    assert_eq!(count(&store, "fetch_queue").await, 0);
    assert_eq!(count(&store, "seen").await, 0);
    let cursor: i64 = sqlx::query_scalar("SELECT cursor_uid FROM folders")
        .fetch_one(&store.reads)
        .await
        .unwrap();
    assert_eq!(cursor, 0);
    discover(&store, false).await;
    let (stub, prepared) = prepare(&store, &files).await;
    let orphan = prepared.payload_path.clone();
    store
        .write(|c| {
            Box::pin(async move {
                sqlx::query(
                    "
CREATE TRIGGER fail_handoff BEFORE INSERT ON outbox BEGIN SELECT RAISE(ABORT,'injected
crash'); END
",
                )
                .execute(c)
                .await?;
                Ok(())
            })
        })
        .await
        .unwrap();
    assert!(handoff(&store, stub, prepared).await.is_err());
    assert_eq!(count(&store, "fetch_queue").await, 1);
    assert_eq!(count(&store, "messages").await, 0);
    assert_eq!(count(&store, "message_files").await, 0);
    store
        .write(|c| {
            Box::pin(async move {
                sqlx::query("DROP TRIGGER fail_handoff").execute(c).await?;
                Ok(())
            })
        })
        .await
        .unwrap();
    let restarted = Store::open(&dir.path().join("db.sqlite")).await.unwrap();
    files
        .sweep(&restarted, &support::config(dir.path()), true)
        .await
        .unwrap();
    assert!(!std::path::Path::new(&orphan).exists());
    let (stub, prepared) = prepare(&restarted, &files).await;
    handoff(&restarted, stub, prepared).await.unwrap();
    assert_eq!(count(&restarted, "fetch_queue").await, 0);
    assert_eq!(count(&restarted, "outbox").await, 1);
    assert_eq!(count(&restarted, "message_payloads").await, 1);
    discover(&restarted, false).await;
    assert_eq!(count(&restarted, "fetch_queue").await, 0);
    // A cross-folder / UIDVALIDITY rediscovery retains the same public identity.
    let p = Pointer {
        uidvalidity: 2,
        uid: 99,
        ..pointer()
    };
    restarted
        .write(move |c| {
            Box::pin(async move {
                assert!(!enqueue(c, &p, "live", None, false).await?);
                Ok(())
            })
        })
        .await
        .unwrap();
    assert_eq!(count(&restarted, "message_index").await, 1);
}
#[tokio::test]
async fn dead_and_retrying_deliveries_retain_files_ack_starts_expiry() {
    let (dir, store, files) = fixture().await;
    discover(&store, false).await;
    let (stub, prepared) = prepare(&store, &files).await;
    let file = prepared.files.first().unwrap().path.clone();
    let payload = prepared.payload_path.clone();
    handoff(&store, stub, prepared).await.unwrap();
    let status = Arc::new(AtomicU16::new(503));
    let state = status.clone();
    let app = axum::Router::new().route(
        "/webhook",
        axum::routing::post(move || {
            let s = state.clone();
            async move { axum::http::StatusCode::from_u16(s.load(Ordering::SeqCst)).unwrap() }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/webhook", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let mut config = support::config(dir.path());
    config.webhook_url = url;
    config.file_retention_secs = 1;
    let config = Arc::new(config);
    let delivery = Delivery::new(store.clone(), config.clone()).unwrap();
    delivery.tick().await.unwrap();
    let state: String = sqlx::query_scalar("SELECT state FROM outbox")
        .fetch_one(&store.reads)
        .await
        .unwrap();
    assert_eq!(state, "pending");
    files.sweep(&store, &config, false).await.unwrap();
    assert!(std::path::Path::new(&file).exists());
    store
        .write(|c| {
            Box::pin(async move {
                sqlx::query("UPDATE outbox SET next_attempt_at=0")
                    .execute(c)
                    .await?;
                Ok(())
            })
        })
        .await
        .unwrap();
    status.store(400, Ordering::SeqCst);
    delivery.tick().await.unwrap();
    let state: String = sqlx::query_scalar("SELECT state FROM outbox")
        .fetch_one(&store.reads)
        .await
        .unwrap();
    assert_eq!(state, "dead");
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    files.sweep(&store, &config, false).await.unwrap();
    assert!(std::path::Path::new(&file).exists());
    store
        .write(|c| {
            Box::pin(async move {
                sqlx::query("UPDATE outbox SET state='pending',next_attempt_at=0,attempts=0")
                    .execute(c)
                    .await?;
                Ok(())
            })
        })
        .await
        .unwrap();
    status.store(200, Ordering::SeqCst);
    // Inject a failure after the HTTP acknowledgment: the row remains replayable.
    store
        .write(|c| {
            Box::pin(async move {
                sqlx::query(
                    "
CREATE TRIGGER fail_ack BEFORE DELETE ON outbox BEGIN SELECT RAISE(ABORT,'injected ack
crash'); END
",
                )
                .execute(c)
                .await?;
                Ok(())
            })
        })
        .await
        .unwrap();
    assert!(delivery.tick().await.is_err());
    assert_eq!(count(&store, "outbox").await, 1);
    store
        .write(|c| {
            Box::pin(async move {
                sqlx::query("DROP TRIGGER fail_ack").execute(c).await?;
                Ok(())
            })
        })
        .await
        .unwrap();
    delivery.tick().await.unwrap();
    assert_eq!(count(&store, "outbox").await, 0);
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    files.sweep(&store, &config, false).await.unwrap();
    assert!(!std::path::Path::new(&file).exists());
    assert!(!std::path::Path::new(&payload).exists());
    assert_eq!(count(&store, "message_files").await, 1);
    task.abort();
}

#[tokio::test]
async fn rediscovery_redirects_in_flight_fetch_and_revives_gone_stub() {
    let (_dir, store, _files) = fixture().await;
    discover(&store, false).await;
    let original = serde_json::to_string(&pointer()).unwrap();
    let moved = Pointer {
        uid: 2,
        ..pointer()
    };
    let replacement = serde_json::to_string(&moved).unwrap();
    store
        .write(move |c| {
            Box::pin(async move {
                assert!(!enqueue(c, &moved, "live", None, false).await?);
                // Simulate the stale fetch completing after watcher rediscovery.
                sqlx::query("UPDATE fetch_queue SET state='gone' WHERE pointer=?")
                    .bind(original)
                    .execute(c)
                    .await?;
                Ok(())
            })
        })
        .await
        .unwrap();
    let state: String = sqlx::query_scalar("SELECT state FROM fetch_queue")
        .fetch_one(&store.reads)
        .await
        .unwrap();
    assert_eq!(state, "pending");
    let stored: String = sqlx::query_scalar("SELECT pointer FROM fetch_queue")
        .fetch_one(&store.reads)
        .await
        .unwrap();
    assert_eq!(stored, replacement);
    store
        .write(|c| {
            Box::pin(async move {
                sqlx::query("UPDATE fetch_queue SET state='gone'")
                    .execute(&mut *c)
                    .await?;
                assert!(
                    enqueue(
                        c,
                        &Pointer {
                            uid: 3,
                            ..pointer()
                        },
                        "live",
                        None,
                        false
                    )
                    .await?
                );
                Ok(())
            })
        })
        .await
        .unwrap();
    assert_eq!(count(&store, "fetch_queue").await, 1);
    assert_eq!(count(&store, "seen").await, 1);
    let state: String = sqlx::query_scalar("SELECT state FROM fetch_queue")
        .fetch_one(&store.reads)
        .await
        .unwrap();
    assert_eq!(state, "pending");
}

#[tokio::test]
async fn missing_payload_is_dead_and_does_not_abort_independent_deliveries() {
    let (dir, store, files) = fixture().await;
    discover(&store, false).await;
    let (stub, prepared) = prepare(&store, &files).await;
    let payload = prepared.payload_path.clone();
    let retained_file = prepared.files.first().unwrap().path.clone();
    handoff(&store, stub, prepared).await.unwrap();
    tokio::fs::remove_file(&payload).await.unwrap();
    store.status("a", "active", None, 0).await.unwrap();
    let received = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let seen = received.clone();
    let app = axum::Router::new().route(
        "/webhook",
        axum::routing::post(move || {
            let seen = seen.clone();
            async move {
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                seen.fetch_add(1, Ordering::SeqCst);
                axum::http::StatusCode::OK
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut config = support::config(dir.path());
    config.webhook_url = format!("http://{}/webhook", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let delivery = Delivery::new(store.clone(), Arc::new(config.clone())).unwrap();
    assert_eq!(delivery.tick().await.unwrap(), 2);
    assert_eq!(received.load(Ordering::SeqCst), 1);
    let failure: (String, String) = sqlx::query_as("SELECT state,last_error FROM outbox")
        .fetch_one(&store.reads)
        .await
        .unwrap();
    assert_eq!(failure, ("dead".into(), "payload_missing".into()));
    assert_eq!(delivery.tick().await.unwrap(), 0);
    files.sweep(&store, &config, false).await.unwrap();
    assert!(std::path::Path::new(&retained_file).exists());
    server.abort();
}

#[tokio::test]
async fn failed_ack_does_not_cancel_slow_independent_delivery() {
    let (dir, store, files) = fixture().await;
    discover(&store, false).await;
    let (stub, prepared) = prepare(&store, &files).await;
    handoff(&store, stub, prepared).await.unwrap();
    store.status("a", "active", None, 0).await.unwrap();
    store.write(|c| Box::pin(async move {
        sqlx::query("CREATE TRIGGER fail_message_ack BEFORE DELETE ON outbox WHEN OLD.kind='email.message.received' BEGIN SELECT RAISE(ABORT,'injected'); END").execute(c).await?;
        Ok(())
    })).await.unwrap();
    let app = axum::Router::new().route(
        "/webhook",
        axum::routing::post(
            |axum::Json(body): axum::Json<serde_json::Value>| async move {
                if body.get("kind").and_then(|v| v.as_str()) == Some("account.status_changed") {
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                }
                axum::http::StatusCode::OK
            },
        ),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut config = support::config(dir.path());
    config.webhook_url = format!("http://{}/webhook", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    assert!(
        Delivery::new(store.clone(), Arc::new(config))
            .unwrap()
            .tick()
            .await
            .is_err()
    );
    let kinds: Vec<String> = sqlx::query_scalar("SELECT kind FROM outbox")
        .fetch_all(&store.reads)
        .await
        .unwrap();
    assert_eq!(kinds, ["email.message.received"]);
    server.abort();
}
