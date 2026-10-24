//! Fault injection lives only in the unit-test binary, never in the service.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use super::*;

#[path = "../../../tests/support/mod.rs"]
mod support;
use secrecy::ExposeSecret;
use std::{
    collections::HashSet,
    path::PathBuf,
    process::{Command, Stdio},
};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::TcpListener,
};

#[derive(Clone, Copy)]
enum Policy {
    GoogleReusable,
    MicrosoftRetainsOld,
    StrictSingleUse,
}

struct Issuer {
    policy: Policy,
    valid: HashSet<String>,
    used: Vec<String>,
    generation: usize,
    revoked: bool,
    expired: bool,
    truncate_next: bool,
    refresh_lifetime: Option<u64>,
}

impl Issuer {
    fn issue(&mut self, refresh: String) -> (u16, serde_json::Value, bool) {
        self.used.push(refresh.clone());

        if self.revoked || self.expired || !self.valid.contains(&refresh) {
            return (400, serde_json::json!({"error":"invalid_grant"}), false);
        }

        self.generation += 1;
        let mut body = serde_json::json!({
            "access_token": format!("access-{}", self.generation), "expires_in": 3600,
            "scope": "https://mail.google.com/ https://outlook.office.com/IMAP.AccessAsUser.All offline_access",
        });

        if !matches!(self.policy, Policy::GoogleReusable) {
            if matches!(self.policy, Policy::StrictSingleUse) {
                self.valid.clear();
            }

            let new = format!("refresh-{}", self.generation);
            self.valid.insert(new.clone());
            body.as_object_mut()
                .unwrap()
                .insert("refresh_token".into(), serde_json::json!(new));
        }
        if let Some(ttl) = self.refresh_lifetime {
            body.as_object_mut()
                .unwrap()
                .insert("refresh_token_expires_in".into(), serde_json::json!(ttl));
        }
        (200, body, std::mem::take(&mut self.truncate_next))
    }
}

struct Server {
    endpoint: String,
    state: Arc<Mutex<Issuer>>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Server {
    async fn new(policy: Policy) -> Self {
        let state = Arc::new(Mutex::new(Issuer {
            policy,
            valid: HashSet::from(["initial-refresh".into()]),
            used: vec![],
            generation: 0,
            revoked: false,
            expired: false,
            truncate_next: false,
            refresh_lifetime: None,
        }));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}/token", listener.local_addr().unwrap());
        let model = state.clone();
        let task = tokio::spawn(async move {
            loop {
                let (socket, _) = listener.accept().await.unwrap();
                let mut io = BufReader::new(socket);
                let mut length = 0;

                loop {
                    let mut line = String::new();

                    if io.read_line(&mut line).await.unwrap() == 0 {
                        break;
                    }
                    if let Some(n) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                        length = n.trim().parse::<usize>().unwrap();
                    }
                    if line == "\r\n" {
                        break;
                    }
                }

                let mut body = vec![0; length];
                io.read_exact(&mut body).await.unwrap();
                let fields: HashMap<_, _> =
                    url::form_urlencoded::parse(&body).into_owned().collect();
                let (status, response, truncated) = model
                    .lock()
                    .await
                    .issue(fields.get("refresh_token").unwrap().clone());
                let body = serde_json::to_vec(&response).unwrap();
                let length = body.len() + if truncated { 100 } else { 0 };
                let header = format!(
                    "HTTP/1.1 {status} Result\r\nContent-Type: application/json\r\nContent-Length: {length}\r\nConnection: close\r\n\r\n"
                );
                io.get_mut().write_all(header.as_bytes()).await.unwrap();
                io.get_mut().write_all(&body).await.unwrap();
                io.get_mut().shutdown().await.unwrap();
            }
        });
        Self {
            endpoint,
            state,
            task,
        }
    }
}

async fn provider(dir: &std::path::Path, endpoint: &str) -> TokenProvider {
    let store = Store::open(&dir.join("test.sqlite")).await.unwrap();
    let mut config = support::config(dir);
    config.token_endpoint_override = Some(endpoint.into());
    TokenProvider::new(store, Arc::new(config)).unwrap()
}

async fn seed(dir: &std::path::Path, server: &Server, kind: AuthKind) -> TokenProvider {
    let p = provider(dir, &server.endpoint).await;
    support::account(&p.store, kind).await;
    p.save(
        "a",
        &Credentials {
            refresh_token: Some("initial-refresh".into()),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    p
}

struct Child(std::process::Child);
impl Drop for Child {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

// Invoked only by the parent tests. The real token code reaches a test-only gate
// after receiving/applying the provider response. The parent then kills this process.
#[tokio::test]
#[ignore = "subprocess helper; executed by crash-before-save tests"]
async fn refresh_child() {
    let dir = PathBuf::from(std::env::var("EPISTLE_CRASH_TEST_DIR").unwrap());
    let endpoint = std::env::var("EPISTLE_CRASH_TEST_ENDPOINT").unwrap();
    let mut p = provider(&dir, &endpoint).await;
    let a = p.store.account("a").await.unwrap();
    let gate = Arc::new((tokio::sync::Notify::new(), tokio::sync::Notify::new()));
    p.refresh_save_gate = Some(gate.clone());
    let task = tokio::spawn(async move {
        p.get_access_token(&a, false).await.unwrap();
    });
    gate.0.notified().await;
    tokio::fs::write(dir.join("response-received"), b"ready")
        .await
        .unwrap();
    task.await.unwrap(); // Never released: parent kills us at the persistence boundary.
}

#[derive(Clone, Copy)]
enum Invalidation {
    None,
    Revoked,
    Expired,
}

async fn crash_case(policy: Policy, invalidate: Invalidation) {
    let dir = tempfile::tempdir().unwrap();
    let server = Server::new(policy).await;
    let kind = if matches!(policy, Policy::GoogleReusable) {
        AuthKind::GoogleOauth
    } else {
        AuthKind::MicrosoftOauth
    };
    let original = seed(dir.path(), &server, kind).await;
    let ciphertext: String =
        sqlx::query_scalar("SELECT ciphertext FROM credentials WHERE account_id='a'")
            .fetch_one(&original.store.reads)
            .await
            .unwrap();
    drop(original);
    let mut child = Child(
        Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "crash_tests::refresh_child",
                "--ignored",
                "--nocapture",
            ])
            .env("EPISTLE_CRASH_TEST_DIR", dir.path())
            .env("EPISTLE_CRASH_TEST_ENDPOINT", &server.endpoint)
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap(),
    );
    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            if tokio::fs::try_exists(dir.path().join("response-received"))
                .await
                .unwrap()
            {
                break;
            }
            assert!(
                child.0.try_wait().unwrap().is_none(),
                "child exited before response gate"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(server.state.lock().await.generation, 1);
    child.0.kill().unwrap();
    assert!(!child.0.wait().unwrap().success());
    {
        let mut state = server.state.lock().await;
        state.revoked = matches!(invalidate, Invalidation::Revoked);
        state.expired = matches!(invalidate, Invalidation::Expired);
    }
    // New process state and new SQLx writer epoch, with no retained response in memory.
    let recovered = provider(dir.path(), &server.endpoint).await;
    let before: String =
        sqlx::query_scalar("SELECT ciphertext FROM credentials WHERE account_id='a'")
            .fetch_one(&recovered.store.reads)
            .await
            .unwrap();
    assert_eq!(
        before, ciphertext,
        "a replacement must not have reached SQLite"
    );
    assert_eq!(
        recovered.load("a").await.unwrap().refresh_token.as_deref(),
        Some("initial-refresh")
    );
    let a = recovered.store.account("a").await.unwrap();

    let result = recovered.get_access_token(&a, false).await;

    if matches!(policy, Policy::StrictSingleUse) || !matches!(invalidate, Invalidation::None) {
        assert!(matches!(result, Err(Error::Reauth("token_revoked"))));
        assert_eq!(
            server.state.lock().await.used.len(),
            2,
            "invalid_grant must not loop"
        );
    } else {
        assert_eq!(result.unwrap().secret.expose_secret(), "access-2");
        let token = recovered
            .load("a")
            .await
            .unwrap()
            .refresh_token
            .clone()
            .unwrap();
        assert_eq!(
            token,
            if matches!(policy, Policy::GoogleReusable) {
                "initial-refresh"
            } else {
                "refresh-2"
            }
        );
        recovered.get_access_token(&a, true).await.unwrap();
        assert_eq!(
            server.state.lock().await.used,
            ["initial-refresh", "initial-refresh", token.as_str()]
        );
    }
}

#[tokio::test]
async fn google_reuses_persisted_token_after_response_before_save_process_crash() {
    crash_case(Policy::GoogleReusable, Invalidation::None).await;
}

#[tokio::test]
async fn microsoft_reuses_previous_token_after_rotation_before_save_process_crash() {
    crash_case(Policy::MicrosoftRetainsOld, Invalidation::None).await;
}

#[tokio::test]
async fn strict_single_use_provider_cannot_recover_a_lost_replacement() {
    crash_case(Policy::StrictSingleUse, Invalidation::None).await;
}

#[tokio::test]
async fn revoked_token_after_crash_requires_reauthorization_without_retry_loop() {
    crash_case(Policy::MicrosoftRetainsOld, Invalidation::Revoked).await;
}

#[tokio::test]
async fn provider_expiration_after_crash_requires_reauthorization_without_retry_loop() {
    crash_case(Policy::GoogleReusable, Invalidation::Expired).await;
}

#[tokio::test]
async fn lost_success_response_is_retryable_with_the_durable_token() {
    for (policy, kind) in [
        (Policy::GoogleReusable, AuthKind::GoogleOauth),
        (Policy::MicrosoftRetainsOld, AuthKind::MicrosoftOauth),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let server = Server::new(policy).await;
        let p = seed(dir.path(), &server, kind).await;
        let a = p.store.account("a").await.unwrap();
        server.state.lock().await.truncate_next = true;
        assert!(matches!(
            p.get_access_token(&a, false).await,
            Err(Error::Temporary)
        ));
        assert_eq!(server.state.lock().await.generation, 1);
        assert_eq!(
            p.load("a").await.unwrap().refresh_token.as_deref(),
            Some("initial-refresh")
        );
        assert_eq!(
            p.get_access_token(&a, false)
                .await
                .unwrap()
                .secret
                .expose_secret(),
            "access-2"
        );
        assert_eq!(
            server.state.lock().await.used,
            ["initial-refresh", "initial-refresh"]
        );
    }
}

#[tokio::test]
async fn reported_refresh_deadline_survives_rotation_and_restart_and_expires() {
    let dir = tempfile::tempdir().unwrap();
    let server = Server::new(Policy::MicrosoftRetainsOld).await;
    server.state.lock().await.refresh_lifetime = Some(120);
    let p = seed(dir.path(), &server, AuthKind::MicrosoftOauth).await;
    let a = p.store.account("a").await.unwrap();
    p.get_access_token(&a, false).await.unwrap();
    let deadline = p.load("a").await.unwrap().refresh_token_expires_at.unwrap();
    assert!((now() + 115..=now() + 120).contains(&deadline));
    server.state.lock().await.refresh_lifetime = None;
    p.get_access_token(&a, true).await.unwrap();
    assert_eq!(
        p.load("a").await.unwrap().refresh_token_expires_at,
        Some(deadline)
    );
    drop(p);
    let p = provider(dir.path(), &server.endpoint).await;
    let mut c = p.load("a").await.unwrap();
    assert_eq!(c.refresh_token_expires_at, Some(deadline));
    assert_eq!(
        sqlx::query_scalar::<_, Option<i64>>(
            "SELECT refresh_expires_at FROM credentials WHERE account_id='a'"
        )
        .fetch_one(&p.store.reads)
        .await
        .unwrap(),
        Some(deadline)
    );
    // A known deadline is independent of access-token expiry and is never extended
    // by rotation. Simulate passage beyond it, not a provider-specific guessed age.
    c.refresh_token_expires_at = Some(now() - 1);
    c.access_expires_at = Some(now() - 1);
    p.save("a", &c).await.unwrap();
    assert!(matches!(
        p.get_access_token(&a, false).await,
        Err(Error::Reauth("refresh_token_expired"))
    ));
    assert_eq!(
        server.state.lock().await.generation,
        2,
        "known-expired token must not be sent"
    );
}

#[tokio::test]
async fn new_consent_resets_deadline_but_missing_refresh_token_does_not() {
    let dir = tempfile::tempdir().unwrap();
    let server = Server::new(Policy::GoogleReusable).await;
    let p = seed(dir.path(), &server, AuthKind::GoogleOauth).await;
    let a = p.store.account("a").await.unwrap();
    let mut c = p.load("a").await.unwrap();
    c.refresh_token_expires_at = Some(1000);

    let response = |token: Option<&str>| {
        serde_json::from_value(serde_json::json!({"access_token":"access", "expires_in":3600,"scope":"https://mail.google.com/","refresh_token":token})).unwrap()
    };
    p.apply_response(&a, &mut c, response(None), false).unwrap();
    assert_eq!(c.refresh_token_expires_at, Some(1000));
    assert_eq!(c.refresh_token.as_deref(), Some("initial-refresh"));
    p.apply_response(&a, &mut c, response(Some("new-grant")), true)
        .unwrap();
    assert_eq!(c.refresh_token_expires_at, None);
}
