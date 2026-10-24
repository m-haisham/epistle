//! Provider exchange, encryption and token lifecycle regressions.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#[path = "../../../tests/support/mod.rs"]
mod support;
use axum::{Json, extract::State};
use epistle_auth::{Credentials, Error, TokenProvider};
use epistle_core::AuthKind;
use epistle_store::Store;
use secrecy::ExposeSecret;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

async fn fixture(
    kind: AuthKind,
) -> (
    tempfile::TempDir,
    TokenProvider,
    epistle_core::Account,
    Arc<AtomicUsize>,
    tokio::task::JoinHandle<()>,
) {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&dir.path().join("test.sqlite")).await.unwrap();
    let a = support::account(&store, kind).await;
    let calls = Arc::new(AtomicUsize::new(0));
    async fn token(
        State(calls): State<Arc<AtomicUsize>>,
        axum::Form(form): axum::Form<std::collections::HashMap<String, String>>,
    ) -> Json<serde_json::Value> {
        let scope = if let Some(assertion) = form.get("assertion") {
            let key = jsonwebtoken::DecodingKey::from_rsa_pem(include_bytes!(
                "../../../tests/fixtures/service-account-test.pub.pem"
            ))
            .unwrap();
            let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
            validation.validate_aud = false;
            let claims = jsonwebtoken::decode::<serde_json::Value>(assertion, &key, &validation)
                .unwrap()
                .claims;
            assert_eq!(
                claims.get("sub").and_then(|v| v.as_str()),
                Some("a@example.test")
            );
            assert_eq!(
                claims.get("iss").and_then(|v| v.as_str()),
                Some("test-service@example.test")
            );
            assert_eq!(
                claims.get("scope").and_then(|v| v.as_str()),
                Some("https://mail.google.com/")
            );
            "https://mail.google.com/"
        } else {
            "https://outlook.office.com/IMAP.AccessAsUser.All offline_access"
        };
        let n = calls.fetch_add(1, Ordering::SeqCst) + 1;
        if form.get("code").is_some_and(|c| c == "hold-until-disable") {
            while calls.load(Ordering::SeqCst) < 100 {
                tokio::task::yield_now().await;
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(30)).await;
        Json(
            serde_json::json!({"access_token":format!("access-{n}"),"refresh_token":format!("refresh-{n}"),"expires_in":3600,"scope":scope}),
        )
    }
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}/token", listener.local_addr().unwrap());
    let app = axum::Router::new()
        .route("/token", axum::routing::post(token))
        .with_state(calls.clone());
    let task = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let mut config = support::config(dir.path());
    config.testing.token_endpoint_override = Some(endpoint);
    let provider = TokenProvider::new(store, Arc::new(config)).unwrap();
    provider
        .save(
            "a",
            &Credentials {
                refresh_token: Some("initial".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    (dir, provider, a, calls, task)
}

#[tokio::test]
async fn concurrent_refresh_is_single_flight_and_rotation_is_durable() {
    let (_dir, provider, a, calls, task) = fixture(AuthKind::MicrosoftOauth).await;
    let mut joins = tokio::task::JoinSet::new();
    for _ in 0..20 {
        let p = provider.clone();
        let a = a.clone();
        joins.spawn(async move { p.get_access_token(&a, false).await.unwrap() });
    }
    while let Some(result) = joins.join_next().await {
        assert_eq!(result.unwrap().secret.expose_secret(), "access-1");
    }
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        provider.load("a").await.unwrap().refresh_token.as_deref(),
        Some("refresh-1")
    );
    let mut c = provider.load("a").await.unwrap();
    c.access_expires_at = Some(1);
    provider.save("a", &c).await.unwrap();
    assert_eq!(
        provider
            .get_access_token(&a, false)
            .await
            .unwrap()
            .secret
            .expose_secret(),
        "access-2"
    );
    assert_eq!(
        provider.load("a").await.unwrap().refresh_token.as_deref(),
        Some("refresh-2")
    );
    task.abort();
}

#[tokio::test]
async fn pkce_signed_state_is_single_use_and_revision_bound() {
    let (_dir, provider, a, _calls, task) = fixture(AuthKind::MicrosoftOauth).await;
    let url = url::Url::parse(&provider.authorization_url(&a).await.unwrap()).unwrap();
    let params: std::collections::HashMap<_, _> = url.query_pairs().into_owned().collect();
    assert_eq!(
        params.get("code_challenge_method").map(String::as_str),
        Some("S256")
    );
    assert!(params.get("code_challenge").is_some_and(|v| v.len() == 43));
    let state = params.get("state").unwrap();
    assert!(matches!(
        provider.callback(&format!("{state}x"), "code").await,
        Err(Error::State)
    ));
    provider.callback(state, "code").await.unwrap();
    assert!(matches!(
        provider.callback(state, "code").await,
        Err(Error::State)
    ));
    let a = provider.store.account("a").await.unwrap();
    let url = url::Url::parse(&provider.authorization_url(&a).await.unwrap()).unwrap();
    let state = url
        .query_pairs()
        .find(|(k, _)| k == "state")
        .unwrap()
        .1
        .into_owned();
    provider
        .store
        .write(|c| {
            Box::pin(async move {
                sqlx::query("UPDATE accounts SET revision=revision+1 WHERE id='a'")
                    .execute(c)
                    .await?;
                Ok(())
            })
        })
        .await
        .unwrap();
    assert!(matches!(
        provider.callback(&state, "code").await,
        Err(Error::State)
    ));
    task.abort();
}

#[tokio::test]
async fn service_account_assertion_is_signed_and_delegates_mailbox() {
    let (_dir, provider, a, calls, task) = fixture(AuthKind::GoogleServiceAccount).await;
    provider
        .save(
            "a",
            &Credentials {
                client_email: Some("test-service@example.test".into()),
                private_key: Some(
                    include_str!("../../../tests/fixtures/service-account-test.pem").into(),
                ),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(
        provider
            .get_access_token(&a, false)
            .await
            .unwrap()
            .secret
            .expose_secret(),
        "access-1"
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    task.abort();
}

#[tokio::test]
async fn callback_activation_and_credentials_roll_back_together() {
    let (_dir, provider, a, _calls, task) = fixture(AuthKind::MicrosoftOauth).await;
    provider
        .store
        .status("a", "needs_reauth", Some("consent_required"), 0)
        .await
        .unwrap();
    let url = url::Url::parse(&provider.authorization_url(&a).await.unwrap()).unwrap();
    let state = url
        .query_pairs()
        .find(|(k, _)| k == "state")
        .unwrap()
        .1
        .into_owned();
    provider
        .store
        .write(|c| {
            Box::pin(async move {
                sqlx::query("CREATE TRIGGER fail_activation BEFORE INSERT ON connection_events BEGIN SELECT RAISE(ABORT,'injected activation crash'); END").execute(c).await?;
                Ok(())
            })
        })
        .await
        .unwrap();
    assert!(provider.callback(&state, "code").await.is_err());
    assert_eq!(
        provider.load("a").await.unwrap().refresh_token.as_deref(),
        Some("initial")
    );
    assert_eq!(
        provider.store.account("a").await.unwrap().status,
        "needs_reauth"
    );
    provider
        .store
        .write(|c| {
            Box::pin(async move {
                sqlx::query("DROP TRIGGER fail_activation")
                    .execute(c)
                    .await?;
                Ok(())
            })
        })
        .await
        .unwrap();
    // Authorization codes are single-use: a failed callback gets a fresh consent flow.
    let url = url::Url::parse(&provider.authorization_url(&a).await.unwrap()).unwrap();
    let state = url
        .query_pairs()
        .find(|(k, _)| k == "state")
        .unwrap()
        .1
        .into_owned();
    provider.callback(&state, "new-code").await.unwrap();
    assert_eq!(
        provider.store.account("a").await.unwrap().status,
        "connecting"
    );
    assert_eq!(
        provider.load("a").await.unwrap().refresh_token.as_deref(),
        Some("refresh-2")
    );
    task.abort();
}

#[tokio::test]
async fn disabling_during_code_exchange_fences_callback_commit() {
    let (_dir, provider, a, calls, task) = fixture(AuthKind::MicrosoftOauth).await;
    let url = url::Url::parse(&provider.authorization_url(&a).await.unwrap()).unwrap();
    let state = url
        .query_pairs()
        .find(|(k, _)| k == "state")
        .unwrap()
        .1
        .into_owned();
    let p = provider.clone();
    let callback = tokio::spawn(async move { p.callback(&state, "hold-until-disable").await });
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while calls.load(Ordering::SeqCst) == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    provider
        .store
        .write(|c| {
            Box::pin(async move {
                sqlx::query("UPDATE accounts SET enabled=0,revision=revision+1 WHERE id='a'")
                    .execute(&mut *c)
                    .await?;
                epistle_store::status_tx(c, "a", "disabled", None, 0).await
            })
        })
        .await
        .unwrap();
    calls.store(100, Ordering::SeqCst);
    assert!(matches!(callback.await.unwrap(), Err(Error::State)));
    assert_eq!(
        provider.store.account("a").await.unwrap().status,
        "disabled"
    );
    assert_eq!(
        provider.load("a").await.unwrap().refresh_token.as_deref(),
        Some("initial")
    );
    task.abort();
}
