//! Shared test configuration and account fixtures.

#![allow(dead_code, clippy::unwrap_used)]
use epistle_core::{
    Config,
    config::{
        AuthConfig, DeliveryConfig, OAuthClientConfig, ServerConfig, StorageConfig, TestingConfig,
    },
};

pub fn config(path: &std::path::Path) -> Config {
    Config {
        server: ServerConfig {
            bind_addr: ([127, 0, 0, 1], 0).into(),
            api_key: "a".repeat(32),
            public_url: "http://localhost".into(),
        },
        storage: StorageConfig {
            data_dir: path.into(),
            disk_reserve_bytes: 0,
            ..Default::default()
        },
        delivery: DeliveryConfig {
            webhook_url: "http://127.0.0.1:1/webhook".into(),
            webhook_secret: "b".repeat(32),
            max_attempts: 3,
        },
        auth: AuthConfig {
            master_key: "01".repeat(32),
            google: OAuthClientConfig {
                client_id: "test-google".into(),
                client_secret: "test-secret".into(),
            },
            microsoft: OAuthClientConfig {
                client_id: "test-microsoft".into(),
                client_secret: "test-secret".into(),
            },
            ..Default::default()
        },
        testing: TestingConfig {
            allow_insecure_endpoints: true,
            ..Default::default()
        },
        ..Default::default()
    }
}

pub async fn account(
    store: &epistle_store::Store,
    kind: epistle_core::AuthKind,
) -> epistle_core::Account {
    let encoded = serde_json::to_string(&kind).unwrap();
    store
        .write(move |c| {
            Box::pin(async move {
                sqlx::query("INSERT INTO accounts(id,external_ref,auth_kind,email,config,status_since,created_at) VALUES('a','ref',?,'a@example.test','{}',0,0)")
                    .bind(encoded).execute(c).await?;

                Ok(())
            })
        })
        .await
        .unwrap();

    store.account("a").await.unwrap()
}
