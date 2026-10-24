//! Shared test configuration and account fixtures.

#![allow(dead_code, clippy::unwrap_used)]
use epistle_core::Config;

pub fn config(path: &std::path::Path) -> Config {
    serde_json::from_value(serde_json::json!({
  "data_dir":path,"bind_addr":"127.0.0.1:0","api_key":"a".repeat(32),"master_key":"01".repeat(32),"webhook_url":"http://127.0.0.1:1/webhook","webhook_secret":"b".repeat(32),"public_url":"http://localhost",
  "file_retention_secs":7200,"inline_body_cap":262144,"index_retention_secs":2592000,"reconcile_secs":180,"watchdog_secs":60,"fetch_batch_count":50,"fetch_batch_bytes":26214400,"max_attempts":3,"allow_insecure_test_endpoints":true,"disk_reserve_bytes":0,"reauth_reminder_secs":0,
  "google_client_id":"test-google","google_client_secret":"test-secret","microsoft_client_id":"test-microsoft","microsoft_client_secret":"test-secret","token_endpoint_override":null
 })).unwrap()
}

pub async fn account(
    store: &epistle_store::Store,
    kind: epistle_core::AuthKind,
) -> epistle_core::Account {
    let encoded = serde_json::to_string(&kind).unwrap();
    store
        .write(move |c| {
            Box::pin(async move {
                sqlx::query("INSERT INTO accounts(id,external_ref,auth_kind,email,config,status_since,created_at) VALUES('a','ref',?,'a@example.test','{}',0,0)").bind(encoded).execute(c).await?;
                Ok(())
            })
        })
        .await
        .unwrap();
    store.account("a").await.unwrap()
}
