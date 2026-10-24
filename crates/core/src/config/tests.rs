//! Configuration layering and migration regressions.

#![allow(clippy::unwrap_used, clippy::expect_used)]
use super::*;

fn secrets() -> HashMap<String, String> {
    HashMap::from([
        ("EPISTLE_SERVER__API_KEY".into(), "a".repeat(32)),
        ("EPISTLE_AUTH__MASTER_KEY".into(), "01".repeat(32)),
        ("EPISTLE_DELIVERY__WEBHOOK_SECRET".into(), "b".repeat(32)),
        (
            "EPISTLE_DELIVERY__WEBHOOK_URL".into(),
            "https://app.example.test/webhook".into(),
        ),
    ])
}

fn load(file: &str, environment: HashMap<String, String>) -> Result<Config, Error> {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("epistle.toml");
    std::fs::write(&path, file).unwrap();
    Config::from_sources(&path, environment)
}

#[test]
fn optional_file_keeps_existing_defaults() {
    let dir = tempfile::tempdir().unwrap();
    let config = Config::from_sources(&dir.path().join("missing.toml"), secrets()).unwrap();
    assert_eq!(config.server.bind_addr.to_string(), "127.0.0.1:8080");
    assert_eq!(config.storage.file_retention_secs, 7200);
    assert_eq!(config.storage.index_retention_secs, 2_592_000);
    assert_eq!(config.mail.fetch.batch_count, 50);
    assert_eq!(config.mail.fetch.batch_bytes, 26_214_400);
    assert_eq!(config.delivery.max_attempts, 12);
    assert!(!config.testing.allow_insecure_endpoints);
    assert!(config.testing.token_endpoint_override.is_none());
}

#[test]
fn example_loads_nested_tables_and_provider_environment() {
    let mut env = secrets();
    env.insert("EPISTLE_AUTH__GOOGLE__CLIENT_ID".into(), "google".into());
    env.insert(
        "EPISTLE_AUTH__MICROSOFT__CLIENT_SECRET".into(),
        "microsoft-secret".into(),
    );
    let config = load(include_str!("../../../../epistle.example.toml"), env).unwrap();
    assert_eq!(config.server.public_url, "https://email.example.com");
    assert_eq!(config.auth.google.client_id, "google");
    assert_eq!(config.auth.microsoft.client_secret, "microsoft-secret");
    assert_eq!(config.mail.inline_body_cap, 262_144);
}

#[test]
fn environment_overrides_file_by_leaf_and_nested_names_win_legacy_names() {
    let file = r#"
        reconcile_secs = 15
        [mail]
        reconcile_secs = 25
        watchdog_secs = 7
        [mail.fetch]
        batch_bytes = 4096
    "#;
    assert_eq!(load(file, secrets()).unwrap().mail.reconcile_secs, 25);
    let mut env = secrets();
    env.insert("RECONCILE_SECS".into(), "35".into());
    assert_eq!(load(file, env.clone()).unwrap().mail.reconcile_secs, 35);
    env.insert("EPISTLE_MAIL__RECONCILE_SECS".into(), "45".into());
    env.insert("EPISTLE_MAIL__FETCH__BATCH_COUNT".into(), "2".into());
    let config = load(file, env).unwrap();
    assert_eq!(config.mail.reconcile_secs, 45);
    assert_eq!(config.mail.watchdog_secs, 7);
    assert_eq!(config.mail.fetch.batch_count, 2);
    assert_eq!(config.mail.fetch.batch_bytes, 4096);
}

#[test]
fn legacy_flat_file_and_environment_remain_compatible() {
    let file = r#"
        data_dir = "/tmp/epistle-legacy"
        bind_addr = "127.0.0.1:9000"
        public_url = "https://legacy.example"
        file_retention_secs = 60
        index_retention_secs = 3600
        inline_body_cap = 100
        fetch_batch_count = 2
        fetch_batch_bytes = 500
        max_attempts = 3
        disk_reserve_bytes = 0
        reauth_reminder_secs = 120
        google_client_id = "legacy-google"
        microsoft_client_id = "legacy-microsoft"
    "#;
    let env = HashMap::from([
        ("API_KEY".into(), "a".repeat(32)),
        ("MASTER_KEY".into(), "01".repeat(32)),
        ("WEBHOOK_SECRET".into(), "b".repeat(32)),
        ("WEBHOOK_URL".into(), "http://127.0.0.1:8090/webhook".into()),
        ("ALLOW_INSECURE_TEST_ENDPOINTS".into(), "true".into()),
        (
            "TOKEN_ENDPOINT_OVERRIDE".into(),
            "http://127.0.0.1:8090/token".into(),
        ),
        ("WATCHDOG_SECS".into(), "5".into()),
        ("GOOGLE_CLIENT_SECRET".into(), "old-google-secret".into()),
        (
            "MICROSOFT_CLIENT_SECRET".into(),
            "old-microsoft-secret".into(),
        ),
    ]);
    let config = load(file, env).unwrap();
    assert_eq!(config.storage.data_dir, Path::new("/tmp/epistle-legacy"));
    assert_eq!(config.server.bind_addr.port(), 9000);
    assert_eq!(config.server.public_url, "https://legacy.example");
    assert_eq!(config.storage.file_retention_secs, 60);
    assert_eq!(config.storage.index_retention_secs, 3600);
    assert_eq!(config.storage.disk_reserve_bytes, 0);
    assert_eq!(config.mail.inline_body_cap, 100);
    assert_eq!(config.mail.fetch.batch_count, 2);
    assert_eq!(config.mail.fetch.batch_bytes, 500);
    assert_eq!(config.mail.watchdog_secs, 5);
    assert_eq!(config.delivery.max_attempts, 3);
    assert_eq!(config.auth.reauth_reminder_secs, 120);
    assert_eq!(config.auth.google.client_id, "legacy-google");
    assert_eq!(config.auth.microsoft.client_id, "legacy-microsoft");
    assert_eq!(config.auth.google.client_secret, "old-google-secret");
    assert_eq!(config.auth.microsoft.client_secret, "old-microsoft-secret");
    assert!(config.testing.allow_insecure_endpoints);
    assert!(config.testing.token_endpoint_override.is_some());
}

#[test]
fn environment_preserves_digit_only_secrets_and_ignores_unrelated_variables() {
    let mut env = secrets();
    let secret = "0000123456789012345678901234567890";
    for key in [
        "EPISTLE_SERVER__API_KEY",
        "EPISTLE_DELIVERY__WEBHOOK_SECRET",
        "EPISTLE_AUTH__GOOGLE__CLIENT_SECRET",
    ] {
        env.insert(key.into(), secret.into());
    }
    env.insert("EPISTLE_AUTH__MASTER_KEY".into(), "0".repeat(64));
    env.insert("EPISTLE_MAIL__FETCH__BATCH_COUNT".into(), "3".into());
    env.insert("PATH".into(), "/unrelated/path".into());
    env.insert("SERVER__API_KEY".into(), "not-an-epistle-setting".into());
    let config = load("", env).unwrap();
    assert_eq!(config.server.api_key, secret);
    assert_eq!(config.delivery.webhook_secret, secret);
    assert_eq!(config.auth.google.client_secret, secret);
    assert_eq!(config.auth.master_key, "0".repeat(64));
    assert_eq!(config.mail.fetch.batch_count, 3);
}

#[test]
fn typos_bad_types_and_validation_fail_without_echoing_values() {
    let invalid_files = [
        "[mail.fetch]\nbatch_count = 0",
        "[mail]\nwatchdog_secs = 0",
        "[storage]\nfile_retention_secs = -1",
        "[delivery]\nmax_attempts = 0",
        "[mail.fetch]\nbatch_cout = 2",
        "[unknown]\nkey = 1",
        "server = false\nbind_addr = '127.0.0.1:9000'",
    ];
    for file in invalid_files {
        assert!(load(file, secrets()).is_err(), "accepted: {file}");
    }
    let mut env = secrets();
    env.insert(
        "EPISTLE_MAIL__WATCHDOG_SECS".into(),
        "private-invalid-value".into(),
    );
    let error = load("", env).err().unwrap().to_string();
    assert!(!error.contains("private-invalid-value"));
    let mut env = secrets();
    env.insert("EPISTLE_AUTH__MASTER_KEY".into(), "z".repeat(64));
    assert!(load("", env).is_err());
    let mut env = secrets();
    env.insert("EPISTLE_MAIL__WATCHDOG_SEC".into(), "3".into());
    assert!(load("", env).is_err());
}

#[test]
fn test_endpoints_require_explicit_opt_in() {
    let mut env = secrets();
    env.insert(
        "EPISTLE_DELIVERY__WEBHOOK_URL".into(),
        "http://localhost/webhook".into(),
    );
    assert!(load("", env.clone()).is_err());
    env.insert(
        "EPISTLE_TESTING__ALLOW_INSECURE_ENDPOINTS".into(),
        "true".into(),
    );
    assert!(load("", env).is_ok());
    let mut env = secrets();
    env.insert(
        "EPISTLE_TESTING__TOKEN_ENDPOINT_OVERRIDE".into(),
        "http://localhost/token".into(),
    );
    assert!(load("", env).is_err());
}
