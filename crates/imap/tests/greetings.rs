#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use epistle_core::{Account, AccountConfig, AuthKind};
use epistle_imap::Connection;
use std::time::Duration;
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::TcpListener,
    time::timeout,
};

fn account(port: u16) -> Account {
    Account {
        id: "greeting-test".into(),
        external_ref: "test".into(),
        auth_kind: AuthKind::GoogleOauth,
        email: "test@example.test".into(),
        config: AccountConfig {
            host: "127.0.0.1".into(),
            port,
            tls: false,
            ..Default::default()
        },
        status: "connecting".into(),
        status_reason: None,
        status_seq: 0,
        status_since: 0,
        consecutive_failures: 0,
        last_success_at: None,
        enabled: true,
        revision: 0,
    }
}

#[tokio::test]
async fn gmail_exchange_and_dovecot_greetings_precede_password_and_xoauth2() {
    for banner in [
        "* OK Gimap ready for requests from 127.0.0.1 test-id\r\n",
        "* OK The Microsoft Exchange IMAP4 service is ready.\r\n",
        "* OK [CAPABILITY IMAP4rev1 AUTH=XOAUTH2] Dovecot ready.\r\n",
    ] {
        for password in [false, true] {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let a = account(listener.local_addr().unwrap().port());
            let server = tokio::spawn(async move {
                let (mut socket, _) = listener.accept().await.unwrap();
                // An eager LOGIN/AUTHENTICATE before the delayed greeting is a failure.
                assert!(
                    timeout(Duration::from_millis(50), socket.read_u8())
                        .await
                        .is_err()
                );
                // Also exercise a fragmented greeting.
                let (head, tail) = banner.as_bytes().split_at_checked(5).unwrap();
                socket.write_all(head).await.unwrap();
                tokio::task::yield_now().await;
                socket.write_all(tail).await.unwrap();
                let mut io = BufReader::new(socket);
                let mut line = String::new();
                io.read_line(&mut line).await.unwrap();
                let tag = line.split_whitespace().next().unwrap().to_string();
                if password {
                    assert!(line.contains(" LOGIN "));
                } else {
                    assert!(line.contains(" AUTHENTICATE XOAUTH2"));
                    io.get_mut().write_all(b"+ \r\n").await.unwrap();
                    line.clear();
                    io.read_line(&mut line).await.unwrap();
                    assert!(!line.trim().is_empty());
                }
                io.get_mut()
                    .write_all(format!("{tag} OK authenticated\r\n").as_bytes())
                    .await
                    .unwrap();
                line.clear();
                io.read_line(&mut line).await.unwrap();
                assert!(line.contains(" CAPABILITY"));
                let tag = line.split_whitespace().next().unwrap();
                io.get_mut()
                    .write_all(
                        format!("* CAPABILITY IMAP4rev1 IDLE\r\n{tag} OK capabilities\r\n")
                            .as_bytes(),
                    )
                    .await
                    .unwrap();
                line.clear();
                io.read_line(&mut line).await.unwrap();
                assert!(line.contains(" LOGOUT"));
                let tag = line.split_whitespace().next().unwrap();
                io.get_mut()
                    .write_all(format!("* BYE logout\r\n{tag} OK logout\r\n").as_bytes())
                    .await
                    .unwrap();
            });
            let conn = Connection::connect(&a, "test-secret".into(), password, 2)
                .await
                .unwrap();
            assert!(conn.idle_supported);
            conn.logout().await;
            server.await.unwrap();
        }
    }
}

#[tokio::test]
async fn rejecting_or_unsupported_greeting_never_receives_credentials() {
    for (banner, reason) in [
        ("* BYE [UNAVAILABLE] test-secret\r\n", "provider_outage"),
        (
            "* PREAUTH authenticated tunnel\r\n",
            "preauthenticated_connection_unsupported",
        ),
        ("* BAD invalid server\r\n", "invalid_greeting"),
    ] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let a = account(listener.local_addr().unwrap().port());
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            socket.write_all(banner.as_bytes()).await.unwrap();
            let mut received = Vec::new();
            timeout(Duration::from_secs(2), socket.read_to_end(&mut received))
                .await
                .unwrap()
                .unwrap();
            assert!(received.is_empty());
        });
        let error = Connection::connect(&a, "test-secret".into(), false, 2)
            .await
            .err()
            .unwrap();
        assert_eq!(error.reason, reason);
        assert!(!error.auth);
        assert!(!error.to_string().contains("test-secret"));
        server.await.unwrap();
    }
}

#[tokio::test]
async fn missing_greeting_is_bounded_by_watchdog() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let a = account(listener.local_addr().unwrap().port());
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut received = Vec::new();
        socket.read_to_end(&mut received).await.unwrap();
        assert!(received.is_empty());
    });
    assert!(
        timeout(
            Duration::from_secs(2),
            Connection::connect(&a, "test-secret".into(), false, 1)
        )
        .await
        .unwrap()
        .is_err()
    );
    server.await.unwrap();
}
