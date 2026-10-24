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

#[tokio::test]
async fn login_outage_is_not_misclassified_as_revoked_credentials() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let a = account(listener.local_addr().unwrap().port());
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        socket.write_all(b"* OK ready\r\n").await.unwrap();
        let mut io = BufReader::new(socket);
        let mut line = String::new();
        io.read_line(&mut line).await.unwrap();
        let tag = line.split_whitespace().next().unwrap();
        io.get_mut()
            .write_all(format!("{tag} NO [UNAVAILABLE] maintenance\r\n").as_bytes())
            .await
            .unwrap();
    });
    let error = Connection::connect(&a, "secret".into(), true, 2)
        .await
        .err()
        .unwrap();
    assert_eq!(error.reason, "provider_outage");
    assert!(!error.auth && !error.permanent);
    server.await.unwrap();
}

#[tokio::test]
async fn epoch_fallback_checks_exact_message_id_before_store() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let a = account(listener.local_addr().unwrap().port());
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        socket.write_all(b"* OK ready\r\n").await.unwrap();
        let mut io = BufReader::new(socket);
        loop {
            let mut line = String::new();
            if io.read_line(&mut line).await.unwrap() == 0 {
                break;
            }
            let tag = line.split_whitespace().next().unwrap();
            let data = if line.contains(" CAPABILITY") {
                "* CAPABILITY IMAP4rev1\r\n"
            } else if line.contains(" SELECT ") {
                "* 2 EXISTS\r\n* OK [UIDVALIDITY 2] epoch\r\n"
            } else if line.contains("UID SEARCH HEADER") {
                "* SEARCH 7 8\r\n"
            } else if line.contains("UID FETCH 7,8 (UID ENVELOPE)") {
                "* 1 FETCH (UID 7 ENVELOPE (NIL NIL NIL NIL NIL NIL NIL NIL NIL \"prefix<target@example.test>suffix\"))\r\n* 2 FETCH (UID 8 ENVELOPE (NIL NIL NIL NIL NIL NIL NIL NIL NIL \"<target@example.test>\"))\r\n"
            } else if line.contains("UID SEARCH UID 8") {
                "* SEARCH 8\r\n"
            } else if line.contains("UID STORE") {
                assert!(
                    line.contains("UID STORE 8 "),
                    "must never modify substring candidate: {line}"
                );
                ""
            } else {
                assert!(line.contains(" LOGIN ") || line.contains(" LOGOUT"));
                ""
            };
            io.get_mut()
                .write_all(format!("{data}{tag} OK done\r\n").as_bytes())
                .await
                .unwrap();
        }
    });
    let mut conn = Connection::connect(&a, "secret".into(), true, 2)
        .await
        .unwrap();
    let pointer = epistle_core::Pointer {
        account_id: a.id.clone(),
        folder_id: "f".into(),
        folder: "INBOX".into(),
        uidvalidity: 1,
        uid: 7,
        rfc_message_id: Some("<target@example.test>".into()),
        gmail_id: None,
        thread_id: None,
        labels: vec![],
        flags: vec![],
        size: 1,
        internal_date: 0,
    };
    let resolved = conn.mark_read(&pointer, true).await.unwrap().unwrap();
    assert_eq!((resolved.uidvalidity, resolved.uid), (2, 8));
    drop(conn);
    server.await.unwrap();
}

#[tokio::test]
async fn rejected_commands_never_expose_partial_results_or_success() {
    for rejected in ["CAPABILITY", "LIST", "UID SEARCH", "UID FETCH", "UID STORE"] {
        for status in ["NO", "BAD"] {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let a = account(listener.local_addr().unwrap().port());
            let server = tokio::spawn(async move {
                let (mut socket, _) = listener.accept().await.unwrap();
                socket.write_all(b"* OK ready\r\n").await.unwrap();
                let mut io = BufReader::new(socket);
                loop {
                    let mut line = String::new();
                    if io.read_line(&mut line).await.unwrap() == 0 {
                        break;
                    }
                    let tag = line.split_whitespace().next().unwrap();
                    let command = line.split_once(' ').unwrap().1;
                    let partial = if command.starts_with("CAPABILITY") {
                        "* CAPABILITY IMAP4rev1\r\n"
                    } else if command.starts_with("LIST") {
                        "* LIST () \"/\" \"Sent\"\r\n"
                    } else if command.starts_with("UID SEARCH") {
                        "* SEARCH 1\r\n"
                    } else if command.starts_with("UID FETCH") {
                        "* 1 FETCH (UID 1 FLAGS (\\Seen))\r\n"
                    } else if command.starts_with("SELECT") {
                        "* 1 EXISTS\r\n* OK [UIDVALIDITY 1] epoch\r\n"
                    } else {
                        ""
                    };
                    let completion = if command.starts_with(rejected) {
                        status
                    } else {
                        "OK"
                    };
                    io.get_mut()
                        .write_all(
                            format!("{partial}{tag} {completion} [UNAVAILABLE] test failure\r\n")
                                .as_bytes(),
                        )
                        .await
                        .unwrap();
                }
            });
            let connection = Connection::connect(&a, "secret".into(), true, 2).await;
            if rejected == "CAPABILITY" {
                assert_eq!(connection.err().unwrap().reason, "provider_outage");
            } else {
                let mut conn = connection.unwrap();
                let error = match rejected {
                    "LIST" => conn.folders(&a).await.err(),
                    "UID SEARCH" => conn.search("ALL").await.err(),
                    "UID FETCH" => conn.metadata(&a, "f", "INBOX", 1, "1").await.err(),
                    "UID STORE" => {
                        let pointer = epistle_core::Pointer {
                            account_id: a.id.clone(),
                            folder_id: "f".into(),
                            folder: "INBOX".into(),
                            uidvalidity: 1,
                            uid: 1,
                            rfc_message_id: None,
                            gmail_id: None,
                            thread_id: None,
                            labels: vec![],
                            flags: vec![],
                            size: 1,
                            internal_date: 0,
                        };
                        conn.mark_read(&pointer, true).await.err()
                    }
                    _ => unreachable!(),
                };
                assert_eq!(
                    error.unwrap().reason,
                    "provider_outage",
                    "{rejected} {status}"
                );
            }
            server.await.unwrap();
        }
    }
}

#[tokio::test]
async fn metadata_ignores_unsolicited_uids_and_flag_only_updates() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let a = account(listener.local_addr().unwrap().port());
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        socket.write_all(b"* OK ready\r\n").await.unwrap();
        let mut io = BufReader::new(socket);
        loop {
            let mut line = String::new();
            if io.read_line(&mut line).await.unwrap() == 0 {
                break;
            }
            let tag = line.split_whitespace().next().unwrap();
            let data = if line.contains(" CAPABILITY") {
                "* CAPABILITY IMAP4rev1\r\n"
            } else if line.contains("UID FETCH") {
                "* 1 FETCH (UID 1 FLAGS (\\Seen))\r\n* 2 FETCH (UID 9 ENVELOPE (NIL NIL NIL NIL NIL NIL NIL NIL NIL \"<other@example.test>\"))\r\n* 1 FETCH (UID 1 FLAGS (\\Seen) RFC822.SIZE 10 INTERNALDATE \"24-Oct-2026 12:00:00 +0000\" ENVELOPE (NIL NIL NIL NIL NIL NIL NIL NIL NIL \"<target@example.test>\"))\r\n"
            } else {
                ""
            };
            io.get_mut()
                .write_all(format!("{data}{tag} OK done\r\n").as_bytes())
                .await
                .unwrap();
        }
    });
    let mut conn = Connection::connect(&a, "secret".into(), true, 2)
        .await
        .unwrap();
    let records = conn.metadata(&a, "f", "INBOX", 1, "1").await.unwrap();
    assert_eq!(records.len(), 1);
    let record = records.first().unwrap();
    assert_eq!(record.uid, 1);
    assert_eq!(
        record.rfc_message_id.as_deref(),
        Some("<target@example.test>")
    );
    assert_eq!(record.flags, ["\\Seen"]);
    drop(conn);
    server.await.unwrap();
}
