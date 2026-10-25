//! MIME parsing and file extraction with raw-message fallback.

use epistle_core::{Message, Pointer};
use epistle_delivery::FileDraft;
use serde_json::json;

/// Parses an email, retaining raw bytes when MIME decoding fails.
pub fn parse_message(
    id: String,
    p: &Pointer,
    raw: Vec<u8>,
    origin: String,
    backfill_id: Option<String>,
    cap: usize,
) -> (Message, Vec<FileDraft>) {
    let mut result = Message {
        id,
        account_id: p.account_id.clone(),
        origin,
        backfill_id,
        envelope: json!({}),
        headers: json!([]),
        flags: p.flags.clone(),
        thread_id: p.thread_id.clone(),
        labels: p.labels.clone(),
        text: None,
        html: None,
        parse_error: false,
        files: vec![],
    };

    let mut files = vec![];

    if let Some(parsed) = mail_parser::MessageParser::default().parse(&raw) {
        result.envelope = envelope(&parsed, p.internal_date);
        result.headers = headers(&parsed);
        result.parse_error = parsed.parts().any(|part| part.has_problems());

        extract_bodies(&parsed, &mut result, &mut files, cap);
        extract_attachments(&parsed, &mut files);
    } else {
        result.parse_error = true;
    }

    files.push(FileDraft {
        role: "raw".into(),
        filename: "message.eml".into(),
        content_type: "message/rfc822".into(),
        content_id: None,
        content_disposition: None,
        content_description: None,
        content_location: None,
        bytes: raw,
    });
    (result, files)
}

// Adapted from Hark: retain address groups and resent/threading envelopes.
fn addresses(list: Option<mail_parser::AddressList<'_>>) -> serde_json::Value {
    let addresses = list.map(|list| {
        list.iter()
            .map(|item| match item {
                mail_parser::Address::Mailbox(mailbox) => json!({
                    "name": mailbox.name(),
                    "address": mailbox.address(),
                }),
                mail_parser::Address::Group(group) => json!({
                    "name": group.name(),
                    "members": group.mailboxes().map(|mailbox| json!({
                        "name": mailbox.name(),
                        "address": mailbox.address(),
                    })).collect::<Vec<_>>(),
                }),
            })
            .collect::<Vec<_>>()
    });

    json!(addresses.unwrap_or_default())
}

fn envelope(message: &mail_parser::Message<'_>, received_at: i64) -> serde_json::Value {
    json!({
        "subject": message.subject(),
        "sender": addresses(message.sender()),
        "from": addresses(message.from()),
        "to": addresses(message.to()),
        "cc": addresses(message.cc()),
        "bcc": addresses(message.bcc()),
        "reply_to": addresses(message.reply_to()),
        "message_id": message.message_id(),
        "in_reply_to": message.in_reply_to().map(|v| v.iter().collect::<Vec<_>>()),
        "references": message.references().map(|v| v.iter().collect::<Vec<_>>()),
        "resent": resent_envelope(message),
        "date": message.date().map(|d| d.to_rfc3339()),
        "received_at": received_at,
    })
}

fn resent_envelope(message: &mail_parser::Message<'_>) -> serde_json::Value {
    let present = message.resent_from().is_some()
        || message.resent_to().is_some()
        || message.resent_message_id().is_some()
        || message.resent_date().is_some();

    if !present {
        return serde_json::Value::Null;
    }

    json!({
        "from": addresses(message.resent_from()),
        "to": addresses(message.resent_to()),
        "cc": addresses(message.resent_cc()),
        "bcc": addresses(message.resent_bcc()),
        "sender": addresses(message.resent_sender()),
        "date": message.resent_date().map(|d| d.to_rfc3339()),
        "message_id": message.resent_message_id().map(|v| v.iter().collect::<Vec<_>>()),
    })
}

fn headers(message: &mail_parser::Message<'_>) -> serde_json::Value {
    json!(
        message
            .headers()
            .iter()
            .map(|header| json!({
                "name": header.raw_name(),
                "value": String::from_utf8_lossy(header.raw_value()),
            }))
            .collect::<Vec<_>>()
    )
}

fn extract_bodies(
    parsed: &mail_parser::Message<'_>,
    message: &mut Message,
    files: &mut Vec<FileDraft>,
    cap: usize,
) {
    for (role, body, mime, name) in [
        (
            "text",
            join_bodies(parsed.text_bodies()),
            "text/plain; charset=utf-8",
            "body.txt",
        ),
        (
            "html",
            join_bodies(parsed.html_bodies()),
            "text/html; charset=utf-8",
            "body.html",
        ),
    ] {
        let Some(body) = body else { continue };

        if body.len() > cap {
            files.push(FileDraft {
                role: role.into(),
                filename: name.into(),
                content_type: mime.into(),
                content_id: None,
                content_disposition: None,
                content_description: None,
                content_location: None,
                bytes: body.as_bytes().to_vec(),
            });
        } else if role == "text" {
            message.text = Some(body);
        } else {
            message.html = Some(body);
        }
    }
}

fn extract_attachments(message: &mail_parser::Message<'_>, files: &mut Vec<FileDraft>) {
    for part in message.attachments() {
        let content_type = part
            .content_type()
            .map(|c| format!("{}/{}", c.ctype(), c.subtype().unwrap_or("octet-stream")))
            .unwrap_or_else(|| "application/octet-stream".into());

        files.push(FileDraft {
            role: if part.is_inline() {
                "inline"
            } else {
                "attachment"
            }
            .into(),
            filename: part.attachment_name().unwrap_or("attachment").into(),
            content_type,
            content_id: part.content_id().map(str::to_owned),
            content_disposition: part.content_disposition().map(|d| d.ctype().to_owned()),
            content_description: part.content_description().map(str::to_owned),
            content_location: part.content_location().map(str::to_owned),
            bytes: part.decoded().into_owned(),
        });
    }
}

fn join_bodies<'a>(bodies: impl Iterator<Item = std::borrow::Cow<'a, str>>) -> Option<String> {
    let parts: Vec<_> = bodies.collect();

    if parts.is_empty() {
        None
    } else {
        Some(parts.join("\n"))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    fn pointer() -> Pointer {
        Pointer {
            account_id: "a".into(),
            folder_id: "f".into(),
            folder: "INBOX".into(),
            uidvalidity: 1,
            uid: 1,
            rfc_message_id: None,
            gmail_id: None,
            thread_id: None,
            labels: vec![],
            flags: vec![],
            size: 0,
            internal_date: 100,
        }
    }

    #[test]
    fn mime_attachments_and_oversized_body_have_manifests_not_inline_bytes() {
        let raw = b"From: Sender <s@example.test>\r\nTo: t@example.test\r\nSubject: Test\r\nMessage-ID: <test@example.test>\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=abc\r\n\r\n--abc\r\nContent-Type: text/plain\r\n\r\nhello world\r\n--abc\r\nContent-Type: application/octet-stream\r\nContent-Disposition: attachment; filename=test.bin\r\nContent-Transfer-Encoding: base64\r\n\r\nAQID\r\n--abc--\r\n";
        let (message, files) =
            parse_message("m".into(), &pointer(), raw.to_vec(), "live".into(), None, 4);

        assert_eq!(
            message.envelope.get("subject").and_then(|x| x.as_str()),
            Some("Test")
        );
        assert!(message.text.is_none());

        assert!(
            files
                .iter()
                .any(|f| f.role == "text" && f.bytes.starts_with(b"hello"))
        );

        assert!(
            files
                .iter()
                .any(|f| f.role == "attachment" && f.bytes == [1, 2, 3])
        );

        assert!(files.iter().any(|f| f.role == "raw" && f.bytes == raw));
    }

    #[test]
    fn unparseable_mail_still_delivers_raw() {
        let (message, files) =
            parse_message("m".into(), &pointer(), vec![], "live".into(), None, 256);

        assert!(message.parse_error);
        assert_eq!(files.len(), 1);
    }
}

#[cfg(test)]
mod hark_regressions {
    use super::*;
    #[test]
    fn groups_resent_threading_and_all_body_parts_survive() {
        let raw = b"From: Sender <s@example.test>\r\nSender: sender@example.test\r\nTo: Team: Alice <a@example.test>, Bob <b@example.test>;\r\nResent-From: relay@example.test\r\nResent-To: destination@example.test\r\nResent-Message-ID: <resent@example.test>\r\nIn-Reply-To: <parent@example.test>\r\nReferences: <root@example.test> <parent@example.test>\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=x\r\n\r\n--x\r\nContent-Type: text/plain\r\n\r\nfirst part\r\n--x\r\nContent-Type: text/plain\r\n\r\nsecond part\r\n--x--\r\n";
        let p = Pointer {
            account_id: "a".into(),
            folder_id: "f".into(),
            folder: "INBOX".into(),
            uidvalidity: 1,
            uid: 1,
            rfc_message_id: None,
            gmail_id: None,
            thread_id: None,
            labels: vec![],
            flags: vec![],
            size: 0,
            internal_date: 100,
        };

        let (message, _) = parse_message("m".into(), &p, raw.to_vec(), "live".into(), None, 1000);

        assert_eq!(
            message
                .envelope
                .pointer("/to/0/members/1/address")
                .and_then(|v| v.as_str()),
            Some("b@example.test")
        );

        assert_eq!(
            message
                .envelope
                .pointer("/resent/from/0/address")
                .and_then(|v| v.as_str()),
            Some("relay@example.test")
        );

        assert_eq!(
            message
                .envelope
                .pointer("/in_reply_to/0")
                .and_then(|v| v.as_str()),
            Some("parent@example.test")
        );

        assert!(
            message
                .text
                .as_ref()
                .is_some_and(|s| s.contains("first part") && s.contains("second part"))
        );
    }
}
