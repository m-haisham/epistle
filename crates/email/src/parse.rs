use epistle_core::{Message, Pointer};
use epistle_delivery::FileDraft;
use serde_json::json;

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
    if let Some(m) = mail_parser::MessageParser::default().parse(&raw) {
        fn addresses(list: Option<mail_parser::AddressList<'_>>) -> serde_json::Value {
            json!(
                list.map(|a| a
                    .iter()
                    .filter_map(|item| match item {
                        mail_parser::Address::Mailbox(m) =>
                            Some(json!({"name":m.name(),"address":m.address()})),
                        mail_parser::Address::Group(_) => None,
                    })
                    .collect::<Vec<_>>())
                    .unwrap_or_default()
            )
        }
        result.envelope = json!({"subject":m.subject(),"from":addresses(m.from()),"to":addresses(m.to()),"cc":addresses(m.cc()),"bcc":addresses(m.bcc()),"reply_to":addresses(m.reply_to()),"message_id":m.message_id(),"date":m.date().map(|d|d.to_rfc3339()),"received_at":p.internal_date});
        result.headers = json!(
            m.headers()
                .iter()
                .map(
                    |h| json!({"name":h.raw_name(),"value":String::from_utf8_lossy(h.raw_value())})
                )
                .collect::<Vec<_>>()
        );
        result.parse_error = m.parts().any(|part| part.has_problems());
        for (role, body, mime, name) in [
            (
                "text",
                m.body_text(0),
                "text/plain; charset=utf-8",
                "body.txt",
            ),
            (
                "html",
                m.body_html(0),
                "text/html; charset=utf-8",
                "body.html",
            ),
        ] {
            if let Some(body) = body {
                if body.len() > cap {
                    files.push(FileDraft {
                        role: role.into(),
                        filename: name.into(),
                        content_type: mime.into(),
                        content_id: None,
                        bytes: body.as_bytes().to_vec(),
                    });
                } else if role == "text" {
                    result.text = Some(body.into_owned());
                } else {
                    result.html = Some(body.into_owned());
                }
            }
        }
        for part in m.attachments() {
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
                bytes: part.decoded().into_owned(),
            });
        }
    } else {
        result.parse_error = true;
    }
    files.push(FileDraft {
        role: "raw".into(),
        filename: "message.eml".into(),
        content_type: "message/rfc822".into(),
        content_id: None,
        bytes: raw,
    });
    (result, files)
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
        let raw=b"From: Sender <s@example.test>\r\nTo: t@example.test\r\nSubject: Test\r\nMessage-ID: <test@example.test>\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=abc\r\n\r\n--abc\r\nContent-Type: text/plain\r\n\r\nhello world\r\n--abc\r\nContent-Type: application/octet-stream\r\nContent-Disposition: attachment; filename=test.bin\r\nContent-Transfer-Encoding: base64\r\n\r\nAQID\r\n--abc--\r\n";
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
