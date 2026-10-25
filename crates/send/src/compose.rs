//! Validated MIME construction with immutable envelope and message bytes.

use crate::Error;
use base64::{Engine, engine::general_purpose::STANDARD};
use lettre::{
    Message,
    message::{Attachment as MimeAttachment, Mailbox, MultiPart, SinglePart, header::ContentType},
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Outbound message; the sender is always the selected account.
#[derive(Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SendRequest {
    pub idempotency_key: String,
    #[serde(default)]
    pub to: Vec<String>,
    #[serde(default)]
    pub cc: Vec<String>,
    #[serde(default)]
    pub bcc: Vec<String>,
    pub subject: String,
    pub text: Option<String>,
    pub html: Option<String>,
    pub reply_to: Option<String>,
    pub in_reply_to: Option<String>,
    #[serde(default)]
    pub references: Vec<String>,
    #[serde(default)]
    pub attachments: Vec<Attachment>,
}

/// A base64 attachment; content is decoded before MIME transfer encoding.
#[derive(Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Attachment {
    pub filename: String,
    pub content_type: String,
    pub content_base64: String,
}

#[derive(Serialize, Deserialize)]
pub(crate) struct Envelope {
    pub from: String,
    pub to: Vec<String>,
}

pub(crate) struct Prepared {
    pub message_id: String,
    pub envelope: String,
    pub message: Vec<u8>,
}

impl SendRequest {
    pub(crate) fn prepare(&self, from: &str, limit: usize) -> Result<Prepared, Error> {
        self.validate()?;

        let sender = mailbox(from)?;
        let message_id = format!("{}@{}", epistle_core::id(), sender.email.domain());
        let mut builder = Message::builder()
            .from(sender)
            .message_id(Some(message_id.clone()))
            .subject(&self.subject);

        for to in &self.to {
            builder = builder.to(mailbox(to)?);
        }

        for cc in &self.cc {
            builder = builder.cc(mailbox(cc)?);
        }

        for bcc in &self.bcc {
            builder = builder.bcc(mailbox(bcc)?);
        }

        if let Some(reply_to) = &self.reply_to {
            builder = builder.reply_to(mailbox(reply_to)?);
        }

        if let Some(in_reply_to) = &self.in_reply_to {
            validate_message_id(in_reply_to)?;
            builder = builder.in_reply_to(in_reply_to.clone());
        }

        for reference in &self.references {
            validate_message_id(reference)?;
        }

        if !self.references.is_empty() {
            builder = builder.references(self.references.join(" "));
        }

        let body = self.body();
        let message = if self.attachments.is_empty() {
            builder.multipart(body)
        } else {
            let mut mixed = MultiPart::mixed().multipart(body);

            for attachment in &self.attachments {
                mixed = mixed.singlepart(attachment.part()?);
            }

            builder.multipart(mixed)
        }
        .map_err(|_| Error::Invalid("invalid_message"))?;

        let bytes = message.formatted();
        if bytes.len() > limit {
            return Err(Error::Invalid("message_too_large"));
        }

        let envelope = Envelope {
            from: message
                .envelope()
                .from()
                .map(ToString::to_string)
                .ok_or(Error::Invalid("sender_required"))?,
            to: message
                .envelope()
                .to()
                .iter()
                .map(ToString::to_string)
                .collect(),
        };

        Ok(Prepared {
            message_id: format!("<{message_id}>"),
            envelope: serde_json::to_string(&envelope)?,
            message: bytes,
        })
    }

    fn validate(&self) -> Result<(), Error> {
        let recipients = self.to.len() + self.cc.len() + self.bcc.len();

        if self.idempotency_key.is_empty() || self.idempotency_key.len() > 200 {
            return Err(Error::Invalid("invalid_idempotency_key"));
        }

        if recipients == 0 || recipients > 100 {
            return Err(Error::Invalid("recipient_count_must_be_1_to_100"));
        }

        if self.text.is_none() && self.html.is_none() {
            return Err(Error::Invalid("message_body_required"));
        }

        if self.attachments.len() > 32 || self.references.len() > 50 {
            return Err(Error::Invalid("too_many_attachments_or_references"));
        }

        header_value(&self.subject)?;
        header_value(&self.idempotency_key)
    }

    fn body(&self) -> MultiPart {
        let mut body = MultiPart::alternative().build();

        if let Some(text) = &self.text {
            body = body.singlepart(SinglePart::plain(text.clone()));
        }

        if let Some(html) = &self.html {
            body = body.singlepart(SinglePart::html(html.clone()));
        }

        body
    }
}

impl Attachment {
    fn part(&self) -> Result<SinglePart, Error> {
        header_value(&self.filename)?;
        header_value(&self.content_type)?;

        if self.filename.is_empty() {
            return Err(Error::Invalid("attachment_filename_required"));
        }

        let content_type = ContentType::parse(&self.content_type)
            .map_err(|_| Error::Invalid("invalid_content_type"))?;
        let bytes = STANDARD
            .decode(&self.content_base64)
            .map_err(|_| Error::Invalid("invalid_attachment_base64"))?;

        Ok(MimeAttachment::new(self.filename.clone()).body(bytes, content_type))
    }
}

fn mailbox(value: &str) -> Result<Mailbox, Error> {
    header_value(value)?;
    value
        .parse()
        .map_err(|_| Error::Invalid("invalid_email_address"))
}

fn header_value(value: &str) -> Result<(), Error> {
    if value.len() > 998 || value.chars().any(char::is_control) {
        return Err(Error::Invalid("invalid_header_value"));
    }

    Ok(())
}

fn validate_message_id(value: &str) -> Result<(), Error> {
    header_value(value)?;

    if !value.starts_with('<')
        || !value.ends_with('>')
        || value.chars().any(char::is_whitespace)
        || value.matches('<').count() != 1
        || value.matches('>').count() != 1
    {
        return Err(Error::Invalid("invalid_message_id"));
    }

    Ok(())
}
