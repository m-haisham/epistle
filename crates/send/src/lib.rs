//! Durable SMTP submission with shared account credentials.

mod compose;
mod queue;
mod transport;
mod worker;

pub use compose::{Attachment, SendRequest};
pub use queue::SendJob;

use epistle_auth::TokenProvider;
use epistle_core::Config;
use epistle_store::Store;
use std::sync::Arc;

/// Queue validation and persistence errors; provider details are never exposed.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Invalid(&'static str),
    #[error("{0}")]
    Store(#[from] epistle_store::Error),
    #[error("storage_error")]
    Sql(#[from] sqlx::Error),
    #[error("invalid_stored_message")]
    Data(#[from] serde_json::Error),
}

/// Shared outbound queue and SMTP worker dependencies.
#[derive(Clone)]
pub struct Sender {
    pub store: Store,
    pub tokens: TokenProvider,
    pub config: Arc<Config>,
}

#[cfg(test)]
mod tests;
