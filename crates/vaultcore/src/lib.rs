#![forbid(unsafe_op_in_unsafe_fn)]

pub mod crypto;
pub mod envelope;
pub mod keyprovider;
pub mod memlock;
pub mod passgen;
pub mod secret;
pub mod vault;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("authentication failed (tamper or wrong key)")]
    AuthFailed,
    #[error("a record named {0:?} already exists")]
    Duplicate(String),
    #[error("no record named {0:?}")]
    NotFound(String),
    #[error("vault format error: {0}")]
    Format(String),
    #[error("key provider: {0}")]
    Provider(String),
    #[error("vault is locked")]
    Locked,
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, Error>;
