use std::time::Duration;

/// Everything an SDK call can fail with.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The server answered with an error envelope (`{"error":{"code","message"}}`).
    #[error("{message} ({status} {code})")]
    Api {
        status: u16,
        /// Stable machine-readable code, see `heaas_core::api::error_codes`.
        code: String,
        message: String,
        /// From `Retry-After`, on 429 and 503.
        retry_after: Option<Duration>,
    },
    /// The request did not complete (connection, TLS, timeout, decoding).
    #[error("request failed: {0}")]
    Http(#[from] reqwest::Error),
    /// The server is not compatible with this SDK.
    #[error("incompatible server: {0}")]
    Incompatible(String),
    /// A key or ciphertext could not be (de)serialized.
    #[error("{0}")]
    Encoding(String),
    #[error("{0}")]
    Io(#[from] std::io::Error),
    /// The job finished without a result.
    #[error("job {id} failed: {message}")]
    JobFailed { id: String, message: String },
    /// [`crate::Client::wait`] gave up.
    #[error("job {id} did not finish within {waited:?}")]
    Timeout { id: String, waited: Duration },
}

impl Error {
    /// The error envelope's code, if the server sent one.
    pub fn code(&self) -> Option<&str> {
        match self {
            Error::Api { code, .. } => Some(code),
            _ => None,
        }
    }
}

pub type Result<T, E = Error> = std::result::Result<T, E>;
