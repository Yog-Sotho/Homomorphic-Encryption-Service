//! `/api/auth`: accounts, sessions and sign-in.
//!
//! - [`session`]: access tokens, the refresh cookie and its rotation.
//! - [`password`]: email/password accounts, email verification, password reset.
//! - [`oauth`]: Google and GitHub sign-in.
//! - [`email`]: the emails those flows send.

pub mod email;
pub mod oauth;
pub mod password;
pub mod session;

#[cfg(test)]
pub use session::make_jwt;

use crate::config::Config;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde::Serialize;
use sha2::{Digest, Sha256};

/// Longest token accepted from a client; real ones are 43 characters.
pub(crate) const MAX_TOKEN_LEN: usize = 256;

/// 256 random bits, base64url: session, verification, reset and login tokens.
pub(crate) fn random_token() -> String {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).expect("the OS random number generator is unavailable");
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Tokens are stored only as their SHA-256, so a database leak reveals none.
pub(crate) fn hash_token(token: &str) -> String {
    format!("{:x}", Sha256::digest(token.as_bytes()))
}

/// A frontend page, e.g. `app_url(config, "/verify#token=…")`. The app is
/// served under `/heaas` (SvelteKit `paths.base`).
pub(crate) fn app_url(config: &Config, path: &str) -> String {
    format!("{}/heaas{path}", config.app_base_url)
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct UserPublic {
    pub id: String,
    pub email: String,
    pub created_at: chrono::NaiveDateTime,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_are_random_url_safe_and_hashed() {
        let (a, b) = (random_token(), random_token());
        assert_ne!(a, b);
        assert_eq!(a.len(), 43);
        assert!(a
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_'));
        assert_eq!(hash_token(&a).len(), 64);
        assert_eq!(hash_token(&a), hash_token(&a));
    }
}
