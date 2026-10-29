//! Google and GitHub sign-in (OAuth 2.0 authorization code flow with PKCE).
//!
//! 1. `GET /api/v1/auth/{provider}` picks a random `state` and PKCE verifier, keeps
//!    them in a short-lived, HMAC-signed `HttpOnly` cookie, and redirects to the
//!    provider with the state and the verifier's S256 challenge.
//! 2. `GET /api/v1/auth/{provider}/callback` accepts the code only if its `state`
//!    matches the cookie, redeems it with the verifier, and reads the account's
//!    *verified* email address.
//! 3. It redirects to the frontend with a one-time login code (never a token),
//!    which the page redeems with `POST /api/v1/auth/exchange`.

use super::session::{create_login_code, COOKIE_PATH};
use super::{app_url, random_token};
use crate::config::Config;
use crate::errors::AppError;
use actix_web::cookie::{time, Cookie, SameSite};
use actix_web::{web, HttpRequest, HttpResponse};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::SqlitePool;
use std::sync::Arc;
use std::time::Duration;
use subtle::ConstantTimeEq;
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

const STATE_COOKIE: &str = "heaas_oauth";
const STATE_TTL_SECS: i64 = 600;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Provider {
    Google,
    Github,
}

impl Provider {
    fn name(self) -> &'static str {
        match self {
            Provider::Google => "google",
            Provider::Github => "github",
        }
    }

    fn client(self, config: &Config) -> Option<(&str, &str)> {
        let (id, secret) = match self {
            Provider::Google => (&config.google_client_id, &config.google_client_secret),
            Provider::Github => (&config.github_client_id, &config.github_client_secret),
        };
        Some((
            id.as_deref().filter(|s| !s.is_empty())?,
            secret.as_deref().filter(|s| !s.is_empty())?,
        ))
    }

    fn callback_url(self, config: &Config) -> String {
        format!(
            "{}/api/v1/auth/{}/callback",
            config.app_base_url,
            self.name()
        )
    }
}

/// The HTTP client for provider calls: bounded time, no redirects followed.
pub fn http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(15))
        .redirect(reqwest::redirect::Policy::none())
        .user_agent(concat!("HE-Engine/", env!("CARGO_PKG_VERSION")))
        .build()
        .expect("TLS backend available")
}

#[derive(Serialize, ToSchema)]
pub struct Providers {
    google: bool,
    github: bool,
}

/// `GET /api/v1/auth/providers` — which sign-in buttons the frontend should show.
#[utoipa::path(get, path = "/auth/providers", tag = "auth", responses((status = 200, description = "Which OAuth providers are configured", body = Providers)))]
pub async fn providers(config: web::Data<Arc<Config>>) -> HttpResponse {
    HttpResponse::Ok().json(Providers {
        google: Provider::Google.client(&config).is_some(),
        github: Provider::Github.client(&config).is_some(),
    })
}

// ── State cookie ─────────────────────────────────────────────────────────────

/// What the callback must match: the provider, `state` and PKCE verifier.
struct Pending {
    provider: String,
    state: String,
    verifier: String,
    expires: i64,
}

fn mac(config: &Config, payload: &str) -> Hmac<Sha256> {
    let mut mac = Hmac::<Sha256>::new_from_slice(&config.keys.oauth_state)
        .expect("HMAC accepts any key length");
    mac.update(payload.as_bytes());
    mac
}

impl Pending {
    fn new(provider: Provider) -> Self {
        Pending {
            provider: provider.name().to_string(),
            state: random_token(),
            verifier: random_token(),
            expires: chrono::Utc::now().timestamp() + STATE_TTL_SECS,
        }
    }

    fn payload(&self) -> String {
        format!(
            "{}.{}.{}.{}",
            self.provider, self.state, self.verifier, self.expires
        )
    }

    fn seal(&self, config: &Config) -> String {
        let payload = self.payload();
        let tag = URL_SAFE_NO_PAD.encode(mac(config, &payload).finalize().into_bytes());
        format!("{payload}.{tag}")
    }

    /// Parses and authenticates a cookie value; `None` if forged or expired.
    fn open(config: &Config, sealed: &str) -> Option<Self> {
        let (payload, tag) = sealed.rsplit_once('.')?;
        let tag = URL_SAFE_NO_PAD.decode(tag).ok()?;
        mac(config, payload).verify_slice(&tag).ok()?;
        let mut parts = payload.split('.');
        let pending = Pending {
            provider: parts.next()?.to_string(),
            state: parts.next()?.to_string(),
            verifier: parts.next()?.to_string(),
            expires: parts.next()?.parse().ok()?,
        };
        (parts.next().is_none() && pending.expires > chrono::Utc::now().timestamp())
            .then_some(pending)
    }

    fn challenge(&self) -> String {
        URL_SAFE_NO_PAD.encode(Sha256::digest(self.verifier.as_bytes()))
    }
}

/// `SameSite=Lax`, unlike the session cookie: it must come back on the
/// provider's top-level redirect to the callback.
fn state_cookie(config: &Config, value: String, max_age: time::Duration) -> Cookie<'static> {
    Cookie::build(STATE_COOKIE, value)
        .path(COOKIE_PATH)
        .http_only(true)
        .secure(config.cookie_secure)
        .same_site(SameSite::Lax)
        .max_age(max_age)
        .finish()
}

// ── Redirects ────────────────────────────────────────────────────────────────

fn redirect(location: &str) -> actix_web::HttpResponseBuilder {
    let mut response = HttpResponse::Found();
    response
        .insert_header(("Location", location))
        .insert_header(("Referrer-Policy", "no-referrer"));
    response
}

/// Back to the sign-in page with a fixed, server-chosen message (never text
/// from the request, which an attacker could craft).
fn fail(config: &Config, message: &'static str) -> HttpResponse {
    let encoded: String = url::form_urlencoded::byte_serialize(message.as_bytes()).collect();
    redirect(&app_url(config, &format!("/login#error={encoded}")))
        .cookie(state_cookie(config, String::new(), time::Duration::ZERO))
        .finish()
}

/// `GET /api/v1/auth/{provider}` — starts sign-in.
pub async fn start(
    config: web::Data<Arc<Config>>,
    provider: Provider,
) -> Result<HttpResponse, AppError> {
    let (client_id, _) = provider.client(&config).ok_or_else(|| {
        AppError::not_found(format!("{} sign-in is not configured", provider.name()))
    })?;
    let pending = Pending::new(provider);
    let (authorize, scope) = match provider {
        Provider::Google => (&config.oauth.google_authorize, "openid email"),
        Provider::Github => (&config.oauth.github_authorize, "user:email"),
    };
    let mut url = url::Url::parse(authorize)
        .map_err(|e| AppError::internal(format!("bad authorize URL: {e}")))?;
    url.query_pairs_mut()
        .append_pair("client_id", client_id)
        .append_pair("redirect_uri", &provider.callback_url(&config))
        .append_pair("response_type", "code")
        .append_pair("scope", scope)
        .append_pair("state", &pending.state)
        .append_pair("code_challenge", &pending.challenge())
        .append_pair("code_challenge_method", "S256");
    if provider == Provider::Google {
        url.query_pairs_mut()
            .append_pair("prompt", "select_account");
    }
    let cookie = state_cookie(
        &config,
        pending.seal(&config),
        time::Duration::seconds(STATE_TTL_SECS),
    );
    Ok(redirect(url.as_str()).cookie(cookie).finish())
}

/// Starts Google sign-in.
#[utoipa::path(get, path = "/auth/google", tag = "auth", responses((status = 302, description = "Redirect to Google, with a state cookie"), (status = 404, description = "Google sign-in is not configured", body = heaas_core::api::ErrorBody)))]
pub async fn google_start(config: web::Data<Arc<Config>>) -> Result<HttpResponse, AppError> {
    start(config, Provider::Google).await
}

/// Starts GitHub sign-in.
#[utoipa::path(get, path = "/auth/github", tag = "auth", responses((status = 302, description = "Redirect to GitHub, with a state cookie"), (status = 404, description = "GitHub sign-in is not configured", body = heaas_core::api::ErrorBody)))]
pub async fn github_start(config: web::Data<Arc<Config>>) -> Result<HttpResponse, AppError> {
    start(config, Provider::Github).await
}

// ── Callback ─────────────────────────────────────────────────────────────────

#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct CallbackQuery {
    pub code: Option<String>,
    pub state: Option<String>,
    pub error: Option<String>,
}

/// The provider's answer about who signed in.
struct Identity {
    provider_id: String,
    email: String,
}

/// Why a callback failed. Details are logged; users see a fixed message.
enum Failure {
    Rejected(&'static str),
    Provider(String),
}

impl From<reqwest::Error> for Failure {
    fn from(e: reqwest::Error) -> Self {
        Failure::Provider(e.to_string())
    }
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
}

async fn redeem_code(
    http: &reqwest::Client,
    config: &Config,
    provider: Provider,
    code: &str,
    verifier: &str,
) -> Result<String, Failure> {
    let (client_id, client_secret) = provider
        .client(config)
        .ok_or(Failure::Rejected("This sign-in method is not configured"))?;
    let endpoint = match provider {
        Provider::Google => &config.oauth.google_token,
        Provider::Github => &config.oauth.github_token,
    };
    let redirect_uri = provider.callback_url(config);
    let tokens: TokenResponse = http
        .post(endpoint)
        .header("Accept", "application/json")
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", code),
            ("client_id", client_id),
            ("client_secret", client_secret),
            ("redirect_uri", redirect_uri.as_str()),
            ("code_verifier", verifier),
        ])
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    Ok(tokens.access_token)
}

#[derive(Deserialize)]
struct GoogleUser {
    id: String,
    email: String,
    /// Google documents this as always true (only the primary, verified
    /// address is returned) and as defaulting to true; we still refuse `false`.
    verified_email: Option<bool>,
}

#[derive(Deserialize)]
struct GithubUser {
    id: i64,
}

#[derive(Deserialize)]
struct GithubEmail {
    email: String,
    primary: bool,
    verified: bool,
}

async fn identity(
    http: &reqwest::Client,
    config: &Config,
    provider: Provider,
    access_token: &str,
) -> Result<Identity, Failure> {
    match provider {
        Provider::Google => {
            let user: GoogleUser = http
                .get(&config.oauth.google_userinfo)
                .bearer_auth(access_token)
                .send()
                .await?
                .error_for_status()?
                .json()
                .await?;
            if user.verified_email == Some(false) || user.email.is_empty() {
                return Err(Failure::Rejected(
                    "Your Google email address is not verified.",
                ));
            }
            Ok(Identity {
                provider_id: user.id,
                email: user.email,
            })
        }
        Provider::Github => {
            let api = config.oauth.github_api.trim_end_matches('/');
            let get = |path: &str| {
                http.get(format!("{api}{path}"))
                    .bearer_auth(access_token)
                    .header("Accept", "application/vnd.github+json")
            };
            let user: GithubUser = get("/user")
                .send()
                .await?
                .error_for_status()?
                .json()
                .await?;
            // The profile's public email may be unverified; only trust the
            // verified primary address from the emails API.
            let emails: Vec<GithubEmail> = get("/user/emails")
                .send()
                .await?
                .error_for_status()?
                .json()
                .await?;
            let email = emails
                .into_iter()
                .find(|e| e.primary && e.verified)
                .ok_or(Failure::Rejected(
                    "Your GitHub account has no verified primary email address.",
                ))?
                .email;
            Ok(Identity {
                provider_id: user.id.to_string(),
                email,
            })
        }
    }
}

/// Finds the user linked to this provider account, or links/creates one by
/// verified email. Runs in one transaction.
pub async fn find_or_create_oauth_user(
    pool: &SqlitePool,
    provider: &str,
    provider_id: &str,
    email: &str,
) -> Result<String, AppError> {
    let mut tx = pool.begin().await?;
    let linked: Option<(String,)> =
        sqlx::query_as("SELECT user_id FROM oauth_accounts WHERE provider = ? AND provider_id = ?")
            .bind(provider)
            .bind(provider_id)
            .fetch_optional(&mut *tx)
            .await?;
    if let Some((user_id,)) = linked {
        tx.commit().await?;
        return Ok(user_id);
    }

    let email_lower = email.trim().to_lowercase();
    #[derive(sqlx::FromRow)]
    struct ByEmail {
        id: String,
        email_verified: bool,
    }
    let by_email: Option<ByEmail> =
        sqlx::query_as("SELECT id, email_verified FROM users WHERE email = ?")
            .bind(&email_lower)
            .fetch_optional(&mut *tx)
            .await?;
    let user_id = match by_email {
        Some(ByEmail {
            id: user_id,
            email_verified,
        }) => {
            if !email_verified {
                // Someone registered this address without proving they own it.
                // The provider just proved the real owner signed in, so drop the
                // unproven password: it must not keep working (account takeover).
                sqlx::query(
                    "UPDATE users SET email_verified = 1, password_hash = '',
                         email_verify_token = NULL, email_verify_expires_at = NULL
                     WHERE id = ?",
                )
                .bind(&user_id)
                .execute(&mut *tx)
                .await?;
                sqlx::query("DELETE FROM refresh_tokens WHERE user_id = ?")
                    .bind(&user_id)
                    .execute(&mut *tx)
                    .await?;
            }
            user_id
        }
        None => {
            let user_id = Uuid::new_v4().to_string();
            sqlx::query(
                "INSERT INTO users (id, email, password_hash, email_verified) VALUES (?, ?, '', 1)",
            )
            .bind(&user_id)
            .bind(&email_lower)
            .execute(&mut *tx)
            .await?;
            user_id
        }
    };
    sqlx::query(
        "INSERT INTO oauth_accounts (id, user_id, provider, provider_id, provider_email)
         VALUES (?, ?, ?, ?, ?)",
    )
    .bind(Uuid::new_v4().to_string())
    .bind(&user_id)
    .bind(provider)
    .bind(provider_id)
    .bind(&email_lower)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(user_id)
}

/// `GET /api/v1/auth/{provider}/callback`
pub async fn callback(
    pool: web::Data<SqlitePool>,
    config: web::Data<Arc<Config>>,
    http: web::Data<reqwest::Client>,
    req: HttpRequest,
    query: web::Query<CallbackQuery>,
    provider: Provider,
) -> HttpResponse {
    if query.error.is_some() {
        return fail(&config, "Sign-in was cancelled.");
    }
    let (Some(code), Some(state)) = (query.code.as_deref(), query.state.as_deref()) else {
        return fail(&config, "Sign-in failed. Please try again.");
    };
    let pending = req
        .cookie(STATE_COOKIE)
        .and_then(|c| Pending::open(&config, c.value()));
    let state_matches = pending.as_ref().is_some_and(|p| {
        p.provider == provider.name() && bool::from(p.state.as_bytes().ct_eq(state.as_bytes()))
    });
    let Some(pending) = pending.filter(|_| state_matches) else {
        return fail(
            &config,
            "Sign-in expired or was started elsewhere. Please try again.",
        );
    };

    let signed_in = async {
        let access_token = redeem_code(&http, &config, provider, code, &pending.verifier).await?;
        identity(&http, &config, provider, &access_token).await
    }
    .await;
    let identity = match signed_in {
        Ok(identity) => identity,
        Err(Failure::Rejected(message)) => return fail(&config, message),
        Err(Failure::Provider(detail)) => {
            tracing::error!("{} sign-in failed: {detail}", provider.name());
            return fail(&config, "Sign-in failed. Please try again.");
        }
    };

    let code = async {
        let user_id = find_or_create_oauth_user(
            &pool,
            provider.name(),
            &identity.provider_id,
            &identity.email,
        )
        .await?;
        create_login_code(&pool, &user_id).await
    }
    .await;
    match code {
        Ok(code) => redirect(&app_url(&config, &format!("/login#code={code}")))
            .cookie(state_cookie(&config, String::new(), time::Duration::ZERO))
            .finish(),
        Err(e) => {
            tracing::error!("{} sign-in: account lookup failed: {e:?}", provider.name());
            fail(&config, "Sign-in failed. Please try again.")
        }
    }
}

/// Where Google returns the user after sign-in.
#[utoipa::path(get, path = "/auth/google/callback", tag = "auth", params(CallbackQuery), responses((status = 302, description = "Redirect to the frontend with `#code=` (exchange it at `/auth/exchange`) or `#error=`")))]
pub async fn google_callback(
    pool: web::Data<SqlitePool>,
    config: web::Data<Arc<Config>>,
    http: web::Data<reqwest::Client>,
    req: HttpRequest,
    query: web::Query<CallbackQuery>,
) -> HttpResponse {
    callback(pool, config, http, req, query, Provider::Google).await
}

/// Where GitHub returns the user after sign-in.
#[utoipa::path(get, path = "/auth/github/callback", tag = "auth", params(CallbackQuery), responses((status = 302, description = "Redirect to the frontend with `#code=` (exchange it at `/auth/exchange`) or `#error=`")))]
pub async fn github_callback(
    pool: web::Data<SqlitePool>,
    config: web::Data<Arc<Config>>,
    http: web::Data<reqwest::Client>,
    req: HttpRequest,
    query: web::Query<CallbackQuery>,
) -> HttpResponse {
    callback(pool, config, http, req, query, Provider::Github).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_cookies_are_authenticated_and_expire() {
        let config = Config::for_tests(std::env::temp_dir());
        let pending = Pending::new(Provider::Github);
        let sealed = pending.seal(&config);
        let opened = Pending::open(&config, &sealed).unwrap();
        assert_eq!(
            (opened.provider.as_str(), opened.state, opened.verifier),
            ("github", pending.state.clone(), pending.verifier.clone())
        );

        // Any change to the payload breaks the tag.
        let forged = sealed.replacen("github", "google", 1);
        assert!(Pending::open(&config, &forged).is_none());
        assert!(Pending::open(&config, "garbage").is_none());

        let mut other = Config::for_tests(std::env::temp_dir());
        other.keys = crate::config::SecretKeys::derive("another-secret-at-least-32-bytes-long!!");
        assert!(Pending::open(&other, &sealed).is_none());

        let expired = Pending {
            expires: chrono::Utc::now().timestamp() - 1,
            ..Pending::new(Provider::Google)
        };
        assert!(Pending::open(&config, &expired.seal(&config)).is_none());
    }

    #[test]
    fn pkce_challenge_is_s256_of_the_verifier() {
        // RFC 7636 appendix B.
        let pending = Pending {
            provider: "google".into(),
            state: "s".into(),
            verifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk".into(),
            expires: 0,
        };
        assert_eq!(
            pending.challenge(),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }

    #[tokio::test]
    async fn oauth_sign_in_cannot_take_over_through_an_unverified_registration() {
        let pool = crate::jobs::queue::test_support::test_pool().await;
        sqlx::query(
            "INSERT INTO users (id, email, password_hash, email_verified, email_verify_token)
             VALUES ('squatter', 'victim@example.com', 'attacker-hash', 0, 'token')",
        )
        .execute(&pool)
        .await
        .unwrap();

        let user_id = find_or_create_oauth_user(&pool, "google", "g-1", "Victim@Example.com")
            .await
            .unwrap();
        assert_eq!(user_id, "squatter");
        let (verified, hash, token): (bool, String, Option<String>) = sqlx::query_as(
            "SELECT email_verified, password_hash, email_verify_token FROM users WHERE id = ?",
        )
        .bind(&user_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(verified);
        assert_eq!(hash, "", "the unproven password no longer works");
        assert_eq!(token, None);

        // Signing in again finds the link instead of creating another account.
        let again = find_or_create_oauth_user(&pool, "google", "g-1", "victim@example.com")
            .await
            .unwrap();
        assert_eq!(again, user_id);
    }
}
