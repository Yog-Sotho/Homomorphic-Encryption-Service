use actix_web::{web, HttpResponse, Responder};
use serde::{Deserialize, Serialize};
use jsonwebtoken::{encode, decode, Header, EncodingKey, DecodingKey, Validation};
use bcrypt::{hash, verify, DEFAULT_COST};
use uuid::Uuid;
use sqlx::SqlitePool;
use std::sync::Arc;
use crate::config::Config;
use crate::db::models::User;
use crate::errors::AppError;

const DUMMY_HASH: &str = "$2b$12$WXQEq5YBFxVkx2j5bVBNNOLIGgWS0DVOvt0gp8b2ioY6O3S9XEi/6";

fn is_valid_email(email: &str) -> bool {
    if let Some(at_pos) = email.find('@') {
        let local = &email[..at_pos];
        let domain = &email[at_pos + 1..];
        !local.is_empty() && domain.contains('.')
    } else {
        false
    }
}

fn is_valid_password(password: &str) -> bool {
    password.len() >= 8
        && password.chars().any(|c| c.is_uppercase())
        && password.chars().any(|c| c.is_lowercase())
        && password.chars().any(|c| c.is_ascii_digit())
}

#[derive(Deserialize)]
pub struct RegisterRequest {
    pub email: String,
    pub password: String,
}

#[derive(Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

#[derive(Serialize)]
pub struct UserPublic {
    pub id: String,
    pub email: String,
    pub created_at: chrono::NaiveDateTime,
}

impl From<User> for UserPublic {
    fn from(u: User) -> Self {
        UserPublic { id: u.id, email: u.email, created_at: u.created_at }
    }
}

#[derive(Serialize)]
pub struct AuthResponse {
    pub token: String,
    pub user: UserPublic,
}

pub fn make_jwt(user_id: &str, config: &Config) -> Result<String, AppError> {
    let claims = crate::middleware::jwt::Claims {
        sub: user_id.to_string(),
        exp: (chrono::Utc::now() + chrono::Duration::hours(1)).timestamp() as usize,
    };
    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(config.jwt_secret.as_ref()),
    )
    .map_err(|e| AppError::internal(e.to_string()))
}

pub async fn register(
    pool: web::Data<SqlitePool>,
    config: web::Data<Arc<Config>>,
    req: web::Json<RegisterRequest>,
) -> Result<impl Responder, AppError> {
    let email = req.email.trim().to_lowercase();
    if !is_valid_email(&email) {
        return Err(AppError::bad_request(
            "Invalid email address. Provide a valid email (e.g. user@example.com).",
        ));
    }
    if !is_valid_password(&req.password) {
        return Err(AppError::bad_request(
            "Password must be at least 8 characters and include uppercase, lowercase, and a digit.",
        ));
    }

    let hashed = hash(&req.password, DEFAULT_COST)
        .map_err(|e| AppError::internal(e.to_string()))?;
    let user_id = Uuid::new_v4().to_string();

    sqlx::query("INSERT INTO users (id, email, password_hash) VALUES (?, ?, ?)")
        .bind(&user_id)
        .bind(&email)
        .bind(&hashed)
        .execute(pool.get_ref())
        .await?;

    let user = User {
        id: user_id.clone(),
        email: email.clone(),
        password_hash: String::new(),
        created_at: chrono::Utc::now().naive_utc(),
    };
    let token = make_jwt(&user_id, &config)?;

    Ok(HttpResponse::Created().json(AuthResponse {
        token,
        user: UserPublic::from(user),
    }))
}

pub async fn login(
    pool: web::Data<SqlitePool>,
    config: web::Data<Arc<Config>>,
    req: web::Json<LoginRequest>,
) -> Result<impl Responder, AppError> {
    let email = req.email.trim().to_lowercase();

    let user: Option<User> = sqlx::query_as(
        "SELECT id, email, password_hash, created_at FROM users WHERE email = ?",
    )
    .bind(&email)
    .fetch_optional(pool.get_ref())
    .await?;

    match user {
        Some(u) => {
            if u.password_hash.is_empty() {
                return Err(AppError::bad_request(
                    "This account was created with social login. Use Google or GitHub to sign in.",
                ));
            }
            let valid = verify(&req.password, &u.password_hash)
                .map_err(|e| AppError::internal(e.to_string()))?;
            if valid {
                let token = make_jwt(&u.id, &config)?;
                Ok(HttpResponse::Ok().json(AuthResponse {
                    token,
                    user: UserPublic::from(u),
                }))
            } else {
                Err(AppError::unauthorized("Invalid credentials"))
            }
        }
        None => {
            let _ = verify(&req.password, DUMMY_HASH);
            Err(AppError::unauthorized("Invalid credentials"))
        }
    }
}

// ── OAuth helpers ─────────────────────────────────────────────────────────────

#[derive(Serialize, Deserialize)]
struct OAuthStateClaims {
    provider: String,
    nonce: String,
    exp: usize,
}

fn make_oauth_state(provider: &str, config: &Config) -> Result<String, AppError> {
    let claims = OAuthStateClaims {
        provider: provider.to_string(),
        nonce: Uuid::new_v4().to_string(),
        exp: (chrono::Utc::now() + chrono::Duration::minutes(10)).timestamp() as usize,
    };
    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(config.jwt_secret.as_ref()),
    )
    .map_err(|e| AppError::internal(e.to_string()))
}

fn verify_oauth_state(state: &str, provider: &str, config: &Config) -> Result<(), AppError> {
    let data = decode::<OAuthStateClaims>(
        state,
        &DecodingKey::from_secret(config.jwt_secret.as_ref()),
        &Validation::default(),
    )
    .map_err(|_| AppError::bad_request("Invalid or expired OAuth state. Please try again."))?;
    if data.claims.provider != provider {
        return Err(AppError::bad_request("OAuth state provider mismatch."));
    }
    Ok(())
}

async fn find_or_create_oauth_user(
    pool: &SqlitePool,
    provider: &str,
    provider_id: &str,
    email: &str,
) -> Result<String, AppError> {
    // 1. Existing OAuth link?
    let existing: Option<(String,)> = sqlx::query_as(
        "SELECT user_id FROM oauth_accounts WHERE provider = ? AND provider_id = ?",
    )
    .bind(provider)
    .bind(provider_id)
    .fetch_optional(pool)
    .await?;

    if let Some((uid,)) = existing {
        return Ok(uid);
    }

    // 2. User with same email (link accounts)?
    let email_lower = email.to_lowercase();
    let by_email: Option<(String,)> =
        sqlx::query_as("SELECT id FROM users WHERE email = ?")
            .bind(&email_lower)
            .fetch_optional(pool)
            .await?;

    let user_id = if let Some((uid,)) = by_email {
        uid
    } else {
        // 3. Create new user with empty password_hash (OAuth-only)
        let new_id = Uuid::new_v4().to_string();
        sqlx::query("INSERT INTO users (id, email, password_hash) VALUES (?, ?, '')")
            .bind(&new_id)
            .bind(&email_lower)
            .execute(pool)
            .await?;
        new_id
    };

    // 4. Record OAuth link
    sqlx::query(
        "INSERT INTO oauth_accounts (id, user_id, provider, provider_id, provider_email) \
         VALUES (?, ?, ?, ?, ?)",
    )
    .bind(Uuid::new_v4().to_string())
    .bind(&user_id)
    .bind(provider)
    .bind(provider_id)
    .bind(email)
    .execute(pool)
    .await?;

    Ok(user_id)
}

fn oauth_error_redirect(base_url: &str, msg: &str) -> HttpResponse {
    let encoded = msg
        .chars()
        .map(|c| {
            if c.is_alphanumeric() || c == ' ' || c == '-' || c == '_' || c == '.' {
                c.to_string()
            } else {
                format!("%{:02X}", c as u32)
            }
        })
        .collect::<String>()
        .replace(' ', "+");
    HttpResponse::Found()
        .insert_header(("Location", format!("{}/heaas/login#error={}", base_url, encoded)))
        .finish()
}

fn oauth_success_redirect(base_url: &str, token: &str, email: &str) -> HttpResponse {
    HttpResponse::Found()
        .insert_header((
            "Location",
            format!("{}/heaas/login#token={}&email={}", base_url, token, email),
        ))
        .finish()
}

// ── Google OAuth ──────────────────────────────────────────────────────────────

pub async fn google_redirect(
    config: web::Data<Arc<Config>>,
) -> Result<impl Responder, AppError> {
    let client_id = config
        .google_client_id
        .as_deref()
        .ok_or_else(|| AppError::bad_request("Google OAuth is not configured on this server."))?;

    let state = make_oauth_state("google", &config)?;
    let redirect_uri = format!("{}/api/auth/google/callback", config.app_base_url);

    let mut auth_url =
        url::Url::parse("https://accounts.google.com/o/oauth2/v2/auth").unwrap();
    auth_url
        .query_pairs_mut()
        .append_pair("client_id", client_id)
        .append_pair("redirect_uri", &redirect_uri)
        .append_pair("response_type", "code")
        .append_pair("scope", "openid email profile")
        .append_pair("state", &state)
        .append_pair("access_type", "online");

    Ok(HttpResponse::Found()
        .insert_header(("Location", auth_url.to_string()))
        .finish())
}

#[derive(Deserialize)]
pub struct OAuthCallbackQuery {
    pub code: Option<String>,
    pub state: Option<String>,
    pub error: Option<String>,
}

#[derive(Deserialize)]
struct GoogleTokenResponse {
    access_token: String,
}

#[derive(Deserialize)]
struct GoogleUserInfo {
    id: String,
    email: String,
}

pub async fn google_callback(
    pool: web::Data<SqlitePool>,
    config: web::Data<Arc<Config>>,
    query: web::Query<OAuthCallbackQuery>,
) -> HttpResponse {
    if let Some(ref err) = query.error {
        return oauth_error_redirect(&config.app_base_url, err);
    }

    let (code, state) = match (&query.code, &query.state) {
        (Some(c), Some(s)) => (c.as_str(), s.as_str()),
        _ => return oauth_error_redirect(&config.app_base_url, "Missing OAuth parameters"),
    };

    if verify_oauth_state(state, "google", &config).is_err() {
        return oauth_error_redirect(&config.app_base_url, "Invalid OAuth state. Please try again.");
    }

    let (client_id, client_secret) = match (
        config.google_client_id.as_deref(),
        config.google_client_secret.as_deref(),
    ) {
        (Some(id), Some(secret)) => (id, secret),
        _ => return oauth_error_redirect(&config.app_base_url, "Google OAuth not configured"),
    };

    let redirect_uri = format!("{}/api/auth/google/callback", config.app_base_url);
    let http = reqwest::Client::new();

    let token_resp = match http
        .post("https://oauth2.googleapis.com/token")
        .form(&[
            ("code", code),
            ("client_id", client_id),
            ("client_secret", client_secret),
            ("redirect_uri", redirect_uri.as_str()),
            ("grant_type", "authorization_code"),
        ])
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            log::error!("Google token exchange: {}", e);
            return oauth_error_redirect(&config.app_base_url, "Google authentication failed");
        }
    };

    let tokens: GoogleTokenResponse = match token_resp.json().await {
        Ok(t) => t,
        Err(e) => {
            log::error!("Google token parse: {}", e);
            return oauth_error_redirect(&config.app_base_url, "Google authentication failed");
        }
    };

    let user_info: GoogleUserInfo = match http
        .get("https://www.googleapis.com/oauth2/v2/userinfo")
        .bearer_auth(&tokens.access_token)
        .send()
        .await
    {
        Ok(r) => match r.json().await {
            Ok(u) => u,
            Err(e) => {
                log::error!("Google userinfo parse: {}", e);
                return oauth_error_redirect(&config.app_base_url, "Failed to retrieve Google profile");
            }
        },
        Err(e) => {
            log::error!("Google userinfo fetch: {}", e);
            return oauth_error_redirect(&config.app_base_url, "Failed to retrieve Google profile");
        }
    };

    let user_id = match find_or_create_oauth_user(
        pool.get_ref(), "google", &user_info.id, &user_info.email,
    )
    .await
    {
        Ok(id) => id,
        Err(e) => {
            log::error!("OAuth user creation: {:?}", e);
            return oauth_error_redirect(&config.app_base_url, "Account creation failed");
        }
    };

    match make_jwt(&user_id, &config) {
        Ok(token) => oauth_success_redirect(&config.app_base_url, &token, &user_info.email),
        Err(e) => {
            log::error!("JWT generation: {:?}", e);
            oauth_error_redirect(&config.app_base_url, "Authentication failed")
        }
    }
}

// ── GitHub OAuth ──────────────────────────────────────────────────────────────

pub async fn github_redirect(
    config: web::Data<Arc<Config>>,
) -> Result<impl Responder, AppError> {
    let client_id = config
        .github_client_id
        .as_deref()
        .ok_or_else(|| AppError::bad_request("GitHub OAuth is not configured on this server."))?;

    let state = make_oauth_state("github", &config)?;
    let redirect_uri = format!("{}/api/auth/github/callback", config.app_base_url);

    let mut auth_url =
        url::Url::parse("https://github.com/login/oauth/authorize").unwrap();
    auth_url
        .query_pairs_mut()
        .append_pair("client_id", client_id)
        .append_pair("redirect_uri", &redirect_uri)
        .append_pair("scope", "user:email")
        .append_pair("state", &state);

    Ok(HttpResponse::Found()
        .insert_header(("Location", auth_url.to_string()))
        .finish())
}

#[derive(Deserialize)]
struct GitHubTokenResponse {
    access_token: String,
}

#[derive(Deserialize)]
struct GitHubUser {
    id: i64,
    email: Option<String>,
}

#[derive(Deserialize)]
struct GitHubEmail {
    email: String,
    primary: bool,
    verified: bool,
}

pub async fn github_callback(
    pool: web::Data<SqlitePool>,
    config: web::Data<Arc<Config>>,
    query: web::Query<OAuthCallbackQuery>,
) -> HttpResponse {
    if let Some(ref err) = query.error {
        return oauth_error_redirect(&config.app_base_url, err);
    }

    let (code, state) = match (&query.code, &query.state) {
        (Some(c), Some(s)) => (c.as_str(), s.as_str()),
        _ => return oauth_error_redirect(&config.app_base_url, "Missing OAuth parameters"),
    };

    if verify_oauth_state(state, "github", &config).is_err() {
        return oauth_error_redirect(&config.app_base_url, "Invalid OAuth state. Please try again.");
    }

    let (client_id, client_secret) = match (
        config.github_client_id.as_deref(),
        config.github_client_secret.as_deref(),
    ) {
        (Some(id), Some(secret)) => (id, secret),
        _ => return oauth_error_redirect(&config.app_base_url, "GitHub OAuth not configured"),
    };

    let redirect_uri = format!("{}/api/auth/github/callback", config.app_base_url);
    let http = reqwest::Client::new();

    let token_resp = match http
        .post("https://github.com/login/oauth/access_token")
        .header("Accept", "application/json")
        .form(&[
            ("code", code),
            ("client_id", client_id),
            ("client_secret", client_secret),
            ("redirect_uri", redirect_uri.as_str()),
        ])
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            log::error!("GitHub token exchange: {}", e);
            return oauth_error_redirect(&config.app_base_url, "GitHub authentication failed");
        }
    };

    let tokens: GitHubTokenResponse = match token_resp.json().await {
        Ok(t) => t,
        Err(e) => {
            log::error!("GitHub token parse: {}", e);
            return oauth_error_redirect(&config.app_base_url, "GitHub authentication failed");
        }
    };

    let gh_user: GitHubUser = match http
        .get("https://api.github.com/user")
        .bearer_auth(&tokens.access_token)
        .header("User-Agent", "HEaaS/1.0")
        .send()
        .await
    {
        Ok(r) => match r.json().await {
            Ok(u) => u,
            Err(e) => {
                log::error!("GitHub user parse: {}", e);
                return oauth_error_redirect(&config.app_base_url, "Failed to retrieve GitHub profile");
            }
        },
        Err(e) => {
            log::error!("GitHub user fetch: {}", e);
            return oauth_error_redirect(&config.app_base_url, "Failed to retrieve GitHub profile");
        }
    };

    // GitHub may omit email from /user — fall back to /user/emails
    let email = if let Some(e) = gh_user.email.filter(|e| !e.is_empty()) {
        e
    } else {
        let emails: Vec<GitHubEmail> = match http
            .get("https://api.github.com/user/emails")
            .bearer_auth(&tokens.access_token)
            .header("User-Agent", "HEaaS/1.0")
            .send()
            .await
        {
            Ok(r) => r.json().await.unwrap_or_default(),
            Err(_) => vec![],
        };
        match emails.into_iter().find(|e| e.primary && e.verified) {
            Some(e) => e.email,
            None => {
                return oauth_error_redirect(
                    &config.app_base_url,
                    "Your GitHub account has no verified primary email.",
                )
            }
        }
    };

    let provider_id = gh_user.id.to_string();
    let user_id =
        match find_or_create_oauth_user(pool.get_ref(), "github", &provider_id, &email).await {
            Ok(id) => id,
            Err(e) => {
                log::error!("OAuth user creation: {:?}", e);
                return oauth_error_redirect(&config.app_base_url, "Account creation failed");
            }
        };

    match make_jwt(&user_id, &config) {
        Ok(token) => oauth_success_redirect(&config.app_base_url, &token, &email),
        Err(e) => {
            log::error!("JWT generation: {:?}", e);
            oauth_error_redirect(&config.app_base_url, "Authentication failed")
        }
    }
}
