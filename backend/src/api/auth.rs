use actix_web::{web, HttpResponse, Responder};
use serde::{Deserialize, Serialize};
use jsonwebtoken::{encode, decode, Header, EncodingKey, DecodingKey, Validation};
use bcrypt::{hash, verify, DEFAULT_COST};
use uuid::Uuid;
use sqlx::SqlitePool;
use std::sync::Arc;
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};
use lettre::transport::smtp::authentication::Credentials;
use crate::config::Config;
use crate::db::models::User;
use crate::errors::AppError;
use crate::api::validation::{is_valid_email, is_strong_password, PASSWORD_REQUIREMENTS};

const DUMMY_HASH: &str = "$2b$12$WXQEq5YBFxVkx2j5bVBNNOLIGgWS0DVOvt0gp8b2ioY6O3S9XEi/6";

fn hash_token(token: &str) -> String {
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    format!("{:x}", hasher.finalize())
}

// ── Request / response types ──────────────────────────────────────────────────

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

#[derive(Deserialize)]
pub struct ResendRequest {
    pub email: String,
}

#[derive(Deserialize)]
pub struct VerifyQuery {
    pub token: Option<String>,
}

#[derive(Deserialize)]
pub struct ForgotPasswordRequest {
    pub email: String,
}

#[derive(Deserialize)]
pub struct ResetPasswordRequest {
    pub token: String,
    pub new_password: String,
}

#[derive(Deserialize)]
pub struct RefreshRequest {
    pub refresh_token: String,
}

#[derive(Deserialize)]
pub struct LogoutRequest {
    pub refresh_token: String,
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
    pub refresh_token: String,
    pub user: UserPublic,
}

// ── JWT ───────────────────────────────────────────────────────────────────────

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

// ── Refresh token helpers ─────────────────────────────────────────────────────

async fn create_refresh_token(pool: &SqlitePool, user_id: &str) -> Result<String, AppError> {
    let raw = Uuid::new_v4().to_string();
    let hash_val = hash_token(&raw);
    let id = Uuid::new_v4().to_string();
    let expires_at = chrono::Utc::now().naive_utc() + chrono::Duration::days(30);
    sqlx::query(
        "INSERT INTO refresh_tokens (id, user_id, token_hash, expires_at) VALUES (?, ?, ?, ?)"
    )
    .bind(&id)
    .bind(user_id)
    .bind(&hash_val)
    .bind(expires_at)
    .execute(pool)
    .await?;
    Ok(raw)
}

pub async fn make_auth_response(
    pool: &SqlitePool,
    user: User,
    config: &Config,
) -> Result<AuthResponse, AppError> {
    let token = make_jwt(&user.id, config)?;
    let refresh_token = create_refresh_token(pool, &user.id).await?;
    Ok(AuthResponse {
        token,
        refresh_token,
        user: UserPublic::from(user),
    })
}

// ── Email sending ─────────────────────────────────────────────────────────────

async fn send_verification_email(
    config: &Config,
    to_email: &str,
    token: &str,
) -> Result<(), AppError> {
    let verify_url = format!("{}/api/auth/verify?token={}", config.app_base_url, token);

    let Some(smtp_host) = config.smtp_host.as_deref() else {
        log::info!(
            "SMTP not configured — verification URL for {}: {}",
            to_email,
            verify_url
        );
        return Ok(());
    };

    let body = format!(
        "<!DOCTYPE html><html><body style=\"font-family:sans-serif;max-width:520px;margin:2rem auto\">\
         <h2>Verify your HEaaS account</h2>\
         <p>Click the link below to activate your account and sign in:</p>\
         <p><a href=\"{0}\" style=\"color:#6366f1\">{0}</a></p>\
         <p style=\"color:#888;font-size:0.85rem\">If you did not create this account, ignore this email.</p>\
         </body></html>",
        verify_url
    );

    let from: lettre::message::Mailbox = config
        .from_email
        .parse()
        .map_err(|_| AppError::internal("Invalid FROM_EMAIL configuration"))?;

    let to: lettre::message::Mailbox = to_email
        .parse()
        .map_err(|_| AppError::internal("Invalid recipient email address"))?;

    let message = Message::builder()
        .from(from)
        .to(to)
        .subject("Verify your HEaaS account")
        .header(lettre::message::header::ContentType::TEXT_HTML)
        .body(body)
        .map_err(|e| AppError::internal(format!("Email build error: {}", e)))?;

    let base = AsyncSmtpTransport::<Tokio1Executor>::relay(smtp_host)
        .map_err(|e| AppError::internal(format!("SMTP relay error: {}", e)))?
        .port(config.smtp_port);

    let mailer = match (config.smtp_user.as_deref(), config.smtp_pass.as_deref()) {
        (Some(u), Some(p)) => base
            .credentials(Credentials::new(u.to_string(), p.to_string()))
            .build(),
        _ => base.build(),
    };

    mailer.send(message).await.map_err(|e| {
        log::error!("SMTP send to {}: {}", to_email, e);
        AppError::internal("Failed to send verification email")
    })?;

    Ok(())
}

async fn send_reset_email(
    config: &Config,
    to_email: &str,
    token: &str,
) -> Result<(), AppError> {
    let reset_url = format!(
        "{}/api/auth/forgot-password/redirect?token={}",
        config.app_base_url, token
    );

    let Some(smtp_host) = config.smtp_host.as_deref() else {
        log::info!(
            "SMTP not configured — password reset URL for {}: {}",
            to_email,
            reset_url
        );
        return Ok(());
    };

    let body = format!(
        "<!DOCTYPE html><html><body style=\"font-family:sans-serif;max-width:520px;margin:2rem auto\">\
         <h2>Reset your HEaaS password</h2>\
         <p>Click the link below to reset your password. This link expires in 1 hour.</p>\
         <p><a href=\"{0}\" style=\"color:#6366f1\">{0}</a></p>\
         <p style=\"color:#888;font-size:0.85rem\">If you did not request a password reset, ignore this email.</p>\
         </body></html>",
        reset_url
    );

    let from: lettre::message::Mailbox = config
        .from_email
        .parse()
        .map_err(|_| AppError::internal("Invalid FROM_EMAIL configuration"))?;

    let to: lettre::message::Mailbox = to_email
        .parse()
        .map_err(|_| AppError::internal("Invalid recipient email address"))?;

    let message = Message::builder()
        .from(from)
        .to(to)
        .subject("Reset your HEaaS password")
        .header(lettre::message::header::ContentType::TEXT_HTML)
        .body(body)
        .map_err(|e| AppError::internal(format!("Email build error: {}", e)))?;

    let base = AsyncSmtpTransport::<Tokio1Executor>::relay(smtp_host)
        .map_err(|e| AppError::internal(format!("SMTP relay error: {}", e)))?
        .port(config.smtp_port);

    let mailer = match (config.smtp_user.as_deref(), config.smtp_pass.as_deref()) {
        (Some(u), Some(p)) => base
            .credentials(Credentials::new(u.to_string(), p.to_string()))
            .build(),
        _ => base.build(),
    };

    mailer.send(message).await.map_err(|e| {
        log::error!("SMTP reset send to {}: {}", to_email, e);
        AppError::internal("Failed to send password reset email")
    })?;

    Ok(())
}

// ── Auth handlers ─────────────────────────────────────────────────────────────

pub async fn register(
    pool: web::Data<SqlitePool>,
    config: web::Data<Arc<Config>>,
    req: web::Json<RegisterRequest>,
) -> Result<impl Responder, AppError> {
    let req = req.into_inner();
    let email = req.email.trim().to_lowercase();
    if !is_valid_email(&email) {
        return Err(AppError::bad_request(
            "Invalid email address. Provide a valid email (e.g. user@example.com).",
        ));
    }
    if !is_strong_password(&req.password) {
        return Err(AppError::bad_request(PASSWORD_REQUIREMENTS));
    }

    // Offload CPU-intensive hashing to a blocking thread to avoid starving the async executor.
    let password = req.password;
    let hashed = tokio::task::spawn_blocking(move || hash(&password, DEFAULT_COST))
        .await
        .map_err(|e| AppError::internal(format!("Task join error: {}", e)))?
        .map_err(|e| AppError::internal(e.to_string()))?;
    let user_id = Uuid::new_v4().to_string();
    let verify_token = Uuid::new_v4().to_string();
    let verify_token_hash = hash_token(&verify_token);

    sqlx::query(
        "INSERT INTO users (id, email, password_hash, email_verified, email_verify_token) \
         VALUES (?, ?, ?, 0, ?)",
    )
    .bind(&user_id)
    .bind(&email)
    .bind(&hashed)
    .bind(&verify_token_hash)
    .execute(pool.get_ref())
    .await?;

    if let Err(e) = send_verification_email(&config, &email, &verify_token).await {
        log::error!("Failed to send verification email to {}: {:?}", email, e);
    }

    Ok(HttpResponse::Accepted().json(serde_json::json!({
        "message": "Account created. Check your inbox to verify your email before signing in."
    })))
}

pub async fn login(
    pool: web::Data<SqlitePool>,
    config: web::Data<Arc<Config>>,
    req: web::Json<LoginRequest>,
) -> Result<impl Responder, AppError> {
    let req = req.into_inner();
    let email = req.email.trim().to_lowercase();

    let user: Option<User> = sqlx::query_as(
        "SELECT id, email, password_hash, created_at, email_verified, email_verify_token, \
         password_reset_token, password_reset_expires_at \
         FROM users WHERE email = ?",
    )
    .bind(&email)
    .fetch_optional(pool.get_ref())
    .await?;

    match user {
        Some(u) => {
            let has_password = !u.password_hash.is_empty();
            let target_hash = if has_password {
                u.password_hash.clone()
            } else {
                DUMMY_HASH.to_string()
            };
            let password = req.password;

            // Offload CPU-intensive verification to a blocking thread.
            let valid = tokio::task::spawn_blocking(move || verify(&password, &target_hash))
                .await
                .map_err(|e| AppError::internal(format!("Task join error: {}", e)))?
                .map_err(|e| AppError::internal(e.to_string()))?;

            if valid && has_password && u.email_verified {
                let resp = make_auth_response(pool.get_ref(), u, &config).await?;
                Ok(HttpResponse::Ok().json(resp))
            } else {
                // Generic error for wrong password, social accounts, or unverified accounts
                // to prevent account enumeration and metadata leakage.
                Err(AppError::unauthorized("Invalid credentials"))
            }
        }
        None => {
            let password = req.password;
            // Constant-time-ish dummy verification to mitigate timing attacks.
            let _ = tokio::task::spawn_blocking(move || {
                let _ = verify(&password, DUMMY_HASH);
            })
            .await;
            Err(AppError::unauthorized("Invalid credentials"))
        }
    }
}

pub async fn verify_email(
    pool: web::Data<SqlitePool>,
    config: web::Data<Arc<Config>>,
    query: web::Query<VerifyQuery>,
) -> HttpResponse {
    let token = match query.token.as_deref() {
        Some(t) if !t.is_empty() => t,
        _ => return oauth_error_redirect(&config.app_base_url, "Missing verification token"),
    };
    let token_hash = hash_token(token);

    let user: Option<User> = match sqlx::query_as(
        "SELECT id, email, password_hash, created_at, email_verified, email_verify_token, \
         password_reset_token, password_reset_expires_at \
         FROM users WHERE email_verify_token = ? OR email_verify_token = ?",
    )
    .bind(&token_hash)
    .bind(token)
    .fetch_optional(pool.get_ref())
    .await
    {
        Ok(u) => u,
        Err(e) => {
            log::error!("DB error in verify_email: {}", e);
            return oauth_error_redirect(&config.app_base_url, "Verification failed");
        }
    };

    match user {
        None => oauth_error_redirect(
            &config.app_base_url,
            "Invalid or already used verification link",
        ),
        Some(u) if u.email_verified => oauth_error_redirect(
            &config.app_base_url,
            "This account is already verified",
        ),
        Some(u) => {
            if let Err(e) = sqlx::query(
                "UPDATE users SET email_verified = 1, email_verify_token = NULL WHERE id = ?",
            )
            .bind(&u.id)
            .execute(pool.get_ref())
            .await
            {
                log::error!("DB error setting email_verified: {}", e);
                return oauth_error_redirect(&config.app_base_url, "Verification failed");
            }

            let jwt = match make_jwt(&u.id, &config) {
                Ok(j) => j,
                Err(e) => {
                    log::error!("JWT error after verify: {:?}", e);
                    return oauth_error_redirect(&config.app_base_url, "Verification failed");
                }
            };

            let refresh_token = match create_refresh_token(pool.get_ref(), &u.id).await {
                Ok(rt) => rt,
                Err(e) => {
                    log::error!("Refresh token error after verify: {:?}", e);
                    return oauth_error_redirect(&config.app_base_url, "Verification failed");
                }
            };

            oauth_success_redirect(&config.app_base_url, &jwt, &refresh_token, &u.email)
        }
    }
}

fn resend_ok() -> HttpResponse {
    HttpResponse::Ok().json(serde_json::json!({
        "message": "If an unverified account exists for that email, a new verification link has been sent."
    }))
}

pub async fn resend_verification(
    pool: web::Data<SqlitePool>,
    config: web::Data<Arc<Config>>,
    req: web::Json<ResendRequest>,
) -> HttpResponse {
    let email = req.email.trim().to_lowercase();

    let user: Option<User> = match sqlx::query_as(
        "SELECT id, email, password_hash, created_at, email_verified, email_verify_token, \
         password_reset_token, password_reset_expires_at \
         FROM users WHERE email = ?",
    )
    .bind(&email)
    .fetch_optional(pool.get_ref())
    .await
    {
        Ok(u) => u,
        Err(e) => {
            log::error!("DB error in resend_verification: {}", e);
            return resend_ok();
        }
    };

    let user = match user {
        Some(u) if !u.email_verified => u,
        _ => return resend_ok(),
    };

    let new_token = Uuid::new_v4().to_string();
    let new_token_hash = hash_token(&new_token);

    if let Err(e) = sqlx::query("UPDATE users SET email_verify_token = ? WHERE id = ?")
        .bind(&new_token_hash)
        .bind(&user.id)
        .execute(pool.get_ref())
        .await
    {
        log::error!("DB error updating verify token: {}", e);
        return resend_ok();
    }

    if let Err(e) = send_verification_email(&config, &email, &new_token).await {
        log::error!("Email send failed in resend: {:?}", e);
    }

    resend_ok()
}

// ── Password reset handlers ───────────────────────────────────────────────────

pub async fn forgot_password(
    pool: web::Data<SqlitePool>,
    config: web::Data<Arc<Config>>,
    req: web::Json<ForgotPasswordRequest>,
) -> Result<impl Responder, AppError> {
    let email = req.email.trim().to_lowercase();

    let user: Option<User> = sqlx::query_as(
        "SELECT id, email, password_hash, created_at, email_verified, email_verify_token, \
         password_reset_token, password_reset_expires_at \
         FROM users WHERE email = ?",
    )
    .bind(&email)
    .fetch_optional(pool.get_ref())
    .await?;

    if let Some(u) = user {
        let reset_token = Uuid::new_v4().to_string();
        let reset_token_hash = hash_token(&reset_token);
        let expires_at = chrono::Utc::now().naive_utc() + chrono::Duration::hours(1);

        if let Err(e) = sqlx::query(
            "UPDATE users SET password_reset_token = ?, password_reset_expires_at = ? WHERE id = ?",
        )
        .bind(&reset_token_hash)
        .bind(expires_at)
        .bind(&u.id)
        .execute(pool.get_ref())
        .await
        {
            log::error!("DB error storing reset token: {}", e);
            // Still return 200 to prevent enumeration
        } else if let Err(e) = send_reset_email(&config, &email, &reset_token).await {
            log::error!("Reset email send failed: {:?}", e);
        }
    }

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "message": "If an account with that email exists, a reset link has been sent."
    })))
}

pub async fn forgot_password_redirect(
    pool: web::Data<SqlitePool>,
    config: web::Data<Arc<Config>>,
    query: web::Query<VerifyQuery>,
) -> HttpResponse {
    let token = match query.token.as_deref() {
        Some(t) if !t.is_empty() => t,
        _ => {
            return HttpResponse::Found()
                .insert_header((
                    "Location",
                    format!(
                        "{}/heaas/login#error=Invalid+or+expired+reset+link",
                        config.app_base_url
                    ),
                ))
                .finish()
        }
    };
    let token_hash = hash_token(token);

    let user: Option<User> = match sqlx::query_as(
        "SELECT id, email, password_hash, created_at, email_verified, email_verify_token, \
         password_reset_token, password_reset_expires_at \
         FROM users WHERE password_reset_token = ? OR password_reset_token = ?",
    )
    .bind(&token_hash)
    .bind(token)
    .fetch_optional(pool.get_ref())
    .await
    {
        Ok(u) => u,
        Err(e) => {
            log::error!("DB error in forgot_password_redirect: {}", e);
            return HttpResponse::Found()
                .insert_header((
                    "Location",
                    format!(
                        "{}/heaas/login#error=Invalid+or+expired+reset+link",
                        config.app_base_url
                    ),
                ))
                .finish();
        }
    };

    match user {
        None => HttpResponse::Found()
            .insert_header((
                "Location",
                format!(
                    "{}/heaas/login#error=Invalid+or+expired+reset+link",
                    config.app_base_url
                ),
            ))
            .finish(),
        Some(u) => {
            let now = chrono::Utc::now().naive_utc();
            let expired = u
                .password_reset_expires_at
                .map(|exp| exp < now)
                .unwrap_or(true);

            if expired {
                HttpResponse::Found()
                    .insert_header((
                        "Location",
                        format!(
                            "{}/heaas/login#error=Invalid+or+expired+reset+link",
                            config.app_base_url
                        ),
                    ))
                    .finish()
            } else {
                HttpResponse::Found()
                    .insert_header((
                        "Location",
                        format!(
                            "{}/heaas/login#reset_token={}",
                            config.app_base_url, token
                        ),
                    ))
                    .finish()
            }
        }
    }
}

pub async fn reset_password(
    pool: web::Data<SqlitePool>,
    req: web::Json<ResetPasswordRequest>,
) -> Result<impl Responder, AppError> {
    let req = req.into_inner();
    let token_hash = hash_token(&req.token);

    let user: Option<User> = sqlx::query_as(
        "SELECT id, email, password_hash, created_at, email_verified, email_verify_token, \
         password_reset_token, password_reset_expires_at \
         FROM users WHERE password_reset_token = ? OR password_reset_token = ?",
    )
    .bind(&token_hash)
    .bind(&req.token)
    .fetch_optional(pool.get_ref())
    .await?;

    let u = match user {
        None => return Err(AppError::bad_request("Invalid or expired reset link")),
        Some(u) => u,
    };

    let now = chrono::Utc::now().naive_utc();
    let expired = u
        .password_reset_expires_at
        .map(|exp| exp < now)
        .unwrap_or(true);

    if expired {
        return Err(AppError::bad_request("Reset link has expired"));
    }

    if !is_strong_password(&req.new_password) {
        return Err(AppError::bad_request(PASSWORD_REQUIREMENTS));
    }

    let new_password = req.new_password;
    let new_hash = tokio::task::spawn_blocking(move || hash(&new_password, DEFAULT_COST))
        .await
        .map_err(|e| AppError::internal(format!("Task join error: {}", e)))?
        .map_err(|e| AppError::internal(e.to_string()))?;

    sqlx::query(
        "UPDATE users SET password_hash = ?, password_reset_token = NULL, \
         password_reset_expires_at = NULL WHERE id = ?",
    )
    .bind(&new_hash)
    .bind(&u.id)
    .execute(pool.get_ref())
    .await?;

    sqlx::query("DELETE FROM refresh_tokens WHERE user_id = ?")
        .bind(&u.id)
        .execute(pool.get_ref())
        .await?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "message": "Password reset successfully. You can now sign in."
    })))
}

// ── Token refresh and logout ──────────────────────────────────────────────────

pub async fn refresh_token_endpoint(
    pool: web::Data<SqlitePool>,
    config: web::Data<Arc<Config>>,
    req: web::Json<RefreshRequest>,
) -> Result<impl Responder, AppError> {
    let hash_val = hash_token(&req.refresh_token);

    let row: Option<(String, String, chrono::NaiveDateTime)> = sqlx::query_as(
        "SELECT id, user_id, expires_at FROM refresh_tokens WHERE token_hash = ?",
    )
    .bind(&hash_val)
    .fetch_optional(pool.get_ref())
    .await?;

    let (token_id, user_id, expires_at) = match row {
        None => return Err(AppError::unauthorized("Invalid refresh token")),
        Some(r) => r,
    };

    let now = chrono::Utc::now().naive_utc();
    if expires_at < now {
        let _ = sqlx::query("DELETE FROM refresh_tokens WHERE id = ?")
            .bind(&token_id)
            .execute(pool.get_ref())
            .await;
        return Err(AppError::unauthorized("Refresh token has expired"));
    }

    // Rotate: issue new token before deleting old one so a failed insert doesn't strand the user
    let new_jwt = make_jwt(&user_id, &config)?;
    let new_refresh = create_refresh_token(pool.get_ref(), &user_id).await?;

    let _ = sqlx::query("DELETE FROM refresh_tokens WHERE id = ?")
        .bind(&token_id)
        .execute(pool.get_ref())
        .await;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "token": new_jwt,
        "refresh_token": new_refresh,
    })))
}

pub async fn logout(
    pool: web::Data<SqlitePool>,
    req: web::Json<LogoutRequest>,
) -> Result<impl Responder, AppError> {
    let hash_val = hash_token(&req.refresh_token);
    sqlx::query("DELETE FROM refresh_tokens WHERE token_hash = ?")
        .bind(&hash_val)
        .execute(pool.get_ref())
        .await?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "message": "Logged out"
    })))
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

    let email_lower = email.to_lowercase();
    let by_email: Option<(String,)> =
        sqlx::query_as("SELECT id FROM users WHERE email = ?")
            .bind(&email_lower)
            .fetch_optional(pool)
            .await?;

    let user_id = if let Some((uid,)) = by_email {
        // Link OAuth to existing account; ensure it is marked verified
        sqlx::query("UPDATE users SET email_verified = 1 WHERE id = ?")
            .bind(&uid)
            .execute(pool)
            .await?;
        uid
    } else {
        let new_id = Uuid::new_v4().to_string();
        sqlx::query(
            "INSERT INTO users (id, email, password_hash, email_verified) VALUES (?, ?, '', 1)",
        )
        .bind(&new_id)
        .bind(&email_lower)
        .execute(pool)
        .await?;
        new_id
    };

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

fn oauth_success_redirect(base_url: &str, token: &str, refresh_token: &str, email: &str) -> HttpResponse {
    HttpResponse::Found()
        .insert_header((
            "Location",
            format!(
                "{}/heaas/login#token={}&refresh_token={}&email={}",
                base_url, token, refresh_token, email
            ),
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

    let jwt = match make_jwt(&user_id, &config) {
        Ok(t) => t,
        Err(e) => {
            log::error!("JWT generation: {:?}", e);
            return oauth_error_redirect(&config.app_base_url, "Authentication failed");
        }
    };

    let refresh_token = match create_refresh_token(pool.get_ref(), &user_id).await {
        Ok(rt) => rt,
        Err(e) => {
            log::error!("Refresh token creation (google): {:?}", e);
            return oauth_error_redirect(&config.app_base_url, "Authentication failed");
        }
    };

    oauth_success_redirect(&config.app_base_url, &jwt, &refresh_token, &user_info.email)
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

    let jwt = match make_jwt(&user_id, &config) {
        Ok(t) => t,
        Err(e) => {
            log::error!("JWT generation: {:?}", e);
            return oauth_error_redirect(&config.app_base_url, "Authentication failed");
        }
    };

    let refresh_token = match create_refresh_token(pool.get_ref(), &user_id).await {
        Ok(rt) => rt,
        Err(e) => {
            log::error!("Refresh token creation (github): {:?}", e);
            return oauth_error_redirect(&config.app_base_url, "Authentication failed");
        }
    };

    oauth_success_redirect(&config.app_base_url, &jwt, &refresh_token, &email)
}
