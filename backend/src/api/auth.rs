use actix_web::{web, HttpResponse, Responder};
use serde::{Deserialize, Serialize};
use jsonwebtoken::{encode, Header, EncodingKey};
use bcrypt::{hash, verify, DEFAULT_COST};
use uuid::Uuid;
use sqlx::SqlitePool;
use std::sync::Arc;
use crate::config::Config;
use crate::db::models::User;
use crate::errors::AppError;

/// A bcrypt-hashed dummy password used to equalise timing when a user is not
/// found, preventing a user-enumeration timing oracle.
const DUMMY_HASH: &str = "$2b$12$WXQEq5YBFxVkx2j5bVBNNOLIGgWS0DVOvt0gp8b2ioY6O3S9XEi/6";

/// Validates that an email address has the minimal structure:
///   - non-empty local part
///   - an '@' separator
///   - a domain that contains at least one '.'
fn is_valid_email(email: &str) -> bool {
    if let Some(at_pos) = email.find('@') {
        let local = &email[..at_pos];
        let domain = &email[at_pos + 1..];
        !local.is_empty() && domain.contains('.')
    } else {
        false
    }
}

/// Validates that a password meets the minimum policy:
///   - at least 8 characters long
///   - contains at least one uppercase letter
///   - contains at least one lowercase letter
///   - contains at least one digit
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

/// Public representation of a user — never includes the password hash.
#[derive(Serialize)]
pub struct UserPublic {
    pub id: String,
    pub email: String,
    pub created_at: chrono::NaiveDateTime,
}

impl From<User> for UserPublic {
    fn from(u: User) -> Self {
        UserPublic {
            id: u.id,
            email: u.email,
            created_at: u.created_at,
        }
    }
}

#[derive(Serialize)]
pub struct AuthResponse {
    pub token: String,
    pub user: UserPublic,
}

fn make_jwt(user_id: &str, config: &Config) -> Result<String, AppError> {
    let claims = crate::middleware::jwt::Claims {
        sub: user_id.to_string(),
        exp: (chrono::Utc::now() + chrono::Duration::hours(1)).timestamp() as usize,
    };
    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(config.jwt_secret.as_ref()),
    )?;
    Ok(token)
}

pub async fn register(
    pool: web::Data<SqlitePool>,
    config: web::Data<Arc<Config>>,
    req: web::Json<RegisterRequest>,
) -> Result<impl Responder, AppError> {
    let email = req.email.trim().to_lowercase();
    let password = &req.password;

    if !is_valid_email(&email) {
        return Err(AppError::bad_request(
            "Invalid email address. Provide a valid email (e.g. user@example.com).",
        ));
    }

    if !is_valid_password(password) {
        return Err(AppError::bad_request(
            "Password must be at least 8 characters and include uppercase, lowercase, and a digit.",
        ));
    }

    let hashed_password = hash(password, DEFAULT_COST)
        .map_err(|e| AppError::internal(e.to_string()))?;
    let user_id = Uuid::new_v4().to_string();

    sqlx::query(
        "INSERT INTO users (id, email, password_hash) VALUES (?, ?, ?)",
    )
    .bind(&user_id)
    .bind(&email)
    .bind(&hashed_password)
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
            // B4 — bubble up real bcrypt errors instead of swallowing them
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
            // S3 — constant-time path: always run bcrypt even when user not found
            let _ = verify(&req.password, DUMMY_HASH);
            Err(AppError::unauthorized("Invalid credentials"))
        }
    }
}
