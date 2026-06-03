use actix_web::{web, HttpResponse, Responder};
use serde::{Deserialize, Serialize};
use jsonwebtoken::{encode, Header, EncodingKey};
use bcrypt::{hash, verify, DEFAULT_COST};
use uuid::Uuid;
use sqlx::SqlitePool;
use crate::db::models::User;
use crate::error::AppError;

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
pub struct AuthResponse {
    pub token: String,
    pub user: User,
}

pub async fn register(
    pool: web::Data<SqlitePool>,
    req: web::Json<RegisterRequest>,
) -> Result<impl Responder, AppError> {
    let email = req.email.trim().to_lowercase();
    let password = &req.password;

    if email.is_empty() || password.len() < 8 {
        return Err(AppError { message: "Invalid input".to_string() });
    }

    let hashed_password = hash(password, DEFAULT_COST).map_err(|e| AppError { message: e.to_string() })?;
    let user_id = Uuid::new_v4().to_string();

    sqlx::query!(
        "INSERT INTO users (id, email, password_hash) VALUES (?, ?, ?)",
        user_id,
        email,
        hashed_password
    )
    .execute(pool.get_ref())
    .await?;

    let user = User {
        id: user_id.clone(),
        email: email.clone(),
        password_hash: "".to_string(),
        created_at: chrono::Utc::now().naive_utc(),
    };

    let claims = crate::middleware::jwt::Claims {
        sub: user_id,
        exp: (chrono::Utc::now() + chrono::Duration::hours(1)).timestamp() as usize,
    };

    let secret = std::env::var("JWT_SECRET").unwrap_or_else(|_| "super-secret-key-2026-change-in-prod".to_string());
    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_ref()),
    ).map_err(|e| AppError { message: e.to_string() })?;

    Ok(HttpResponse::Created().json(AuthResponse { token, user }))
}

pub async fn login(
    pool: web::Data<SqlitePool>,
    req: web::Json<LoginRequest>,
) -> Result<impl Responder, AppError> {
    let email = req.email.trim().to_lowercase();
    
    let user = sqlx::query_as!(
        User,
        "SELECT id, email, password_hash, created_at FROM users WHERE email = ?",
        email
    )
    .fetch_optional(pool.get_ref())
    .await?;

    match user {
        Some(u) => {
            if verify(&req.password, &u.password_hash).unwrap_or(false) {
                let claims = crate::middleware::jwt::Claims {
                    sub: u.id.clone(),
                    exp: (chrono::Utc::now() + chrono::Duration::hours(1)).timestamp() as usize,
                };
                
                let secret = std::env::var("JWT_SECRET").unwrap_or_else(|_| "super-secret-key-2026-change-in-prod".to_string());
                let token = encode(
                    &Header::default(),
                    &claims,
                    &EncodingKey::from_secret(secret.as_ref()),
                ).map_err(|e| AppError { message: e.to_string() })?;

                Ok(HttpResponse::Ok().json(AuthResponse { token, user: u }))
            } else {
                Err(AppError { message: "Invalid credentials".to_string() })
            }
        }
        None => Err(AppError { message: "Invalid credentials".to_string() }),
    }
}
