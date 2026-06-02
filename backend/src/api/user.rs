use actix_web::{web, HttpRequest, HttpResponse, Responder};
use sqlx::SqlitePool;
use serde::{Deserialize, Serialize};
use bcrypt::{hash, verify, DEFAULT_COST};
use std::sync::Arc;
use crate::config::Config;
use crate::errors::AppError;

#[derive(Serialize)]
pub struct MeResponse {
    pub id: String,
    pub email: String,
    pub email_verified: bool,
    pub created_at: chrono::NaiveDateTime,
    pub oauth_providers: Vec<String>,
    pub daily_usage: DailyUsage,
}

#[derive(Serialize)]
pub struct DailyUsage {
    pub count: i64,
    pub quota: i64,
    pub date: String,
}

#[derive(Deserialize)]
pub struct ChangePasswordRequest {
    pub current_password: String,
    pub new_password: String,
}

#[derive(Deserialize)]
pub struct DeleteAccountRequest {
    pub password: String,
}

fn is_valid_password(password: &str) -> bool {
    password.len() >= 8
        && password.chars().any(|c| c.is_uppercase())
        && password.chars().any(|c| c.is_lowercase())
        && password.chars().any(|c| c.is_ascii_digit())
}

pub async fn get_me(
    pool: web::Data<SqlitePool>,
    config: web::Data<Arc<Config>>,
    req: HttpRequest,
) -> Result<impl Responder, AppError> {
    let user_id = req
        .extensions()
        .get::<String>()
        .cloned()
        .ok_or_else(|| AppError::unauthorized("Not authenticated"))?;

    let row: Option<(String, String, bool, chrono::NaiveDateTime)> = sqlx::query_as(
        "SELECT id, email, email_verified, created_at FROM users WHERE id = ?",
    )
    .bind(&user_id)
    .fetch_optional(pool.get_ref())
    .await?;

    let (id, email, email_verified, created_at) = match row {
        None => return Err(AppError::not_found("User not found")),
        Some(r) => r,
    };

    let providers: Vec<(String,)> = sqlx::query_as(
        "SELECT provider FROM oauth_accounts WHERE user_id = ?",
    )
    .bind(&user_id)
    .fetch_all(pool.get_ref())
    .await?;

    let oauth_providers: Vec<String> = providers.into_iter().map(|(p,)| p).collect();

    let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
    let usage_row: Option<(i64,)> = sqlx::query_as(
        "SELECT count FROM daily_compute_usage WHERE user_id = ? AND date = ?",
    )
    .bind(&user_id)
    .bind(&today)
    .fetch_optional(pool.get_ref())
    .await?;

    let count = usage_row.map(|(c,)| c).unwrap_or(0);

    Ok(HttpResponse::Ok().json(MeResponse {
        id,
        email,
        email_verified,
        created_at,
        oauth_providers,
        daily_usage: DailyUsage {
            count,
            quota: config.daily_compute_quota as i64,
            date: today,
        },
    }))
}

pub async fn change_password(
    pool: web::Data<SqlitePool>,
    body: web::Json<ChangePasswordRequest>,
    req: HttpRequest,
) -> Result<impl Responder, AppError> {
    let user_id = req
        .extensions()
        .get::<String>()
        .cloned()
        .ok_or_else(|| AppError::unauthorized("Not authenticated"))?;

    let row: Option<(String,)> = sqlx::query_as(
        "SELECT password_hash FROM users WHERE id = ?",
    )
    .bind(&user_id)
    .fetch_optional(pool.get_ref())
    .await?;

    let (password_hash,) = match row {
        None => return Err(AppError::not_found("User not found")),
        Some(r) => r,
    };

    if password_hash.is_empty() {
        return Err(AppError::bad_request(
            "This account uses social login, no password to change",
        ));
    }

    let valid = verify(&body.current_password, &password_hash)
        .map_err(|e| AppError::internal(e.to_string()))?;
    if !valid {
        return Err(AppError::unauthorized("Current password is incorrect"));
    }

    if !is_valid_password(&body.new_password) {
        return Err(AppError::bad_request(
            "Password must be at least 8 characters and include uppercase, lowercase, and a digit.",
        ));
    }

    let new_hash = hash(&body.new_password, DEFAULT_COST)
        .map_err(|e| AppError::internal(e.to_string()))?;

    sqlx::query("UPDATE users SET password_hash = ? WHERE id = ?")
        .bind(&new_hash)
        .bind(&user_id)
        .execute(pool.get_ref())
        .await?;

    sqlx::query("DELETE FROM refresh_tokens WHERE user_id = ?")
        .bind(&user_id)
        .execute(pool.get_ref())
        .await?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "message": "Password changed. Please sign in again."
    })))
}

pub async fn delete_account(
    pool: web::Data<SqlitePool>,
    body: web::Json<DeleteAccountRequest>,
    req: HttpRequest,
) -> Result<impl Responder, AppError> {
    let user_id = req
        .extensions()
        .get::<String>()
        .cloned()
        .ok_or_else(|| AppError::unauthorized("Not authenticated"))?;

    let row: Option<(String,)> = sqlx::query_as(
        "SELECT password_hash FROM users WHERE id = ?",
    )
    .bind(&user_id)
    .fetch_optional(pool.get_ref())
    .await?;

    let (password_hash,) = match row {
        None => return Err(AppError::not_found("User not found")),
        Some(r) => r,
    };

    if !password_hash.is_empty() {
        let valid = verify(&body.password, &password_hash)
            .map_err(|e| AppError::internal(e.to_string()))?;
        if !valid {
            return Err(AppError::forbidden("Invalid password"));
        }
    }

    sqlx::query("DELETE FROM jobs WHERE user_id = ?")
        .bind(&user_id)
        .execute(pool.get_ref())
        .await?;

    sqlx::query("DELETE FROM users WHERE id = ?")
        .bind(&user_id)
        .execute(pool.get_ref())
        .await?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "message": "Account deleted successfully."
    })))
}
