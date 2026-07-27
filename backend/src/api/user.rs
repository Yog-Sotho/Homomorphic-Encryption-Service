use actix_web::{web, HttpMessage, HttpRequest, HttpResponse, Responder};
use sqlx::SqlitePool;
use serde::{Deserialize, Serialize};
use bcrypt::{hash, verify, DEFAULT_COST};
use std::sync::Arc;
use crate::config::Config;
use crate::errors::AppError;
use crate::api::validation::{is_strong_password, PASSWORD_REQUIREMENTS};

#[derive(Serialize)]
pub struct MeResponse {
    pub id: String,
    pub email: String,
    pub email_verified: bool,
    pub has_password: bool,
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

    let today = chrono::Utc::now().format("%Y-%m-%d").to_string();

    // Optimized: Combined fetching of user details, oauth providers, and daily usage
    // into a single query using LEFT JOIN and GROUP_CONCAT to reduce DB roundtrips from 3 to 1.
    let row: Option<(String, String, bool, String, chrono::NaiveDateTime, Option<String>, i64)> = sqlx::query_as(
        "SELECT \
            u.id, \
            u.email, \
            u.email_verified, \
            u.password_hash, \
            u.created_at, \
            GROUP_CONCAT(DISTINCT oa.provider) AS oauth_providers, \
            COALESCE(MAX(dcu.count), 0) AS daily_usage_count \
         FROM users u \
         LEFT JOIN oauth_accounts oa ON u.id = oa.user_id \
         LEFT JOIN daily_compute_usage dcu ON u.id = dcu.user_id AND dcu.date = ? \
         WHERE u.id = ? \
         GROUP BY u.id",
    )
    .bind(&today)
    .bind(&user_id)
    .fetch_optional(pool.get_ref())
    .await?;

    let (id, email, email_verified, password_hash, created_at, oauth_providers_raw, count) = match row {
        None => return Err(AppError::not_found("User not found")),
        Some(r) => r,
    };

    let oauth_providers = match oauth_providers_raw {
        Some(s) => s.split(',').map(|p| p.to_string()).filter(|p| !p.is_empty()).collect(),
        None => vec![],
    };

    Ok(HttpResponse::Ok().json(MeResponse {
        id,
        email,
        email_verified,
        has_password: !password_hash.is_empty(),
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
    if body.current_password.len() > 128 || body.new_password.len() > 128 {
        return Err(AppError::bad_request("Password exceeds maximum allowed length of 128 characters"));
    }

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

    // Offload CPU-intensive bcrypt verification to a blocking thread.
    let current_password = body.current_password.clone();
    let valid = tokio::task::spawn_blocking(move || verify(current_password, &password_hash))
        .await
        .map_err(|e| AppError::internal(format!("Task join error: {}", e)))?
        .map_err(|e| AppError::internal(e.to_string()))?;
    if !valid {
        return Err(AppError::unauthorized("Current password is incorrect"));
    }

    if !is_strong_password(&body.new_password) {
        return Err(AppError::bad_request(PASSWORD_REQUIREMENTS));
    }

    // Offload CPU-intensive bcrypt hashing to a blocking thread.
    let new_password = body.new_password.clone();
    let new_hash = tokio::task::spawn_blocking(move || hash(new_password, DEFAULT_COST))
        .await
        .map_err(|e| AppError::internal(format!("Task join error: {}", e)))?
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
        if body.password.len() > 128 {
            return Err(AppError::forbidden("Invalid password"));
        }
        // Offload CPU-intensive bcrypt verification to a blocking thread.
        let password = body.password.clone();
        let valid = tokio::task::spawn_blocking(move || verify(password, &password_hash))
            .await
            .map_err(|e| AppError::internal(format!("Task join error: {}", e)))?
            .map_err(|e| AppError::internal(e.to_string()))?;
        if !valid {
            return Err(AppError::forbidden("Invalid password"));
        }
    }

    // Revoke all sessions immediately (belt-and-suspenders alongside FK cascade)
    sqlx::query("DELETE FROM refresh_tokens WHERE user_id = ?")
        .bind(&user_id)
        .execute(pool.get_ref())
        .await?;

    sqlx::query("DELETE FROM jobs WHERE user_id = ?")
        .bind(&user_id)
        .execute(pool.get_ref())
        .await?;

    sqlx::query("DELETE FROM oauth_accounts WHERE user_id = ?")
        .bind(&user_id)
        .execute(pool.get_ref())
        .await?;

    sqlx::query("DELETE FROM daily_compute_usage WHERE user_id = ?")
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
