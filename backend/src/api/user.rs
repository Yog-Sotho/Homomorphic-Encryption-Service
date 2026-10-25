use crate::api::validation::{is_strong_password, PASSWORD_REQUIREMENTS};
use crate::config::Config;
use crate::errors::AppError;
use actix_web::{web, HttpMessage, HttpRequest, HttpResponse, Responder};
use bcrypt::{hash, verify, DEFAULT_COST};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use std::sync::Arc;

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

/// Row of the combined profile query in `get_me`.
#[derive(sqlx::FromRow)]
struct MeRow {
    id: String,
    email: String,
    email_verified: bool,
    has_password: bool,
    created_at: chrono::NaiveDateTime,
    oauth_providers: Option<String>,
    daily_usage_count: i64,
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
    let row: Option<MeRow> = sqlx::query_as(
        "SELECT \
            u.id, \
            u.email, \
            u.email_verified, \
            u.password_hash != '' AS has_password, \
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

    let row = row.ok_or_else(|| AppError::not_found("User not found"))?;

    let oauth_providers = match row.oauth_providers {
        Some(s) => s
            .split(',')
            .map(|p| p.to_string())
            .filter(|p| !p.is_empty())
            .collect(),
        None => vec![],
    };

    Ok(HttpResponse::Ok().json(MeResponse {
        id: row.id,
        email: row.email,
        email_verified: row.email_verified,
        has_password: row.has_password,
        created_at: row.created_at,
        oauth_providers,
        daily_usage: DailyUsage {
            count: row.daily_usage_count,
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
        return Err(AppError::bad_request(
            "Password exceeds maximum allowed length of 128 characters",
        ));
    }

    let user_id = req
        .extensions()
        .get::<String>()
        .cloned()
        .ok_or_else(|| AppError::unauthorized("Not authenticated"))?;

    let row: Option<(String,)> = sqlx::query_as("SELECT password_hash FROM users WHERE id = ?")
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

    let row: Option<(String,)> = sqlx::query_as("SELECT password_hash FROM users WHERE id = ?")
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

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{body::to_bytes, test::TestRequest};

    fn test_config() -> Arc<Config> {
        Arc::new(Config {
            database_url: "sqlite::memory:".to_string(),
            jwt_secret: "test_secret_key_at_least_32_bytes_long".to_string(),
            server_addr: "127.0.0.1:8080".to_string(),
            he_pool_size: 1,
            app_base_url: "http://localhost:3000".to_string(),
            google_client_id: None,
            google_client_secret: None,
            github_client_id: None,
            github_client_secret: None,
            smtp_host: None,
            smtp_port: 587,
            smtp_user: None,
            smtp_pass: None,
            from_email: "noreply@heaas.local".to_string(),
            daily_compute_quota: 100,
        })
    }

    async fn me_json(pool: &SqlitePool, user_id: &str) -> serde_json::Value {
        let req = TestRequest::default().to_http_request();
        req.extensions_mut().insert(user_id.to_string());
        let resp = get_me(
            web::Data::new(pool.clone()),
            web::Data::new(test_config()),
            req.clone(),
        )
        .await
        .unwrap()
        .respond_to(&req)
        .map_into_boxed_body();
        assert_eq!(resp.status(), 200);
        let body = to_bytes(resp.into_body()).await.expect("readable body");
        serde_json::from_slice(&body).unwrap()
    }

    #[tokio::test]
    async fn get_me_combines_profile_providers_and_usage() {
        let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
        sqlx::migrate!("./migrations").run(&pool).await.unwrap();
        let today = chrono::Utc::now().format("%Y-%m-%d").to_string();

        sqlx::query("INSERT INTO users (id, email, password_hash, email_verified) VALUES ('u1', 'a@example.com', 'hash', 1), ('u2', 'b@example.com', '', 1)")
            .execute(&pool).await.unwrap();
        sqlx::query("INSERT INTO oauth_accounts (id, user_id, provider, provider_id) VALUES ('o1', 'u2', 'google', 'g'), ('o2', 'u2', 'github', 'h')")
            .execute(&pool).await.unwrap();
        sqlx::query("INSERT INTO daily_compute_usage (user_id, date, count) VALUES ('u2', ?, 7), ('u2', '2000-01-01', 99)")
            .bind(&today).execute(&pool).await.unwrap();

        let password_user = me_json(&pool, "u1").await;
        assert_eq!(password_user["email"], "a@example.com");
        assert_eq!(password_user["has_password"], true);
        assert_eq!(password_user["oauth_providers"], serde_json::json!([]));
        assert_eq!(password_user["daily_usage"]["count"], 0);
        assert!(password_user.get("password_hash").is_none());

        let social_user = me_json(&pool, "u2").await;
        assert_eq!(social_user["has_password"], false);
        let mut providers: Vec<String> =
            serde_json::from_value(social_user["oauth_providers"].clone()).unwrap();
        providers.sort();
        assert_eq!(providers, ["github", "google"]);
        // Only today's usage counts toward the quota display.
        assert_eq!(social_user["daily_usage"]["count"], 7);
        assert_eq!(social_user["daily_usage"]["quota"], 100);
    }
}
