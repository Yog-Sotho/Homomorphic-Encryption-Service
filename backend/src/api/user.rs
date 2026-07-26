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

#[derive(Deserialize)]
pub struct ChangePasswordRequest {
    pub current_password: String,
    pub new_password: String,
}

#[derive(Deserialize)]
pub struct DeleteAccountRequest {
    pub password: String,
}

#[derive(sqlx::FromRow)]
struct GetMeRow {
    id: String,
    email: String,
    email_verified: bool,
    password_hash: String,
    created_at: chrono::NaiveDateTime,
    oauth_providers: Option<String>,
    daily_count: i64,
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

    // OPTIMIZATION: Consolidated 3 separate sequential database queries (fetching user,
    // OAuth accounts, and daily compute usage) into 1 single database query using LEFT JOIN,
    // COALESCE, and GROUP_CONCAT. This reduces database roundtrips from 3 to 1, significantly
    // improving response times and query overhead on a frequently accessed endpoint.
    let row: Option<GetMeRow> = sqlx::query_as(
        "SELECT \
            u.id, \
            u.email, \
            u.email_verified, \
            u.password_hash, \
            u.created_at, \
            GROUP_CONCAT(oa.provider) AS oauth_providers, \
            COALESCE(MAX(dcu.count), 0) AS daily_count \
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

    let r = match row {
        None => return Err(AppError::not_found("User not found")),
        Some(inner) => inner,
    };

    let oauth_providers: Vec<String> = match r.oauth_providers {
        Some(ref s) if !s.is_empty() => s.split(',').map(|p| p.to_string()).collect(),
        _ => vec![],
    };

    Ok(HttpResponse::Ok().json(MeResponse {
        id: r.id,
        email: r.email,
        email_verified: r.email_verified,
        has_password: !r.password_hash.is_empty(),
        created_at: r.created_at,
        oauth_providers,
        daily_usage: DailyUsage {
            count: r.daily_count,
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
    use actix_web::test;

    #[tokio::test]
    async fn test_get_me_consolidated_query() {
        let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
        sqlx::migrate!("./migrations").run(&pool).await.unwrap();

        let config = Arc::new(Config {
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
        });

        let user_id = "user-123".to_string();
        let email = "user@example.com".to_string();
        let password_hash = "some_hash".to_string();

        // Insert a test user
        sqlx::query(
            "INSERT INTO users (id, email, password_hash, email_verified) VALUES (?, ?, ?, 1)",
        )
        .bind(&user_id)
        .bind(&email)
        .bind(&password_hash)
        .execute(&pool)
        .await
        .unwrap();

        // Insert linked oauth accounts
        sqlx::query(
            "INSERT INTO oauth_accounts (id, user_id, provider, provider_id, provider_email) VALUES (?, ?, ?, ?, ?)"
        )
        .bind("oa-1")
        .bind(&user_id)
        .bind("google")
        .bind("g-123")
        .bind("g@example.com")
        .execute(&pool)
        .await
        .unwrap();

        sqlx::query(
            "INSERT INTO oauth_accounts (id, user_id, provider, provider_id, provider_email) VALUES (?, ?, ?, ?, ?)"
        )
        .bind("oa-2")
        .bind(&user_id)
        .bind("github")
        .bind("gh-123")
        .bind("gh@example.com")
        .execute(&pool)
        .await
        .unwrap();

        // Insert daily usage count
        let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
        sqlx::query("INSERT INTO daily_compute_usage (user_id, date, count) VALUES (?, ?, ?)")
            .bind(&user_id)
            .bind(&today)
            .bind(42i64)
            .execute(&pool)
            .await
            .unwrap();

        // Setup actix environment
        let req = test::TestRequest::default().to_http_request();
        req.extensions_mut().insert(user_id.clone());

        let pool_data = web::Data::new(pool);
        let config_data = web::Data::new(config);

        let resp_result = get_me(pool_data, config_data, req).await;
        assert!(resp_result.is_ok());

        let response = resp_result
            .unwrap()
            .respond_to(&test::TestRequest::default().to_http_request());
        assert_eq!(response.status(), actix_web::http::StatusCode::OK);

        // Read and deserialize body
        let body = actix_web::body::to_bytes(response.into_body())
            .await
            .unwrap_or_else(|_| panic!("Failed to read body"));
        let me_resp: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(me_resp["id"], user_id);
        assert_eq!(me_resp["email"], email);
        assert!(me_resp["email_verified"].as_bool().unwrap());
        assert!(me_resp["has_password"].as_bool().unwrap());
        assert_eq!(me_resp["daily_usage"]["count"].as_i64().unwrap(), 42);
        assert_eq!(me_resp["daily_usage"]["quota"].as_i64().unwrap(), 100);
        assert_eq!(me_resp["daily_usage"]["date"], today);

        // Check that sorted / deduplicated / mapped provider strings are present
        let mut providers: Vec<String> = me_resp["oauth_providers"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_string())
            .collect();
        providers.sort();
        assert_eq!(providers, vec!["github".to_string(), "google".to_string()]);
    }

    #[tokio::test]
    async fn test_get_me_empty_relations() {
        let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
        sqlx::migrate!("./migrations").run(&pool).await.unwrap();

        let config = Arc::new(Config {
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
        });

        let user_id = "user-456".to_string();
        let email = "user2@example.com".to_string();
        let password_hash = "some_hash_2".to_string();

        // Insert a test user
        sqlx::query(
            "INSERT INTO users (id, email, password_hash, email_verified) VALUES (?, ?, ?, 1)",
        )
        .bind(&user_id)
        .bind(&email)
        .bind(&password_hash)
        .execute(&pool)
        .await
        .unwrap();

        // Setup actix environment
        let req = test::TestRequest::default().to_http_request();
        req.extensions_mut().insert(user_id.clone());

        let pool_data = web::Data::new(pool);
        let config_data = web::Data::new(config);

        let resp_result = get_me(pool_data, config_data, req).await;
        assert!(resp_result.is_ok());

        let response = resp_result
            .unwrap()
            .respond_to(&test::TestRequest::default().to_http_request());
        assert_eq!(response.status(), actix_web::http::StatusCode::OK);

        // Read and deserialize body
        let body = actix_web::body::to_bytes(response.into_body())
            .await
            .unwrap_or_else(|_| panic!("Failed to read body"));
        let me_resp: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(me_resp["id"], user_id);
        assert_eq!(me_resp["email"], email);
        assert!(me_resp["email_verified"].as_bool().unwrap());
        assert!(me_resp["has_password"].as_bool().unwrap());
        assert_eq!(me_resp["daily_usage"]["count"].as_i64().unwrap(), 0); // COALESCE fallback to 0
        assert_eq!(me_resp["daily_usage"]["quota"].as_i64().unwrap(), 100);

        // oauth_providers must be empty
        let providers: Vec<String> = me_resp["oauth_providers"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_string())
            .collect();
        assert!(providers.is_empty());
    }
}
