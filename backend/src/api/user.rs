use crate::api::auth::password::{hash_password, verify_password};
use crate::api::auth::session::{clear_refresh_cookie, revoke_all};
use crate::api::validation::{is_strong_password, PASSWORD_REQUIREMENTS};
use crate::config::Config;
use crate::crypto::keys::KeyStore;
use crate::errors::AppError;
use crate::jobs::store::JobStore;
use crate::middleware::jwt::AuthTime;
use actix_web::{web, HttpMessage, HttpRequest, HttpResponse, Responder};
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
    let user_id = user_id(&req)?;

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

/// The signed-in user's id, set by the JWT middleware.
fn user_id(req: &HttpRequest) -> Result<String, AppError> {
    req.extensions()
        .get::<String>()
        .cloned()
        .ok_or_else(|| AppError::unauthorized("Not authenticated"))
}

/// How recently an account without a password must have signed in to delete
/// itself: there is no password to re-enter, so a fresh sign-in stands in.
const RECENT_AUTH_SECS: i64 = 5 * 60;

fn signed_out_response(config: &Config, message: &str) -> HttpResponse {
    HttpResponse::Ok()
        .cookie(clear_refresh_cookie(config))
        .json(serde_json::json!({ "message": message }))
}

/// `PUT /api/v1/user/password` — changes the password and signs out every session.
pub async fn change_password(
    pool: web::Data<SqlitePool>,
    config: web::Data<Arc<Config>>,
    body: web::Json<ChangePasswordRequest>,
    req: HttpRequest,
) -> Result<HttpResponse, AppError> {
    let body = body.into_inner();
    if body.current_password.len() > 128 || body.new_password.len() > 128 {
        return Err(AppError::bad_request(
            "Password exceeds maximum allowed length of 128 characters",
        ));
    }
    let user_id = user_id(&req)?;

    let (password_hash,): (String,) =
        sqlx::query_as("SELECT password_hash FROM users WHERE id = ?")
            .bind(&user_id)
            .fetch_optional(pool.get_ref())
            .await?
            .ok_or_else(|| AppError::not_found("User not found"))?;
    if password_hash.is_empty() {
        return Err(AppError::bad_request(
            "This account uses social login, no password to change",
        ));
    }
    if !verify_password(body.current_password, password_hash.clone()).await? {
        return Err(AppError::unauthorized("Current password is incorrect"));
    }
    if !is_strong_password(&body.new_password) {
        return Err(AppError::bad_request(PASSWORD_REQUIREMENTS));
    }
    let new_hash = hash_password(body.new_password).await?;

    let mut tx = pool.begin().await?;
    // Only if the password is still the one just verified (no concurrent change).
    let changed =
        sqlx::query("UPDATE users SET password_hash = ? WHERE id = ? AND password_hash = ?")
            .bind(&new_hash)
            .bind(&user_id)
            .bind(&password_hash)
            .execute(&mut *tx)
            .await?;
    if changed.rows_affected() != 1 {
        return Err(AppError::conflict(
            "Your password was changed meanwhile. Try again.",
        ));
    }
    revoke_all(&mut *tx, &user_id).await?;
    tx.commit().await?;

    Ok(signed_out_response(
        &config,
        "Password changed. Please sign in again.",
    ))
}

/// `DELETE /api/v1/user/account` — deletes the account and everything it owns.
pub async fn delete_account(
    pool: web::Data<SqlitePool>,
    config: web::Data<Arc<Config>>,
    store: web::Data<KeyStore>,
    jobs: web::Data<JobStore>,
    body: web::Json<DeleteAccountRequest>,
    req: HttpRequest,
) -> Result<HttpResponse, AppError> {
    let user_id = user_id(&req)?;
    let (password_hash,): (String,) =
        sqlx::query_as("SELECT password_hash FROM users WHERE id = ?")
            .bind(&user_id)
            .fetch_optional(pool.get_ref())
            .await?
            .ok_or_else(|| AppError::not_found("User not found"))?;

    if password_hash.is_empty() {
        let auth_time = req.extensions().get::<AuthTime>().map_or(0, |t| t.0);
        if chrono::Utc::now().timestamp() - auth_time > RECENT_AUTH_SECS {
            return Err(AppError::forbidden(
                "For your security, sign in again, then delete your account within 5 minutes.",
            ));
        }
    } else if body.password.len() > 128
        || !verify_password(body.password.clone(), password_hash).await?
    {
        return Err(AppError::forbidden("Invalid password"));
    }

    let mut tx = pool.begin().await?;
    let key_ids: Vec<(String,)> = sqlx::query_as("SELECT id FROM server_keys WHERE user_id = ?")
        .bind(&user_id)
        .fetch_all(&mut *tx)
        .await?;
    let job_ids: Vec<(String,)> = sqlx::query_as("DELETE FROM jobs WHERE user_id = ? RETURNING id")
        .bind(&user_id)
        .fetch_all(&mut *tx)
        .await?;
    // Most of these also cascade; deleting explicitly keeps the intent visible.
    for table in [
        "refresh_tokens",
        "login_codes",
        "oauth_accounts",
        "daily_compute_usage",
        "server_keys",
    ] {
        sqlx::query(&format!("DELETE FROM {table} WHERE user_id = ?"))
            .bind(&user_id)
            .execute(&mut *tx)
            .await?;
    }
    sqlx::query("DELETE FROM users WHERE id = ?")
        .bind(&user_id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;

    // Files are removed once their rows are gone, so a failure here only leaves
    // unreachable bytes on disk. A job still running finds its row gone and
    // deletes its own data when it finishes.
    let _ = web::block(move || {
        for (key_id,) in key_ids {
            if let Err(e) = store.remove(&key_id) {
                log::error!("Failed to delete key file {key_id} for deleted account: {e}");
            }
        }
        for (job_id,) in job_ids {
            jobs.remove_logged(&job_id);
        }
    })
    .await;

    Ok(signed_out_response(
        &config,
        "Account deleted successfully.",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{body::to_bytes, test::TestRequest};

    fn test_config() -> Arc<Config> {
        Arc::new(Config::for_tests(std::env::temp_dir()))
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
