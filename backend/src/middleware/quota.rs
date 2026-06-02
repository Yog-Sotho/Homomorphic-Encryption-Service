use actix_web::{body::BoxBody, dev::{ServiceRequest, ServiceResponse}, Error, HttpMessage, HttpResponse};
use actix_web::middleware::Next;
use sqlx::SqlitePool;
use std::sync::Arc;
use crate::config::Config;

pub async fn quota_middleware<B: actix_web::body::MessageBody + 'static>(
    req: ServiceRequest,
    next: Next<B>,
) -> Result<ServiceResponse<BoxBody>, Error> {
    let user_id = req.extensions().get::<String>().cloned();
    let user_id = match user_id {
        Some(id) => id,
        None => return next.call(req).await.map(|r| r.map_into_boxed_body()),
    };

    let pool = req.app_data::<actix_web::web::Data<SqlitePool>>().cloned();
    let config = req.app_data::<actix_web::web::Data<Arc<Config>>>().cloned();

    if let (Some(pool), Some(config)) = (pool, config) {
        let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
        let quota = config.daily_compute_quota as i64;

        let row: Option<(i64,)> = sqlx::query_as(
            "SELECT count FROM daily_compute_usage WHERE user_id = ? AND date = ?"
        )
        .bind(&user_id)
        .bind(&today)
        .fetch_optional(pool.get_ref())
        .await
        .unwrap_or(None);

        let count = row.map(|(c,)| c).unwrap_or(0);

        if count >= quota {
            let resp = HttpResponse::TooManyRequests().json(serde_json::json!({
                "message": format!("Daily compute quota of {} operations reached. Resets at midnight UTC.", quota)
            }));
            let (parts, _) = req.into_parts();
            return Ok(ServiceResponse::new(parts, resp).map_into_boxed_body());
        }

        let _ = sqlx::query(
            "INSERT INTO daily_compute_usage (user_id, date, count) VALUES (?, ?, 1)
             ON CONFLICT(user_id, date) DO UPDATE SET count = count + 1"
        )
        .bind(&user_id)
        .bind(&today)
        .execute(pool.get_ref())
        .await;
    }

    next.call(req).await.map(|r| r.map_into_boxed_body())
}
