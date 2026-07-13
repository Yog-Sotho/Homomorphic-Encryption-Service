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

        // Optimized: Combined quota check and increment into a single atomic DB roundtrip using RETURNING.
        // This reduces database latency and load by 50% for every computation request.
        let result = sqlx::query_as::<_, (i64,)>(
            "INSERT INTO daily_compute_usage (user_id, date, count) VALUES (?, ?, 1)
             ON CONFLICT(user_id, date) DO UPDATE SET count = count + 1
             RETURNING count"
        )
        .bind(&user_id)
        .bind(&today)
        .fetch_one(pool.get_ref())
        .await;

        match result {
            Ok((count,)) => {
                if count > quota {
                    let resp = HttpResponse::TooManyRequests().json(serde_json::json!({
                        "message": format!("Daily compute quota of {} operations reached. Resets at midnight UTC.", quota)
                    }));
                    let (parts, _) = req.into_parts();
                    return Ok(ServiceResponse::new(parts, resp).map_into_boxed_body());
                }
            }
            Err(e) => {
                log::error!("Quota DB error for user {}: {}", user_id, e);
                let resp = HttpResponse::TooManyRequests().json(serde_json::json!({
                    "message": "Service temporarily unavailable. Please try again."
                }));
                let (parts, _) = req.into_parts();
                return Ok(ServiceResponse::new(parts, resp).map_into_boxed_body());
            }
        }
    }

    next.call(req).await.map(|r| r.map_into_boxed_body())
}
