use crate::errors::AppError;
use chrono::{Duration, NaiveDateTime, Utc};
use sqlx::SqlitePool;

/// The UTC day a computation was charged to, so it can be refunded to the same day.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuotaCharge {
    date: String,
}

fn unavailable(err: sqlx::Error) -> AppError {
    tracing::error!("Compute quota unavailable: {err}");
    AppError::service_unavailable("Compute quota is temporarily unavailable", 5)
}

/// Seconds from `now` until the quota resets at the next midnight UTC.
fn seconds_until_reset(now: NaiveDateTime) -> u64 {
    let midnight = (now.date() + Duration::days(1)).and_hms_opt(0, 0, 0);
    midnight.map_or(0, |m| (m - now).num_seconds().max(1) as u64)
}

/// Charges one computation against the user's daily quota (UTC days).
///
/// Called by job submission only, so polling a job's status or listing jobs never
/// uses up quota. Check and increment happen in one atomic statement. A database
/// failure is reported as 503 (retry), never as a quota rejection.
pub async fn consume_compute_quota(
    pool: &SqlitePool,
    user_id: &str,
    daily_quota: usize,
) -> Result<QuotaCharge, AppError> {
    let now = Utc::now().naive_utc();
    let date = now.format("%Y-%m-%d").to_string();
    let (count,): (i64,) = sqlx::query_as(
        "INSERT INTO daily_compute_usage (user_id, date, count) VALUES (?, ?, 1)
         ON CONFLICT(user_id, date) DO UPDATE SET count = count + 1
         RETURNING count",
    )
    .bind(user_id)
    .bind(&date)
    .fetch_one(pool)
    .await
    .map_err(unavailable)?;

    if count > daily_quota as i64 {
        return Err(AppError::too_many_requests(
            format!(
                "Daily compute quota of {daily_quota} operations reached. Resets at midnight UTC."
            ),
            Some(seconds_until_reset(now)),
        ));
    }
    Ok(QuotaCharge { date })
}

/// Gives back a charge for a submission that was not accepted after all.
pub async fn refund_compute_quota(pool: &SqlitePool, user_id: &str, charge: &QuotaCharge) {
    let refunded = sqlx::query(
        "UPDATE daily_compute_usage SET count = count - 1
         WHERE user_id = ? AND date = ? AND count > 0",
    )
    .bind(user_id)
    .bind(&charge.date)
    .execute(pool)
    .await;
    if let Err(e) = refunded {
        tracing::error!("Failed to refund compute quota for {user_id}: {e}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::NaiveDate;

    async fn pool_with_user() -> SqlitePool {
        let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
        sqlx::migrate!("./migrations").run(&pool).await.unwrap();
        sqlx::query(
            "INSERT INTO users (id, email, password_hash) VALUES ('u1', 'a@example.com', '')",
        )
        .execute(&pool)
        .await
        .unwrap();
        pool
    }

    #[tokio::test]
    async fn allows_up_to_the_quota_then_rejects() {
        let pool = pool_with_user().await;
        for _ in 0..3 {
            consume_compute_quota(&pool, "u1", 3).await.unwrap();
        }
        let err = consume_compute_quota(&pool, "u1", 3).await.unwrap_err();
        assert!(matches!(
            err,
            AppError::TooManyRequests {
                retry_after: Some(1..=86_400),
                ..
            }
        ));
    }

    #[tokio::test]
    async fn refunds_make_room_again() {
        let pool = pool_with_user().await;
        let charge = consume_compute_quota(&pool, "u1", 1).await.unwrap();
        refund_compute_quota(&pool, "u1", &charge).await;
        consume_compute_quota(&pool, "u1", 1).await.unwrap();
    }

    #[tokio::test]
    async fn database_failures_are_503_not_429() {
        let pool = pool_with_user().await;
        pool.close().await;
        let err = consume_compute_quota(&pool, "u1", 3).await.unwrap_err();
        assert!(matches!(err, AppError::ServiceUnavailable { .. }));
    }

    #[test]
    fn reset_is_counted_to_the_next_utc_midnight() {
        let at = |h, m, s| {
            NaiveDate::from_ymd_opt(2026, 10, 26)
                .unwrap()
                .and_hms_opt(h, m, s)
                .unwrap()
        };
        assert_eq!(seconds_until_reset(at(23, 59, 30)), 30);
        assert_eq!(seconds_until_reset(at(0, 0, 0)), 86_400);
    }
}
