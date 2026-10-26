use crate::errors::AppError;
use sqlx::SqlitePool;

/// Charges one computation against the user's daily quota (UTC days).
///
/// Called by job submission only, so polling a job's status or listing jobs never
/// uses up quota. Check and increment happen in one atomic statement.
pub async fn consume_compute_quota(
    pool: &SqlitePool,
    user_id: &str,
    daily_quota: usize,
) -> Result<(), AppError> {
    let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
    let (count,): (i64,) = sqlx::query_as(
        "INSERT INTO daily_compute_usage (user_id, date, count) VALUES (?, ?, 1)
         ON CONFLICT(user_id, date) DO UPDATE SET count = count + 1
         RETURNING count",
    )
    .bind(user_id)
    .bind(&today)
    .fetch_one(pool)
    .await?;

    if count > daily_quota as i64 {
        return Err(AppError::too_many_requests(format!(
            "Daily compute quota of {daily_quota} operations reached. Resets at midnight UTC."
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn allows_up_to_the_quota_then_rejects() {
        let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
        sqlx::migrate!("./migrations").run(&pool).await.unwrap();
        sqlx::query(
            "INSERT INTO users (id, email, password_hash) VALUES ('u1', 'a@example.com', '')",
        )
        .execute(&pool)
        .await
        .unwrap();

        for _ in 0..3 {
            consume_compute_quota(&pool, "u1", 3).await.unwrap();
        }
        let err = consume_compute_quota(&pool, "u1", 3).await.unwrap_err();
        assert!(matches!(err, AppError::TooManyRequests(_)));
    }
}
