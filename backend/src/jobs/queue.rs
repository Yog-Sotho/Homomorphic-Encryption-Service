//! The durable job queue: state transitions on the `jobs` table.
//!
//! `pending → processing → completed | failed`, with `processing → pending` for a
//! retry. Every transition is one SQL statement, so concurrent workers (and a
//! restarted server) never run the same attempt twice. Transitions out of
//! `processing` only apply while the job is still `processing`, so a job deleted
//! or recovered meanwhile is left alone.

use sqlx::{FromRow, SqlitePool};

/// A job a worker has claimed and must now finish.
#[derive(Debug, Clone, FromRow)]
pub struct ClaimedJob {
    pub id: String,
    /// `None` once the job's server key has been deleted.
    pub key_id: Option<String>,
    pub operation: String,
    /// Including the attempt just started.
    pub attempts: i64,
}

/// Claims the oldest runnable pending job, if any.
pub async fn claim_next(pool: &SqlitePool) -> sqlx::Result<Option<ClaimedJob>> {
    sqlx::query_as(
        "UPDATE jobs
         SET status = 'processing', attempts = attempts + 1, started_at = datetime('now'),
             not_before = NULL, updated_at = datetime('now')
         WHERE id = (
             SELECT id FROM jobs
             WHERE status = 'pending' AND (not_before IS NULL OR not_before <= datetime('now'))
             ORDER BY created_at, rowid
             LIMIT 1
         )
         RETURNING id, key_id, operation, attempts",
    )
    .fetch_optional(pool)
    .await
}

/// Marks a claimed job as done. Returns `false` if the job is no longer ours.
pub async fn complete(pool: &SqlitePool, job_id: &str, result_bytes: usize) -> sqlx::Result<bool> {
    let done = sqlx::query(
        "UPDATE jobs
         SET status = 'completed', result_bytes = ?, error_message = NULL,
             finished_at = datetime('now'), updated_at = datetime('now')
         WHERE id = ? AND status = 'processing'",
    )
    .bind(result_bytes as i64)
    .bind(job_id)
    .execute(pool)
    .await?;
    Ok(done.rows_affected() == 1)
}

/// Marks a claimed job as finally failed; `message` is shown to its owner.
pub async fn fail(pool: &SqlitePool, job_id: &str, message: &str) -> sqlx::Result<bool> {
    let done = sqlx::query(
        "UPDATE jobs
         SET status = 'failed', error_message = ?,
             finished_at = datetime('now'), updated_at = datetime('now')
         WHERE id = ? AND status = 'processing'",
    )
    .bind(message)
    .bind(job_id)
    .execute(pool)
    .await?;
    Ok(done.rows_affected() == 1)
}

/// Seconds to wait before retrying after `attempts` failed attempts: 2, 4, 8, … (≤ 5 min).
pub fn backoff_secs(attempts: i64) -> i64 {
    1_i64 << attempts.clamp(1, 8)
}

/// Puts a claimed job back in the queue after a transient failure.
pub async fn retry_later(pool: &SqlitePool, job_id: &str, attempts: i64) -> sqlx::Result<bool> {
    let done = sqlx::query(
        "UPDATE jobs
         SET status = 'pending', started_at = NULL,
             not_before = datetime('now', '+' || ? || ' seconds'), updated_at = datetime('now')
         WHERE id = ? AND status = 'processing'",
    )
    .bind(backoff_secs(attempts))
    .bind(job_id)
    .execute(pool)
    .await?;
    Ok(done.rows_affected() == 1)
}

/// What [`recover_interrupted`] did with jobs left `processing` by a stopped server.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Recovered {
    pub requeued: u64,
    pub failed: u64,
}

/// Called once at startup, before any worker runs: every `processing` job was
/// interrupted. Jobs with attempts left go back to the queue; the rest fail.
pub async fn recover_interrupted(pool: &SqlitePool, max_attempts: i64) -> sqlx::Result<Recovered> {
    let mut tx = pool.begin().await?;
    let failed = sqlx::query(
        "UPDATE jobs
         SET status = 'failed', error_message = 'Interrupted too many times; please resubmit',
             finished_at = datetime('now'), updated_at = datetime('now')
         WHERE status = 'processing' AND attempts >= ?",
    )
    .bind(max_attempts)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    let requeued = sqlx::query(
        "UPDATE jobs SET status = 'pending', started_at = NULL, updated_at = datetime('now')
         WHERE status = 'processing'",
    )
    .execute(&mut *tx)
    .await?
    .rows_affected();
    tx.commit().await?;
    Ok(Recovered { requeued, failed })
}

/// Deletes jobs that finished more than `retention_days` ago and returns their
/// ids so their stored data can be removed too.
pub async fn purge_finished(pool: &SqlitePool, retention_days: i64) -> sqlx::Result<Vec<String>> {
    let rows: Vec<(String,)> = sqlx::query_as(
        "DELETE FROM jobs
         WHERE status IN ('completed', 'failed')
           AND COALESCE(finished_at, updated_at) < datetime('now', '-' || ? || ' days')
         RETURNING id",
    )
    .bind(retention_days)
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(|(id,)| id).collect())
}

/// Shared helpers for queue, worker and API tests.
#[cfg(test)]
pub mod test_support {
    use super::*;

    /// A one-connection in-memory database (every connection would otherwise
    /// get its own empty database) with one user, `u1`.
    pub async fn test_pool() -> SqlitePool {
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        sqlx::migrate!("./migrations").run(&pool).await.unwrap();
        sqlx::query(
            "INSERT INTO users (id, email, password_hash) VALUES ('u1', 'u1@example.com', '')",
        )
        .execute(&pool)
        .await
        .unwrap();
        pool
    }

    /// Queues a job for `u1` directly in the database.
    pub async fn insert_pending(pool: &SqlitePool, operation: &str) -> String {
        let id = uuid::Uuid::new_v4().to_string();
        sqlx::query(
            "INSERT INTO jobs (id, user_id, status, input_data_b64, operation)
             VALUES (?, 'u1', 'pending', '', ?)",
        )
        .bind(&id)
        .bind(operation)
        .execute(pool)
        .await
        .unwrap();
        id
    }

    pub async fn status_of(pool: &SqlitePool, id: &str) -> (String, i64, Option<String>) {
        sqlx::query_as("SELECT status, attempts, error_message FROM jobs WHERE id = ?")
            .bind(id)
            .fetch_one(pool)
            .await
            .unwrap()
    }

    /// Makes a job that is waiting for its retry runnable now.
    pub async fn make_runnable(pool: &SqlitePool, id: &str) {
        sqlx::query("UPDATE jobs SET not_before = NULL WHERE id = ?")
            .bind(id)
            .execute(pool)
            .await
            .unwrap();
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::*;
    use super::*;

    #[tokio::test]
    async fn claims_in_order_and_only_once() {
        let pool = test_pool().await;
        let first = insert_pending(&pool, "add").await;
        let second = insert_pending(&pool, "max").await;

        let a = claim_next(&pool).await.unwrap().unwrap();
        let b = claim_next(&pool).await.unwrap().unwrap();
        assert_eq!((a.id.as_str(), a.attempts), (first.as_str(), 1));
        assert_eq!(b.id, second);
        assert!(claim_next(&pool).await.unwrap().is_none());

        assert!(complete(&pool, &a.id, 10).await.unwrap());
        assert!(
            !complete(&pool, &a.id, 10).await.unwrap(),
            "already finished"
        );
        assert!(fail(&pool, &b.id, "bad input").await.unwrap());
        assert_eq!(status_of(&pool, &a.id).await.0, "completed");
        assert_eq!(
            status_of(&pool, &b.id).await,
            ("failed".into(), 1, Some("bad input".into()))
        );
    }

    #[tokio::test]
    async fn retries_wait_for_their_backoff() {
        let pool = test_pool().await;
        let id = insert_pending(&pool, "add").await;
        let job = claim_next(&pool).await.unwrap().unwrap();
        assert!(retry_later(&pool, &id, job.attempts).await.unwrap());

        assert!(
            claim_next(&pool).await.unwrap().is_none(),
            "backoff not over"
        );
        make_runnable(&pool, &id).await;
        let again = claim_next(&pool).await.unwrap().unwrap();
        assert_eq!(again.attempts, 2);
        assert_eq!(backoff_secs(1), 2);
        assert_eq!(backoff_secs(100), 256);
    }

    #[tokio::test]
    async fn recovery_requeues_or_fails_interrupted_jobs() {
        let pool = test_pool().await;
        let fresh = insert_pending(&pool, "add").await;
        let worn = insert_pending(&pool, "add").await;
        sqlx::query("UPDATE jobs SET status = 'processing', attempts = 3 WHERE id = ?")
            .bind(&worn)
            .execute(&pool)
            .await
            .unwrap();
        claim_next(&pool).await.unwrap().unwrap();

        let recovered = recover_interrupted(&pool, 3).await.unwrap();
        assert_eq!(
            recovered,
            Recovered {
                requeued: 1,
                failed: 1
            }
        );
        assert_eq!(status_of(&pool, &fresh).await.0, "pending");
        assert_eq!(status_of(&pool, &worn).await.0, "failed");
    }

    #[tokio::test]
    async fn purges_only_old_finished_jobs() {
        let pool = test_pool().await;
        let old = insert_pending(&pool, "add").await;
        let recent = insert_pending(&pool, "add").await;
        let waiting = insert_pending(&pool, "add").await;
        sqlx::query(
            "UPDATE jobs SET status = 'completed', finished_at = datetime('now', '-8 days')
             WHERE id = ?",
        )
        .bind(&old)
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "UPDATE jobs SET status = 'failed', finished_at = datetime('now') WHERE id = ?",
        )
        .bind(&recent)
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query("UPDATE jobs SET created_at = datetime('now', '-30 days') WHERE id = ?")
            .bind(&waiting)
            .execute(&pool)
            .await
            .unwrap();

        assert_eq!(purge_finished(&pool, 7).await.unwrap(), [old]);
    }
}
