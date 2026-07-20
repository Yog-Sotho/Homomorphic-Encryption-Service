pub mod models;
use sqlx::SqlitePool;
use sqlx::sqlite::SqliteConnectOptions;
use std::str::FromStr;

pub async fn connect(database_url: &str) -> Result<SqlitePool, sqlx::Error> {
    // Enable Write-Ahead Logging (WAL) and set synchronous to Normal.
    // This optimization dramatically increases database write throughput, improves concurrency,
    // and prevents "database is locked" errors under multi-threaded web application loads.
    let options = SqliteConnectOptions::from_str(database_url)?
        .foreign_keys(true)
        .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal)
        .synchronous(sqlx::sqlite::SqliteSynchronous::Normal);
    let pool = SqlitePool::connect_with(options).await?;
    sqlx::migrate!("./migrations").run(&pool).await?;
    Ok(pool)
}
