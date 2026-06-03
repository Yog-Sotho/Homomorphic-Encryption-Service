pub mod models;
use sqlx::SqlitePool;

pub async fn connect(database_url: &str) -> Result<SqlitePool, sqlx::Error> {
    let pool = SqlitePool::connect(database_url).await?;
    // sqlx::migrate!("./migrations").run(&pool).await?; // Assuming migrations exist or not needed for check
    Ok(pool)
}
