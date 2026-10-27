mod api;
mod config;
mod crypto;
mod db;
mod errors;
mod jobs;
mod middleware;
mod storage;

use crate::crypto::keys::KeyStore;
use crate::jobs::store::JobStore;
use crate::jobs::worker::{WorkerPool, WorkerSettings};
use crate::middleware::rate_limit::RateLimiter;
use actix_cors::Cors;
use actix_web::{web, App, HttpResponse, HttpServer};
use std::sync::Arc;
use std::time::Duration;

/// How long a stopping server waits for running jobs before abandoning them
/// (they are requeued at the next start).
const SHUTDOWN_GRACE: Duration = Duration::from_secs(30);

async fn health() -> HttpResponse {
    HttpResponse::Ok().json(serde_json::json!({
        "status": "ok",
        "version": env!("CARGO_PKG_VERSION")
    }))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init();
    let config = config::Config::init();
    let config = Arc::new(config);

    let pool = db::connect(&config.database_url)
        .await
        .expect("Failed to connect to DB");

    // The server only ever holds users' evaluation keys, never a secret key.
    let key_store = web::Data::new(
        KeyStore::new(
            &config.key_store_dir,
            config.max_server_key_bytes,
            config.key_cache_capacity,
        )
        .expect("Failed to open the server key store directory"),
    );
    let job_store = web::Data::new(
        JobStore::new(&config.job_store_dir).expect("Failed to open the job store directory"),
    );
    let workers = WorkerPool::start(
        pool.clone(),
        job_store.clone().into_inner(),
        jobs::evaluator(key_store.clone().into_inner()),
        WorkerSettings {
            workers: config.he_workers,
            job_timeout: config.job_timeout,
            max_attempts: config.max_job_attempts,
            retention_days: config.job_retention_days,
        },
    )
    .await
    .expect("Failed to start the job workers");
    let notifier = web::Data::new(workers.notifier());

    log::info!("Starting HE SaaS Backend on {}", config.server_addr);

    let config_data = web::Data::new(config.clone());
    let rate_limiter = web::Data::new(RateLimiter::new());

    let server_addr = config.server_addr.clone();
    let app_pool = pool.clone();
    HttpServer::new(move || {
        let cors = build_cors();
        let config = config.clone();

        App::new()
            .wrap(cors)
            .app_data(web::Data::new(app_pool.clone()))
            .app_data(key_store.clone())
            .app_data(job_store.clone())
            .app_data(notifier.clone())
            .app_data(config_data.clone())
            .app_data(rate_limiter.clone())
            .route("/api/health", web::get().to(health))
            .configure(|cfg| api::configure(cfg, &config))
    })
    .bind(&server_addr)?
    .run()
    .await?;

    // `run` returns once actix has stopped accepting requests (SIGTERM/SIGINT).
    log::info!("Waiting for running jobs to finish");
    workers.shutdown(SHUTDOWN_GRACE).await;
    pool.close().await;
    Ok(())
}

fn build_cors() -> Cors {
    #[cfg(debug_assertions)]
    {
        let allowed_origins = std::env::var("ALLOWED_ORIGINS")
            .unwrap_or_else(|_| "http://localhost:3000,http://localhost:5173".to_string());
        let origins: Vec<String> = allowed_origins
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();

        Cors::default()
            .allowed_origin_fn(move |origin, _req_head| {
                let o = origin.to_str().unwrap_or("");
                origins.iter().any(|allowed| allowed == o)
            })
            .allow_any_method()
            .allow_any_header()
    }

    #[cfg(not(debug_assertions))]
    {
        let allowed_origins_str = std::env::var("ALLOWED_ORIGINS")
            .expect("ALLOWED_ORIGINS environment variable must be set in release builds");
        let origins: Vec<String> = allowed_origins_str
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();

        Cors::default()
            .allowed_origin_fn(move |origin, _req_head| {
                let o = origin.to_str().unwrap_or("");
                origins.iter().any(|allowed| allowed == o)
            })
            .allow_any_method()
            .allow_any_header()
    }
}
