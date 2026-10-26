mod api;
mod config;
mod crypto;
mod db;
mod errors;
mod middleware;

use crate::crypto::keys::KeyStore;
use crate::middleware::rate_limit::RateLimiter;
use actix_cors::Cors;
use actix_web::{web, App, HttpResponse, HttpServer};
use std::sync::Arc;

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

    log::info!("Starting HE SaaS Backend on {}", config.server_addr);

    let config_data = web::Data::new(config.clone());
    let rate_limiter = web::Data::new(RateLimiter::new());

    let server_addr = config.server_addr.clone();
    HttpServer::new(move || {
        let cors = build_cors();
        let config = config.clone();

        App::new()
            .wrap(cors)
            .app_data(web::Data::new(pool.clone()))
            .app_data(key_store.clone())
            .app_data(config_data.clone())
            .app_data(rate_limiter.clone())
            .route("/api/health", web::get().to(health))
            .configure(|cfg| api::configure(cfg, &config))
    })
    .bind(&server_addr)?
    .run()
    .await
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
