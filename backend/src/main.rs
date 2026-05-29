mod api;
mod config;
mod crypto;
mod db;
mod errors;
mod middleware;

use actix_web::{web, App, HttpServer};
use actix_web::middleware::from_fn;
use actix_cors::Cors;
use crate::crypto::engine::{AppState, HeContextPool};
use crate::middleware::rate_limit::RateLimiter;
use std::sync::Arc;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init();
    let config = config::Config::init();
    let config = Arc::new(config);

    let pool = db::connect(&config.database_url).await.expect("Failed to connect to DB");

    let pool_size = num_cpus::get().max(2);
    let he_pool = HeContextPool::new(pool_size).expect("Failed to initialize HE Context pool");
    let app_state = web::Data::new(AppState {
        he_pool: Arc::new(he_pool),
    });

    log::info!("Starting HE SaaS Backend on {}", config.server_addr);

    let config_data = web::Data::new(config.clone());
    let rate_limiter = web::Data::new(RateLimiter::new());

    HttpServer::new(move || {
        // S2 — read ALLOWED_ORIGINS from env, fall back to localhost in debug
        let cors = build_cors();

        App::new()
            .wrap(cors)
            .app_data(web::Data::new(pool.clone()))
            .app_data(app_state.clone())
            .app_data(config_data.clone())
            .app_data(rate_limiter.clone())
            .service(
                web::scope("/api")
                    .service(
                        web::scope("/auth")
                            .wrap(from_fn(middleware::rate_limit::rate_limit_middleware))
                            .route("/register", web::post().to(api::auth::register))
                            .route("/login", web::post().to(api::auth::login))
                    )
                    .service(
                        web::scope("/compute")
                            .wrap(from_fn(middleware::jwt::jwt_validator))
                            .route("/sandbox", web::post().to(api::compute::sandbox_compute))
                            .route("/jobs", web::post().to(api::compute::submit_job))
                            .route("/jobs", web::get().to(api::compute::list_jobs))
                            .route("/jobs/{id}", web::get().to(api::compute::get_job_status))
                    )
            )
    })
    .bind(&config.server_addr)?
    .run()
    .await
}

fn build_cors() -> Cors {
    #[cfg(debug_assertions)]
    {
        // Development: fall back to allowing localhost origins
        let allowed_origins = std::env::var("ALLOWED_ORIGINS")
            .unwrap_or_else(|_| "http://localhost:3000,http://localhost:5173,http://localhost:8080".to_string());
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
