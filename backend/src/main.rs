mod api;
mod config;
mod crypto;
mod db;
mod errors;
mod middleware;

use actix_web::{web, App, HttpResponse, HttpServer};
use actix_web::middleware::from_fn;
use actix_cors::Cors;
use crate::crypto::engine::{AppState, HeContextPool};
use crate::middleware::rate_limit::RateLimiter;
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

    let pool = db::connect(&config.database_url).await.expect("Failed to connect to DB");

    let he_pool = HeContextPool::new(config.he_pool_size)
        .expect("Failed to initialize HE Context pool");
    let app_state = web::Data::new(AppState {
        he_pool: Arc::new(he_pool),
    });

    log::info!("Starting HE SaaS Backend on {}", config.server_addr);

    let config_data = web::Data::new(config.clone());
    let rate_limiter = web::Data::new(RateLimiter::new());

    HttpServer::new(move || {
        let cors = build_cors();

        App::new()
            .wrap(cors)
            .app_data(web::Data::new(pool.clone()))
            .app_data(app_state.clone())
            .app_data(config_data.clone())
            .app_data(rate_limiter.clone())
            .route("/api/health", web::get().to(health))
            .service(
                web::scope("/api")
                    .service(
                        web::scope("/auth")
                            .wrap(from_fn(middleware::rate_limit::rate_limit_middleware))
                            .route("/register", web::post().to(api::auth::register))
                            .route("/login", web::post().to(api::auth::login))
                            .route("/verify", web::get().to(api::auth::verify_email))
                            .route("/resend-verification", web::post().to(api::auth::resend_verification))
                            .route("/google", web::get().to(api::auth::google_redirect))
                            .route("/google/callback", web::get().to(api::auth::google_callback))
                            .route("/github", web::get().to(api::auth::github_redirect))
                            .route("/github/callback", web::get().to(api::auth::github_callback))
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
