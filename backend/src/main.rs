mod api;
mod config;
mod crypto;
mod db;
mod errors;
mod jobs;
mod middleware;
mod storage;

use crate::api::auth::email::Mailer;
use crate::crypto::keys::KeyStore;
use crate::jobs::store::JobStore;
use crate::jobs::worker::{WorkerPool, WorkerSettings};
use crate::middleware::rate_limit::RateLimits;
use actix_cors::Cors;
use actix_web::http::{header, Method};
use actix_web::middleware::DefaultHeaders;
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
    let config = match config::Config::from_env() {
        Ok(config) => Arc::new(config),
        Err(e) => {
            log::error!("Invalid configuration:\n{e}");
            std::process::exit(2);
        }
    };
    let mailer = match Mailer::new(&config.mail) {
        Ok(mailer) => web::Data::new(mailer),
        Err(e) => {
            log::error!("Invalid configuration: {e}");
            std::process::exit(2);
        }
    };

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
    let rate_limits = web::Data::new(RateLimits::new(&config));
    let oauth_http = web::Data::new(api::auth::oauth::http_client());
    tokio::spawn(maintenance(pool.clone(), rate_limits.clone()));

    let server_addr = config.server_addr.clone();
    let app_pool = pool.clone();
    HttpServer::new(move || {
        let config = config.clone();

        App::new()
            .wrap(security_headers())
            .wrap(build_cors(&config))
            .app_data(web::Data::new(app_pool.clone()))
            .app_data(key_store.clone())
            .app_data(job_store.clone())
            .app_data(notifier.clone())
            .app_data(config_data.clone())
            .app_data(rate_limits.clone())
            .app_data(oauth_http.clone())
            .app_data(mailer.clone())
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

/// Browsers may call the API only from the configured origins, with the
/// methods and headers the API uses, and may send the session cookie.
fn build_cors(config: &config::Config) -> Cors {
    let origins = config.allowed_origins.clone();
    Cors::default()
        .allowed_origin_fn(move |origin, _| {
            origin
                .to_str()
                .is_ok_and(|o| origins.iter().any(|allowed| allowed == o))
        })
        .allowed_methods([Method::GET, Method::POST, Method::PUT, Method::DELETE])
        .allowed_headers([
            header::AUTHORIZATION,
            header::CONTENT_TYPE,
            header::ACCEPT,
            header::HeaderName::from_static("idempotency-key"),
        ])
        .expose_headers([
            header::LOCATION,
            header::RETRY_AFTER,
            header::HeaderName::from_static("idempotent-replayed"),
        ])
        .supports_credentials()
        .max_age(3600)
}

/// Headers for every API response (handlers may override them). The API only
/// serves JSON and ciphertexts: nothing should render, frame, sniff or cache it.
fn security_headers() -> DefaultHeaders {
    DefaultHeaders::new()
        .add((header::X_CONTENT_TYPE_OPTIONS, "nosniff"))
        .add((
            header::CONTENT_SECURITY_POLICY,
            "default-src 'none'; frame-ancestors 'none'",
        ))
        .add((header::X_FRAME_OPTIONS, "DENY"))
        .add((header::REFERRER_POLICY, "no-referrer"))
        .add(("Cross-Origin-Resource-Policy", "same-origin"))
        .add(("Cross-Origin-Opener-Policy", "same-origin"))
        .add((header::CACHE_CONTROL, "no-store"))
}

/// Periodic cleanup: forgets idle rate-limit buckets and deletes expired
/// sessions and login codes.
async fn maintenance(pool: sqlx::SqlitePool, limits: web::Data<RateLimits>) {
    let mut tick = tokio::time::interval(std::time::Duration::from_secs(600));
    loop {
        tick.tick().await;
        limits.purge();
        match api::auth::session::purge_expired(&pool).await {
            Ok(0) => {}
            Ok(n) => log::info!("Deleted {n} expired sessions and login codes"),
            Err(e) => log::error!("Failed to delete expired sessions: {e}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::test;

    #[actix_web::test]
    async fn api_responses_carry_security_headers() {
        let app = test::init_service(
            App::new()
                .wrap(security_headers())
                .route("/api/health", web::get().to(health)),
        )
        .await;
        let resp = test::call_service(
            &app,
            test::TestRequest::get().uri("/api/health").to_request(),
        )
        .await;
        let header = |name: &str| {
            resp.headers()
                .get(name)
                .unwrap()
                .to_str()
                .unwrap()
                .to_string()
        };
        assert_eq!(header("x-content-type-options"), "nosniff");
        assert!(header("content-security-policy").contains("frame-ancestors 'none'"));
        assert_eq!(header("referrer-policy"), "no-referrer");
        assert_eq!(header("cross-origin-resource-policy"), "same-origin");
        assert_eq!(header("cache-control"), "no-store");
    }

    #[actix_web::test]
    async fn cors_admits_only_configured_origins_methods_and_headers() {
        let config = config::Config::for_tests(std::env::temp_dir());
        let app = test::init_service(
            App::new()
                .wrap(build_cors(&config))
                .route("/api/health", web::get().to(health)),
        )
        .await;
        let preflight = |origin: &str, method: &str, headers: &str| {
            test::TestRequest::default()
                .method(Method::OPTIONS)
                .uri("/api/health")
                .insert_header(("Origin", origin))
                .insert_header(("Access-Control-Request-Method", method))
                .insert_header(("Access-Control-Request-Headers", headers))
                .to_request()
        };

        let ok = test::call_service(
            &app,
            preflight(
                "http://localhost:3000",
                "POST",
                "authorization,idempotency-key",
            ),
        )
        .await;
        assert!(ok.status().is_success());
        assert_eq!(
            ok.headers().get("access-control-allow-origin").unwrap(),
            "http://localhost:3000"
        );
        assert_eq!(
            ok.headers()
                .get("access-control-allow-credentials")
                .unwrap(),
            "true"
        );

        for (origin, method, headers) in [
            ("https://evil.example", "POST", "authorization"),
            ("http://localhost:3000", "PATCH", "authorization"),
            ("http://localhost:3000", "POST", "x-anything"),
        ] {
            let resp = test::try_call_service(&app, preflight(origin, method, headers)).await;
            let allowed = resp.is_ok_and(|r| {
                r.status().is_success() && r.headers().contains_key("access-control-allow-origin")
            });
            assert!(!allowed, "{origin} {method} {headers}");
        }
    }
}
