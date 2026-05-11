mod api;
mod config;
mod crypto;
mod db;
mod error;
mod middleware;

use actix_web::{web, App, HttpServer};
use actix_cors::Cors;
use crate::crypto::engine::{HeContext, AppState};
use std::sync::Arc;
use tokio::sync::Mutex;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init();
    let config = config::Config::init();

    let pool = db::connect(&config.database_url).await.expect("Failed to connect to DB");
    
    let he_context = HeContext::new().expect("Failed to initialize HE Context");
    let app_state = web::Data::new(AppState {
        he_context: Arc::new(Mutex::new(he_context)),
    });

    log::info!("Starting HE SaaS Backend on {}", config.server_addr);

    HttpServer::new(move || {
        let cors = Cors::default()
            .allow_any_origin()
            .allow_any_method()
            .allow_any_header();

        App::new()
            .wrap(cors)
            .app_data(web::Data::new(pool.clone()))
            .app_data(app_state.clone())
            .service(
                web::scope("/api")
                    .route("/auth/register", web::post().to(api::auth::register))
                    .route("/auth/login", web::post().to(api::auth::login))
                    .route("/compute/jobs", web::post().to(api::compute::submit_job))
                    .route("/compute/jobs/{id}", web::get().to(api::compute::get_job_status))
            )
    })
    .bind(&config.server_addr)?
    .run()
    .await
}