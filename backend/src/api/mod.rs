pub mod auth;
#[cfg(test)]
mod auth_tests;
pub mod compute;
#[cfg(test)]
mod integration_tests;
pub mod keys;
pub mod user;
pub mod validation;

use crate::config::Config;
use crate::crypto::params;
use crate::middleware;
use actix_web::middleware::from_fn;
use actix_web::web;
use auth::{oauth, password, session};

/// Registers every `/api` route. Shared by `main` and the integration tests so
/// both exercise the same routing, guards and body limits.
pub fn configure(cfg: &mut web::ServiceConfig, config: &Config) {
    // Compressed server keys are tens of megabytes; only this route accepts that.
    let key_upload_limit =
        web::PayloadConfig::new(usize::try_from(config.max_server_key_bytes).unwrap_or(usize::MAX));
    // Two base64 ciphertexts exceed actix's 2 MB JSON default at the size limit.
    let submit_limit = web::JsonConfig::default().limit(compute::MAX_SUBMIT_BODY_BYTES);

    cfg.service(
        web::scope("/api")
            .route("/he/params", web::get().to(params::get_params))
            .service(
                web::scope("/auth")
                    .wrap(from_fn(middleware::rate_limit::limit_auth_requests))
                    .wrap(from_fn(middleware::origin::require_allowed_origin))
                    .route("/register", web::post().to(password::register))
                    .route("/login", web::post().to(password::login))
                    .route("/verify", web::post().to(password::verify_email))
                    .route("/verify", web::get().to(password::verify_link))
                    .route(
                        "/resend-verification",
                        web::post().to(password::resend_verification),
                    )
                    .route(
                        "/forgot-password",
                        web::post().to(password::forgot_password),
                    )
                    .route(
                        "/forgot-password/redirect",
                        web::get().to(password::reset_link),
                    )
                    .route("/reset-password", web::post().to(password::reset_password))
                    .route("/refresh", web::post().to(session::refresh))
                    .route("/logout", web::post().to(session::logout))
                    .route("/exchange", web::post().to(session::exchange))
                    .route("/providers", web::get().to(oauth::providers))
                    .route("/google", web::get().to(oauth::google_start))
                    .route("/google/callback", web::get().to(oauth::google_callback))
                    .route("/github", web::get().to(oauth::github_start))
                    .route("/github/callback", web::get().to(oauth::github_callback)),
            )
            .service(
                web::scope("/user")
                    .wrap(from_fn(middleware::jwt::jwt_validator))
                    .route("/me", web::get().to(user::get_me))
                    .route("/password", web::put().to(user::change_password))
                    .route("/account", web::delete().to(user::delete_account)),
            )
            .service(
                web::scope("/keys")
                    .wrap(from_fn(middleware::jwt::jwt_validator))
                    .service(
                        web::resource("")
                            .app_data(key_upload_limit)
                            .route(web::post().to(keys::upload_key))
                            .route(web::get().to(keys::list_keys)),
                    )
                    .route("/{id}", web::delete().to(keys::delete_key)),
            )
            .service(
                web::scope("/compute")
                    .wrap(from_fn(middleware::jwt::jwt_validator))
                    .service(
                        web::resource("/jobs")
                            .app_data(submit_limit)
                            .route(web::post().to(compute::submit_job))
                            .route(web::get().to(compute::list_jobs)),
                    )
                    .service(
                        web::resource("/jobs/{id}")
                            .route(web::get().to(compute::get_job_status))
                            .route(web::delete().to(compute::delete_job)),
                    )
                    .route("/jobs/{id}/result", web::get().to(compute::get_job_result)),
            ),
    );
}
