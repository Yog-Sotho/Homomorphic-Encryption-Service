pub mod auth;
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

/// Registers every `/api` route. Shared by `main` and the integration tests so
/// both exercise the same routing, guards and body limits.
pub fn configure(cfg: &mut web::ServiceConfig, config: &Config) {
    // Compressed server keys are tens of megabytes; only this route accepts that.
    let key_upload_limit =
        web::PayloadConfig::new(usize::try_from(config.max_server_key_bytes).unwrap_or(usize::MAX));

    cfg.service(
        web::scope("/api")
            .route("/he/params", web::get().to(params::get_params))
            .service(
                web::scope("/auth")
                    .wrap(from_fn(middleware::rate_limit::rate_limit_middleware))
                    .route("/register", web::post().to(auth::register))
                    .route("/login", web::post().to(auth::login))
                    .route("/verify", web::get().to(auth::verify_email))
                    .route(
                        "/resend-verification",
                        web::post().to(auth::resend_verification),
                    )
                    .route("/google", web::get().to(auth::google_redirect))
                    .route("/google/callback", web::get().to(auth::google_callback))
                    .route("/github", web::get().to(auth::github_redirect))
                    .route("/github/callback", web::get().to(auth::github_callback))
                    .route("/forgot-password", web::post().to(auth::forgot_password))
                    .route(
                        "/forgot-password/redirect",
                        web::get().to(auth::forgot_password_redirect),
                    )
                    .route("/reset-password", web::post().to(auth::reset_password))
                    .route("/refresh", web::post().to(auth::refresh_token_endpoint))
                    .route("/logout", web::post().to(auth::logout)),
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
                    .route("/jobs", web::post().to(compute::submit_job))
                    .route("/jobs", web::get().to(compute::list_jobs))
                    .route("/jobs/{id}", web::get().to(compute::get_job_status)),
            ),
    );
}
