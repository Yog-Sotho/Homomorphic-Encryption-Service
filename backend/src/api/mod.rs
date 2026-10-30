pub mod auth;
#[cfg(test)]
mod auth_tests;
pub mod compute;
pub mod health;
#[cfg(test)]
mod integration_tests;
pub mod keys;
pub mod openapi;
pub mod user;
pub mod validation;

use crate::config::Config;
use crate::crypto::params;
use crate::errors::{self, AppError};
use crate::middleware;
use actix_web::middleware::{from_fn, DefaultHeaders};
use actix_web::{web, HttpResponse};
use auth::{oauth, password, session};

/// Where the current API lives.
pub const API_PREFIX: &str = "/api/v1";
/// The unversioned API from before `/api/v1`: the same routes, answered with
/// `Deprecation` and `Link: rel="successor-version"` headers.
const LEGACY_PREFIX: &str = "/api";
/// RFC 9745 `Deprecation`: deprecated since 2026-10-27 (Unix seconds).
const DEPRECATED_SINCE: &str = "@1793059200";

/// Registers every API route. Shared by `main` and the integration tests so
/// both exercise the same routing, guards, body limits and error envelope.
pub fn configure(cfg: &mut web::ServiceConfig, config: &Config) {
    cfg.app_data(web::JsonConfig::default().error_handler(errors::json_error))
        .app_data(web::QueryConfig::default().error_handler(errors::query_error))
        .app_data(web::PathConfig::default().error_handler(errors::path_error))
        .service(api_scope(API_PREFIX, config).wrap(errors::envelope_errors()))
        .service(
            api_scope(LEGACY_PREFIX, config)
                .wrap(errors::envelope_errors())
                .wrap(
                    DefaultHeaders::new()
                        .add(("Deprecation", DEPRECATED_SINCE))
                        .add(("Link", format!("<{API_PREFIX}>; rel=\"successor-version\""))),
                ),
        );
}

async fn no_such_endpoint() -> Result<HttpResponse, AppError> {
    Err(AppError::not_found("No such endpoint"))
}

fn api_scope(prefix: &str, config: &Config) -> actix_web::Scope {
    // Compressed server keys are tens of megabytes; only this route accepts that.
    let key_upload_limit =
        web::PayloadConfig::new(usize::try_from(config.max_server_key_bytes).unwrap_or(usize::MAX));
    // Two base64 ciphertexts exceed actix's 2 MB JSON default at the size limit.
    let submit_limit = web::JsonConfig::default()
        .limit(compute::MAX_SUBMIT_BODY_BYTES)
        .error_handler(errors::json_error);

    web::scope(prefix)
        .route("/health", web::get().to(health::health))
        .route("/health/ready", web::get().to(health::ready))
        .route("/he/params", web::get().to(params::get_params))
        // ~2 MB to anyone: limited per client IP (clients cache it by ETag).
        .service(
            web::resource("/he/crs")
                .wrap(from_fn(middleware::rate_limit::limit_per_client_ip))
                .route(web::get().to(params::get_crs)),
        )
        .route("/openapi.json", web::get().to(openapi::openapi_json))
        .service(
            web::scope("/auth")
                .wrap(from_fn(middleware::rate_limit::limit_per_client_ip))
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
                // Outermost last: the token is checked, then the account's budget.
                .wrap(from_fn(middleware::rate_limit::limit_per_user))
                .wrap(from_fn(middleware::jwt::jwt_validator))
                .route("/me", web::get().to(user::get_me))
                .route("/password", web::put().to(user::change_password))
                .route("/account", web::delete().to(user::delete_account)),
        )
        .service(
            web::scope("/keys")
                // Outermost last: the token is checked, then the account's budget.
                .wrap(from_fn(middleware::rate_limit::limit_per_user))
                .wrap(from_fn(middleware::jwt::jwt_validator))
                .service(
                    web::resource("")
                        .app_data(key_upload_limit)
                        .route(web::post().to(keys::upload_key))
                        .route(web::get().to(keys::list_keys)),
                )
                .route("/{id}", web::delete().to(keys::delete_key))
                .service(
                    web::resource("/{id}/public-key")
                        .app_data(web::PayloadConfig::new(
                            crate::crypto::params::MAX_PUBLIC_KEY_BYTES as usize,
                        ))
                        .route(web::put().to(keys::upload_public_key)),
                ),
        )
        .service(
            web::scope("/compute")
                // Outermost last: the token is checked, then the account's budget.
                .wrap(from_fn(middleware::rate_limit::limit_per_user))
                .wrap(from_fn(middleware::jwt::jwt_validator))
                .service(
                    web::resource("/jobs")
                        .app_data(submit_limit.clone())
                        .route(web::post().to(compute::submit_job))
                        .route(web::get().to(compute::list_jobs)),
                )
                // Before /jobs/{id}, which would otherwise match "batch".
                .service(
                    web::resource("/jobs/batch")
                        .app_data(submit_limit)
                        .route(web::post().to(compute::submit_batch)),
                )
                .service(
                    web::resource("/jobs/{id}")
                        .route(web::get().to(compute::get_job_status))
                        .route(web::delete().to(compute::delete_job)),
                )
                .route("/jobs/{id}/result", web::get().to(compute::get_job_result)),
        )
        .default_service(web::to(no_such_endpoint))
}
