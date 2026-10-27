//! The OpenAPI 3.1 description of `/api/v1`, generated from the handlers'
//! `#[utoipa::path]` annotations and served at `GET /api/v1/openapi.json`.
//!
//! A copy is committed at `docs/api/openapi.json`; a test fails when it no longer
//! matches the code (regenerate it with `UPDATE_OPENAPI=1 cargo test -p he-backend openapi`).

use super::auth::session::REFRESH_COOKIE;
use super::{auth, compute, keys, user};
use crate::crypto::params;
use actix_web::HttpResponse;
use std::sync::OnceLock;
use utoipa::openapi::header::HeaderBuilder;
use utoipa::openapi::schema::{KnownFormat, ObjectBuilder, Schema, SchemaFormat, Type};
use utoipa::openapi::security::{
    ApiKey, ApiKeyValue, HttpAuthScheme, HttpBuilder, SecurityRequirement, SecurityScheme,
};
use utoipa::openapi::{ContentBuilder, Ref, RefOr, ResponseBuilder};
use utoipa::{Modify, OpenApi};

#[derive(OpenApi)]
#[openapi(
    info(
        title = "HEaaS API",
        description = "Homomorphic encryption as a service. Clients keep their TFHE client key; \
                       the server evaluates on ciphertexts with the server key they upload. \
                       Every error is `{\"error\": {\"code\", \"message\"}}`."
    ),
    servers((url = "/api/v1")),
    paths(
        super::health::health,
        super::health::ready,
        params::get_params,
        auth::password::register,
        auth::password::login,
        auth::password::verify_email,
        auth::password::verify_link,
        auth::password::resend_verification,
        auth::password::forgot_password,
        auth::password::reset_link,
        auth::password::reset_password,
        auth::session::refresh,
        auth::session::logout,
        auth::session::exchange,
        auth::oauth::providers,
        auth::oauth::google_start,
        auth::oauth::google_callback,
        auth::oauth::github_start,
        auth::oauth::github_callback,
        user::get_me,
        user::change_password,
        user::delete_account,
        keys::upload_key,
        keys::list_keys,
        keys::delete_key,
        compute::submit_job,
        compute::list_jobs,
        compute::get_job_status,
        compute::get_job_result,
        compute::delete_job,
    ),
    components(schemas(heaas_core::api::ErrorDetail, heaas_core::api::JobStatus)),
    modifiers(&Conventions),
    tags(
        (name = "meta", description = "Service status"),
        (name = "he", description = "Encryption parameters"),
        (name = "auth", description = "Accounts and sessions. Browser calls must come from an allowed `Origin`."),
        (name = "user", description = "The signed-in account"),
        (name = "keys", description = "Your TFHE server keys"),
        (name = "jobs", description = "Homomorphic computations"),
    )
)]
pub struct ApiDoc;

/// Raw bytes (keys and ciphertexts), sent as `application/octet-stream`.
pub struct Binary;

impl utoipa::PartialSchema for Binary {
    fn schema() -> RefOr<Schema> {
        ObjectBuilder::new()
            .schema_type(Type::String)
            .format(Some(SchemaFormat::KnownFormat(KnownFormat::Binary)))
            .into()
    }
}

impl utoipa::ToSchema for Binary {}

/// What every operation shares: the security schemes and the error envelope as
/// the `default` response.
struct Conventions;

impl Modify for Conventions {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        // The derive would emit an empty license: the project has none yet.
        openapi.info.license = None;
        let components = openapi.components.get_or_insert_with(Default::default);
        components.add_security_scheme(
            "bearer",
            SecurityScheme::Http(
                HttpBuilder::new()
                    .scheme(HttpAuthScheme::Bearer)
                    .bearer_format("JWT")
                    .description(Some(
                        "The access token from sign-in or `/auth/refresh` (15 minutes by default)",
                    ))
                    .build(),
            ),
        );
        components.add_security_scheme(
            "refresh_cookie",
            SecurityScheme::ApiKey(ApiKey::Cookie(ApiKeyValue::with_description(
                REFRESH_COOKIE,
                "`HttpOnly` cookie set at sign-in; only sent to `/api/v1/auth`",
            ))),
        );
        let error = |description: &str, retry_after: bool| {
            let mut response = ResponseBuilder::new().description(description).content(
                "application/json",
                ContentBuilder::new()
                    .schema(Some(Ref::from_schema_name("ErrorBody")))
                    .build(),
            );
            if retry_after {
                response = response.header(
                    "Retry-After",
                    HeaderBuilder::new()
                        .schema(Some(ObjectBuilder::new().schema_type(Type::Integer)))
                        .description(Some("Seconds to wait before retrying"))
                        .build(),
                );
            }
            RefOr::T(response.build())
        };
        for (name, description, retry_after) in [
            ("Error", "Any other error, in the error envelope", false),
            (
                "Unauthorized",
                "Missing, invalid or expired access token",
                false,
            ),
            (
                "RateLimited",
                "Too many requests from this client or for this account",
                true,
            ),
            (
                "CrossOrigin",
                "A browser request from an origin that is not allowed",
                false,
            ),
        ] {
            components
                .responses
                .insert(name.to_string(), error(description, retry_after));
        }

        for (path, item) in openapi.paths.paths.iter_mut() {
            let auth_route = path.starts_with("/auth/");
            for (method, operation) in [
                ("get", &mut item.get),
                ("put", &mut item.put),
                ("post", &mut item.post),
                ("delete", &mut item.delete),
            ] {
                let Some(operation) = operation else {
                    continue;
                };
                // Say explicitly that an operation without a scheme is public.
                let security = operation
                    .security
                    .get_or_insert_with(|| vec![SecurityRequirement::default()]);
                let bearer = security
                    .iter()
                    .any(|s| serde_json::to_value(s).is_ok_and(|v| v.get("bearer").is_some()));
                let responses = &mut operation.responses.responses;
                let mut add = |status: &str, name: &str| {
                    responses
                        .entry(status.to_string())
                        .or_insert_with(|| RefOr::Ref(Ref::from_response_name(name)));
                };
                if bearer {
                    add("401", "Unauthorized");
                }
                if auth_route {
                    // The whole /auth scope is rate-limited per client and
                    // Origin-checked for state changes.
                    add("429", "RateLimited");
                    if method == "post" {
                        add("403", "CrossOrigin");
                    }
                }
                add("default", "Error");
            }
        }
    }
}

/// The document as served and committed.
pub fn document() -> &'static str {
    static JSON: OnceLock<String> = OnceLock::new();
    JSON.get_or_init(|| {
        let mut json = ApiDoc::openapi()
            .to_pretty_json()
            .expect("the OpenAPI document serializes");
        json.push('\n');
        json
    })
}

/// `GET /api/v1/openapi.json`
pub async fn openapi_json() -> HttpResponse {
    HttpResponse::Ok()
        .content_type("application/json")
        .body(document())
}

/// Every documented operation as `(method, path under /api/v1)`.
#[cfg(test)]
pub fn operations() -> Vec<(&'static str, String)> {
    let doc = ApiDoc::openapi();
    let mut ops = Vec::new();
    for (path, item) in &doc.paths.paths {
        for (method, op) in [
            ("GET", &item.get),
            ("PUT", &item.put),
            ("POST", &item.post),
            ("DELETE", &item.delete),
        ] {
            if op.is_some() {
                ops.push((method, path.clone()));
            }
        }
    }
    ops
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn the_committed_document_matches_the_code() {
        let committed = Path::new(env!("CARGO_MANIFEST_DIR")).join("../docs/api/openapi.json");
        if std::env::var_os("UPDATE_OPENAPI").is_some() {
            std::fs::create_dir_all(committed.parent().unwrap()).unwrap();
            std::fs::write(&committed, document()).unwrap();
            return;
        }
        let on_disk = std::fs::read_to_string(&committed).unwrap_or_default();
        assert!(
            on_disk == document(),
            "docs/api/openapi.json is out of date; regenerate it with \
             `UPDATE_OPENAPI=1 cargo test -p he-backend openapi`"
        );
    }

    #[test]
    fn every_operation_has_an_error_response_and_protected_ones_a_scheme() {
        let doc: serde_json::Value = serde_json::from_str(document()).unwrap();
        for (path, item) in doc["paths"].as_object().unwrap() {
            for (method, op) in item.as_object().unwrap() {
                assert!(
                    op["responses"]["default"].is_object(),
                    "{method} {path} has no default response"
                );
                let public = path.starts_with("/auth/")
                    || path.starts_with("/health")
                    || path == "/he/params";
                if !public {
                    assert_eq!(
                        op["security"][0]["bearer"],
                        serde_json::json!([]),
                        "{method} {path} needs the bearer scheme"
                    );
                }
            }
        }
    }
}
