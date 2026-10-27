//! CSRF defence for the cookie-authenticated `/api/auth` routes.
//!
//! The refresh cookie is `SameSite=Strict`, so browsers already withhold it from
//! cross-site requests. As a second layer, state-changing requests that carry an
//! `Origin` (every browser `fetch` and form POST does) must come from an allowed
//! origin. Requests without `Origin` or `Sec-Fetch-Site` are not from a browser
//! page, so they carry no ambient cookies to abuse and pass.

use crate::config::Config;
use crate::errors::AppError;
use actix_web::body::{BoxBody, MessageBody};
use actix_web::dev::{ServiceRequest, ServiceResponse};
use actix_web::http::{header::HeaderMap, Method};
use actix_web::middleware::Next;
use actix_web::{web, Error, ResponseError};
use std::sync::Arc;

/// Whether a request with these headers may change state.
pub fn origin_allowed(method: &Method, headers: &HeaderMap, allowed: &[String]) -> bool {
    if matches!(*method, Method::GET | Method::HEAD | Method::OPTIONS) {
        return true;
    }
    if let Some(origin) = headers.get("origin") {
        return origin
            .to_str()
            .is_ok_and(|o| allowed.iter().any(|a| a.eq_ignore_ascii_case(o)));
    }
    // No Origin: an older browser may still say where the request came from.
    !headers
        .get("sec-fetch-site")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|site| site.eq_ignore_ascii_case("cross-site"))
}

pub async fn require_allowed_origin(
    req: ServiceRequest,
    next: Next<impl MessageBody + 'static>,
) -> Result<ServiceResponse<BoxBody>, Error> {
    let allowed = req
        .app_data::<web::Data<Arc<Config>>>()
        .is_none_or(|config| origin_allowed(req.method(), req.headers(), &config.allowed_origins));
    if allowed {
        next.call(req)
            .await
            .map(ServiceResponse::map_into_boxed_body)
    } else {
        let response = AppError::forbidden("Cross-origin request refused").error_response();
        Ok(req.into_response(response))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::http::header::{HeaderName, HeaderValue};

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in pairs {
            map.insert(
                HeaderName::from_bytes(name.as_bytes()).unwrap(),
                HeaderValue::from_str(value).unwrap(),
            );
        }
        map
    }

    #[test]
    fn only_allowed_origins_may_post() {
        let allowed = vec!["https://app.example".to_string()];
        let post = Method::POST;
        assert!(origin_allowed(
            &post,
            &headers(&[("origin", "https://app.example")]),
            &allowed
        ));
        assert!(!origin_allowed(
            &post,
            &headers(&[("origin", "https://evil.example")]),
            &allowed
        ));
        assert!(!origin_allowed(
            &post,
            &headers(&[("origin", "null")]),
            &allowed
        ));
        assert!(!origin_allowed(
            &post,
            &headers(&[("sec-fetch-site", "cross-site")]),
            &allowed
        ));
        assert!(origin_allowed(
            &post,
            &headers(&[("sec-fetch-site", "same-origin")]),
            &allowed
        ));
        // Non-browser clients send neither header.
        assert!(origin_allowed(&post, &headers(&[]), &allowed));
        // Safe methods never change state.
        assert!(origin_allowed(
            &Method::GET,
            &headers(&[("origin", "https://evil.example")]),
            &allowed
        ));
    }
}
