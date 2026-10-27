//! Access tokens: short-lived HS256 JWTs sent as `Authorization: Bearer`.
//!
//! Validation pins the algorithm, issuer, audience and token type, so a JWT
//! signed for any other purpose or service is rejected even if the key matched.

use crate::config::Config;
use crate::errors::AppError;
use actix_web::body::{BoxBody, MessageBody};
use actix_web::dev::{ServiceRequest, ServiceResponse};
use actix_web::middleware::Next;
use actix_web::{web, Error, HttpMessage, ResponseError};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

pub const ISSUER: &str = "heaas";
pub const AUDIENCE: &str = "heaas-api";
const TOKEN_TYPE: &str = "access";

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub iss: String,
    pub aud: String,
    pub typ: String,
    pub iat: i64,
    pub exp: i64,
    pub jti: String,
    /// When the user last authenticated (Unix seconds), carried across refreshes.
    pub auth_time: i64,
}

/// When the bearer of the current request last authenticated (Unix seconds).
/// Inserted into request extensions next to the user id.
#[derive(Debug, Clone, Copy)]
pub struct AuthTime(pub i64);

pub fn issue_access_token(
    user_id: &str,
    auth_time: i64,
    config: &Config,
) -> Result<String, AppError> {
    let now = chrono::Utc::now().timestamp();
    let claims = Claims {
        sub: user_id.to_string(),
        iss: ISSUER.to_string(),
        aud: AUDIENCE.to_string(),
        typ: TOKEN_TYPE.to_string(),
        iat: now,
        exp: now + config.ttl.access_token_secs,
        jti: uuid::Uuid::new_v4().to_string(),
        auth_time,
    };
    encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(&config.keys.access_token),
    )
    .map_err(|e| AppError::internal(e.to_string()))
}

pub fn validate_access_token(token: &str, config: &Config) -> Option<Claims> {
    let mut validation = Validation::new(Algorithm::HS256);
    validation.set_issuer(&[ISSUER]);
    validation.set_audience(&[AUDIENCE]);
    validation.set_required_spec_claims(&["exp", "iat", "iss", "aud", "sub"]);
    let data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(&config.keys.access_token),
        &validation,
    )
    .ok()?;
    (data.claims.typ == TOKEN_TYPE).then_some(data.claims)
}

/// Admits requests with a valid access token. Refusals are answered here (not
/// returned as errors) so outer middleware can still add headers to them.
pub async fn jwt_validator(
    req: ServiceRequest,
    next: Next<impl MessageBody + 'static>,
) -> Result<ServiceResponse<BoxBody>, Error> {
    let config = req
        .app_data::<web::Data<Arc<Config>>>()
        .cloned()
        .ok_or_else(|| AppError::internal("Config not found"))?;

    let claims = req
        .headers()
        .get("Authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
        .and_then(|token| validate_access_token(token, &config));

    match claims {
        Some(claims) => {
            req.extensions_mut().insert(AuthTime(claims.auth_time));
            req.extensions_mut().insert(claims.sub);
            next.call(req)
                .await
                .map(ServiceResponse::map_into_boxed_body)
        }
        None => {
            let response = AppError::unauthorized("Invalid or missing token").error_response();
            Ok(req.into_response(response))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::SecretKeys;

    /// jsonwebtoken 10+ panics at sign/verify time when no crypto backend feature
    /// is enabled; this catches that (and secret mismatches) in a unit test.
    #[test]
    fn tokens_round_trip_and_reject_other_keys() {
        let config = Config::for_tests(std::env::temp_dir());
        let token = issue_access_token("user-1", 1_700_000_000, &config).unwrap();
        let claims = validate_access_token(&token, &config).unwrap();
        assert_eq!(
            (claims.sub.as_str(), claims.auth_time),
            ("user-1", 1_700_000_000)
        );
        assert_eq!(claims.exp - claims.iat, config.ttl.access_token_secs);

        let mut other = Config::for_tests(std::env::temp_dir());
        other.keys = SecretKeys::derive("a-different-secret-of-sufficient-length");
        assert!(validate_access_token(&token, &other).is_none());
    }

    fn sign(claims: serde_json::Value, header: Header, config: &Config) -> String {
        encode(
            &header,
            &claims,
            &EncodingKey::from_secret(&config.keys.access_token),
        )
        .unwrap()
    }

    #[test]
    fn rejects_tokens_for_other_audiences_types_and_algorithms() {
        let config = Config::for_tests(std::env::temp_dir());
        let now = chrono::Utc::now().timestamp();
        let valid = serde_json::json!({
            "sub": "u", "iss": ISSUER, "aud": AUDIENCE, "typ": "access",
            "iat": now, "exp": now + 60, "jti": "j", "auth_time": now,
        });
        let hs256 = Header::new(Algorithm::HS256);
        assert!(
            validate_access_token(&sign(valid.clone(), hs256.clone(), &config), &config).is_some()
        );

        for (field, value) in [("aud", "someone-else"), ("iss", "evil"), ("typ", "refresh")] {
            let mut claims = valid.clone();
            claims[field] = value.into();
            let token = sign(claims, hs256.clone(), &config);
            assert!(
                validate_access_token(&token, &config).is_none(),
                "{field}={value}"
            );
        }
        let mut expired = valid.clone();
        expired["exp"] = (now - 3600).into();
        assert!(validate_access_token(&sign(expired, hs256, &config), &config).is_none());

        let hs512 = sign(valid, Header::new(Algorithm::HS512), &config);
        assert!(validate_access_token(&hs512, &config).is_none());
    }
}
