use crate::config::Config;
use actix_web::middleware::Next;
use actix_web::{dev::ServiceRequest, Error, HttpMessage};
use jsonwebtoken::{decode, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub exp: usize,
}

pub async fn jwt_validator<B: actix_web::body::MessageBody>(
    req: ServiceRequest,
    next: Next<B>,
) -> Result<actix_web::dev::ServiceResponse<B>, Error> {
    let config = req
        .app_data::<actix_web::web::Data<Arc<Config>>>()
        .cloned()
        .ok_or_else(|| actix_web::error::ErrorInternalServerError("Config not found"))?;

    let auth_header = req.headers().get("Authorization");

    if let Some(auth_header) = auth_header {
        if let Ok(auth_str) = auth_header.to_str() {
            if let Some(token) = auth_str.strip_prefix("Bearer ") {
                if let Ok(token_data) = decode::<Claims>(
                    token,
                    &DecodingKey::from_secret(config.jwt_secret.as_ref()),
                    &Validation::default(),
                ) {
                    req.extensions_mut().insert(token_data.claims.sub);
                    return next.call(req).await;
                }
            }
        }
    }

    Err(actix_web::error::ErrorUnauthorized(
        "Invalid or missing token",
    ))
}
