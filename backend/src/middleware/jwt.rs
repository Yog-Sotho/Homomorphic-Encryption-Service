use actix_web::{dev::ServiceRequest, Error, HttpMessage};
use actix_web_lab::middleware::Next;
use jsonwebtoken::{decode, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use crate::config::Config;

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub exp: usize,
}

pub async fn jwt_validator(
    req: ServiceRequest,
    next: Next<impl actix_web::body::MessageBody>,
) -> Result<actix_web::dev::ServiceResponse<impl actix_web::body::MessageBody>, Error> {
    let config = req
        .app_data::<actix_web::web::Data<Arc<Config>>>()
        .cloned()
        .ok_or_else(|| actix_web::error::ErrorInternalServerError("Config not found"))?;

    let auth_header = req.headers().get("Authorization");

    if let Some(auth_header) = auth_header {
        if let Ok(auth_str) = auth_header.to_str() {
            if auth_str.starts_with("Bearer ") {
                let token = &auth_str[7..];

                match decode::<Claims>(
                    token,
                    &DecodingKey::from_secret(config.jwt_secret.as_ref()),
                    &Validation::default(),
                ) {
                    Ok(token_data) => {
                        req.extensions_mut().insert(token_data.claims.sub);
                        return next.call(req).await;
                    }
                    Err(_) => {}
                }
            }
        }
    }

    Err(actix_web::error::ErrorUnauthorized("Invalid or missing token"))
}
