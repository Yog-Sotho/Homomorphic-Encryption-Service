//! `/api/v1/keys`: register, list and delete the caller's TFHE server keys, and
//! attach the compact public keys proven inputs are checked against.

use crate::config::Config;
use crate::crypto::keys::{validate_compressed_key, validate_public_key, KeyStore, KeyStoreError};
use crate::errors::AppError;
use actix_web::{web, HttpResponse, Responder};
use sha2::{Digest, Sha256};
use sqlx::SqlitePool;
use std::sync::Arc;
use uuid::Uuid;

pub use heaas_core::api::ServerKeyInfo;

const KEY_COLUMNS: &str =
    "id, sha256, size_bytes, created_at, supports_proofs, public_key_sha256 IS NOT NULL AS has_public_key";

/// `POST /api/v1/keys` — body is a `safe_serialize`d TFHE `CompressedServerKey`.
#[utoipa::path(post, path = "/keys", tag = "keys", security(("bearer" = [])), request_body(content = inline(crate::api::openapi::Binary), content_type = "application/octet-stream", description = "A `safe_serialize`d TFHE-rs `CompressedServerKey` for the parameters of `/he/params`"), responses((status = 201, description = "Registered", body = heaas_core::api::ServerKeyInfo, headers(("Location" = String, description = "The new key"))), (status = 400, description = "Not a compressed server key for these parameters", body = heaas_core::api::ErrorBody), (status = 409, description = "The account already has its maximum number of keys", body = heaas_core::api::ErrorBody), (status = 413, description = "Larger than `max_server_key_bytes`", body = heaas_core::api::ErrorBody)))]
pub async fn upload_key(
    pool: web::Data<SqlitePool>,
    config: web::Data<Arc<Config>>,
    store: web::Data<KeyStore>,
    user_id: web::ReqData<String>,
    body: web::Bytes,
) -> Result<impl Responder, AppError> {
    let user_id = user_id.into_inner();
    if body.is_empty() {
        return Err(AppError::bad_request(
            "Request body must be a compressed server key",
        ));
    }

    // Parsing a ~60 MB key is CPU work; keep it off the async workers.
    let limit = config.max_server_key_bytes;
    let bytes = body.clone();
    let (sha256, supports_proofs) = web::block(move || {
        let valid = validate_compressed_key(&bytes, limit)?;
        Ok::<_, KeyStoreError>((
            format!("{:x}", Sha256::digest(&bytes)),
            valid.supports_proofs,
        ))
    })
    .await
    .map_err(|e| AppError::internal(format!("key validation task: {e}")))?
    .map_err(key_store_error)?;

    let size_bytes = body.len() as i64;
    let key_id = Uuid::new_v4().to_string();
    let save_store = store.clone();
    let save_id = key_id.clone();
    web::block(move || save_store.save(&save_id, &body))
        .await
        .map_err(|e| AppError::internal(format!("key save task: {e}")))?
        .map_err(key_store_error)?;

    // The per-user limit is part of the insert, so concurrent uploads cannot both
    // get past it.
    let inserted: Option<ServerKeyInfo> = sqlx::query_as(&format!(
        "INSERT INTO server_keys (id, user_id, sha256, size_bytes, supports_proofs)
         SELECT ?, ?, ?, ?, ?
         WHERE (SELECT COUNT(*) FROM server_keys WHERE user_id = ?) < ?
         RETURNING {KEY_COLUMNS}"
    ))
    .bind(&key_id)
    .bind(&user_id)
    .bind(&sha256)
    .bind(size_bytes)
    .bind(supports_proofs)
    .bind(&user_id)
    .bind(config.max_keys_per_user)
    .fetch_optional(pool.get_ref())
    .await
    .inspect_err(|_| {
        let _ = store.remove(&key_id);
    })?;

    match inserted {
        Some(info) => Ok(HttpResponse::Created()
            .insert_header(("Location", format!("/api/v1/keys/{}", info.id)))
            .json(info)),
        None => {
            let _ = store.remove(&key_id);
            Err(AppError::conflict(format!(
                "You already have {} server keys. Delete one before adding another.",
                config.max_keys_per_user
            )))
        }
    }
}

/// `GET /api/v1/keys` — the caller's keys, newest first.
#[utoipa::path(get, path = "/keys", tag = "keys", security(("bearer" = [])), responses((status = 200, description = "The caller's keys, newest first", body = Vec<heaas_core::api::ServerKeyInfo>)))]
pub async fn list_keys(
    pool: web::Data<SqlitePool>,
    user_id: web::ReqData<String>,
) -> Result<impl Responder, AppError> {
    let keys: Vec<ServerKeyInfo> = sqlx::query_as(&format!(
        "SELECT {KEY_COLUMNS} FROM server_keys
         WHERE user_id = ? ORDER BY created_at DESC, id"
    ))
    .bind(user_id.into_inner())
    .fetch_all(pool.get_ref())
    .await?;
    Ok(HttpResponse::Ok().json(keys))
}

/// `DELETE /api/v1/keys/{id}` — removes the key; its jobs stay but lose the reference.
#[utoipa::path(delete, path = "/keys/{id}", tag = "keys", security(("bearer" = [])), params(("id" = String, Path, description = "Key id")), responses((status = 204, description = "Deleted"), (status = 404, description = "No such key", body = heaas_core::api::ErrorBody)))]
pub async fn delete_key(
    pool: web::Data<SqlitePool>,
    store: web::Data<KeyStore>,
    user_id: web::ReqData<String>,
    key_id: web::Path<String>,
) -> Result<impl Responder, AppError> {
    let key_id = key_id.into_inner();
    let deleted = sqlx::query("DELETE FROM server_keys WHERE id = ? AND user_id = ?")
        .bind(&key_id)
        .bind(user_id.into_inner())
        .execute(pool.get_ref())
        .await?
        .rows_affected();
    if deleted == 0 {
        return Err(AppError::not_found("Server key not found"));
    }
    if let Err(e) = store.remove(&key_id) {
        // The row is gone, so the key is unusable; the orphaned file is only disk space.
        tracing::error!("Failed to delete key file {key_id}: {e}");
    }
    Ok(HttpResponse::NoContent().finish())
}

/// `PUT /api/v1/keys/{id}/public-key` — body is a `safe_serialize`d TFHE
/// `CompactPublicKey` made from the same client key as server key `id`.
#[utoipa::path(put, path = "/keys/{id}/public-key", tag = "keys", security(("bearer" = [])), params(("id" = String, Path, description = "Key id")), request_body(content = inline(crate::api::openapi::Binary), content_type = "application/octet-stream", description = "A `safe_serialize`d TFHE-rs `CompactPublicKey` (at most `proofs.max_public_key_bytes`)"), responses((status = 200, description = "Stored; proven inputs can now be sent for this key", body = heaas_core::api::ServerKeyInfo), (status = 400, description = "Not a compact public key for these parameters", body = heaas_core::api::ErrorBody), (status = 404, description = "No such key", body = heaas_core::api::ErrorBody), (status = 413, description = "Larger than `proofs.max_public_key_bytes`", body = heaas_core::api::ErrorBody), (status = 422, description = "The server key was made without proof support", body = heaas_core::api::ErrorBody)))]
pub async fn upload_public_key(
    pool: web::Data<SqlitePool>,
    store: web::Data<KeyStore>,
    user_id: web::ReqData<String>,
    key_id: web::Path<String>,
    body: web::Bytes,
) -> Result<impl Responder, AppError> {
    let (key_id, user_id) = (key_id.into_inner(), user_id.into_inner());
    let key: Option<(bool,)> =
        sqlx::query_as("SELECT supports_proofs FROM server_keys WHERE id = ? AND user_id = ?")
            .bind(&key_id)
            .bind(&user_id)
            .fetch_optional(pool.get_ref())
            .await?;
    match key {
        None => return Err(AppError::not_found("Server key not found")),
        Some((false,)) => {
            return Err(AppError::unprocessable(
                "This server key was made before HE Engine 0.5 and cannot take proven inputs",
            ))
        }
        Some((true,)) => {}
    }

    let (save_store, save_id) = (store.clone(), key_id.clone());
    let sha256 = web::block(move || {
        validate_public_key(&body)?;
        save_store.save_public_key(&save_id, &body)?;
        Ok::<_, KeyStoreError>(format!("{:x}", Sha256::digest(&body)))
    })
    .await
    .map_err(|e| AppError::internal(format!("public key task: {e}")))?
    .map_err(key_store_error)?;

    let info: Option<ServerKeyInfo> = sqlx::query_as(&format!(
        "UPDATE server_keys SET public_key_sha256 = ? WHERE id = ? AND user_id = ?
         RETURNING {KEY_COLUMNS}"
    ))
    .bind(&sha256)
    .bind(&key_id)
    .bind(&user_id)
    .fetch_optional(pool.get_ref())
    .await?;
    // Deleted meanwhile: its files are being removed too.
    info.map(|info| HttpResponse::Ok().json(info))
        .ok_or_else(|| AppError::not_found("Server key not found"))
}

/// Maps key store failures to API errors without leaking filesystem details.
pub fn key_store_error(e: KeyStoreError) -> AppError {
    match e {
        KeyStoreError::Invalid(m) => AppError::bad_request(m),
        KeyStoreError::NotFound => AppError::not_found("Server key not found"),
        KeyStoreError::Io(e) => AppError::internal(format!("key store: {e}")),
    }
}
