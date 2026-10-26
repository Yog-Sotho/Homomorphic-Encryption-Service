//! `/api/keys`: register, list and delete the caller's TFHE server keys.

use crate::config::Config;
use crate::crypto::keys::{validate_compressed_key, KeyStore, KeyStoreError};
use crate::errors::AppError;
use actix_web::{web, HttpResponse, Responder};
use serde::Serialize;
use sha2::{Digest, Sha256};
use sqlx::SqlitePool;
use std::sync::Arc;
use uuid::Uuid;

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct ServerKeyInfo {
    pub id: String,
    pub sha256: String,
    pub size_bytes: i64,
    pub created_at: chrono::NaiveDateTime,
}

/// `POST /api/keys` — body is a `safe_serialize`d TFHE `CompressedServerKey`.
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
    let sha256 = web::block(move || {
        validate_compressed_key(&bytes, limit)?;
        Ok::<_, KeyStoreError>(format!("{:x}", Sha256::digest(&bytes)))
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
    let inserted: Option<ServerKeyInfo> = sqlx::query_as(
        "INSERT INTO server_keys (id, user_id, sha256, size_bytes)
         SELECT ?, ?, ?, ?
         WHERE (SELECT COUNT(*) FROM server_keys WHERE user_id = ?) < ?
         RETURNING id, sha256, size_bytes, created_at",
    )
    .bind(&key_id)
    .bind(&user_id)
    .bind(&sha256)
    .bind(size_bytes)
    .bind(&user_id)
    .bind(config.max_keys_per_user)
    .fetch_optional(pool.get_ref())
    .await
    .inspect_err(|_| {
        let _ = store.remove(&key_id);
    })?;

    match inserted {
        Some(info) => Ok(HttpResponse::Created()
            .insert_header(("Location", format!("/api/keys/{}", info.id)))
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

/// `GET /api/keys` — the caller's keys, newest first.
pub async fn list_keys(
    pool: web::Data<SqlitePool>,
    user_id: web::ReqData<String>,
) -> Result<impl Responder, AppError> {
    let keys: Vec<ServerKeyInfo> = sqlx::query_as(
        "SELECT id, sha256, size_bytes, created_at FROM server_keys
         WHERE user_id = ? ORDER BY created_at DESC, id",
    )
    .bind(user_id.into_inner())
    .fetch_all(pool.get_ref())
    .await?;
    Ok(HttpResponse::Ok().json(keys))
}

/// `DELETE /api/keys/{id}` — removes the key; its jobs stay but lose the reference.
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
        log::error!("Failed to delete key file {key_id}: {e}");
    }
    Ok(HttpResponse::NoContent().finish())
}

/// Maps key store failures to API errors without leaking filesystem details.
pub fn key_store_error(e: KeyStoreError) -> AppError {
    match e {
        KeyStoreError::Invalid(m) => AppError::bad_request(m),
        KeyStoreError::NotFound => AppError::not_found("Server key not found"),
        KeyStoreError::Io(e) => AppError::internal(format!("key store: {e}")),
    }
}
