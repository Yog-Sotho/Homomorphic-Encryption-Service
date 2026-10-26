//! End-to-end tests over HTTP: the test plays the client (it holds the secret key
//! and encrypts/decrypts), the app under test only ever receives the compressed
//! server key and ciphertexts.

use crate::api::{self, auth::make_jwt};
use crate::config::Config;
use crate::crypto::eval::Operation;
use crate::crypto::keys::test_support::{client_key, compressed_server_key_bytes, temp_store_dir};
use crate::crypto::keys::KeyStore;
use crate::crypto::params::{MAX_CIPHERTEXT_BYTES, TFHE_VERSION};
use crate::middleware::rate_limit::RateLimiter;
use actix_web::dev::{Service, ServiceResponse};
use actix_web::http::StatusCode;
use actix_web::{test, web, App};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde_json::{json, Value};
use sqlx::sqlite::SqlitePoolOptions;
use sqlx::SqlitePool;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tfhe::prelude::*;
use tfhe::safe_serialization::{safe_deserialize, safe_serialize};
use tfhe::FheUint16;

struct TestEnv {
    pool: SqlitePool,
    config: Arc<Config>,
    store: web::Data<KeyStore>,
    dir: PathBuf,
}

impl TestEnv {
    async fn new() -> Self {
        // One connection: every connection to `sqlite::memory:` is its own database.
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        sqlx::migrate!("./migrations").run(&pool).await.unwrap();
        let dir = temp_store_dir();
        let config = Arc::new(Config::for_tests(dir.clone()));
        let store = web::Data::new(
            KeyStore::new(&dir, config.max_server_key_bytes, config.key_cache_capacity).unwrap(),
        );
        TestEnv {
            pool,
            config,
            store,
            dir,
        }
    }

    async fn app(
        &self,
    ) -> impl Service<actix_http::Request, Response = ServiceResponse, Error = actix_web::Error>
    {
        let config = self.config.clone();
        test::init_service(
            App::new()
                .app_data(web::Data::new(self.pool.clone()))
                .app_data(web::Data::new(self.config.clone()))
                .app_data(self.store.clone())
                .app_data(web::Data::new(RateLimiter::new()))
                .configure(move |cfg| api::configure(cfg, &config)),
        )
        .await
    }

    /// Creates a verified user and returns a bearer token for them.
    async fn user(&self, id: &str) -> String {
        sqlx::query(
            "INSERT INTO users (id, email, password_hash, email_verified) VALUES (?, ?, '', 1)",
        )
        .bind(id)
        .bind(format!("{id}@example.com"))
        .execute(&self.pool)
        .await
        .unwrap();
        format!("Bearer {}", make_jwt(id, &self.config).unwrap())
    }
}

impl Drop for TestEnv {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn encrypt_b64(value: u16) -> String {
    let mut bytes = Vec::new();
    safe_serialize(
        &FheUint16::encrypt(value, client_key()),
        &mut bytes,
        MAX_CIPHERTEXT_BYTES,
    )
    .unwrap();
    STANDARD.encode(bytes)
}

fn decrypt_b64(b64: &str) -> u16 {
    let bytes = STANDARD.decode(b64).unwrap();
    let ct: FheUint16 = safe_deserialize(bytes.as_slice(), MAX_CIPHERTEXT_BYTES).unwrap();
    ct.decrypt(client_key())
}

async fn upload_key(
    app: &impl Service<actix_http::Request, Response = ServiceResponse, Error = actix_web::Error>,
    token: &str,
    body: &[u8],
) -> ServiceResponse {
    let req = test::TestRequest::post()
        .uri("/api/keys")
        .insert_header(("Authorization", token))
        .insert_header(("Content-Type", "application/octet-stream"))
        .set_payload(body.to_vec())
        .to_request();
    test::call_service(app, req).await
}

async fn submit_job(
    app: &impl Service<actix_http::Request, Response = ServiceResponse, Error = actix_web::Error>,
    token: &str,
    body: Value,
) -> ServiceResponse {
    let req = test::TestRequest::post()
        .uri("/api/compute/jobs")
        .insert_header(("Authorization", token))
        .set_json(body)
        .to_request();
    test::call_service(app, req).await
}

/// Polls a job until it leaves pending/processing.
async fn wait_for_job(
    app: &impl Service<actix_http::Request, Response = ServiceResponse, Error = actix_web::Error>,
    token: &str,
    job_id: &str,
) -> Value {
    let deadline = Instant::now() + Duration::from_secs(120);
    loop {
        let req = test::TestRequest::get()
            .uri(&format!("/api/compute/jobs/{job_id}"))
            .insert_header(("Authorization", token))
            .to_request();
        let job: Value = test::call_and_read_body_json(app, req).await;
        if job["status"] != "pending" && job["status"] != "processing" {
            return job;
        }
        assert!(
            Instant::now() < deadline,
            "job {job_id} did not finish: {job}"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

async fn usage_count(pool: &SqlitePool, user_id: &str) -> i64 {
    sqlx::query_as::<_, (i64,)>(
        "SELECT COALESCE(SUM(count), 0) FROM daily_compute_usage WHERE user_id = ?",
    )
    .bind(user_id)
    .fetch_one(pool)
    .await
    .unwrap()
    .0
}

#[actix_web::test]
async fn client_key_never_leaves_the_client_and_results_decrypt_correctly() {
    let env = TestEnv::new().await;
    let app = env.app().await;
    let alice = env.user("alice").await;

    let resp = upload_key(&app, &alice, compressed_server_key_bytes()).await;
    assert_eq!(resp.status(), StatusCode::CREATED);
    let key: Value = test::read_body_json(resp).await;
    let key_id = key["id"].as_str().unwrap().to_string();
    assert_eq!(key["size_bytes"], compressed_server_key_bytes().len());
    assert!(env.store.contains_file(&key_id));

    let req = test::TestRequest::get()
        .uri("/api/keys")
        .insert_header(("Authorization", alice.as_str()))
        .to_request();
    let keys: Value = test::call_and_read_body_json(&app, req).await;
    assert_eq!(keys.as_array().unwrap().len(), 1);

    for (op, a, b) in [
        (Operation::Add, 40_000u16, 30_000u16),
        (Operation::Subtract, 3, 10),
        (Operation::Multiply, 300, 300),
        (Operation::Min, 9, 4),
        (Operation::Max, 9, 4),
    ] {
        let resp = submit_job(
            &app,
            &alice,
            json!({ "key_id": key_id, "operation": op, "inputs": [encrypt_b64(a), encrypt_b64(b)] }),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::ACCEPTED);
        let job: Value = test::read_body_json(resp).await;

        let done = wait_for_job(&app, &alice, job["id"].as_str().unwrap()).await;
        assert_eq!(done["status"], "completed", "{op:?}: {done}");
        assert_eq!(done["key_id"], key_id);
        let result = decrypt_b64(done["result_b64"].as_str().unwrap());
        assert_eq!(result, op.apply_plain(a, b), "{op:?}({a}, {b})");
    }

    // Five submissions, many status polls: only submissions are charged.
    assert_eq!(usage_count(&env.pool, "alice").await, 5);
}

#[actix_web::test]
async fn keys_are_private_to_their_owner() {
    let env = TestEnv::new().await;
    let app = env.app().await;
    let alice = env.user("alice").await;
    let mallory = env.user("mallory").await;

    let key: Value =
        test::read_body_json(upload_key(&app, &alice, compressed_server_key_bytes()).await).await;
    let key_id = key["id"].as_str().unwrap();

    let resp = submit_job(
        &app,
        &mallory,
        json!({ "key_id": key_id, "operation": "add", "inputs": [encrypt_b64(1), encrypt_b64(2)] }),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        usage_count(&env.pool, "mallory").await,
        0,
        "rejected jobs are not charged"
    );

    let req = test::TestRequest::delete()
        .uri(&format!("/api/keys/{key_id}"))
        .insert_header(("Authorization", mallory.as_str()))
        .to_request();
    assert_eq!(
        test::call_service(&app, req).await.status(),
        StatusCode::NOT_FOUND
    );

    let req = test::TestRequest::get()
        .uri("/api/keys")
        .insert_header(("Authorization", mallory.as_str()))
        .to_request();
    let keys: Value = test::call_and_read_body_json(&app, req).await;
    assert_eq!(keys, json!([]));
    assert!(env.store.contains_file(key_id));
}

#[actix_web::test]
async fn key_uploads_are_validated_limited_and_authenticated() {
    let env = TestEnv::new().await;
    let app = env.app().await;
    let alice = env.user("alice").await;

    assert_eq!(
        upload_key(&app, &alice, b"not a key").await.status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        upload_key(&app, &alice, b"").await.status(),
        StatusCode::BAD_REQUEST
    );
    // The JWT guard rejects with a service error rather than a response.
    let unauthenticated = test::TestRequest::post()
        .uri("/api/keys")
        .insert_header(("Authorization", "Bearer nope"))
        .set_payload(compressed_server_key_bytes().to_vec())
        .to_request();
    let err = test::try_call_service(&app, unauthenticated)
        .await
        .expect_err("rejected");
    assert_eq!(
        err.as_response_error().status_code(),
        StatusCode::UNAUTHORIZED
    );

    for _ in 0..env.config.max_keys_per_user {
        assert_eq!(
            upload_key(&app, &alice, compressed_server_key_bytes())
                .await
                .status(),
            StatusCode::CREATED
        );
    }
    let resp = upload_key(&app, &alice, compressed_server_key_bytes()).await;
    assert_eq!(resp.status(), StatusCode::CONFLICT);

    // Exactly the accepted keys are on disk; rejected uploads leave nothing behind.
    let files = std::fs::read_dir(&env.dir)
        .unwrap()
        .filter_map(Result::ok)
        .count();
    assert_eq!(files as i64, env.config.max_keys_per_user);
}

#[actix_web::test]
async fn invalid_ciphertexts_fail_the_job_with_a_clear_message() {
    let env = TestEnv::new().await;
    let app = env.app().await;
    let alice = env.user("alice").await;
    let key: Value =
        test::read_body_json(upload_key(&app, &alice, compressed_server_key_bytes()).await).await;

    // Rejected before queueing: wrong count, not base64.
    let bad_shape = submit_job(
        &app,
        &alice,
        json!({ "key_id": key["id"], "operation": "add", "inputs": [encrypt_b64(1)] }),
    )
    .await;
    assert_eq!(bad_shape.status(), StatusCode::BAD_REQUEST);
    let bad_op = submit_job(&app, &alice, json!({ "key_id": key["id"], "operation": "divide", "inputs": [encrypt_b64(1), encrypt_b64(2)] })).await;
    assert_eq!(bad_op.status(), StatusCode::BAD_REQUEST);

    // Well-formed request, but input 1 is not a ciphertext: the job fails cleanly.
    let resp = submit_job(
        &app,
        &alice,
        json!({ "key_id": key["id"], "operation": "add", "inputs": [STANDARD.encode(b"junk"), encrypt_b64(2)] }),
    )
    .await;
    let job: Value = test::read_body_json(resp).await;
    let done = wait_for_job(&app, &alice, job["id"].as_str().unwrap()).await;
    assert_eq!(done["status"], "failed");
    assert_eq!(
        done["error_message"],
        "Input 1 is not a valid FheUint16 ciphertext for this key"
    );
}

#[actix_web::test]
async fn deleting_a_key_or_the_account_removes_key_files() {
    let env = TestEnv::new().await;
    let app = env.app().await;
    let alice = env.user("alice").await;

    let first: Value =
        test::read_body_json(upload_key(&app, &alice, compressed_server_key_bytes()).await).await;
    let first_id = first["id"].as_str().unwrap().to_string();
    let req = test::TestRequest::delete()
        .uri(&format!("/api/keys/{first_id}"))
        .insert_header(("Authorization", alice.as_str()))
        .to_request();
    assert_eq!(
        test::call_service(&app, req).await.status(),
        StatusCode::NO_CONTENT
    );
    assert!(!env.store.contains_file(&first_id));
    let resp = submit_job(&app, &alice, json!({ "key_id": first_id, "operation": "add", "inputs": [encrypt_b64(1), encrypt_b64(2)] })).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    let second: Value =
        test::read_body_json(upload_key(&app, &alice, compressed_server_key_bytes()).await).await;
    let second_id = second["id"].as_str().unwrap().to_string();
    let req = test::TestRequest::delete()
        .uri("/api/user/account")
        .insert_header(("Authorization", alice.as_str()))
        .set_json(json!({ "password": "" }))
        .to_request();
    assert_eq!(test::call_service(&app, req).await.status(), StatusCode::OK);
    assert!(!env.store.contains_file(&second_id));
}

#[actix_web::test]
async fn params_endpoint_describes_what_clients_must_match() {
    let env = TestEnv::new().await;
    let app = env.app().await;
    let req = test::TestRequest::get().uri("/api/he/params").to_request();
    let params: Value = test::call_and_read_body_json(&app, req).await;
    assert_eq!(params["tfhe_version"], TFHE_VERSION);
    assert_eq!(params["integer_type"], "FheUint16");
    assert_eq!(
        params["operations"],
        json!(["add", "subtract", "multiply", "min", "max"])
    );
    assert_eq!(params["max_keys_per_user"], env.config.max_keys_per_user);
}
