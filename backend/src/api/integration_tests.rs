//! End-to-end tests over HTTP: the test plays the client (it holds the secret key
//! and encrypts/decrypts), the app under test only ever receives the compressed
//! server key and ciphertexts.

use crate::api::{self, auth::make_jwt};
use crate::config::Config;
use crate::crypto::eval::Operation;
use crate::crypto::keys::test_support::{client_key, compressed_server_key_bytes, temp_store_dir};
use crate::crypto::keys::KeyStore;
use crate::crypto::params::{MAX_CIPHERTEXT_BYTES, TFHE_VERSION};
use crate::jobs::store::JobStore;
use crate::jobs::worker::{JobNotifier, WorkerPool, WorkerSettings};
use crate::middleware::rate_limit::RateLimits;
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

pub(super) struct TestEnv {
    pub(super) pool: SqlitePool,
    pub(super) config: Arc<Config>,
    store: web::Data<KeyStore>,
    jobs: web::Data<JobStore>,
    notifier: web::Data<JobNotifier>,
    /// Kept alive for the test; dropping it stops the workers.
    _workers: Option<WorkerPool>,
    dir: PathBuf,
}

impl TestEnv {
    /// An app with running workers: submitted jobs are evaluated.
    async fn new() -> Self {
        Self::with(|_| {}, true).await
    }

    /// An app whose jobs stay queued, for testing the queue's limits.
    pub(super) async fn without_workers(adjust: impl FnOnce(&mut Config)) -> Self {
        Self::with(adjust, false).await
    }

    async fn with(adjust: impl FnOnce(&mut Config), run_workers: bool) -> Self {
        // One connection: every connection to `sqlite::memory:` is its own database.
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        sqlx::migrate!("./migrations").run(&pool).await.unwrap();
        let dir = temp_store_dir();
        let mut config = Config::for_tests(dir.clone());
        adjust(&mut config);
        let config = Arc::new(config);
        let store = web::Data::new(
            KeyStore::new(
                &config.key_store_dir,
                config.max_server_key_bytes,
                config.key_cache_capacity,
            )
            .unwrap(),
        );
        let jobs = web::Data::new(JobStore::new(&config.job_store_dir).unwrap());
        let workers = if run_workers {
            let settings = WorkerSettings {
                workers: config.he_workers,
                job_timeout: config.job_timeout,
                max_attempts: config.max_job_attempts,
                retention_days: config.job_retention_days,
            };
            let processor = crate::jobs::evaluator(store.clone().into_inner());
            Some(
                WorkerPool::start(pool.clone(), jobs.clone().into_inner(), processor, settings)
                    .await
                    .unwrap(),
            )
        } else {
            None
        };
        let notifier = web::Data::new(
            workers
                .as_ref()
                .map_or_else(JobNotifier::default, WorkerPool::notifier),
        );
        TestEnv {
            pool,
            config,
            store,
            jobs,
            notifier,
            _workers: workers,
            dir,
        }
    }

    pub(super) async fn app(
        &self,
    ) -> impl Service<actix_http::Request, Response = ServiceResponse, Error = actix_web::Error>
    {
        let config = self.config.clone();
        test::init_service(
            App::new()
                .app_data(web::Data::new(self.pool.clone()))
                .app_data(web::Data::new(self.config.clone()))
                .app_data(self.store.clone())
                .app_data(self.jobs.clone())
                .app_data(self.notifier.clone())
                .app_data(web::Data::new(RateLimits::new(&self.config)))
                .app_data(web::Data::new(crate::api::auth::oauth::http_client()))
                .app_data(web::Data::new(
                    crate::api::auth::email::Mailer::new(&self.config.mail).unwrap(),
                ))
                .configure(move |cfg| api::configure(cfg, &config)),
        )
        .await
    }

    /// Creates a verified user and returns a bearer token for them.
    pub(super) async fn user(&self, id: &str) -> String {
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

fn decrypt(bytes: &[u8]) -> u16 {
    let ct: FheUint16 = safe_deserialize(bytes, MAX_CIPHERTEXT_BYTES).unwrap();
    ct.decrypt(client_key())
}

async fn get(
    app: &impl Service<actix_http::Request, Response = ServiceResponse, Error = actix_web::Error>,
    token: &str,
    uri: &str,
) -> ServiceResponse {
    let req = test::TestRequest::get()
        .uri(uri)
        .insert_header(("Authorization", token))
        .to_request();
    test::call_service(app, req).await
}

async fn delete(
    app: &impl Service<actix_http::Request, Response = ServiceResponse, Error = actix_web::Error>,
    token: &str,
    uri: &str,
) -> ServiceResponse {
    let req = test::TestRequest::delete()
        .uri(uri)
        .insert_header(("Authorization", token))
        .to_request();
    test::call_service(app, req).await
}

/// Uploads the shared test key and returns its id.
async fn register_key(
    app: &impl Service<actix_http::Request, Response = ServiceResponse, Error = actix_web::Error>,
    token: &str,
) -> String {
    let resp = upload_key(app, token, compressed_server_key_bytes()).await;
    assert_eq!(resp.status(), StatusCode::CREATED);
    let key: Value = test::read_body_json(resp).await;
    key["id"].as_str().unwrap().to_string()
}

fn add_request(key_id: &str, a: u16, b: u16) -> Value {
    json!({ "key_id": key_id, "operation": "add", "inputs": [encrypt_b64(a), encrypt_b64(b)] })
}

/// Submits a job that must be accepted and returns its id.
async fn queue_job(
    app: &impl Service<actix_http::Request, Response = ServiceResponse, Error = actix_web::Error>,
    token: &str,
    body: Value,
) -> String {
    let resp = submit_job(app, token, body).await;
    assert_eq!(resp.status(), StatusCode::ACCEPTED);
    let job: Value = test::read_body_json(resp).await;
    job["id"].as_str().unwrap().to_string()
}

async fn upload_key(
    app: &impl Service<actix_http::Request, Response = ServiceResponse, Error = actix_web::Error>,
    token: &str,
    body: &[u8],
) -> ServiceResponse {
    let req = test::TestRequest::post()
        .uri("/api/v1/keys")
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
        .uri("/api/v1/compute/jobs")
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
            .uri(&format!("/api/v1/compute/jobs/{job_id}"))
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
        .uri("/api/v1/keys")
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
        assert_eq!(done["attempts"], 1);

        let id = done["id"].as_str().unwrap();
        let resp = get(&app, &alice, &format!("/api/v1/compute/jobs/{id}/result")).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers().get("content-type").unwrap(),
            "application/octet-stream"
        );
        let bytes = test::read_body(resp).await;
        assert_eq!(done["result_bytes"], bytes.len());
        assert_eq!(decrypt(&bytes), op.apply_plain(a, b), "{op:?}({a}, {b})");
        // Only the result is kept once a job has finished.
        assert!(env.jobs.read_inputs(id, 2).is_err());
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
        .uri(&format!("/api/v1/keys/{key_id}"))
        .insert_header(("Authorization", mallory.as_str()))
        .to_request();
    assert_eq!(
        test::call_service(&app, req).await.status(),
        StatusCode::NOT_FOUND
    );

    let req = test::TestRequest::get()
        .uri("/api/v1/keys")
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
        .uri("/api/v1/keys")
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
    let files = std::fs::read_dir(&env.config.key_store_dir)
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
    // Valid JSON of the wrong shape (an unknown operation) is 422.
    let bad_op = submit_job(&app, &alice, json!({ "key_id": key["id"], "operation": "divide", "inputs": [encrypt_b64(1), encrypt_b64(2)] })).await;
    assert_eq!(bad_op.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let body: Value = test::read_body_json(bad_op).await;
    assert_eq!(body["error"]["code"], "unprocessable");

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
        .uri(&format!("/api/v1/keys/{first_id}"))
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
    let job_id = queue_job(&app, &alice, add_request(&second_id, 1, 2)).await;
    wait_for_job(&app, &alice, &job_id).await;
    assert!(env.jobs.read_result(&job_id).is_ok());
    let req = test::TestRequest::delete()
        .uri("/api/v1/user/account")
        .insert_header(("Authorization", alice.as_str()))
        .set_json(json!({ "password": "" }))
        .to_request();
    assert_eq!(test::call_service(&app, req).await.status(), StatusCode::OK);
    assert!(!env.store.contains_file(&second_id));
    assert!(
        !env.jobs.has_data(&job_id),
        "job ciphertexts deleted with the account"
    );
}

#[actix_web::test]
async fn idempotency_keys_replay_the_original_job() {
    let env = TestEnv::without_workers(|_| {}).await;
    let app = env.app().await;
    let alice = env.user("alice").await;
    let key_id = register_key(&app, &alice).await;
    let body = add_request(&key_id, 1, 2);

    let send = |body: Value, key: &str| {
        test::TestRequest::post()
            .uri("/api/v1/compute/jobs")
            .insert_header(("Authorization", alice.as_str()))
            .insert_header(("Idempotency-Key", key))
            .set_json(body)
            .to_request()
    };
    let first = test::call_service(&app, send(body.clone(), "retry-1")).await;
    assert_eq!(first.status(), StatusCode::ACCEPTED);
    assert!(first.headers().get("Idempotent-Replayed").is_none());
    let location = first.headers().get("location").unwrap().clone();
    let first: Value = test::read_body_json(first).await;

    let again = test::call_service(&app, send(body.clone(), "retry-1")).await;
    assert_eq!(again.status(), StatusCode::ACCEPTED);
    assert_eq!(again.headers().get("Idempotent-Replayed").unwrap(), "true");
    assert_eq!(again.headers().get("location").unwrap(), &location);
    let again: Value = test::read_body_json(again).await;
    assert_eq!(again["id"], first["id"]);
    assert_eq!(usage_count(&env.pool, "alice").await, 1, "replays are free");

    let other = test::call_service(&app, send(add_request(&key_id, 5, 6), "retry-1")).await;
    assert_eq!(other.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let bad = test::call_service(&app, send(body, "has space")).await;
    assert_eq!(bad.status(), StatusCode::BAD_REQUEST);
    assert_eq!(usage_count(&env.pool, "alice").await, 1);
}

#[actix_web::test]
async fn full_queues_push_back_without_charging() {
    let env = TestEnv::without_workers(|c| {
        c.max_active_jobs_per_user = 2;
        c.max_queued_jobs = 3;
    })
    .await;
    let app = env.app().await;
    let alice = env.user("alice").await;
    let bob = env.user("bob").await;
    let alice_key = register_key(&app, &alice).await;
    let bob_key = register_key(&app, &bob).await;

    for _ in 0..2 {
        queue_job(&app, &alice, add_request(&alice_key, 1, 2)).await;
    }
    let resp = submit_job(&app, &alice, add_request(&alice_key, 1, 2)).await;
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    assert!(resp.headers().get("retry-after").is_some());
    assert_eq!(
        usage_count(&env.pool, "alice").await,
        2,
        "refused job refunded"
    );

    queue_job(&app, &bob, add_request(&bob_key, 1, 2)).await;
    let resp = submit_job(&app, &bob, add_request(&bob_key, 1, 2)).await;
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(resp.headers().get("retry-after").unwrap(), "10");
    assert_eq!(usage_count(&env.pool, "bob").await, 1);

    // Refused submissions leave no ciphertexts behind.
    let stored = std::fs::read_dir(&env.config.job_store_dir)
        .unwrap()
        .count();
    assert_eq!(stored, 3);
}

#[actix_web::test]
async fn jobs_are_listed_in_pages_without_ciphertexts() {
    let env = TestEnv::without_workers(|_| {}).await;
    let app = env.app().await;
    let alice = env.user("alice").await;
    let bob = env.user("bob").await;
    let key_id = register_key(&app, &alice).await;
    let mut ids = Vec::new();
    for i in 0..3 {
        ids.push(queue_job(&app, &alice, add_request(&key_id, i, i)).await);
    }

    let page: Value =
        test::read_body_json(get(&app, &alice, "/api/v1/compute/jobs?limit=2").await).await;
    let first = page["data"].as_array().unwrap();
    assert_eq!(first.len(), 2);
    for job in first {
        let fields: Vec<&str> = job
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        for hidden in ["user_id", "input_data_b64", "result_b64", "idempotency_key"] {
            assert!(!fields.contains(&hidden), "{hidden} leaked: {job}");
        }
        assert_eq!(job["status"], "pending");
    }
    let cursor = page["next_cursor"].as_str().unwrap();
    let rest: Value = test::read_body_json(
        get(
            &app,
            &alice,
            &format!("/api/v1/compute/jobs?limit=2&cursor={cursor}"),
        )
        .await,
    )
    .await;
    assert_eq!(rest["data"].as_array().unwrap().len(), 1);
    assert!(rest["next_cursor"].is_null());

    let mut seen: Vec<String> = first
        .iter()
        .chain(rest["data"].as_array().unwrap())
        .map(|j| j["id"].as_str().unwrap().to_string())
        .collect();
    seen.sort();
    ids.sort();
    assert_eq!(seen, ids, "every job exactly once");

    let empty: Value = test::read_body_json(get(&app, &bob, "/api/v1/compute/jobs").await).await;
    assert_eq!(empty, json!({ "data": [], "next_cursor": null }));
    for bad in ["limit=0", "limit=101", "cursor=garbage"] {
        let resp = get(&app, &alice, &format!("/api/v1/compute/jobs?{bad}")).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "{bad}");
    }
}

#[actix_web::test]
async fn results_and_deletion_follow_the_job_state() {
    let env = TestEnv::without_workers(|_| {}).await;
    let app = env.app().await;
    let alice = env.user("alice").await;
    let mallory = env.user("mallory").await;
    let key_id = register_key(&app, &alice).await;
    let job_id = queue_job(&app, &alice, add_request(&key_id, 1, 2)).await;
    let job_uri = format!("/api/v1/compute/jobs/{job_id}");
    let result_uri = format!("{job_uri}/result");

    assert_eq!(
        get(&app, &alice, &result_uri).await.status(),
        StatusCode::CONFLICT
    );
    assert_eq!(
        get(&app, &mallory, &job_uri).await.status(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        get(&app, &mallory, &result_uri).await.status(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        delete(&app, &mallory, &job_uri).await.status(),
        StatusCode::NOT_FOUND
    );

    sqlx::query("UPDATE jobs SET status = 'processing' WHERE id = ?")
        .bind(&job_id)
        .execute(&env.pool)
        .await
        .unwrap();
    assert_eq!(
        delete(&app, &alice, &job_uri).await.status(),
        StatusCode::CONFLICT
    );

    sqlx::query("UPDATE jobs SET status = 'failed' WHERE id = ?")
        .bind(&job_id)
        .execute(&env.pool)
        .await
        .unwrap();
    assert!(env.jobs.has_data(&job_id));
    assert_eq!(
        delete(&app, &alice, &job_uri).await.status(),
        StatusCode::NO_CONTENT
    );
    assert!(!env.jobs.has_data(&job_id));
    assert_eq!(
        get(&app, &alice, &job_uri).await.status(),
        StatusCode::NOT_FOUND
    );
}

#[actix_web::test]
async fn results_stored_before_the_job_store_are_still_served() {
    let env = TestEnv::without_workers(|_| {}).await;
    let app = env.app().await;
    let alice = env.user("alice").await;
    sqlx::query(
        "INSERT INTO jobs (id, user_id, status, input_data_b64, operation, result_b64)
         VALUES ('6f1c1d4e-0000-4000-8000-000000000001', 'alice', 'completed', '', 'add', ?)",
    )
    .bind(encrypt_b64(42))
    .execute(&env.pool)
    .await
    .unwrap();

    let resp = get(
        &app,
        &alice,
        "/api/v1/compute/jobs/6f1c1d4e-0000-4000-8000-000000000001/result",
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(decrypt(&test::read_body(resp).await), 42);
}

#[actix_web::test]
async fn params_endpoint_describes_what_clients_must_match() {
    let env = TestEnv::new().await;
    let app = env.app().await;
    let req = test::TestRequest::get()
        .uri("/api/v1/he/params")
        .to_request();
    let params: Value = test::call_and_read_body_json(&app, req).await;
    assert_eq!(params["tfhe_version"], TFHE_VERSION);
    assert_eq!(params["integer_type"], "FheUint16");
    assert_eq!(
        params["operations"],
        json!(["add", "subtract", "multiply", "min", "max"])
    );
    assert_eq!(params["max_keys_per_user"], env.config.max_keys_per_user);
}

#[actix_web::test]
async fn every_error_uses_the_same_envelope() {
    let env = TestEnv::without_workers(|c| c.max_server_key_bytes = 1024).await;
    let app = env.app().await;
    let alice = env.user("alice").await;

    async fn envelope(resp: ServiceResponse) -> (StatusCode, Value) {
        let status = resp.status();
        let content_type = resp.headers().get("content-type").cloned();
        let body: Value = test::read_body_json(resp).await;
        assert_eq!(
            content_type.unwrap().to_str().unwrap(),
            "application/json",
            "{body}"
        );
        assert!(
            body["error"]["message"]
                .as_str()
                .is_some_and(|m| !m.is_empty()),
            "{body}"
        );
        (status, body["error"]["code"].clone())
    }
    let call = |req: test::TestRequest| test::call_service(&app, req.to_request());

    // Unknown route and wrong method: produced by actix itself.
    let (status, code) = envelope(call(test::TestRequest::get().uri("/api/v1/nope")).await).await;
    assert_eq!((status, code), (StatusCode::NOT_FOUND, json!("not_found")));
    let wrong_method = test::TestRequest::patch()
        .uri(&format!("/api/v1/compute/jobs/{}", uuid::Uuid::new_v4()))
        .insert_header(("Authorization", alice.as_str()));
    let (status, code) = envelope(call(wrong_method).await).await;
    assert_eq!(
        (status, code),
        (StatusCode::METHOD_NOT_ALLOWED, json!("method_not_allowed"))
    );

    // Body problems: malformed JSON, wrong content type, oversized upload.
    let malformed = test::TestRequest::post()
        .uri("/api/v1/auth/login")
        .insert_header(("content-type", "application/json"))
        .set_payload("{not json");
    let (status, code) = envelope(call(malformed).await).await;
    assert_eq!(
        (status, code),
        (StatusCode::BAD_REQUEST, json!("bad_request"))
    );
    let form = test::TestRequest::post()
        .uri("/api/v1/auth/login")
        .insert_header(("content-type", "text/plain"))
        .set_payload("email=a");
    let (status, code) = envelope(call(form).await).await;
    assert_eq!(
        (status, code),
        (
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            json!("unsupported_media_type")
        )
    );
    let oversized = test::TestRequest::post()
        .uri("/api/v1/keys")
        .insert_header(("Authorization", alice.as_str()))
        .insert_header(("content-type", "application/octet-stream"))
        .set_payload(vec![0u8; 4096]);
    let (status, code) = envelope(call(oversized).await).await;
    assert_eq!(
        (status, code),
        (StatusCode::PAYLOAD_TOO_LARGE, json!("payload_too_large"))
    );

    // Handler errors and bad query strings.
    let missing = test::TestRequest::get()
        .uri(&format!("/api/v1/compute/jobs/{}", uuid::Uuid::new_v4()))
        .insert_header(("Authorization", alice.as_str()));
    let (status, code) = envelope(call(missing).await).await;
    assert_eq!((status, code), (StatusCode::NOT_FOUND, json!("not_found")));
    let bad_query = test::TestRequest::get()
        .uri("/api/v1/compute/jobs?limit=lots")
        .insert_header(("Authorization", alice.as_str()));
    let (status, code) = envelope(call(bad_query).await).await;
    assert_eq!(
        (status, code),
        (StatusCode::BAD_REQUEST, json!("bad_request"))
    );
}

#[actix_web::test]
async fn the_unversioned_api_still_answers_but_is_marked_deprecated() {
    let env = TestEnv::without_workers(|_| {}).await;
    let app = env.app().await;

    let legacy = test::call_service(
        &app,
        test::TestRequest::get().uri("/api/he/params").to_request(),
    )
    .await;
    assert_eq!(legacy.status(), StatusCode::OK);
    assert_eq!(legacy.headers().get("deprecation").unwrap(), "@1793059200");
    assert_eq!(
        legacy.headers().get("link").unwrap(),
        "</api/v1>; rel=\"successor-version\""
    );

    let current = test::call_service(
        &app,
        test::TestRequest::get()
            .uri("/api/v1/he/params")
            .to_request(),
    )
    .await;
    assert_eq!(current.status(), StatusCode::OK);
    assert!(current.headers().get("deprecation").is_none());
}

#[actix_web::test]
async fn every_documented_operation_is_routed() {
    let env = TestEnv::without_workers(|_| {}).await;
    let app = env.app().await;
    let alice = env.user("alice").await;

    let operations = api::openapi::operations();
    assert!(operations.len() >= 25, "{operations:?}");
    for (method, path) in operations {
        let uri = format!(
            "/api/v1{}",
            path.replace("{id}", &uuid::Uuid::new_v4().to_string())
        );
        let req = test::TestRequest::default()
            .method(method.parse().unwrap())
            .uri(&uri)
            .insert_header(("Authorization", alice.as_str()))
            .insert_header(("Origin", "http://localhost:3000"))
            .to_request();
        let resp = test::call_service(&app, req).await;
        let status = resp.status();
        let body = test::read_body(resp).await;
        let unrouted = status == StatusCode::METHOD_NOT_ALLOWED
            || (status == StatusCode::NOT_FOUND
                && String::from_utf8_lossy(&body).contains("No such endpoint"));
        assert!(
            !unrouted,
            "{method} {uri} is documented but not routed ({status})"
        );
    }

    // And the document itself is served.
    let resp = test::call_service(
        &app,
        test::TestRequest::get()
            .uri("/api/v1/openapi.json")
            .to_request(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let doc: Value = test::read_body_json(resp).await;
    assert_eq!(doc["servers"][0]["url"], "/api/v1");
}
