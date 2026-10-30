//! End-to-end tests over HTTP: the test plays the client (it holds the secret key
//! and encrypts/decrypts), the app under test only ever receives the compressed
//! server key and ciphertexts.

use crate::api::{self, auth::make_jwt};
use crate::config::Config;
use crate::crypto::eval::Operation;
use crate::crypto::keys::test_support::{
    client_key, compressed_server_key_bytes, public_key_bytes, temp_store_dir,
};
use crate::crypto::keys::KeyStore;
use crate::crypto::params::{MAX_CIPHERTEXT_BYTES, TFHE_VERSION};
use crate::crypto::proofs::{test_support::crs, Crs};
use crate::jobs::store::JobStore;
use crate::jobs::worker::{JobNotifier, Liveness, WorkerPool, WorkerSettings};
use crate::middleware::rate_limit::RateLimits;
use actix_web::dev::{Service, ServiceResponse};
use actix_web::http::StatusCode;
use actix_web::{test, web, App};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use heaas_core::{IntegerType, PlainValue, ValueType};
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
    crs: web::Data<Crs>,
    jobs: web::Data<JobStore>,
    notifier: web::Data<JobNotifier>,
    liveness: web::Data<Liveness>,
    /// Kept alive for the test; dropping it stops the workers.
    _workers: Option<WorkerPool>,
    dir: PathBuf,
}

/// The app `main` builds, from a test environment's parts.
macro_rules! app {
    ($pool:expr, $config:expr, $store:expr, $crs:expr, $jobs:expr, $notifier:expr, $liveness:expr) => {{
        let config: Arc<Config> = $config;
        let routes = config.clone();
        App::new()
            .wrap(actix_web::middleware::from_fn(
                crate::telemetry::request_context,
            ))
            .app_data(web::Data::new($pool))
            .app_data(web::Data::new(config.clone()))
            .app_data($store)
            .app_data($crs)
            .app_data($jobs)
            .app_data($notifier)
            .app_data($liveness)
            .app_data(web::Data::new(RateLimits::new(&config)))
            .app_data(web::Data::new(crate::api::auth::oauth::http_client()))
            .app_data(web::Data::new(
                crate::api::auth::email::Mailer::new(&config.mail).unwrap(),
            ))
            .configure(crate::telemetry::configure)
            .configure(move |cfg| api::configure(cfg, &routes))
    }};
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
        let crs = web::Data::from(crs());
        let jobs = web::Data::new(JobStore::new(&config.job_store_dir).unwrap());
        let workers = if run_workers {
            let settings = WorkerSettings {
                workers: config.he_workers,
                job_timeout: config.job_timeout,
                max_attempts: config.max_job_attempts,
                retention_days: config.job_retention_days,
            };
            let processor =
                crate::jobs::evaluator(store.clone().into_inner(), crs.clone().into_inner());
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
        let liveness = web::Data::new(
            workers
                .as_ref()
                .map_or_else(Liveness::default, WorkerPool::liveness),
        );
        TestEnv {
            pool,
            config,
            store,
            crs,
            jobs,
            notifier,
            liveness,
            _workers: workers,
            dir,
        }
    }

    pub(super) async fn app(
        &self,
    ) -> impl Service<actix_http::Request, Response = ServiceResponse, Error = actix_web::Error>
    {
        test::init_service(app!(
            self.pool.clone(),
            self.config.clone(),
            self.store.clone(),
            self.crs.clone(),
            self.jobs.clone(),
            self.notifier.clone(),
            self.liveness.clone()
        ))
        .await
    }

    /// Runs the app on a real HTTP server on a free local port, for clients
    /// such as the SDK. Returns its URL; the server stops with the test.
    pub(super) async fn serve(&self) -> String {
        let parts = (
            self.pool.clone(),
            self.config.clone(),
            self.store.clone(),
            self.crs.clone(),
            self.jobs.clone(),
            self.notifier.clone(),
            self.liveness.clone(),
        );
        let server = actix_web::HttpServer::new(move || {
            let (pool, config, store, crs, jobs, notifier, liveness) = parts.clone();
            app!(pool, config, store, crs, jobs, notifier, liveness)
        })
        .workers(1)
        .bind(("127.0.0.1", 0))
        .unwrap();
        let url = format!("http://{}", server.addrs()[0]);
        actix_web::rt::spawn(server.run());
        url
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
        assert_eq!(
            PlainValue::Int(decrypt(&bytes).into()),
            op.apply_plain(IntegerType::U16, &[a.into(), b.into()]),
            "{op:?}({a}, {b})"
        );
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
    let unauthenticated = test::TestRequest::post()
        .uri("/api/v1/keys")
        .insert_header(("Authorization", "Bearer nope"))
        .set_payload(compressed_server_key_bytes().to_vec())
        .to_request();
    assert_eq!(
        test::call_service(&app, unauthenticated).await.status(),
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
    assert_eq!(params["operations"], json!(Operation::ALL));
    assert_eq!(params["integer_types"], json!(IntegerType::ALL));
    assert_eq!(params["max_keys_per_user"], env.config.max_keys_per_user);
    assert_eq!(params["proofs"]["crs_sha256"], env.crs.sha256);

    // The CRS is served as advertised, and revalidates by its ETag.
    let resp = test::call_service(
        &app,
        test::TestRequest::get().uri("/api/v1/he/crs").to_request(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let etag = resp
        .headers()
        .get("etag")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    assert_eq!(etag, format!("\"{}\"", env.crs.sha256));
    let bytes = test::read_body(resp).await;
    assert_eq!(bytes.as_ref(), env.crs.bytes.as_slice());
    heaas_sdk::fhe::crs_from_bytes(&bytes).unwrap();
    let req = test::TestRequest::get()
        .uri("/api/v1/he/crs")
        .insert_header(("If-None-Match", etag))
        .to_request();
    assert_eq!(
        test::call_service(&app, req).await.status(),
        StatusCode::NOT_MODIFIED
    );
}

async fn upload_public_key(
    app: &impl Service<actix_http::Request, Response = ServiceResponse, Error = actix_web::Error>,
    token: &str,
    key_id: &str,
    body: &[u8],
) -> ServiceResponse {
    let req = test::TestRequest::put()
        .uri(&format!("/api/v1/keys/{key_id}/public-key"))
        .insert_header(("Authorization", token))
        .insert_header(("Content-Type", "application/octet-stream"))
        .set_payload(body.to_vec())
        .to_request();
    test::call_service(app, req).await
}

/// Submits a job, waits for it and decrypts its result as its `result_type`.
async fn run_job(
    app: &impl Service<actix_http::Request, Response = ServiceResponse, Error = actix_web::Error>,
    token: &str,
    body: Value,
) -> PlainValue {
    let id = queue_job(app, token, body).await;
    let done = wait_for_job(app, token, &id).await;
    assert_eq!(done["status"], "completed", "{done}");
    let resp = get(app, token, &format!("/api/v1/compute/jobs/{id}/result")).await;
    let result_type: ValueType = serde_json::from_value(done["result_type"].clone()).unwrap();
    heaas_sdk::fhe::decrypt_as(client_key(), result_type, &test::read_body(resp).await).unwrap()
}

fn ciphertexts(ty: IntegerType, values: &[i128]) -> Vec<String> {
    values
        .iter()
        .map(|&v| STANDARD.encode(heaas_sdk::fhe::encrypt_as(client_key(), ty, v).unwrap()))
        .collect()
}

#[actix_web::test]
async fn typed_jobs_take_scalars_and_sums_and_report_result_types() {
    let env = TestEnv::new().await;
    let app = env.app().await;
    let alice = env.user("alice").await;
    let key_id = register_key(&app, &alice).await;

    // A signed comparison with a scalar: the result is an encrypted boolean.
    let lt = json!({ "key_id": key_id, "operation": "lt", "integer_type": "i32",
                     "inputs": ciphertexts(IntegerType::I32, &[-5]), "scalar": "-4" });
    assert_eq!(run_job(&app, &alice, lt).await, PlainValue::Bool(true));

    // A sum that wraps around.
    let sum = json!({ "key_id": key_id, "operation": "sum", "integer_type": "u8",
                      "inputs": ciphertexts(IntegerType::U8, &[200, 100, 1, 2, 3]) });
    assert_eq!(run_job(&app, &alice, sum).await, PlainValue::Int(50));

    let page: Value = test::read_body_json(get(&app, &alice, "/api/v1/compute/jobs").await).await;
    let (sum_job, lt_job) = (&page["data"][0], &page["data"][1]);
    assert_eq!(
        (
            &lt_job["result_type"],
            &lt_job["scalar"],
            &lt_job["input_count"]
        ),
        (&json!("bool"), &json!("-4"), &json!(1))
    );
    assert_eq!(
        (&sum_job["integer_type"], &sum_job["input_count"]),
        (&json!("u8"), &json!(5))
    );

    // Shapes the server refuses before queuing anything.
    let one = ciphertexts(IntegerType::U8, &[1]);
    for (body, why) in [
        (
            json!({ "key_id": key_id, "operation": "add", "integer_type": "u8", "inputs": one, "scalar": "256" }),
            "scalar out of range",
        ),
        (
            json!({ "key_id": key_id, "operation": "add", "integer_type": "u8", "inputs": one }),
            "one input, no scalar",
        ),
        (
            json!({ "key_id": key_id, "operation": "sum", "integer_type": "u8", "inputs": one }),
            "sum of one",
        ),
        (
            json!({ "key_id": key_id, "operation": "sum", "integer_type": "u8", "inputs": [one[0], one[0]], "scalar": "1" }),
            "sum with a scalar",
        ),
        (
            json!({ "key_id": key_id, "operation": "add", "integer_type": "u8", "inputs": one, "proven_inputs": "AAAA" }),
            "both kinds of input",
        ),
        (
            json!({ "key_id": key_id, "operation": "add", "integer_type": "u8" }),
            "no inputs",
        ),
        (
            json!({ "key_id": key_id, "operation": "add", "proven_inputs": "bm90IGEgbGlzdA==" }),
            "a malformed proven list",
        ),
    ] {
        let resp = submit_job(&app, &alice, body).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "{why}");
    }
    let resp = submit_job(
        &app,
        &alice,
        json!({ "key_id": key_id, "operation": "add", "integer_type": "u128", "inputs": one }),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);

    // Ciphertexts of another type than declared fail the job, not the server.
    let wrong = json!({ "key_id": key_id, "operation": "add", "integer_type": "u16",
                        "inputs": ciphertexts(IntegerType::U8, &[1, 2]) });
    let id = queue_job(&app, &alice, wrong).await;
    let done = wait_for_job(&app, &alice, &id).await;
    assert_eq!(done["status"], "failed");
    assert!(
        done["error_message"]
            .as_str()
            .unwrap()
            .contains("FheUint16"),
        "{done}"
    );
}

#[actix_web::test]
async fn program_jobs_run_several_operations_on_encrypted_values() {
    let env = TestEnv::new().await;
    let app = env.app().await;
    let alice = env.user("alice").await;
    let key_id = register_key(&app, &alice).await;

    // (a + b) * 3 < c ? a - b : b - a, all encrypted on the server.
    let compiled = heaas_core::parse_expression("(a + b) * 3 < c ? a - b : b - a").unwrap();
    let body = json!({
        "key_id": key_id, "operation": "program", "integer_type": "i16",
        "inputs": ciphertexts(IntegerType::I16, &[5, 7, 100]),
        "program": compiled.program,
    });
    assert_eq!(run_job(&app, &alice, body).await, PlainValue::Int(-2));

    let page: Value = test::read_body_json(get(&app, &alice, "/api/v1/compute/jobs").await).await;
    let job = &page["data"][0];
    assert_eq!(
        (&job["operation"], &job["result_type"]),
        (&json!("program"), &json!("i16"))
    );
    assert_eq!(job["program"], json!(compiled.program));

    // A program ending in a comparison returns an encrypted boolean.
    let compare = heaas_core::parse_expression("a / b >= 3 && a % b == 1").unwrap();
    let body = json!({
        "key_id": key_id, "operation": "program", "integer_type": "u8",
        "inputs": ciphertexts(IntegerType::U8, &[10, 3]), "program": compare.program,
    });
    assert_eq!(run_job(&app, &alice, body).await, PlainValue::Bool(true));

    // Refused before anything is queued.
    let one = ciphertexts(IntegerType::U8, &[1]);
    let add = heaas_core::parse_expression("a + b").unwrap().program;
    for (body, why) in [
        (
            json!({ "key_id": key_id, "operation": "program", "integer_type": "u8", "inputs": one }),
            "no program",
        ),
        (
            json!({ "key_id": key_id, "operation": "add", "integer_type": "u8", "inputs": [one[0], one[0]], "program": add }),
            "a program on another operation",
        ),
        (
            json!({ "key_id": key_id, "operation": "program", "integer_type": "u8", "inputs": one, "program": add }),
            "reads an input it does not have",
        ),
        (
            json!({ "key_id": key_id, "operation": "program", "integer_type": "u8", "inputs": one, "scalar": "1",
                 "program": heaas_core::parse_expression("a + 1").unwrap().program }),
            "a scalar",
        ),
        (
            json!({ "key_id": key_id, "operation": "program", "integer_type": "u8", "inputs": one,
                 "program": { "steps": [{ "op": "divide", "args": [{ "input": 0 }, { "const": "0" }] }] } }),
            "division by the constant 0",
        ),
    ] {
        let resp = submit_job(&app, &alice, body).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "{why}");
    }
    let resp = submit_job(
        &app,
        &alice,
        json!({ "key_id": key_id, "operation": "program", "integer_type": "u8",
        "inputs": one, "program": { "steps": [{ "op": "sqrt", "args": [{ "input": 0 }] }] } }),
    )
    .await;
    assert_eq!(
        resp.status(),
        StatusCode::UNPROCESSABLE_ENTITY,
        "unknown step operation"
    );
}

async fn submit_batch(
    app: &impl Service<actix_http::Request, Response = ServiceResponse, Error = actix_web::Error>,
    token: &str,
    key: Option<&str>,
    jobs: Vec<Value>,
) -> ServiceResponse {
    let mut req = test::TestRequest::post()
        .uri("/api/v1/compute/jobs/batch")
        .insert_header(("Authorization", token))
        .set_json(json!({ "jobs": jobs }));
    if let Some(key) = key {
        req = req.insert_header(("Idempotency-Key", key));
    }
    test::call_service(app, req.to_request()).await
}

#[actix_web::test]
async fn batches_queue_every_job_or_none() {
    let env = TestEnv::new().await;
    let app = env.app().await;
    let alice = env.user("alice").await;
    let key_id = register_key(&app, &alice).await;
    let program = heaas_core::parse_expression("a * b - 1").unwrap().program;
    let jobs = vec![
        json!({ "key_id": key_id, "operation": "add", "integer_type": "u8",
                "inputs": ciphertexts(IntegerType::U8, &[200, 100]) }),
        json!({ "key_id": key_id, "operation": "program", "integer_type": "i16",
                "inputs": ciphertexts(IntegerType::I16, &[-3, 4]), "program": program }),
        json!({ "key_id": key_id, "operation": "lt", "integer_type": "u16",
                "inputs": ciphertexts(IntegerType::U16, &[7]), "scalar": "9" }),
    ];
    let resp = submit_batch(&app, &alice, Some("batch-1"), jobs.clone()).await;
    assert_eq!(resp.status(), StatusCode::ACCEPTED);
    let body: Value = test::read_body_json(resp).await;
    let ids: Vec<String> = body["jobs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|j| j["id"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(ids.len(), 3);
    assert_eq!(body["jobs"][1]["operation"], "program");
    assert_eq!(usage_count(&env.pool, "alice").await, 3);

    let expected = [
        PlainValue::Int(44),
        PlainValue::Int(-13),
        PlainValue::Bool(true),
    ];
    for (id, want) in ids.iter().zip(expected) {
        let done = wait_for_job(&app, &alice, id).await;
        assert_eq!(done["status"], "completed", "{done}");
        let result_type: ValueType = serde_json::from_value(done["result_type"].clone()).unwrap();
        let resp = get(&app, &alice, &format!("/api/v1/compute/jobs/{id}/result")).await;
        let bytes = test::read_body(resp).await;
        assert_eq!(
            heaas_sdk::fhe::decrypt_as(client_key(), result_type, &bytes).unwrap(),
            want
        );
    }

    // The same batch with the same key is the same jobs, not charged again;
    // the key with another batch is refused.
    let resp = submit_batch(&app, &alice, Some("batch-1"), jobs.clone()).await;
    assert_eq!(resp.status(), StatusCode::ACCEPTED);
    assert_eq!(resp.headers().get("Idempotent-Replayed").unwrap(), "true");
    let again: Value = test::read_body_json(resp).await;
    assert_eq!(again["jobs"][2]["id"], json!(ids[2]));
    assert_eq!(usage_count(&env.pool, "alice").await, 3);
    let resp = submit_batch(&app, &alice, Some("batch-1"), jobs[..2].to_vec()).await;
    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);

    // One bad job refuses the batch, naming it; nothing is queued or charged.
    let mut bad = jobs.clone();
    bad[1]["scalar"] = json!("1");
    let resp = submit_batch(&app, &alice, None, bad).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let error: Value = test::read_body_json(resp).await;
    assert!(
        error["error"]["message"]
            .as_str()
            .unwrap()
            .starts_with("Job 2: "),
        "{error}"
    );
    for (jobs, why) in [(vec![], "empty"), (vec![jobs[0].clone(); 17], "too many")] {
        let resp = submit_batch(&app, &alice, None, jobs).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "{why}");
    }
    let page: Value = test::read_body_json(get(&app, &alice, "/api/v1/compute/jobs").await).await;
    assert_eq!(page["data"].as_array().unwrap().len(), 3);
    assert_eq!(usage_count(&env.pool, "alice").await, 3);
}

#[actix_web::test]
async fn a_batch_beyond_the_limits_queues_nothing_and_charges_nothing() {
    let env = TestEnv::without_workers(|c| {
        c.max_active_jobs_per_user = 2;
        c.daily_compute_quota = 4;
    })
    .await;
    let app = env.app().await;
    let alice = env.user("alice").await;
    let key_id = register_key(&app, &alice).await;
    let job = json!({ "key_id": key_id, "operation": "add", "integer_type": "u8",
                      "inputs": ciphertexts(IntegerType::U8, &[1, 2]) });

    // Three jobs, room for two: none is queued.
    let resp = submit_batch(&app, &alice, None, vec![job.clone(); 3]).await;
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(usage_count(&env.pool, "alice").await, 0);
    let page: Value = test::read_body_json(get(&app, &alice, "/api/v1/compute/jobs").await).await;
    assert!(page["data"].as_array().unwrap().is_empty());
    assert!(std::fs::read_dir(&env.config.job_store_dir)
        .unwrap()
        .next()
        .is_none());

    // Two fit. Then a batch the quota cannot cover leaves the rest of it.
    let resp = submit_batch(&app, &alice, None, vec![job.clone(); 2]).await;
    assert_eq!(resp.status(), StatusCode::ACCEPTED);
    sqlx::query("UPDATE jobs SET status = 'completed'")
        .execute(&env.pool)
        .await
        .unwrap();
    let resp = submit_batch(&app, &alice, None, vec![job.clone(); 3]).await;
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    let error: Value = test::read_body_json(resp).await;
    assert!(
        error["error"]["message"]
            .as_str()
            .unwrap()
            .contains("2 left"),
        "{error}"
    );
    assert_eq!(usage_count(&env.pool, "alice").await, 2);
}

#[actix_web::test]
async fn proven_inputs_need_the_public_key_and_a_valid_proof() {
    let env = TestEnv::new().await;
    let app = env.app().await;
    let alice = env.user("alice").await;
    let key_id = register_key(&app, &alice).await;
    // Proofs are checked against the uploaded public key: prove with that one.
    let public_key = crate::crypto::keys::test_support::public_key();
    let prove = |key: &str, values: &[i128]| {
        STANDARD.encode(
            heaas_sdk::fhe::prove(public_key, &env.crs.crs, key, IntegerType::I16, values).unwrap(),
        )
    };
    let body = |list: String| json!({ "key_id": key_id, "operation": "multiply", "integer_type": "i16", "proven_inputs": list });

    // Without the public key the server cannot check the proof.
    let resp = submit_job(&app, &alice, body(prove(&key_id, &[-3, 7]))).await;
    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);

    let resp = upload_public_key(&app, &alice, &key_id, b"not a key").await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let resp = upload_public_key(&app, &alice, &key_id, public_key_bytes()).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let info: Value = test::read_body_json(resp).await;
    assert_eq!(
        (&info["supports_proofs"], &info["has_public_key"]),
        (&json!(true), &json!(true))
    );
    let mallory = env.user("mallory").await;
    let resp = upload_public_key(&app, &mallory, &key_id, public_key_bytes()).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    assert_eq!(
        run_job(&app, &alice, body(prove(&key_id, &[-3, 7]))).await,
        PlainValue::Int(-21)
    );

    // A proof bound to another key id is refused when the job runs.
    let other = prove(&uuid::Uuid::new_v4().to_string(), &[1, 2]);
    let id = queue_job(&app, &alice, body(other)).await;
    let done = wait_for_job(&app, &alice, &id).await;
    assert_eq!(done["status"], "failed");
    assert!(
        done["error_message"].as_str().unwrap().contains("proof"),
        "{done}"
    );

    // A list of another type is refused at submission.
    let u8_list = STANDARD.encode(
        heaas_sdk::fhe::prove(public_key, &env.crs.crs, &key_id, IntegerType::U8, &[1, 2]).unwrap(),
    );
    let resp = submit_job(&app, &alice, body(u8_list)).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
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

/// What a Rust customer does, through the SDK and a real HTTP server: sign in,
/// register a key, compute every operation on ciphertexts, decrypt locally.
#[actix_web::test]
async fn the_sdk_runs_the_whole_flow_against_a_live_server() {
    use heaas_sdk::{fhe, Client};

    let env = TestEnv::new().await;
    let password = "Correct-horse-battery-1";
    let hash = crate::api::auth::password::hash_password(password.into())
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO users (id, email, password_hash, email_verified)
         VALUES ('sdk', 'sdk@example.com', ?, 1)",
    )
    .bind(hash)
    .execute(&env.pool)
    .await
    .unwrap();
    let client = Client::new(&env.serve().await).unwrap();

    let refused = client.login("sdk@example.com", "wrong").await.unwrap_err();
    assert_eq!(refused.code(), Some("unauthorized"), "{refused}");
    client.login("sdk@example.com", password).await.unwrap();
    let params = client.check_compatible().await.unwrap();
    assert_eq!(params.tfhe_version, TFHE_VERSION);

    let key = client
        .upload_key(compressed_server_key_bytes().to_vec())
        .await
        .unwrap();
    assert_eq!(client.list_keys().await.unwrap()[0].id, key.id);

    let secret = client_key();
    let (a, b) = (
        fhe::encrypt(secret, 300).unwrap(),
        fhe::encrypt(secret, 7).unwrap(),
    );
    for op in Operation::BASIC {
        let request = heaas_core::api::CreateJobRequest {
            key_id: key.id.clone(),
            operation: op,
            integer_type: IntegerType::U16,
            inputs: vec![heaas_sdk::encode(&a), heaas_sdk::encode(&b)],
            proven_inputs: None,
            scalar: None,
            program: None,
        };
        let (job, result) = client
            .compute_job(&request, Duration::from_secs(300))
            .await
            .unwrap();
        assert_eq!(
            fhe::decrypt_as(secret, job.result_type, &result).unwrap(),
            op.apply_plain(IntegerType::U16, &[300, 7]),
            "{op}"
        );
    }
    let result = client
        .compute(
            &key.id,
            Operation::Multiply,
            &a,
            &b,
            Duration::from_secs(300),
        )
        .await
        .unwrap();
    assert_eq!(fhe::decrypt(secret, &result).unwrap(), 2100);

    // Proven inputs: the public key, the server's CRS, a proof bound to the key
    // and made with the public key that was uploaded.
    let public_key = fhe::public_key(secret);
    let with_public_key = client
        .upload_public_key(&key.id, fhe::public_key_bytes(&public_key).unwrap())
        .await
        .unwrap();
    assert!(with_public_key.has_public_key);
    let crs = client.crs().await.unwrap();
    let list = fhe::prove(&public_key, &crs, &key.id, IntegerType::U64, &[1, 2, 3]).unwrap();
    let request = heaas_core::api::CreateJobRequest {
        key_id: key.id.clone(),
        operation: Operation::Sum,
        integer_type: IntegerType::U64,
        inputs: Vec::new(),
        proven_inputs: Some(heaas_sdk::encode(&list)),
        scalar: None,
        program: None,
    };
    let (job, result) = client
        .compute_job(&request, Duration::from_secs(300))
        .await
        .unwrap();
    assert!(job.proven);
    assert_eq!(
        fhe::decrypt_as(secret, job.result_type, &result).unwrap(),
        PlainValue::Int(6)
    );

    // A batch: both jobs queued in one request.
    let make = |op: Operation, x: u16, y: u16| heaas_core::api::CreateJobRequest {
        key_id: key.id.clone(),
        operation: op,
        integer_type: IntegerType::U16,
        inputs: vec![
            heaas_sdk::encode(&fhe::encrypt(secret, x).unwrap()),
            heaas_sdk::encode(&fhe::encrypt(secret, y).unwrap()),
        ],
        proven_inputs: None,
        scalar: None,
        program: None,
    };
    let batch = client
        .submit_batch(&[make(Operation::Max, 3, 9), make(Operation::Subtract, 3, 9)])
        .await
        .unwrap();
    assert_eq!(batch.len(), 2);
    let mut decrypted = Vec::new();
    for job in &batch {
        client
            .wait(&job.id, Duration::from_secs(300))
            .await
            .unwrap();
        decrypted.push(fhe::decrypt(secret, &client.result(&job.id).await.unwrap()).unwrap());
    }
    assert_eq!(decrypted, [9, 65530]);

    // A program, compiled from an expression by the SDK's parser.
    let compiled = heaas_sdk::parse_expression("a * a - b > 80 ? a : b").unwrap();
    let request = heaas_core::api::CreateJobRequest {
        key_id: key.id.clone(),
        operation: Operation::Program,
        integer_type: IntegerType::I32,
        inputs: vec![
            heaas_sdk::encode(&fhe::encrypt_as(secret, IntegerType::I32, 9).unwrap()),
            heaas_sdk::encode(&fhe::encrypt_as(secret, IntegerType::I32, -4).unwrap()),
        ],
        proven_inputs: None,
        scalar: None,
        program: Some(compiled.program),
    };
    let (job, result) = client
        .compute_job(&request, Duration::from_secs(300))
        .await
        .unwrap();
    assert_eq!(
        fhe::decrypt_as(secret, job.result_type, &result).unwrap(),
        PlainValue::Int(9)
    );

    // A resubmission with the same idempotency key is the same job.
    let first = client
        .submit_idempotent(&key.id, Operation::Add, &a, &b, "sdk-retry")
        .await
        .unwrap();
    let again = client
        .submit_idempotent(&key.id, Operation::Add, &a, &b, "sdk-retry")
        .await
        .unwrap();
    assert_eq!(first.id, again.id);
    client
        .wait(&first.id, Duration::from_secs(300))
        .await
        .unwrap();

    let page = client.list_jobs(None, Some(2)).await.unwrap();
    assert_eq!(page.data.len(), 2);
    let rest = client
        .list_jobs(page.next_cursor.as_deref(), None)
        .await
        .unwrap();
    assert_eq!(
        page.data.len() + rest.data.len(),
        Operation::BASIC.len() + 6
    );

    // Errors arrive typed, with the envelope's code.
    let missing = client
        .job(&uuid::Uuid::new_v4().to_string())
        .await
        .unwrap_err();
    assert_eq!(missing.code(), Some("not_found"));

    client.delete_job(&first.id).await.unwrap();
    client.delete_key(&key.id).await.unwrap();
    assert!(client.list_keys().await.unwrap().is_empty());
}

#[actix_web::test]
async fn readiness_checks_the_database_stores_and_workers() {
    let env = TestEnv::new().await;
    let app = env.app().await;
    async fn ready(
        app: &impl Service<actix_http::Request, Response = ServiceResponse, Error = actix_web::Error>,
    ) -> (StatusCode, Value) {
        let resp = test::call_service(
            app,
            test::TestRequest::get()
                .uri("/api/v1/health/ready")
                .to_request(),
        )
        .await;
        let status = resp.status();
        (status, test::read_body_json(resp).await)
    }

    let (status, body) = ready(&app).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body["checks"],
        json!({ "database": "ok", "key_store": "ok", "job_store": "ok", "workers": "2/2" })
    );

    // A store that can no longer take files makes the instance unready.
    std::fs::remove_dir_all(&env.config.key_store_dir).unwrap();
    let (status, body) = ready(&app).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["error"]["code"], "unavailable");
    assert_eq!(body["error"]["message"], "Not ready: key store");
    assert_eq!(body["checks"]["key_store"], "unavailable");
    assert_eq!(body["checks"]["database"], "ok");
}

#[actix_web::test]
async fn metrics_need_the_token_and_label_routes_by_pattern() {
    let token = "metrics-token-that-is-at-least-32-bytes";
    let disabled = TestEnv::without_workers(|_| {}).await;
    let app = disabled.app().await;
    let resp =
        test::call_service(&app, test::TestRequest::get().uri("/metrics").to_request()).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    let env = TestEnv::without_workers(|c| c.metrics_token = Some(token.into())).await;
    let app = env.app().await;
    let alice = env.user("alice").await;
    // A request with an id in its path, to see how it is labelled.
    let missing = test::TestRequest::get()
        .uri(&format!("/api/v1/compute/jobs/{}", uuid::Uuid::new_v4()))
        .insert_header(("Authorization", alice.as_str()))
        .to_request();
    assert_eq!(
        test::call_service(&app, missing).await.status(),
        StatusCode::NOT_FOUND
    );

    for presented in [None, Some("Bearer wrong"), Some(token)] {
        let mut req = test::TestRequest::get().uri("/metrics");
        if let Some(value) = presented {
            req = req.insert_header(("Authorization", value));
        }
        let status = test::call_service(&app, req.to_request()).await.status();
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{presented:?}");
    }
    let resp = test::call_service(
        &app,
        test::TestRequest::get()
            .uri("/metrics")
            .insert_header(("Authorization", format!("Bearer {token}")))
            .to_request(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let text = String::from_utf8(test::read_body(resp).await.to_vec()).unwrap();
    for expected in [
        r#"heaas_http_requests_total{method="GET",route="/api/v1/compute/jobs/{id}",status="404"}"#,
        r#"heaas_jobs{status="pending"} 0"#,
        "heaas_server_keys 0",
        "heaas_build_info{",
    ] {
        assert!(text.contains(expected), "{expected} missing from\n{text}");
    }
}

#[actix_web::test]
async fn every_response_carries_a_request_id() {
    let env = TestEnv::without_workers(|_| {}).await;
    let app = env.app().await;
    // Including errors raised by middleware before any handler runs.
    for req in [
        test::TestRequest::get().uri("/api/v1/health"),
        test::TestRequest::get().uri("/api/v1/keys"),
        test::TestRequest::get().uri("/api/v1/nope"),
    ] {
        let resp = test::call_service(&app, req.to_request()).await;
        let id = resp.headers().get("x-request-id").expect("x-request-id");
        assert!(uuid::Uuid::parse_str(id.to_str().unwrap()).is_ok());
    }
    let resp = test::call_service(
        &app,
        test::TestRequest::get()
            .uri("/api/v1/keys")
            .insert_header(("X-Request-Id", "trace-42"))
            .to_request(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(resp.headers().get("x-request-id").unwrap(), "trace-42");
    let body: Value = test::read_body_json(resp).await;
    assert_eq!(body["error"]["code"], "unauthorized");
}
