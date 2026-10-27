//! The HTTP client against a mock server: requests, error handling, retries.

use heaas_sdk::{Client, Error, Operation};
use serde_json::{json, Value};
use std::time::Duration;
use wiremock::matchers::{body_json, header, header_exists, method, path, query_param};
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

fn job(id: &str, status: &str) -> Value {
    let error_message = if status == "failed" {
        json!("Internal error")
    } else {
        Value::Null
    };
    json!({
        "id": id,
        "status": status,
        "operation": "multiply",
        "key_id": "key-1",
        "attempts": 1,
        "error_message": error_message,
        "input_bytes": 264_000,
        "result_bytes": null,
        "created_at": "2026-10-27T10:00:00",
        "started_at": null,
        "finished_at": null
    })
}

fn envelope(status: u16, code: &str, message: &str) -> ResponseTemplate {
    ResponseTemplate::new(status)
        .set_body_json(json!({ "error": { "code": code, "message": message } }))
}

#[tokio::test]
async fn login_stores_the_token_and_later_calls_send_it() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/v1/auth/login"))
        .and(body_json(
            json!({ "email": "a@example.com", "password": "pw" }),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "token": "access-1",
            "expires_in": 900,
            "user": { "id": "u1", "email": "a@example.com", "created_at": "2026-10-25T00:00:00" }
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/v1/keys"))
        .and(header("authorization", "Bearer access-1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
        .expect(2)
        .mount(&server)
        .await;

    // The site's URL, with or without /api/v1 and a trailing slash.
    let client = Client::new(&format!("{}/", server.uri())).unwrap();
    let auth = client.login("a@example.com", "pw").await.unwrap();
    assert_eq!(auth.expires_in, 900);
    assert_eq!(client.token().as_deref(), Some("access-1"));
    assert!(client.list_keys().await.unwrap().is_empty());

    let explicit = Client::new(&format!("{}/api/v1", server.uri()))
        .unwrap()
        .with_token("access-1");
    assert!(explicit.list_keys().await.unwrap().is_empty());
}

#[tokio::test]
async fn errors_carry_the_envelope_code_and_retry_after() {
    let server = MockServer::start().await;
    Mock::given(path("/api/v1/keys"))
        .respond_with(envelope(429, "rate_limited", "Slow down").insert_header("Retry-After", "7"))
        .mount(&server)
        .await;
    // A proxy's own error page: no envelope.
    Mock::given(path("/api/v1/he/params"))
        .respond_with(ResponseTemplate::new(502).set_body_string("<html>Bad gateway</html>"))
        .mount(&server)
        .await;

    let client = Client::new(&server.uri()).unwrap().with_token("t");
    match client.list_keys().await {
        Err(Error::Api {
            status,
            code,
            message,
            retry_after,
        }) => {
            assert_eq!(
                (status, code.as_str(), message.as_str()),
                (429, "rate_limited", "Slow down")
            );
            assert_eq!(retry_after, Some(Duration::from_secs(7)));
        }
        other => panic!("{other:?}"),
    }
    let err = client.params().await.unwrap_err();
    assert_eq!(err.code(), Some("internal"));
    assert!(err.to_string().contains("Bad gateway"), "{err}");
}

#[tokio::test]
async fn incompatible_servers_are_refused() {
    let server = MockServer::start().await;
    Mock::given(path("/api/v1/he/params"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "scheme": "TFHE (CGGI)",
            "library": "TFHE-rs",
            "tfhe_version": "0.0.1",
            "config": "ConfigBuilder::default()",
            "integer_type": "FheUint16",
            "plaintext_modulus": 65536,
            "operations": ["add"],
            "max_ciphertext_bytes": 1_048_576,
            "max_server_key_bytes": 83_886_080,
            "max_keys_per_user": 2
        })))
        .mount(&server)
        .await;
    let client = Client::new(&server.uri()).unwrap();
    assert!(matches!(
        client.check_compatible().await,
        Err(Error::Incompatible(m)) if m.contains("0.0.1")
    ));
}

/// Answers 503 (queue full) first, then accepts; records the idempotency keys.
struct BusyThenAccepted(std::sync::Mutex<Vec<String>>);

impl Respond for BusyThenAccepted {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let mut keys = self.0.lock().unwrap();
        let key = request.headers.get("idempotency-key").unwrap();
        keys.push(key.to_str().unwrap().to_string());
        if keys.len() == 1 {
            envelope(503, "unavailable", "The job queue is full").insert_header("Retry-After", "0")
        } else {
            ResponseTemplate::new(202).set_body_json(job("job-1", "pending"))
        }
    }
}

#[tokio::test]
async fn submissions_are_retried_with_the_same_idempotency_key() {
    let server = MockServer::start().await;
    let responder = std::sync::Arc::new(BusyThenAccepted(Default::default()));
    Mock::given(method("POST"))
        .and(path("/api/v1/compute/jobs"))
        .and(header_exists("idempotency-key"))
        .respond_with(SharedResponder(responder.clone()))
        .expect(2)
        .mount(&server)
        .await;

    let client = Client::new(&server.uri()).unwrap().with_token("t");
    let job = client
        .submit("key-1", Operation::Multiply, b"ct-a", b"ct-b")
        .await
        .unwrap();
    assert_eq!(job.id, "job-1");
    let keys = responder.0.lock().unwrap().clone();
    assert_eq!(keys.len(), 2);
    assert_eq!(keys[0], keys[1]);

    let requests = server.received_requests().await.unwrap();
    let body: Value = serde_json::from_slice(&requests[0].body).unwrap();
    assert_eq!(body["operation"], "multiply");
    assert_eq!(body["inputs"], json!(["Y3QtYQ==", "Y3QtYg=="]));
}

/// Other refusals are returned at once: retrying would not help.
#[tokio::test]
async fn client_errors_are_not_retried() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/v1/compute/jobs"))
        .respond_with(envelope(404, "not_found", "Server key not found"))
        .expect(1)
        .mount(&server)
        .await;
    let client = Client::new(&server.uri()).unwrap().with_token("t");
    let err = client
        .submit_idempotent("nope", Operation::Add, b"a", b"b", "my-key")
        .await
        .unwrap_err();
    assert_eq!(err.code(), Some("not_found"));
    let requests = server.received_requests().await.unwrap();
    assert_eq!(
        requests[0].headers.get("idempotency-key").unwrap(),
        "my-key"
    );
}

struct SharedResponder<R>(std::sync::Arc<R>);

impl<R: Respond> Respond for SharedResponder<R> {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        self.0.respond(request)
    }
}

/// Answers each poll with the next status in the list.
struct Statuses(std::sync::Mutex<Vec<&'static str>>);

impl Respond for Statuses {
    fn respond(&self, _: &Request) -> ResponseTemplate {
        let mut statuses = self.0.lock().unwrap();
        let status = if statuses.len() > 1 {
            statuses.remove(0)
        } else {
            statuses[0]
        };
        ResponseTemplate::new(200).set_body_json(job("job-1", status))
    }
}

#[tokio::test]
async fn wait_polls_until_the_job_finishes() {
    let server = MockServer::start().await;
    Mock::given(path("/api/v1/compute/jobs/job-1"))
        .respond_with(Statuses(std::sync::Mutex::new(vec![
            "pending",
            "processing",
            "completed",
        ])))
        .expect(3)
        .mount(&server)
        .await;
    Mock::given(path("/api/v1/compute/jobs/job-1/result"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(b"ciphertext".to_vec()))
        .mount(&server)
        .await;

    let client = Client::new(&server.uri()).unwrap().with_token("t");
    let job = client.wait("job-1", Duration::from_secs(10)).await.unwrap();
    assert_eq!(job.status.as_str(), "completed");
    assert_eq!(client.result("job-1").await.unwrap(), b"ciphertext");
}

#[tokio::test]
async fn failed_and_slow_jobs_are_errors() {
    let server = MockServer::start().await;
    Mock::given(path("/api/v1/compute/jobs/bad"))
        .respond_with(ResponseTemplate::new(200).set_body_json(job("bad", "failed")))
        .mount(&server)
        .await;
    Mock::given(path("/api/v1/compute/jobs/slow"))
        .respond_with(ResponseTemplate::new(200).set_body_json(job("slow", "processing")))
        .mount(&server)
        .await;

    let client = Client::new(&server.uri()).unwrap().with_token("t");
    assert!(matches!(
        client.wait("bad", Duration::from_secs(5)).await,
        Err(Error::JobFailed { message, .. }) if message == "Internal error"
    ));
    assert!(matches!(
        client.wait("slow", Duration::from_millis(300)).await,
        Err(Error::Timeout { .. })
    ));
}

#[tokio::test]
async fn ids_are_sent_as_single_path_segments_and_pages_as_queries() {
    let server = MockServer::start().await;
    Mock::given(method("DELETE"))
        .and(path("/api/v1/keys/a%2Fb"))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/v1/compute/jobs"))
        .and(query_param("cursor", "abc"))
        .and(query_param("limit", "5"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({ "data": [job("j", "completed")], "next_cursor": null })),
        )
        .expect(1)
        .mount(&server)
        .await;

    let client = Client::new(&server.uri()).unwrap().with_token("t");
    client.delete_key("a/b").await.unwrap();
    let page = client.list_jobs(Some("abc"), Some(5)).await.unwrap();
    assert_eq!(page.data.len(), 1);
    assert!(page.next_cursor.is_none());
}

#[test]
fn only_http_urls_are_accepted() {
    for bad in ["ftp://example.com", "not a url", "file:///tmp"] {
        assert!(Client::new(bad).is_err(), "{bad}");
    }
}
