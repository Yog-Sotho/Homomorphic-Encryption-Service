//! The HTTP client for `/api/v1`.

use crate::error::{Error, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use heaas_core::api::{
    error_codes, AuthResponse, BatchJobsRequest, BatchJobsResponse, CreateJobRequest, Credentials,
    ErrorBody, HeParams, JobPage, JobStatus, JobSummary, ServerKeyInfo,
};
use heaas_core::params::{DEFAULT_INTEGER_TYPE, TFHE_VERSION};
use heaas_core::Operation;
use reqwest::{header, Method, RequestBuilder, Response, Url};
use serde::de::DeserializeOwned;
use sha2::{Digest, Sha256};
use std::sync::RwLock;
use std::time::{Duration, Instant};

const API_PATH: &str = "api/v1";
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Most requests are small and quick.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(60);
/// Server keys are ~60 MB and validated before the server answers.
const UPLOAD_TIMEOUT: Duration = Duration::from_secs(600);
/// Submissions are retried (with the same idempotency key) this many times.
const SUBMIT_ATTEMPTS: u32 = 3;
/// A `Retry-After` longer than this is not waited out; the error is returned.
const MAX_RETRY_AFTER: Duration = Duration::from_secs(30);

/// A client for one HE Engine server.
///
/// ```no_run
/// # async fn demo() -> heaas_sdk::Result<()> {
/// use heaas_sdk::{fhe, Client, Operation};
/// use std::time::Duration;
///
/// let client = Client::new("https://heaas.example.com")?;
/// client.login("you@example.com", "your password").await?;
/// client.check_compatible().await?;
///
/// let (secret, server) = fhe::generate_keys();
/// let key = client.upload_key(fhe::server_key_bytes(&server)?).await?;
/// let a = fhe::encrypt(&secret, 300)?;
/// let b = fhe::encrypt(&secret, 300)?;
/// let result = client
///     .compute(&key.id, Operation::Multiply, &a, &b, Duration::from_secs(600))
///     .await?;
/// assert_eq!(fhe::decrypt(&secret, &result)?, 24464); // 90000 mod 65536
/// # Ok(()) }
/// ```
pub struct Client {
    http: reqwest::Client,
    api: Url,
    token: RwLock<Option<String>>,
}

impl Client {
    /// `server` is the site's URL, e.g. `https://heaas.example.com` (a URL
    /// already ending in `/api/v1` is used as is).
    pub fn new(server: &str) -> Result<Self> {
        let http = reqwest::Client::builder()
            .connect_timeout(CONNECT_TIMEOUT)
            .user_agent(concat!("heaas-sdk/", env!("CARGO_PKG_VERSION")))
            .build()?;
        Ok(Client {
            http,
            api: api_base(server)?,
            token: RwLock::new(None),
        })
    }

    /// Uses an access token obtained elsewhere instead of [`Client::login`].
    pub fn with_token(self, token: impl Into<String>) -> Self {
        self.set_token(Some(token.into()));
        self
    }

    /// The current access token, if signed in.
    pub fn token(&self) -> Option<String> {
        self.token.read().unwrap_or_else(|e| e.into_inner()).clone()
    }

    fn set_token(&self, token: Option<String>) {
        *self.token.write().unwrap_or_else(|e| e.into_inner()) = token;
    }

    /// The API URL of `segments`, each percent-encoded as one path segment.
    fn url(&self, segments: &[&str]) -> Url {
        let mut url = self.api.clone();
        url.path_segments_mut()
            .expect("an http(s) URL has path segments")
            .pop_if_empty()
            .extend(segments);
        url
    }

    fn request(&self, method: Method, segments: &[&str]) -> RequestBuilder {
        let builder = self
            .http
            .request(method, self.url(segments))
            .timeout(REQUEST_TIMEOUT);
        match self.token() {
            Some(token) => builder.bearer_auth(token),
            None => builder,
        }
    }

    /// Sends the request; any status but 2xx becomes [`Error::Api`].
    async fn send(&self, builder: RequestBuilder) -> Result<Response> {
        let response = builder.send().await?;
        if response.status().is_success() {
            Ok(response)
        } else {
            Err(api_error(response).await)
        }
    }

    async fn json<T: DeserializeOwned>(&self, builder: RequestBuilder) -> Result<T> {
        Ok(self.send(builder).await?.json().await?)
    }

    /// Signs in with email and password; later calls use the access token.
    /// (The refresh cookie is for browsers; sign in again when the token expires.)
    pub async fn login(&self, email: &str, password: &str) -> Result<AuthResponse> {
        let auth: AuthResponse = self
            .json(
                self.request(Method::POST, &["auth", "login"])
                    .json(&Credentials {
                        email: email.to_string(),
                        password: password.to_string(),
                    }),
            )
            .await?;
        self.set_token(Some(auth.token.clone()));
        Ok(auth)
    }

    /// The server's scheme, TFHE-rs version and limits (no sign-in needed).
    pub async fn params(&self) -> Result<HeParams> {
        self.json(self.request(Method::GET, &["he", "params"]))
            .await
    }

    /// Fails unless the server uses this SDK's TFHE-rs release and integer types,
    /// i.e. unless keys and ciphertexts made here will be accepted.
    pub async fn check_compatible(&self) -> Result<HeParams> {
        let params = self.params().await?;
        if params.tfhe_version != TFHE_VERSION {
            return Err(Error::Incompatible(format!(
                "the server uses TFHE-rs {}, this SDK {TFHE_VERSION}",
                params.tfhe_version
            )));
        }
        if params.integer_type != DEFAULT_INTEGER_TYPE.tfhe_name() {
            return Err(Error::Incompatible(format!(
                "the server's default type is {}, this SDK's {}",
                params.integer_type,
                DEFAULT_INTEGER_TYPE.tfhe_name()
            )));
        }
        Ok(params)
    }

    /// The server's CRS for proven inputs (see [`crate::fhe::prove`]), checked
    /// against the SHA-256 the server advertises in [`Client::params`].
    pub async fn crs(&self) -> Result<tfhe::zk::CompactPkeCrs> {
        let expected = self
            .params()
            .await?
            .proofs
            .ok_or_else(|| Error::Incompatible("the server takes no proven inputs".into()))?
            .crs_sha256;
        let bytes = self
            .send(
                self.request(Method::GET, &["he", "crs"])
                    .timeout(UPLOAD_TIMEOUT),
            )
            .await?
            .bytes()
            .await?;
        if format!("{:x}", Sha256::digest(&bytes)) != expected {
            return Err(Error::Encoding(
                "the CRS does not match the server's advertised hash".into(),
            ));
        }
        crate::fhe::crs_from_bytes(&bytes)
    }

    /// Registers a compressed server key (see [`crate::fhe::server_key_bytes`]).
    pub async fn upload_key(&self, compressed_server_key: Vec<u8>) -> Result<ServerKeyInfo> {
        self.json(
            self.request(Method::POST, &["keys"])
                .timeout(UPLOAD_TIMEOUT)
                .header(header::CONTENT_TYPE, "application/octet-stream")
                .body(compressed_server_key),
        )
        .await
    }

    /// Attaches the key's compact public key (see [`crate::fhe::public_key_bytes`]),
    /// so the server can check proofs of inputs for it.
    pub async fn upload_public_key(
        &self,
        key_id: &str,
        public_key: Vec<u8>,
    ) -> Result<ServerKeyInfo> {
        self.json(
            self.request(Method::PUT, &["keys", key_id, "public-key"])
                .header(header::CONTENT_TYPE, "application/octet-stream")
                .body(public_key),
        )
        .await
    }

    pub async fn list_keys(&self) -> Result<Vec<ServerKeyInfo>> {
        self.json(self.request(Method::GET, &["keys"])).await
    }

    pub async fn delete_key(&self, key_id: &str) -> Result<()> {
        self.send(self.request(Method::DELETE, &["keys", key_id]))
            .await
            .map(drop)
    }

    /// Queues `operation(a, b)` on two serialized `u16` ciphertexts (see
    /// [`crate::fhe::encrypt`]). Transport failures and a full queue are retried
    /// with the same idempotency key, so the job is created (and charged) once.
    /// [`Client::submit_job`] takes any job.
    pub async fn submit(
        &self,
        key_id: &str,
        operation: Operation,
        a: &[u8],
        b: &[u8],
    ) -> Result<JobSummary> {
        let idempotency_key = uuid::Uuid::new_v4().to_string();
        self.submit_idempotent(key_id, operation, a, b, &idempotency_key)
            .await
    }

    /// [`Client::submit`] with your own idempotency key (1–255 visible ASCII
    /// characters): submitting again with the same key and inputs returns the
    /// original job, e.g. after a crash.
    pub async fn submit_idempotent(
        &self,
        key_id: &str,
        operation: Operation,
        a: &[u8],
        b: &[u8],
        idempotency_key: &str,
    ) -> Result<JobSummary> {
        self.submit_job_idempotent(&binary_request(key_id, operation, a, b), idempotency_key)
            .await
    }

    /// Queues any job: other types, a scalar, a sum, proven inputs. Build
    /// `inputs` with [`encode`]. Retried like [`Client::submit`].
    pub async fn submit_job(&self, request: &CreateJobRequest) -> Result<JobSummary> {
        let idempotency_key = uuid::Uuid::new_v4().to_string();
        self.submit_job_idempotent(request, &idempotency_key).await
    }

    /// [`Client::submit_job`] with your own idempotency key.
    pub async fn submit_job_idempotent(
        &self,
        request: &CreateJobRequest,
        idempotency_key: &str,
    ) -> Result<JobSummary> {
        self.post_retried(&["compute", "jobs"], request, idempotency_key)
            .await
    }

    /// Queues several jobs at once: all of them, or none (e.g. when the quota
    /// does not cover them all). Retried like [`Client::submit`].
    pub async fn submit_batch(&self, requests: &[CreateJobRequest]) -> Result<Vec<JobSummary>> {
        let idempotency_key = uuid::Uuid::new_v4().to_string();
        self.submit_batch_idempotent(requests, &idempotency_key)
            .await
    }

    /// [`Client::submit_batch`] with your own idempotency key.
    pub async fn submit_batch_idempotent(
        &self,
        requests: &[CreateJobRequest],
        idempotency_key: &str,
    ) -> Result<Vec<JobSummary>> {
        let body = BatchJobsRequest {
            jobs: requests.to_vec(),
        };
        let response: BatchJobsResponse = self
            .post_retried(&["compute", "jobs", "batch"], &body, idempotency_key)
            .await?;
        Ok(response.jobs)
    }

    /// POSTs `body` with an idempotency key, retrying transport failures and a
    /// full queue (503) with the same key.
    async fn post_retried<B: serde::Serialize, T: DeserializeOwned>(
        &self,
        path: &[&str],
        body: &B,
        idempotency_key: &str,
    ) -> Result<T> {
        let mut attempt = 1;
        loop {
            let sent = self
                .json(
                    self.request(Method::POST, path)
                        .header("Idempotency-Key", idempotency_key)
                        .json(body),
                )
                .await;
            let wait = match &sent {
                Err(Error::Http(e)) if !e.is_decode() => Duration::from_secs(1 << (attempt - 1)),
                Err(Error::Api {
                    status: 503,
                    retry_after,
                    ..
                }) => retry_after.unwrap_or(Duration::from_secs(1)),
                _ => return sent,
            };
            if attempt >= SUBMIT_ATTEMPTS || wait > MAX_RETRY_AFTER {
                return sent;
            }
            tokio::time::sleep(wait).await;
            attempt += 1;
        }
    }

    pub async fn job(&self, job_id: &str) -> Result<JobSummary> {
        self.json(self.request(Method::GET, &["compute", "jobs", job_id]))
            .await
    }

    /// Polls until the job has finished. A failed job is [`Error::JobFailed`].
    pub async fn wait(&self, job_id: &str, timeout: Duration) -> Result<JobSummary> {
        let started = Instant::now();
        let mut interval = Duration::from_millis(200);
        loop {
            let job = self.job(job_id).await?;
            match job.status {
                JobStatus::Completed => return Ok(job),
                JobStatus::Failed => {
                    return Err(Error::JobFailed {
                        id: job.id,
                        message: job.error_message.unwrap_or_else(|| "unknown error".into()),
                    })
                }
                JobStatus::Pending | JobStatus::Processing => {}
            }
            let waited = started.elapsed();
            if waited >= timeout {
                return Err(Error::Timeout { id: job.id, waited });
            }
            tokio::time::sleep(interval.min(timeout - waited)).await;
            interval = (interval * 3 / 2).min(Duration::from_secs(2));
        }
    }

    /// The encrypted result of a completed job (decrypt it with
    /// [`crate::fhe::decrypt`]).
    pub async fn result(&self, job_id: &str) -> Result<Vec<u8>> {
        let response = self
            .send(self.request(Method::GET, &["compute", "jobs", job_id, "result"]))
            .await?;
        Ok(response.bytes().await?.to_vec())
    }

    /// Submits, waits and fetches the encrypted result.
    pub async fn compute(
        &self,
        key_id: &str,
        operation: Operation,
        a: &[u8],
        b: &[u8],
        timeout: Duration,
    ) -> Result<Vec<u8>> {
        let job = self.submit(key_id, operation, a, b).await?;
        self.wait(&job.id, timeout).await?;
        self.result(&job.id).await
    }

    /// Submits any job, waits and fetches the encrypted result. Decrypt it as the
    /// returned job's `result_type` (see [`crate::fhe::decrypt_as`]).
    pub async fn compute_job(
        &self,
        request: &CreateJobRequest,
        timeout: Duration,
    ) -> Result<(JobSummary, Vec<u8>)> {
        let job = self.submit_job(request).await?;
        let job = self.wait(&job.id, timeout).await?;
        let result = self.result(&job.id).await?;
        Ok((job, result))
    }

    /// One page of jobs, newest first; pass `next_cursor` to get the next.
    pub async fn list_jobs(&self, cursor: Option<&str>, limit: Option<u32>) -> Result<JobPage> {
        let mut builder = self.request(Method::GET, &["compute", "jobs"]);
        if let Some(cursor) = cursor {
            builder = builder.query(&[("cursor", cursor)]);
        }
        if let Some(limit) = limit {
            builder = builder.query(&[("limit", limit)]);
        }
        self.json(builder).await
    }

    pub async fn delete_job(&self, job_id: &str) -> Result<()> {
        self.send(self.request(Method::DELETE, &["compute", "jobs", job_id]))
            .await
            .map(drop)
    }
}

/// Base64 for the `inputs` and `proven_inputs` of a [`CreateJobRequest`].
pub fn encode(bytes: &[u8]) -> String {
    STANDARD.encode(bytes)
}

fn binary_request(key_id: &str, operation: Operation, a: &[u8], b: &[u8]) -> CreateJobRequest {
    CreateJobRequest {
        key_id: key_id.to_string(),
        operation,
        integer_type: DEFAULT_INTEGER_TYPE,
        inputs: vec![encode(a), encode(b)],
        proven_inputs: None,
        scalar: None,
        program: None,
    }
}

fn api_base(server: &str) -> Result<Url> {
    let invalid = || Error::Encoding(format!("{server:?} is not an http(s) URL"));
    let mut url = Url::parse(server).map_err(|_| invalid())?;
    if !matches!(url.scheme(), "http" | "https") || url.host().is_none() {
        return Err(invalid());
    }
    url.set_query(None);
    url.set_fragment(None);
    let path = url.path().trim_end_matches('/').to_string();
    if !path.ends_with(API_PATH) {
        url.set_path(&format!("{path}/{API_PATH}"));
    } else {
        url.set_path(&path);
    }
    Ok(url)
}

/// Reads an error response. Every error from `/api/v1` is an envelope; anything
/// else (a proxy's HTML page) keeps its status and a short excerpt.
async fn api_error(response: Response) -> Error {
    let status = response.status();
    let retry_after = response
        .headers()
        .get(header::RETRY_AFTER)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.trim().parse().ok())
        .map(Duration::from_secs);
    let body = response.text().await.unwrap_or_default();
    let (code, message) = match serde_json::from_str::<ErrorBody>(&body) {
        Ok(envelope) => (envelope.error.code, envelope.error.message),
        Err(_) => {
            let excerpt: String = body.trim().chars().take(200).collect();
            let message = if excerpt.is_empty() {
                status
                    .canonical_reason()
                    .unwrap_or("Request failed")
                    .to_string()
            } else {
                excerpt
            };
            (
                error_codes::for_status(status.as_u16()).to_string(),
                message,
            )
        }
    };
    Error::Api {
        status: status.as_u16(),
        code,
        message,
        retry_after,
    }
}
