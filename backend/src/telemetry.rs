//! Logs, request ids and Prometheus metrics.
//!
//! - [`init_logging`]: `tracing` to stdout, JSON lines by default in release
//!   builds (`LOG_FORMAT=pretty` for humans), filtered by `RUST_LOG`. Records
//!   from libraries that use `log` (actix, sqlx) are bridged in.
//! - [`request_context`]: every request gets an id (a client's `X-Request-Id`
//!   when it is sane, else a new UUID), echoed in the response. Everything
//!   logged while handling the request carries it, and one line per request
//!   records method, route, status and latency.
//! - [`metrics_endpoint`]: `GET /metrics` in the Prometheus text format, only
//!   with `Authorization: Bearer $METRICS_TOKEN` (404 when no token is set).
//!   nginx does not proxy it; scrape the backend directly.

use crate::config::Config;
use crate::jobs::worker::Liveness;
use actix_web::body::{BoxBody, MessageBody};
use actix_web::dev::{ServiceRequest, ServiceResponse};
use actix_web::http::header::{self, HeaderName, HeaderValue};
use actix_web::middleware::Next;
use actix_web::{web, Error, HttpRequest, HttpResponse};
use prometheus::{
    Encoder, HistogramOpts, HistogramVec, IntCounterVec, IntGauge, IntGaugeVec, Opts, Registry,
    TextEncoder,
};
use sqlx::SqlitePool;
use std::sync::{Arc, LazyLock};
use std::time::{Duration, Instant};
use subtle::ConstantTimeEq;
use tracing::Instrument;

pub const REQUEST_ID_HEADER: HeaderName = HeaderName::from_static("x-request-id");
const MAX_REQUEST_ID_LEN: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LogFormat {
    Json,
    Pretty,
}

/// Installs the global subscriber. Call once, before anything logs.
pub fn init_logging(format: LogFormat) {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    let builder = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stdout)
        // Colours only for a terminal, never in files or log collectors.
        .with_ansi(std::io::IsTerminal::is_terminal(&std::io::stdout()));
    let installed = match format {
        LogFormat::Json => builder
            .json()
            .flatten_event(true)
            .with_current_span(true)
            .with_span_list(false)
            .try_init(),
        LogFormat::Pretty => builder.try_init(),
    };
    if let Err(e) = installed {
        eprintln!("logging was already initialised: {e}");
    }
}

/// A client-supplied id is kept only if it is short and plainly printable, so
/// it cannot forge log lines or bloat them.
fn client_request_id(req: &ServiceRequest) -> Option<String> {
    let value = req.headers().get(&REQUEST_ID_HEADER)?.to_str().ok()?;
    let sane = !value.is_empty()
        && value.len() <= MAX_REQUEST_ID_LEN
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b':'));
    sane.then(|| value.to_string())
}

/// Request id, span, access log line and HTTP metrics. Wrap the whole app.
pub async fn request_context(
    req: ServiceRequest,
    next: Next<impl MessageBody + 'static>,
) -> Result<ServiceResponse<BoxBody>, Error> {
    let request_id = client_request_id(&req).unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
    // The route pattern, not the path: ids in paths would explode the metrics.
    let route = req
        .match_pattern()
        .unwrap_or_else(|| "unmatched".to_string());
    let method = req.method().to_string();
    let quiet =
        route.ends_with("/health") || route.ends_with("/health/ready") || route == "/metrics";

    let span = tracing::info_span!("request", request_id = %request_id);
    let started = Instant::now();
    let result = next.call(req).instrument(span.clone()).await;
    let elapsed = started.elapsed();

    // Our middleware answers refusals with responses; an `Err` here comes from
    // actix itself and is turned into a response by the server.
    let status = match &result {
        Ok(response) => response.status().as_u16(),
        Err(e) => e.as_response_error().status_code().as_u16(),
    };
    METRICS.observe_http(&method, &route, status, elapsed);
    span.in_scope(|| {
        let latency_ms = elapsed.as_secs_f64() * 1000.0;
        if quiet {
            tracing::debug!(method, route, status, latency_ms, "request");
        } else if status >= 500 {
            tracing::error!(method, route, status, latency_ms, "request");
        } else {
            tracing::info!(method, route, status, latency_ms, "request");
        }
    });
    let mut response = result?.map_into_boxed_body();
    if let Ok(value) = HeaderValue::from_str(&request_id) {
        response.headers_mut().insert(REQUEST_ID_HEADER, value);
    }
    Ok(response)
}

/// Everything the service exports, in one registry (prefix `heaas_`).
pub struct Metrics {
    registry: Registry,
    http_requests: IntCounterVec,
    http_duration: HistogramVec,
    jobs_finished: IntCounterVec,
    job_evaluation: HistogramVec,
    job_wait: HistogramVec,
    key_cache: IntCounterVec,
    // Sampled at scrape time.
    jobs: IntGaugeVec,
    server_keys: IntGauge,
    workers_alive: IntGauge,
    workers_expected: IntGauge,
}

pub static METRICS: LazyLock<Metrics> = LazyLock::new(Metrics::new);

fn register<T: prometheus::core::Collector + Clone + 'static>(registry: &Registry, metric: T) -> T {
    registry
        .register(Box::new(metric.clone()))
        .expect("metric names are unique");
    metric
}

impl Metrics {
    fn new() -> Self {
        let registry =
            Registry::new_custom(Some("heaas".into()), None).expect("valid metric prefix");
        let seconds = |name: &str, help: &str, buckets: Vec<f64>, labels: &[&str]| {
            register(
                &registry,
                HistogramVec::new(HistogramOpts::new(name, help).buckets(buckets), labels)
                    .expect("valid histogram"),
            )
        };
        let counter = |name: &str, help: &str, labels: &[&str]| {
            register(
                &registry,
                IntCounterVec::new(Opts::new(name, help), labels).expect("valid counter"),
            )
        };
        let gauge = |name: &str, help: &str| {
            register(&registry, IntGauge::new(name, help).expect("valid gauge"))
        };

        let build_info = register(
            &registry,
            IntGaugeVec::new(
                Opts::new("build_info", "Always 1; the version is a label."),
                &["version", "tfhe_version"],
            )
            .expect("valid gauge"),
        );
        build_info
            .with_label_values(&[env!("CARGO_PKG_VERSION"), heaas_core::params::TFHE_VERSION])
            .set(1);

        Metrics {
            http_requests: counter(
                "http_requests_total",
                "HTTP requests by method, route pattern and status.",
                &["method", "route", "status"],
            ),
            http_duration: seconds(
                "http_request_duration_seconds",
                "Time to answer HTTP requests (key uploads include validation).",
                vec![0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0],
                &["method", "route"],
            ),
            jobs_finished: counter(
                "jobs_finished_total",
                "Job attempts by operation and outcome (completed, rejected, retried, failed, timed_out).",
                &["operation", "outcome"],
            ),
            job_evaluation: seconds(
                "job_evaluation_seconds",
                "Time to evaluate one job (homomorphic operation, key load included).",
                vec![0.1, 0.25, 0.5, 1.0, 2.0, 5.0, 10.0, 20.0, 40.0, 80.0, 160.0, 320.0],
                &["operation"],
            ),
            job_wait: seconds(
                "job_wait_seconds",
                "Time from submission to the start of an attempt.",
                vec![0.5, 1.0, 2.0, 5.0, 10.0, 30.0, 60.0, 120.0, 300.0, 600.0, 1800.0],
                &["operation"],
            ),
            key_cache: counter(
                "key_cache_lookups_total",
                "Server key lookups by result (hit: already decompressed in memory).",
                &["result"],
            ),
            jobs: register(
                &registry,
                IntGaugeVec::new(Opts::new("jobs", "Jobs by status."), &["status"])
                    .expect("valid gauge"),
            ),
            server_keys: gauge("server_keys", "Registered server keys."),
            workers_alive: gauge("workers_alive", "Job workers running."),
            workers_expected: gauge("workers_expected", "Job workers started."),
            registry,
        }
    }

    fn observe_http(&self, method: &str, route: &str, status: u16, elapsed: Duration) {
        self.http_requests
            .with_label_values(&[method, route, &status.to_string()])
            .inc();
        self.http_duration
            .with_label_values(&[method, route])
            .observe(elapsed.as_secs_f64());
    }

    pub fn job_attempt(&self, operation: &str, outcome: &str, evaluation: Option<Duration>) {
        self.jobs_finished
            .with_label_values(&[operation, outcome])
            .inc();
        if let Some(elapsed) = evaluation {
            self.job_evaluation
                .with_label_values(&[operation])
                .observe(elapsed.as_secs_f64());
        }
    }

    #[cfg(test)]
    pub fn jobs_finished(&self, operation: &str, outcome: &str) -> u64 {
        self.jobs_finished
            .with_label_values(&[operation, outcome])
            .get()
    }

    pub fn job_started(&self, operation: &str, waited: Duration) {
        self.job_wait
            .with_label_values(&[operation])
            .observe(waited.as_secs_f64());
    }

    pub fn key_cache_lookup(&self, hit: bool) {
        self.key_cache
            .with_label_values(&[if hit { "hit" } else { "miss" }])
            .inc();
    }

    /// Refreshes the sampled gauges and renders everything.
    async fn render(&self, pool: &SqlitePool, liveness: &Liveness) -> Result<String, String> {
        let counts: Vec<(String, i64)> =
            sqlx::query_as("SELECT status, COUNT(*) FROM jobs GROUP BY status")
                .fetch_all(pool)
                .await
                .map_err(|e| e.to_string())?;
        for status in ["pending", "processing", "completed", "failed"] {
            let count = counts
                .iter()
                .find(|(s, _)| s == status)
                .map_or(0, |(_, n)| *n);
            self.jobs.with_label_values(&[status]).set(count);
        }
        let (keys,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM server_keys")
            .fetch_one(pool)
            .await
            .map_err(|e| e.to_string())?;
        self.server_keys.set(keys);
        self.workers_alive.set(liveness.alive() as i64);
        self.workers_expected.set(liveness.expected() as i64);

        TextEncoder::new()
            .encode_to_string(&self.registry.gather())
            .map_err(|e| e.to_string())
    }
}

/// `GET /metrics`
pub async fn metrics_endpoint(
    req: HttpRequest,
    config: web::Data<Arc<Config>>,
    pool: web::Data<SqlitePool>,
    liveness: Option<web::Data<Liveness>>,
) -> HttpResponse {
    let Some(token) = config.metrics_token.as_deref() else {
        return HttpResponse::NotFound().finish();
    };
    let presented = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .unwrap_or_default();
    if !bool::from(presented.as_bytes().ct_eq(token.as_bytes())) {
        return HttpResponse::Unauthorized()
            .insert_header((header::WWW_AUTHENTICATE, "Bearer"))
            .finish();
    }
    let liveness = liveness.map(|l| l.get_ref().clone()).unwrap_or_default();
    match METRICS.render(&pool, &liveness).await {
        Ok(text) => HttpResponse::Ok()
            .content_type(TextEncoder::new().format_type())
            .body(text),
        Err(e) => {
            tracing::error!("rendering metrics failed: {e}");
            HttpResponse::ServiceUnavailable().finish()
        }
    }
}

/// Routes outside `/api`: `GET /metrics`.
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.route("/metrics", web::get().to(metrics_endpoint));
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{middleware::from_fn, test, App};

    #[actix_web::test]
    async fn requests_get_an_id_that_is_echoed_and_counted() {
        let app = test::init_service(
            App::new()
                .wrap(from_fn(request_context))
                .route("/things/{id}", web::get().to(HttpResponse::Ok)),
        )
        .await;

        let resp = test::call_service(
            &app,
            test::TestRequest::get()
                .uri("/things/42")
                .insert_header(("X-Request-Id", "abc-123"))
                .to_request(),
        )
        .await;
        assert_eq!(resp.headers().get("x-request-id").unwrap(), "abc-123");

        // Unusable ids are replaced with a fresh UUID.
        for bad in ["has space", &"x".repeat(65), "new\nline"] {
            let Ok(value) = HeaderValue::from_str(bad) else {
                continue;
            };
            let resp = test::call_service(
                &app,
                test::TestRequest::get()
                    .uri("/things/1")
                    .insert_header(("X-Request-Id", value))
                    .to_request(),
            )
            .await;
            let id = resp
                .headers()
                .get("x-request-id")
                .unwrap()
                .to_str()
                .unwrap();
            assert!(uuid::Uuid::parse_str(id).is_ok(), "{bad:?} -> {id}");
        }

        let text = TextEncoder::new()
            .encode_to_string(&METRICS.registry.gather())
            .unwrap();
        // Counted by pattern, never by the concrete path.
        assert!(
            text.contains(
                r#"heaas_http_requests_total{method="GET",route="/things/{id}",status="200"}"#
            ),
            "{text}"
        );
        assert!(!text.contains("/things/42"));
    }
}
