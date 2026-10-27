//! Probes for orchestrators: `GET /api/v1/health` (liveness: the process
//! answers) and `GET /api/v1/health/ready` (readiness: it can do its work).

use crate::crypto::keys::KeyStore;
use crate::jobs::store::JobStore;
use crate::jobs::worker::Liveness;
use actix_web::{web, HttpResponse};
use heaas_core::api::{error_codes, ErrorDetail};
use serde::Serialize;
use sqlx::SqlitePool;
use std::time::Duration;
use utoipa::ToSchema;

/// A check slower than this counts as failed: a probe must answer quickly.
const CHECK_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Serialize, ToSchema)]
pub struct Health {
    #[schema(example = "ok")]
    status: &'static str,
    /// The server's version.
    version: &'static str,
}

/// Liveness: the process is up and answering.
#[utoipa::path(get, path = "/health", tag = "meta", responses((status = 200, description = "The server is up", body = Health)))]
pub async fn health() -> HttpResponse {
    HttpResponse::Ok().json(Health {
        status: "ok",
        version: env!("CARGO_PKG_VERSION"),
    })
}

/// Each check: `"ok"`, or why it failed.
#[derive(Serialize, ToSchema)]
pub struct Checks {
    /// The database answers a query.
    #[schema(example = "ok")]
    database: String,
    /// Files can be created in the key store.
    #[schema(example = "ok")]
    key_store: String,
    /// Files can be created in the job store.
    #[schema(example = "ok")]
    job_store: String,
    /// Running job workers out of those started, e.g. `2/2`.
    #[schema(example = "2/2")]
    workers: String,
}

impl Checks {
    fn all_ok(&self, liveness: &Liveness) -> bool {
        [&self.database, &self.key_store, &self.job_store]
            .iter()
            .all(|c| *c == "ok")
            && liveness.alive() == liveness.expected()
    }

    fn failing(&self, liveness: &Liveness) -> Vec<&'static str> {
        let mut failing: Vec<_> = [
            ("database", &self.database),
            ("key store", &self.key_store),
            ("job store", &self.job_store),
        ]
        .into_iter()
        .filter(|(_, c)| *c != "ok")
        .map(|(name, _)| name)
        .collect();
        if liveness.alive() != liveness.expected() {
            failing.push("workers");
        }
        failing
    }
}

#[derive(Serialize, ToSchema)]
pub struct Ready {
    #[schema(example = "ready")]
    status: &'static str,
    checks: Checks,
}

/// The error envelope, plus what failed.
#[derive(Serialize, ToSchema)]
pub struct NotReady {
    error: ErrorDetail,
    checks: Checks,
}

fn outcome(name: &str, result: Result<Result<(), String>, tokio::time::error::Elapsed>) -> String {
    match result {
        Ok(Ok(())) => "ok".to_string(),
        Ok(Err(detail)) => {
            tracing::warn!("readiness: {name} failed: {detail}");
            "unavailable".to_string()
        }
        Err(_) => {
            tracing::warn!("readiness: {name} timed out");
            "timed out".to_string()
        }
    }
}

async fn writable(
    probe: impl FnOnce() -> std::io::Result<()> + Send + 'static,
) -> Result<(), String> {
    match web::block(probe).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(e)) => Err(e.to_string()),
        Err(e) => Err(e.to_string()),
    }
}

/// Readiness: the database answers, both stores accept new files and every
/// job worker is running. Only `200` means the instance should get traffic.
#[utoipa::path(get, path = "/health/ready", tag = "meta", responses(
    (status = 200, description = "Ready", body = Ready),
    (status = 503, description = "Not ready; `checks` says what failed", body = NotReady),
))]
pub async fn ready(
    pool: web::Data<SqlitePool>,
    keys: web::Data<KeyStore>,
    jobs: web::Data<JobStore>,
    liveness: Option<web::Data<Liveness>>,
) -> HttpResponse {
    let liveness = liveness.map(|l| l.get_ref().clone()).unwrap_or_default();
    let database = async {
        sqlx::query("SELECT 1")
            .execute(pool.get_ref())
            .await
            .map(drop)
            .map_err(|e| e.to_string())
    };
    let (keys, jobs) = (keys.into_inner(), jobs.into_inner());
    let (database, key_store, job_store) = tokio::join!(
        tokio::time::timeout(CHECK_TIMEOUT, database),
        tokio::time::timeout(CHECK_TIMEOUT, writable(move || keys.probe_writable())),
        tokio::time::timeout(CHECK_TIMEOUT, writable(move || jobs.probe_writable())),
    );
    let checks = Checks {
        database: outcome("database", database),
        key_store: outcome("key store", key_store),
        job_store: outcome("job store", job_store),
        workers: format!("{}/{}", liveness.alive(), liveness.expected()),
    };

    if checks.all_ok(&liveness) {
        HttpResponse::Ok().json(Ready {
            status: "ready",
            checks,
        })
    } else {
        let message = format!("Not ready: {}", checks.failing(&liveness).join(", "));
        HttpResponse::ServiceUnavailable().json(NotReady {
            error: ErrorDetail {
                code: error_codes::UNAVAILABLE.to_string(),
                message,
            },
            checks,
        })
    }
}
