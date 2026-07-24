use actix_web::middleware::Next;
use actix_web::{
    body::BoxBody,
    dev::{ServiceRequest, ServiceResponse},
    Error, HttpResponse,
};
use dashmap::DashMap;
use std::{
    sync::Arc,
    time::{Duration, Instant},
};

const MAX_REQUESTS: usize = 10;
const WINDOW_SECS: u64 = 60;

/// Sliding-window IP-based rate limiter.
///
/// Allows up to `MAX_REQUESTS` requests per `WINDOW_SECS`-second window per IP.
#[derive(Clone)]
pub struct RateLimiter {
    pub map: Arc<DashMap<String, Vec<Instant>>>,
}

impl RateLimiter {
    pub fn new() -> Self {
        RateLimiter {
            map: Arc::new(DashMap::new()),
        }
    }
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

/// Actix `from_fn`-compatible middleware function that enforces rate limiting.
pub async fn rate_limit_middleware<B: actix_web::body::MessageBody + 'static>(
    req: ServiceRequest,
    next: Next<B>,
) -> Result<ServiceResponse<BoxBody>, Error> {
    let ip = req
        .connection_info()
        .realip_remote_addr()
        .unwrap_or("unknown")
        .to_string();

    // Retrieve the shared rate limiter stored in app data.
    let limiter = req.app_data::<actix_web::web::Data<RateLimiter>>().cloned();

    if let Some(limiter) = limiter {
        let window = Duration::from_secs(WINDOW_SECS);
        let now = Instant::now();

        let mut entry = limiter.map.entry(ip.clone()).or_insert_with(Vec::new);
        // Drop timestamps outside the sliding window.
        entry.retain(|t| now.duration_since(*t) < window);

        if entry.len() >= MAX_REQUESTS {
            let response = HttpResponse::TooManyRequests()
                .json(serde_json::json!({ "message": "Rate limit exceeded. Try again later." }));
            let (req_parts, _) = req.into_parts();
            return Ok(ServiceResponse::new(req_parts, response).map_into_boxed_body());
        }

        entry.push(now);
    }

    next.call(req).await.map(|r| r.map_into_boxed_body())
}
