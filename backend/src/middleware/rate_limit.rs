//! Rate limits keyed on the real client IP and on email addresses.
//!
//! The client IP is the TCP peer, unless that peer is one of `TRUSTED_PROXIES`:
//! then it is the rightmost `X-Forwarded-For` hop that is not a trusted proxy.
//! Hops further left were written by the client and are never believed, so a
//! client cannot pick its own rate-limit bucket.

use crate::config::{Config, RateLimitSettings};
use crate::errors::AppError;
use actix_web::body::{BoxBody, MessageBody};
use actix_web::dev::{ServiceRequest, ServiceResponse};
use actix_web::http::header::HeaderMap;
use actix_web::middleware::Next;
use actix_web::{web, Error, HttpRequest, ResponseError};
use governor::clock::Clock;
use governor::{DefaultKeyedRateLimiter, Quota};
use ipnet::IpNet;
use std::hash::Hash;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::num::NonZeroU32;
use std::time::Duration;

/// Finds the client address; see the module docs. `None` peers (only in tests)
/// map to `0.0.0.0`.
pub fn client_ip(peer: Option<IpAddr>, forwarded_for: Option<&str>, trusted: &[IpNet]) -> IpAddr {
    let Some(peer) = peer else {
        return IpAddr::V4(Ipv4Addr::UNSPECIFIED);
    };
    let is_trusted = |ip: &IpAddr| trusted.iter().any(|net| net.contains(ip));
    if !is_trusted(&peer) {
        return peer;
    }
    let mut client = peer;
    for hop in forwarded_for.unwrap_or_default().rsplit(',') {
        let Some(ip) = parse_hop(hop.trim()) else {
            // Garbage can only come from the client; the hop to its right is
            // the closest address a trusted proxy vouched for.
            return client;
        };
        client = ip;
        if !is_trusted(&ip) {
            return ip;
        }
    }
    client
}

/// An `X-Forwarded-For` entry: an address, optionally with a port.
fn parse_hop(hop: &str) -> Option<IpAddr> {
    hop.parse::<IpAddr>()
        .ok()
        .or_else(|| hop.parse::<SocketAddr>().ok().map(|s| s.ip()))
}

fn client_ip_of(peer: Option<SocketAddr>, headers: &HeaderMap, trusted: &[IpNet]) -> IpAddr {
    let forwarded = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok());
    client_ip(peer.map(|p| p.ip()), forwarded, trusted)
}

fn nonzero(n: u32) -> NonZeroU32 {
    NonZeroU32::new(n.max(1)).expect("max(1) is non-zero")
}

/// `n` requests, then one more every `period / n`.
fn quota(n: u32, period: Duration) -> Quota {
    let n = nonzero(n);
    Quota::with_period(period / n.get())
        .expect("rate-limit periods are non-zero")
        .allow_burst(n)
}

const LOGIN_WINDOW: Duration = Duration::from_secs(15 * 60);
const HOUR: Duration = Duration::from_secs(3600);

fn check<K: Clone + Hash + Eq>(
    limiter: &DefaultKeyedRateLimiter<K>,
    key: &K,
    message: &str,
) -> Result<(), AppError> {
    limiter.check_key(key).map_err(|not_until| {
        let wait = not_until.wait_time_from(limiter.clock().now());
        AppError::too_many_requests(message, Some(wait.as_secs_f64().ceil().max(1.0) as u64))
    })
}

/// All of the service's rate limiters, shared as app data.
pub struct RateLimits {
    trusted_proxies: Vec<IpNet>,
    auth: DefaultKeyedRateLimiter<IpAddr>,
    logins: DefaultKeyedRateLimiter<String>,
    emails_by_ip: DefaultKeyedRateLimiter<IpAddr>,
    emails_by_address: DefaultKeyedRateLimiter<String>,
}

impl RateLimits {
    pub fn new(config: &Config) -> Self {
        let RateLimitSettings {
            auth_per_minute,
            logins_per_email,
            emails_per_ip_per_hour,
            emails_per_address_per_hour,
        } = config.rate_limits;
        RateLimits {
            trusted_proxies: config.trusted_proxies.clone(),
            auth: DefaultKeyedRateLimiter::keyed(quota(auth_per_minute, Duration::from_secs(60))),
            logins: DefaultKeyedRateLimiter::keyed(quota(logins_per_email, LOGIN_WINDOW)),
            emails_by_ip: DefaultKeyedRateLimiter::keyed(quota(emails_per_ip_per_hour, HOUR)),
            emails_by_address: DefaultKeyedRateLimiter::keyed(quota(
                emails_per_address_per_hour,
                HOUR,
            )),
        }
    }

    pub fn client_ip(&self, req: &HttpRequest) -> IpAddr {
        client_ip_of(req.peer_addr(), req.headers(), &self.trusted_proxies)
    }

    /// Sign-in attempts per email address, whatever IP they come from.
    pub fn check_login(&self, email: &str) -> Result<(), AppError> {
        check(
            &self.logins,
            &email.to_string(),
            "Too many sign-in attempts for this account. Try again later.",
        )
    }

    /// Requests that send email, per client IP.
    pub fn check_email_request(&self, req: &HttpRequest) -> Result<(), AppError> {
        check(
            &self.emails_by_ip,
            &self.client_ip(req),
            "Too many email requests. Try again later.",
        )
    }

    /// Whether another email may be sent to `address` now. Callers skip the
    /// email silently when it may not, so the response never reveals whether
    /// an address received mail recently.
    pub fn may_email(&self, address: &str) -> bool {
        self.emails_by_address
            .check_key(&address.to_string())
            .is_ok()
    }

    /// Forgets clients whose limits have fully replenished.
    pub fn purge(&self) {
        for limiter in [&self.auth, &self.emails_by_ip] {
            limiter.retain_recent();
            limiter.shrink_to_fit();
        }
        for limiter in [&self.logins, &self.emails_by_address] {
            limiter.retain_recent();
            limiter.shrink_to_fit();
        }
    }
}

/// `from_fn` middleware limiting every request in its scope per client IP.
pub async fn limit_auth_requests(
    req: ServiceRequest,
    next: Next<impl MessageBody + 'static>,
) -> Result<ServiceResponse<BoxBody>, Error> {
    let limited = req.app_data::<web::Data<RateLimits>>().map(|limits| {
        let ip = client_ip_of(req.peer_addr(), req.headers(), &limits.trusted_proxies);
        check(&limits.auth, &ip, "Rate limit exceeded. Try again later.")
    });
    match limited {
        Some(Err(error)) => {
            let response = error.error_response();
            Ok(req.into_response(response))
        }
        _ => next
            .call(req)
            .await
            .map(ServiceResponse::map_into_boxed_body),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::parse_trusted_proxies;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn untrusted_peers_cannot_spoof_forwarded_for() {
        let trusted = parse_trusted_proxies("127.0.0.1,172.16.0.0/12").unwrap();
        // A direct client: its header is ignored.
        assert_eq!(
            client_ip(Some(ip("203.0.113.9")), Some("1.2.3.4"), &trusted),
            ip("203.0.113.9")
        );
        // No proxies configured: the peer is always the client.
        assert_eq!(
            client_ip(Some(ip("127.0.0.1")), Some("1.2.3.4"), &[]),
            ip("127.0.0.1")
        );
    }

    #[test]
    fn trusted_proxies_yield_the_rightmost_untrusted_hop() {
        let trusted = parse_trusted_proxies("127.0.0.1,172.16.0.0/12").unwrap();
        let peer = Some(ip("172.18.0.3"));
        // nginx appended the client; the vite proxy appended nginx.
        assert_eq!(
            client_ip(peer, Some("198.51.100.7, 172.18.0.1"), &trusted),
            ip("198.51.100.7")
        );
        // A forged leftmost entry is skipped: the proxy-added hop wins.
        assert_eq!(
            client_ip(peer, Some("6.6.6.6, 198.51.100.7, 172.18.0.1"), &trusted),
            ip("198.51.100.7")
        );
        assert_eq!(
            client_ip(peer, Some("[2001:db8::1]:443"), &trusted),
            ip("2001:db8::1")
        );
        assert_eq!(
            client_ip(peer, Some("garbage, 198.51.100.7"), &trusted),
            ip("198.51.100.7")
        );
        // Only proxies in the chain (or no header): the leftmost proxy.
        assert_eq!(
            client_ip(peer, Some("127.0.0.1"), &trusted),
            ip("127.0.0.1")
        );
        assert_eq!(client_ip(peer, None, &trusted), ip("172.18.0.3"));
        assert_eq!(client_ip(None, Some("1.2.3.4"), &trusted), ip("0.0.0.0"));
    }

    fn limits(settings: RateLimitSettings) -> RateLimits {
        let mut config = Config::for_tests(std::env::temp_dir());
        config.rate_limits = settings;
        RateLimits::new(&config)
    }

    #[test]
    fn limits_answer_429_with_retry_after() {
        let limits = limits(RateLimitSettings {
            auth_per_minute: 1,
            logins_per_email: 2,
            emails_per_ip_per_hour: 1,
            emails_per_address_per_hour: 1,
        });
        limits.check_login("a@example.com").unwrap();
        limits.check_login("a@example.com").unwrap();
        let err = limits.check_login("a@example.com").unwrap_err();
        // 15 minutes / 2 attempts: the next one is ~450 s away.
        assert!(matches!(
            err,
            AppError::TooManyRequests {
                retry_after: Some(400..=450),
                ..
            }
        ));
        // Other addresses are unaffected.
        limits.check_login("b@example.com").unwrap();

        assert!(limits.may_email("v@example.com"));
        assert!(!limits.may_email("v@example.com"));
        limits.purge();
    }
}
