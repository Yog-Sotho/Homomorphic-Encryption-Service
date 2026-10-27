use dotenvy::dotenv;
use hkdf::Hkdf;
use ipnet::IpNet;
use sha2::Sha256;
use std::env;
use std::path::PathBuf;
use std::time::Duration;

/// HS256 needs a key at least as long as its 256-bit output to be full strength.
pub const MIN_JWT_SECRET_BYTES: usize = 32;

/// Keys derived from `JWT_SECRET`, one per purpose, so a value signed for one
/// purpose (an OAuth state cookie) can never be accepted as another (a token).
pub struct SecretKeys {
    pub access_token: [u8; 32],
    pub oauth_state: [u8; 32],
}

impl SecretKeys {
    pub fn derive(secret: &str) -> Self {
        let hkdf = Hkdf::<Sha256>::new(Some(b"heaas"), secret.as_bytes());
        let expand = |info: &[u8]| {
            let mut key = [0u8; 32];
            hkdf.expand(info, &mut key)
                .expect("32 bytes is a valid HKDF-SHA256 output length");
            key
        };
        SecretKeys {
            access_token: expand(b"access-token/v1"),
            oauth_state: expand(b"oauth-state/v1"),
        }
    }
}

/// Requests per client before the limiters answer 429 (see `middleware::rate_limit`).
#[derive(Clone)]
pub struct RateLimitSettings {
    /// Any `/api/auth` request, per client IP, per minute.
    pub auth_per_minute: u32,
    /// Sign-in attempts per email address, per 15 minutes.
    pub logins_per_email: u32,
    /// Requests that send an email (register, resend, forgot), per client IP, per hour.
    pub emails_per_ip_per_hour: u32,
    /// Emails sent to one address, per hour.
    pub emails_per_address_per_hour: u32,
}

/// Where the OAuth providers live; overridden in tests by a mock server.
#[derive(Clone)]
pub struct OAuthEndpoints {
    pub google_authorize: String,
    pub google_token: String,
    pub google_userinfo: String,
    pub github_authorize: String,
    pub github_token: String,
    pub github_api: String,
}

impl Default for OAuthEndpoints {
    fn default() -> Self {
        OAuthEndpoints {
            google_authorize: "https://accounts.google.com/o/oauth2/v2/auth".into(),
            google_token: "https://oauth2.googleapis.com/token".into(),
            google_userinfo: "https://www.googleapis.com/oauth2/v2/userinfo".into(),
            github_authorize: "https://github.com/login/oauth/authorize".into(),
            github_token: "https://github.com/login/oauth/access_token".into(),
            github_api: "https://api.github.com".into(),
        }
    }
}

/// `scheme://host[:port]` of a URL, as browsers send it in `Origin`.
pub fn origin_of(url: &str) -> Option<String> {
    let parsed = url::Url::parse(url).ok()?;
    let origin = parsed.origin();
    origin.is_tuple().then(|| origin.ascii_serialization())
}

fn parse_list(value: &str) -> impl Iterator<Item = &str> {
    value.split(',').map(str::trim).filter(|s| !s.is_empty())
}

/// Parses `TRUSTED_PROXIES`: comma-separated CIDRs or single addresses.
pub fn parse_trusted_proxies(value: &str) -> Result<Vec<IpNet>, String> {
    parse_list(value)
        .map(|entry| {
            entry
                .parse::<IpNet>()
                .or_else(|_| entry.parse::<std::net::IpAddr>().map(IpNet::from))
                .map_err(|_| format!("invalid TRUSTED_PROXIES entry {entry:?}"))
        })
        .collect()
}

fn env_flag(name: &str, default: bool) -> bool {
    match env::var(name).map(|v| v.trim().to_ascii_lowercase()) {
        Ok(v) if ["1", "true", "yes", "on"].contains(&v.as_str()) => true,
        Ok(v) if ["0", "false", "no", "off"].contains(&v.as_str()) => false,
        _ => default,
    }
}

/// Compressed TFHE server keys are ~60 MB with the default parameters.
const DEFAULT_MAX_SERVER_KEY_BYTES: u64 = 80 * 1024 * 1024;

pub struct Config {
    pub database_url: String,
    pub keys: SecretKeys,
    pub server_addr: String,
    /// Origins allowed to call the API from a browser (CORS) and to use the
    /// session cookie (`Origin` check): APP_BASE_URL's origin plus ALLOWED_ORIGINS.
    pub allowed_origins: Vec<String>,
    /// Proxies whose `X-Forwarded-For` is believed when finding the client IP.
    pub trusted_proxies: Vec<IpNet>,
    /// Mark session cookies `Secure` (sent over HTTPS only; browsers also accept
    /// them on http://localhost). Turn off only for plain-HTTP test setups.
    pub cookie_secure: bool,
    /// Log verification and reset links when SMTP is not configured. On by
    /// default in debug builds only: the links are credentials.
    pub log_email_links: bool,
    pub rate_limits: RateLimitSettings,
    pub oauth: OAuthEndpoints,
    /// Directory holding users' uploaded compressed server keys.
    pub key_store_dir: PathBuf,
    /// Largest accepted compressed server key upload.
    pub max_server_key_bytes: u64,
    /// How many server keys one user may register.
    pub max_keys_per_user: i64,
    /// Decompressed server keys kept in memory (~180 MB each).
    pub key_cache_capacity: usize,
    /// Directory holding job inputs and results (`<id>/{in0,in1,out}`).
    pub job_store_dir: PathBuf,
    /// Jobs evaluated concurrently. TFHE already parallelises each operation
    /// across cores, so a small number keeps the CPU busy without thrashing.
    pub he_workers: usize,
    /// A job running longer than this is failed.
    pub job_timeout: Duration,
    /// Attempts per job before an internal error becomes final.
    pub max_job_attempts: i64,
    /// Pending + running jobs across all users before submissions get 503.
    pub max_queued_jobs: i64,
    /// Pending + running jobs per user before submissions get 429.
    pub max_active_jobs_per_user: i64,
    /// Finished jobs (and their stored ciphertexts) are deleted after this many days.
    pub job_retention_days: i64,
    pub app_base_url: String,
    pub google_client_id: Option<String>,
    pub google_client_secret: Option<String>,
    pub github_client_id: Option<String>,
    pub github_client_secret: Option<String>,
    pub smtp_host: Option<String>,
    pub smtp_port: u16,
    pub smtp_user: Option<String>,
    pub smtp_pass: Option<String>,
    pub from_email: String,
    pub daily_compute_quota: usize,
}

impl Config {
    pub fn init() -> Self {
        dotenv().ok();

        let jwt_secret =
            env::var("JWT_SECRET").expect("FATAL: JWT_SECRET environment variable must be set.");
        assert!(
            jwt_secret.len() >= MIN_JWT_SECRET_BYTES,
            "FATAL: JWT_SECRET must be at least {MIN_JWT_SECRET_BYTES} bytes \
             (e.g. `openssl rand -base64 48`)."
        );

        let app_base_url = env::var("APP_BASE_URL")
            .unwrap_or_else(|_| "http://localhost:3000".to_string())
            .trim_end_matches('/')
            .to_string();
        let mut allowed_origins: Vec<String> =
            vec![origin_of(&app_base_url).expect("FATAL: APP_BASE_URL must be an http(s) URL")];
        let extra_origins = env::var("ALLOWED_ORIGINS").unwrap_or_else(|_| {
            if cfg!(debug_assertions) {
                "http://localhost:3000,http://localhost:5173".to_string()
            } else {
                String::new()
            }
        });
        for origin in parse_list(&extra_origins) {
            let origin = origin_of(origin)
                .unwrap_or_else(|| panic!("FATAL: invalid ALLOWED_ORIGINS entry {origin:?}"));
            if !allowed_origins.contains(&origin) {
                allowed_origins.push(origin);
            }
        }
        let trusted_proxies =
            parse_trusted_proxies(&env::var("TRUSTED_PROXIES").unwrap_or_default())
                .unwrap_or_else(|e| panic!("FATAL: {e}"));

        let limit = |name: &str, default: u32| {
            env::var(name)
                .ok()
                .and_then(|v| v.parse::<u32>().ok())
                .unwrap_or(default)
                .max(1)
        };
        let rate_limits = RateLimitSettings {
            auth_per_minute: limit("RATE_LIMIT_AUTH_PER_MINUTE", 30),
            logins_per_email: limit("RATE_LIMIT_LOGINS_PER_EMAIL", 5),
            emails_per_ip_per_hour: limit("RATE_LIMIT_EMAILS_PER_IP_PER_HOUR", 10),
            emails_per_address_per_hour: limit("RATE_LIMIT_EMAILS_PER_ADDRESS_PER_HOUR", 3),
        };

        let max_server_key_bytes = env::var("MAX_SERVER_KEY_BYTES")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(DEFAULT_MAX_SERVER_KEY_BYTES);

        let max_keys_per_user = env::var("MAX_KEYS_PER_USER")
            .ok()
            .and_then(|v| v.parse::<i64>().ok())
            .unwrap_or(2)
            .max(1);

        let job_number = |name: &str, default: i64| {
            env::var(name)
                .ok()
                .and_then(|v| v.parse::<i64>().ok())
                .unwrap_or(default)
                .max(1)
        };

        let key_cache_capacity = env::var("KEY_CACHE_CAPACITY")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(2)
            .max(1);

        let smtp_port = env::var("SMTP_PORT")
            .ok()
            .and_then(|v| v.parse::<u16>().ok())
            .unwrap_or(587);

        let daily_compute_quota = env::var("DAILY_COMPUTE_QUOTA")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(100);

        Config {
            database_url: env::var("DATABASE_URL")
                .unwrap_or_else(|_| "sqlite://./he_saas.db".to_string()),
            keys: SecretKeys::derive(&jwt_secret),
            server_addr: env::var("SERVER_ADDR").unwrap_or_else(|_| "127.0.0.1:8080".to_string()),
            allowed_origins,
            trusted_proxies,
            cookie_secure: env_flag("COOKIE_SECURE", true),
            log_email_links: env_flag("LOG_EMAIL_LINKS", cfg!(debug_assertions)),
            rate_limits,
            oauth: OAuthEndpoints::default(),
            key_store_dir: env::var("KEY_STORE_DIR")
                .unwrap_or_else(|_| "./data/keys".to_string())
                .into(),
            max_server_key_bytes,
            max_keys_per_user,
            key_cache_capacity,
            job_store_dir: env::var("JOB_STORE_DIR")
                .unwrap_or_else(|_| "./data/jobs".to_string())
                .into(),
            he_workers: job_number("HE_WORKERS", 2) as usize,
            job_timeout: Duration::from_secs(job_number("JOB_TIMEOUT_SECS", 300) as u64),
            max_job_attempts: job_number("MAX_JOB_ATTEMPTS", 3),
            max_queued_jobs: job_number("MAX_QUEUED_JOBS", 1000),
            max_active_jobs_per_user: job_number("MAX_ACTIVE_JOBS_PER_USER", 10),
            job_retention_days: job_number("JOB_RETENTION_DAYS", 7),
            app_base_url,
            google_client_id: env::var("GOOGLE_CLIENT_ID").ok(),
            google_client_secret: env::var("GOOGLE_CLIENT_SECRET").ok(),
            github_client_id: env::var("GITHUB_CLIENT_ID").ok(),
            github_client_secret: env::var("GITHUB_CLIENT_SECRET").ok(),
            smtp_host: env::var("SMTP_HOST").ok(),
            smtp_port,
            smtp_user: env::var("SMTP_USER").ok(),
            smtp_pass: env::var("SMTP_PASS").ok(),
            from_email: env::var("FROM_EMAIL")
                .unwrap_or_else(|_| "noreply@heaas.local".to_string()),
            daily_compute_quota,
        }
    }
}

#[cfg(test)]
impl Config {
    /// Configuration for unit and integration tests. Keys and job data go in
    /// `keys/` and `jobs/` under the caller's temporary directory.
    pub fn for_tests(data_dir: PathBuf) -> Self {
        Config {
            database_url: "sqlite::memory:".to_string(),
            keys: SecretKeys::derive("test_secret_key_at_least_32_bytes_long"),
            server_addr: "127.0.0.1:8080".to_string(),
            allowed_origins: vec!["http://localhost:3000".to_string()],
            trusted_proxies: vec![],
            cookie_secure: true,
            log_email_links: true,
            // High enough that functional tests never hit them; the rate-limit
            // tests set their own.
            rate_limits: RateLimitSettings {
                auth_per_minute: 10_000,
                logins_per_email: 10_000,
                emails_per_ip_per_hour: 10_000,
                emails_per_address_per_hour: 10_000,
            },
            oauth: OAuthEndpoints::default(),
            key_store_dir: data_dir.join("keys"),
            max_server_key_bytes: DEFAULT_MAX_SERVER_KEY_BYTES,
            max_keys_per_user: 2,
            key_cache_capacity: 2,
            job_store_dir: data_dir.join("jobs"),
            he_workers: 2,
            job_timeout: Duration::from_secs(120),
            max_job_attempts: 3,
            max_queued_jobs: 1000,
            max_active_jobs_per_user: 10,
            job_retention_days: 7,
            app_base_url: "http://localhost:3000".to_string(),
            google_client_id: None,
            google_client_secret: None,
            github_client_id: None,
            github_client_secret: None,
            smtp_host: None,
            smtp_port: 587,
            smtp_user: None,
            smtp_pass: None,
            from_email: "noreply@heaas.local".to_string(),
            daily_compute_quota: 100,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derived_keys_differ_per_purpose_and_secret() {
        let a = SecretKeys::derive("a-secret-that-is-at-least-32-bytes-long");
        let b = SecretKeys::derive("another-secret-at-least-32-bytes-long!!");
        assert_ne!(a.access_token, a.oauth_state);
        assert_ne!(a.access_token, b.access_token);
        assert_eq!(
            a.access_token,
            SecretKeys::derive("a-secret-that-is-at-least-32-bytes-long").access_token
        );
    }

    #[test]
    fn origins_and_proxies_parse_strictly() {
        assert_eq!(
            origin_of("https://example.com/heaas/").as_deref(),
            Some("https://example.com")
        );
        assert_eq!(
            origin_of("http://localhost:4174").as_deref(),
            Some("http://localhost:4174")
        );
        assert_eq!(origin_of("not a url"), None);

        let proxies = parse_trusted_proxies(" 10.0.0.0/8, 127.0.0.1 ,::1").unwrap();
        assert_eq!(proxies.len(), 3);
        assert!(proxies[1].contains(&"127.0.0.1".parse::<std::net::IpAddr>().unwrap()));
        assert!(parse_trusted_proxies("10.0.0.0/33").is_err());
        assert!(parse_trusted_proxies("").unwrap().is_empty());
    }
}
