use crate::telemetry::LogFormat;
use dotenvy::dotenv;
use hkdf::Hkdf;
use ipnet::IpNet;
use lettre::message::Mailbox;
use sha2::Sha256;
use std::env;
use std::fmt;
use std::ops::RangeInclusive;
use std::path::PathBuf;
use std::str::FromStr;
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
    /// Any `/api/v1/auth` request, per client IP, per minute.
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

/// Compressed TFHE server keys are ~60 MB with the default parameters.
const DEFAULT_MAX_SERVER_KEY_BYTES: u64 = 80 * 1024 * 1024;

/// How long the credentials the server hands out stay valid.
#[derive(Clone)]
pub struct TokenLifetimes {
    /// Access tokens cannot be revoked, so they stay short.
    pub access_token_secs: i64,
    /// A sign-in lasts this long without a password (refresh cookie).
    pub session_days: i64,
    pub verify_link_hours: i64,
    pub reset_link_minutes: i64,
}

impl Default for TokenLifetimes {
    fn default() -> Self {
        TokenLifetimes {
            access_token_secs: 15 * 60,
            session_days: 30,
            verify_link_hours: 24,
            reset_link_minutes: 60,
        }
    }
}

/// How the SMTP connection is secured.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SmtpTls {
    /// Plain connection upgraded with STARTTLS, which is required (port 587).
    StartTls,
    /// TLS from the first byte (port 465).
    Implicit,
    /// No encryption: only for a relay on the same host or network.
    None,
}

impl SmtpTls {
    fn default_port(self) -> u16 {
        match self {
            SmtpTls::StartTls => 587,
            SmtpTls::Implicit => 465,
            SmtpTls::None => 25,
        }
    }
}

#[derive(Clone)]
pub struct SmtpSettings {
    pub host: String,
    pub port: u16,
    pub tls: SmtpTls,
    /// User name and password, when the relay requires them.
    pub credentials: Option<(String, String)>,
}

#[derive(Clone)]
pub struct MailSettings {
    pub from: Mailbox,
    /// `None`: no email is sent (links may be logged, see `log_links`).
    pub smtp: Option<SmtpSettings>,
    /// Log verification and reset links when SMTP is not configured. On by
    /// default in debug builds only: the links are credentials.
    pub log_links: bool,
}

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
    pub rate_limits: RateLimitSettings,
    pub ttl: TokenLifetimes,
    pub oauth: OAuthEndpoints,
    pub mail: MailSettings,
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
    pub daily_compute_quota: usize,
    pub log_format: LogFormat,
    /// Bearer token for `GET /metrics`; without one the endpoint is off.
    pub metrics_token: Option<String>,
}

/// A Prometheus scraper's token is a credential like any other.
pub const MIN_METRICS_TOKEN_BYTES: usize = 32;

/// Every problem found in the environment, so one start reports them all.
#[derive(Debug)]
pub struct ConfigError(pub Vec<String>);

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for problem in &self.0 {
            writeln!(f, "  - {problem}")?;
        }
        Ok(())
    }
}

impl std::error::Error for ConfigError {}

/// Reads settings from environment variables, recording what is invalid
/// instead of stopping at (or silently defaulting past) the first problem.
/// Empty values count as unset, as Compose passes `VAR=${VAR:-}` through.
struct Vars<F> {
    lookup: F,
    errors: Vec<String>,
}

impl<F: Fn(&str) -> Option<String>> Vars<F> {
    fn get(&self, name: &str) -> Option<String> {
        (self.lookup)(name)
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
    }

    fn text(&self, name: &str, default: &str) -> String {
        self.get(name).unwrap_or_else(|| default.to_string())
    }

    fn required(&mut self, name: &str, hint: &str) -> Option<String> {
        let value = self.get(name);
        if value.is_none() {
            self.errors.push(format!("{name} must be set ({hint})"));
        }
        value
    }

    fn number<T>(&mut self, name: &str, default: T, range: RangeInclusive<T>) -> T
    where
        T: FromStr + PartialOrd + fmt::Display + Copy,
    {
        let Some(raw) = self.get(name) else {
            return default;
        };
        match raw.parse::<T>() {
            Ok(value) if range.contains(&value) => value,
            _ => {
                self.errors.push(format!(
                    "{name} must be a whole number from {} to {}, not {raw:?}",
                    range.start(),
                    range.end()
                ));
                default
            }
        }
    }

    fn flag(&mut self, name: &str, default: bool) -> bool {
        let Some(raw) = self.get(name) else {
            return default;
        };
        match raw.to_ascii_lowercase().as_str() {
            "1" | "true" | "yes" | "on" => true,
            "0" | "false" | "no" | "off" => false,
            _ => {
                self.errors
                    .push(format!("{name} must be true or false, not {raw:?}"));
                default
            }
        }
    }

    /// Both or neither of a client id and its secret.
    fn pair(&mut self, id: &str, secret: &str) -> (Option<String>, Option<String>) {
        match (self.get(id), self.get(secret)) {
            (Some(a), Some(b)) => (Some(a), Some(b)),
            (None, None) => (None, None),
            _ => {
                self.errors
                    .push(format!("{id} and {secret} must be set together"));
                (None, None)
            }
        }
    }
}

impl Config {
    /// Reads the configuration from the environment (and `.env`).
    pub fn from_env() -> Result<Self, ConfigError> {
        dotenv().ok();
        Self::from_vars(|name| env::var(name).ok(), cfg!(debug_assertions))
    }

    /// `debug_build` relaxes what local development needs: a default
    /// APP_BASE_URL, the Vite dev server's origins, logged email links.
    fn from_vars(
        lookup: impl Fn(&str) -> Option<String>,
        debug_build: bool,
    ) -> Result<Self, ConfigError> {
        let mut vars = Vars {
            lookup,
            errors: Vec::new(),
        };

        let jwt_secret = vars
            .required("JWT_SECRET", "e.g. `openssl rand -base64 48`")
            .unwrap_or_default();
        if !jwt_secret.is_empty() && jwt_secret.len() < MIN_JWT_SECRET_BYTES {
            vars.errors.push(format!(
                "JWT_SECRET must be at least {MIN_JWT_SECRET_BYTES} bytes (e.g. `openssl rand -base64 48`)"
            ));
        }

        let app_base_url = if debug_build {
            Some(vars.text("APP_BASE_URL", "http://localhost:3000"))
        } else {
            vars.required(
                "APP_BASE_URL",
                "the public URL of the app, used in emailed links and OAuth callbacks",
            )
        }
        .map(|url| url.trim_end_matches('/').to_string())
        .unwrap_or_default();
        let mut allowed_origins = Vec::new();
        if !app_base_url.is_empty() {
            match url::Url::parse(&app_base_url) {
                Ok(url)
                    if url.query().is_none()
                        && url.fragment().is_none()
                        && origin_of(&app_base_url).is_some() =>
                {
                    allowed_origins.push(origin_of(&app_base_url).unwrap_or_default())
                }
                _ => vars.errors.push(format!(
                    "APP_BASE_URL must be an http(s) URL without query or fragment, not {app_base_url:?}"
                )),
            }
        }
        let default_origins = if debug_build {
            "http://localhost:3000,http://localhost:5173"
        } else {
            ""
        };
        for entry in parse_list(&vars.text("ALLOWED_ORIGINS", default_origins)) {
            match origin_of(entry) {
                Some(origin) if !allowed_origins.contains(&origin) => allowed_origins.push(origin),
                Some(_) => {}
                None => vars
                    .errors
                    .push(format!("invalid ALLOWED_ORIGINS entry {entry:?}")),
            }
        }
        let trusted_proxies = parse_trusted_proxies(&vars.text("TRUSTED_PROXIES", ""))
            .unwrap_or_else(|e| {
                vars.errors.push(e);
                Vec::new()
            });

        let database_url = vars.text("DATABASE_URL", "sqlite://./he_saas.db");
        if !database_url.starts_with("sqlite:") {
            vars.errors.push(format!(
                "DATABASE_URL must be a sqlite: URL, not {database_url:?}"
            ));
        }
        let server_addr = vars.text("SERVER_ADDR", "127.0.0.1:8080");
        if !server_addr
            .rsplit_once(':')
            .is_some_and(|(host, port)| !host.is_empty() && port.parse::<u16>().is_ok())
        {
            vars.errors.push(format!(
                "SERVER_ADDR must be host:port, not {server_addr:?}"
            ));
        }

        let rate_limits = RateLimitSettings {
            auth_per_minute: vars.number("RATE_LIMIT_AUTH_PER_MINUTE", 30, 1..=100_000),
            logins_per_email: vars.number("RATE_LIMIT_LOGINS_PER_EMAIL", 5, 1..=1_000),
            emails_per_ip_per_hour: vars.number(
                "RATE_LIMIT_EMAILS_PER_IP_PER_HOUR",
                10,
                1..=10_000,
            ),
            emails_per_address_per_hour: vars.number(
                "RATE_LIMIT_EMAILS_PER_ADDRESS_PER_HOUR",
                3,
                1..=1_000,
            ),
        };
        let defaults = TokenLifetimes::default();
        let ttl = TokenLifetimes {
            access_token_secs: vars.number(
                "ACCESS_TOKEN_TTL_SECS",
                defaults.access_token_secs,
                60..=3_600,
            ),
            session_days: vars.number("SESSION_TTL_DAYS", defaults.session_days, 1..=365),
            verify_link_hours: vars.number(
                "VERIFY_LINK_TTL_HOURS",
                defaults.verify_link_hours,
                1..=168,
            ),
            reset_link_minutes: vars.number(
                "RESET_LINK_TTL_MINUTES",
                defaults.reset_link_minutes,
                5..=1_440,
            ),
        };

        let mail = Self::mail_settings(&mut vars, debug_build);
        let log_format = match vars
            .get("LOG_FORMAT")
            .map(|v| v.to_ascii_lowercase())
            .as_deref()
        {
            None if debug_build => LogFormat::Pretty,
            None | Some("json") => LogFormat::Json,
            Some("pretty") => LogFormat::Pretty,
            Some(other) => {
                vars.errors
                    .push(format!("LOG_FORMAT must be json or pretty, not {other:?}"));
                LogFormat::Json
            }
        };
        let metrics_token = vars.get("METRICS_TOKEN");
        if metrics_token
            .as_ref()
            .is_some_and(|t| t.len() < MIN_METRICS_TOKEN_BYTES)
        {
            vars.errors.push(format!(
                "METRICS_TOKEN must be at least {MIN_METRICS_TOKEN_BYTES} bytes (e.g. `openssl rand -hex 32`)"
            ));
        }
        let (google_client_id, google_client_secret) =
            vars.pair("GOOGLE_CLIENT_ID", "GOOGLE_CLIENT_SECRET");
        let (github_client_id, github_client_secret) =
            vars.pair("GITHUB_CLIENT_ID", "GITHUB_CLIENT_SECRET");

        let config = Config {
            database_url,
            keys: SecretKeys::derive(&jwt_secret),
            server_addr,
            allowed_origins,
            trusted_proxies,
            cookie_secure: vars.flag("COOKIE_SECURE", true),
            rate_limits,
            ttl,
            oauth: OAuthEndpoints::default(),
            mail,
            key_store_dir: vars.text("KEY_STORE_DIR", "./data/keys").into(),
            max_server_key_bytes: vars.number(
                "MAX_SERVER_KEY_BYTES",
                DEFAULT_MAX_SERVER_KEY_BYTES,
                1024 * 1024..=heaas_core::params::MAX_SERVER_KEY_BYTES,
            ),
            max_keys_per_user: vars.number("MAX_KEYS_PER_USER", 2, 1..=100),
            key_cache_capacity: vars.number("KEY_CACHE_CAPACITY", 2, 1..=64),
            job_store_dir: vars.text("JOB_STORE_DIR", "./data/jobs").into(),
            he_workers: vars.number("HE_WORKERS", 2, 1..=256),
            job_timeout: Duration::from_secs(vars.number("JOB_TIMEOUT_SECS", 300, 1..=86_400)),
            max_job_attempts: vars.number("MAX_JOB_ATTEMPTS", 3, 1..=10),
            max_queued_jobs: vars.number("MAX_QUEUED_JOBS", 1000, 1..=1_000_000),
            max_active_jobs_per_user: vars.number("MAX_ACTIVE_JOBS_PER_USER", 10, 1..=10_000),
            job_retention_days: vars.number("JOB_RETENTION_DAYS", 7, 1..=3_650),
            app_base_url,
            google_client_id,
            google_client_secret,
            github_client_id,
            github_client_secret,
            daily_compute_quota: vars.number("DAILY_COMPUTE_QUOTA", 100, 1..=1_000_000),
            log_format,
            metrics_token,
        };
        if vars.errors.is_empty() {
            Ok(config)
        } else {
            Err(ConfigError(vars.errors))
        }
    }

    fn mail_settings(
        vars: &mut Vars<impl Fn(&str) -> Option<String>>,
        debug_build: bool,
    ) -> MailSettings {
        let smtp_host = vars.get("SMTP_HOST");
        let from = match vars.get("FROM_EMAIL") {
            Some(raw) => raw.parse::<Mailbox>().unwrap_or_else(|_| {
                vars.errors.push(format!(
                    "FROM_EMAIL must be an address like \"HEaaS <noreply@example.com>\", not {raw:?}"
                ));
                Self::placeholder_sender()
            }),
            None => {
                if smtp_host.is_some() {
                    vars.errors
                        .push("FROM_EMAIL must be set when SMTP_HOST is".to_string());
                }
                Self::placeholder_sender()
            }
        };
        let tls = match vars
            .get("SMTP_TLS")
            .map(|v| v.to_ascii_lowercase())
            .as_deref()
        {
            None | Some("starttls") => SmtpTls::StartTls,
            Some("implicit") | Some("tls") => SmtpTls::Implicit,
            Some("none") => SmtpTls::None,
            Some(other) => {
                vars.errors.push(format!(
                    "SMTP_TLS must be starttls, implicit or none, not {other:?}"
                ));
                SmtpTls::StartTls
            }
        };
        let port = vars.number("SMTP_PORT", tls.default_port(), 1..=u16::MAX);
        let credentials = match vars.pair("SMTP_USER", "SMTP_PASS") {
            (Some(user), Some(pass)) => Some((user, pass)),
            _ => None,
        };
        MailSettings {
            from,
            smtp: smtp_host.map(|host| SmtpSettings {
                host,
                port,
                tls,
                credentials,
            }),
            log_links: vars.flag("LOG_EMAIL_LINKS", debug_build),
        }
    }

    /// The sender when no email is sent at all (SMTP unset).
    fn placeholder_sender() -> Mailbox {
        Mailbox::new(
            None,
            lettre::Address::new("noreply", "heaas.local").expect("valid address"),
        )
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
            // High enough that functional tests never hit them; the rate-limit
            // tests set their own.
            rate_limits: RateLimitSettings {
                auth_per_minute: 10_000,
                logins_per_email: 10_000,
                emails_per_ip_per_hour: 10_000,
                emails_per_address_per_hour: 10_000,
            },
            ttl: TokenLifetimes::default(),
            oauth: OAuthEndpoints::default(),
            mail: MailSettings {
                from: Self::placeholder_sender(),
                smtp: None,
                log_links: true,
            },
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
            daily_compute_quota: 100,
            log_format: LogFormat::Pretty,
            metrics_token: None,
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

    const SECRET: &str = "a-secret-that-is-at-least-32-bytes-long";

    fn from(vars: &[(&str, &str)], debug_build: bool) -> Result<Config, ConfigError> {
        let vars: std::collections::HashMap<String, String> = vars
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        Config::from_vars(|name| vars.get(name).cloned(), debug_build)
    }

    fn problems(vars: &[(&str, &str)], debug_build: bool) -> Vec<String> {
        match from(vars, debug_build) {
            Ok(_) => Vec::new(),
            Err(e) => e.0,
        }
    }

    #[test]
    fn defaults_apply_to_unset_and_empty_variables() {
        let config = from(
            &[
                ("JWT_SECRET", SECRET),
                ("HE_WORKERS", ""),
                ("SMTP_PORT", " "),
            ],
            true,
        )
        .unwrap();
        assert_eq!(config.he_workers, 2);
        assert_eq!(config.app_base_url, "http://localhost:3000");
        assert_eq!(config.ttl.access_token_secs, 900);
        assert_eq!(config.rate_limits.auth_per_minute, 30);
        assert!(config.mail.smtp.is_none());
        assert!(config.mail.log_links);
        assert_eq!(config.log_format, LogFormat::Pretty);
        assert!(config.metrics_token.is_none());
        assert!(config
            .allowed_origins
            .contains(&"http://localhost:5173".to_string()));
    }

    #[test]
    fn every_invalid_value_is_reported_at_once() {
        let found = problems(
            &[
                ("JWT_SECRET", "short"),
                ("HE_WORKERS", "0"),
                ("JOB_TIMEOUT_SECS", "5m"),
                ("RATE_LIMIT_AUTH_PER_MINUTE", "-1"),
                ("SESSION_TTL_DAYS", "1000"),
                ("COOKIE_SECURE", "maybe"),
                ("ALLOWED_ORIGINS", "https://ok.example,nonsense"),
                ("TRUSTED_PROXIES", "10.0.0.0/33"),
                ("GOOGLE_CLIENT_ID", "id-without-secret"),
                ("DATABASE_URL", "postgres://db"),
                ("SERVER_ADDR", "8080"),
                ("LOG_FORMAT", "xml"),
                ("METRICS_TOKEN", "short"),
            ],
            true,
        );
        for name in [
            "JWT_SECRET",
            "HE_WORKERS",
            "JOB_TIMEOUT_SECS",
            "RATE_LIMIT_AUTH_PER_MINUTE",
            "SESSION_TTL_DAYS",
            "COOKIE_SECURE",
            "ALLOWED_ORIGINS",
            "TRUSTED_PROXIES",
            "GOOGLE_CLIENT_ID",
            "DATABASE_URL",
            "SERVER_ADDR",
            "LOG_FORMAT",
            "METRICS_TOKEN",
        ] {
            assert!(
                found.iter().any(|p| p.contains(name)),
                "{name} not reported in {found:#?}"
            );
        }
        assert_eq!(found.len(), 13, "{found:#?}");
    }

    #[test]
    fn release_builds_need_the_public_url_and_never_log_links() {
        assert_eq!(
            problems(&[("JWT_SECRET", SECRET)], false),
            vec!["APP_BASE_URL must be set (the public URL of the app, used in emailed links and OAuth callbacks)"]
        );
        let config = from(
            &[
                ("JWT_SECRET", SECRET),
                ("APP_BASE_URL", "https://heaas.example/"),
            ],
            false,
        )
        .unwrap();
        assert_eq!(config.app_base_url, "https://heaas.example");
        assert_eq!(config.allowed_origins, vec!["https://heaas.example"]);
        assert!(!config.mail.log_links);
        assert_eq!(config.log_format, LogFormat::Json);
        assert!(!problems(
            &[
                ("JWT_SECRET", SECRET),
                ("APP_BASE_URL", "https://heaas.example/?x=1")
            ],
            false
        )
        .is_empty());
    }

    #[test]
    fn smtp_settings_are_checked_together() {
        let base = [("JWT_SECRET", SECRET), ("SMTP_HOST", "smtp.example")];
        assert_eq!(
            problems(&base, true),
            vec!["FROM_EMAIL must be set when SMTP_HOST is"]
        );

        let config = from(
            &[
                base[0],
                base[1],
                ("FROM_EMAIL", "HEaaS <noreply@heaas.example>"),
                ("SMTP_TLS", "implicit"),
                ("SMTP_USER", "mailer"),
                ("SMTP_PASS", "hunter2"),
            ],
            true,
        )
        .unwrap();
        let smtp = config.mail.smtp.unwrap();
        assert_eq!((smtp.tls, smtp.port), (SmtpTls::Implicit, 465));
        assert_eq!(smtp.credentials.unwrap().0, "mailer");
        assert_eq!(config.mail.from.email.to_string(), "noreply@heaas.example");

        let found = problems(
            &[
                base[0],
                base[1],
                ("FROM_EMAIL", "not an address"),
                ("SMTP_TLS", "ssl3"),
                ("SMTP_USER", "mailer"),
            ],
            true,
        );
        assert_eq!(found.len(), 3, "{found:#?}");
    }
}
