use dotenvy::dotenv;
use std::env;
use std::path::PathBuf;

/// Compressed TFHE server keys are ~60 MB with the default parameters.
const DEFAULT_MAX_SERVER_KEY_BYTES: u64 = 80 * 1024 * 1024;

pub struct Config {
    pub database_url: String,
    pub jwt_secret: String,
    pub server_addr: String,
    /// Directory holding users' uploaded compressed server keys.
    pub key_store_dir: PathBuf,
    /// Largest accepted compressed server key upload.
    pub max_server_key_bytes: u64,
    /// How many server keys one user may register.
    pub max_keys_per_user: i64,
    /// Decompressed server keys kept in memory (~180 MB each).
    pub key_cache_capacity: usize,
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

        let max_server_key_bytes = env::var("MAX_SERVER_KEY_BYTES")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(DEFAULT_MAX_SERVER_KEY_BYTES);

        let max_keys_per_user = env::var("MAX_KEYS_PER_USER")
            .ok()
            .and_then(|v| v.parse::<i64>().ok())
            .unwrap_or(2)
            .max(1);

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
            jwt_secret,
            server_addr: env::var("SERVER_ADDR").unwrap_or_else(|_| "127.0.0.1:8080".to_string()),
            key_store_dir: env::var("KEY_STORE_DIR")
                .unwrap_or_else(|_| "./data/keys".to_string())
                .into(),
            max_server_key_bytes,
            max_keys_per_user,
            key_cache_capacity,
            app_base_url: env::var("APP_BASE_URL")
                .unwrap_or_else(|_| "http://localhost:3000".to_string()),
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
    /// Configuration for unit and integration tests; `key_store_dir` is the
    /// caller's temporary directory.
    pub fn for_tests(key_store_dir: PathBuf) -> Self {
        Config {
            database_url: "sqlite::memory:".to_string(),
            jwt_secret: "test_secret_key_at_least_32_bytes_long".to_string(),
            server_addr: "127.0.0.1:8080".to_string(),
            key_store_dir,
            max_server_key_bytes: DEFAULT_MAX_SERVER_KEY_BYTES,
            max_keys_per_user: 2,
            key_cache_capacity: 2,
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
