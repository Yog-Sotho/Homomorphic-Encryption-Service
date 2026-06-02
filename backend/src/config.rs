use dotenvy::dotenv;
use std::env;

pub struct Config {
    pub database_url: String,
    pub jwt_secret: String,
    pub server_addr: String,
    pub he_pool_size: usize,
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

        let jwt_secret = match env::var("JWT_SECRET") {
            Ok(s) if !s.is_empty() => s,
            _ => {
                #[cfg(debug_assertions)]
                {
                    log::warn!(
                        "JWT_SECRET is not set! Using insecure default. \
                        Set JWT_SECRET in your environment before deploying to production."
                    );
                    "super-secret-key-2026-change-in-prod".to_string()
                }
                #[cfg(not(debug_assertions))]
                {
                    panic!(
                        "FATAL: JWT_SECRET environment variable must be set in release builds."
                    );
                }
            }
        };

        let he_pool_size = env::var("HE_POOL_SIZE")
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
            server_addr: env::var("SERVER_ADDR")
                .unwrap_or_else(|_| "127.0.0.1:8080".to_string()),
            he_pool_size,
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
