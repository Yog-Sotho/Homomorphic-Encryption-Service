use dotenvy::dotenv;
use std::env;

pub struct Config {
    pub database_url: String,
    pub jwt_secret: String,
    pub server_addr: String,
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
                        "FATAL: JWT_SECRET environment variable must be set in release builds. \
                        Generate a strong random secret and set it before running."
                    );
                }
            }
        };

        Config {
            database_url: env::var("DATABASE_URL")
                .unwrap_or_else(|_| "sqlite://./he_saas.db".to_string()),
            jwt_secret,
            server_addr: env::var("SERVER_ADDR")
                .unwrap_or_else(|_| "127.0.0.1:8080".to_string()),
        }
    }
}
