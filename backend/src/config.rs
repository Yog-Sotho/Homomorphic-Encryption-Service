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
        Config {
            database_url: env::var("DATABASE_URL").unwrap_or_else(|_| "sqlite://./he_saas.db".to_string()),
            jwt_secret: env::var("JWT_SECRET").unwrap_or_else(|_| "super-secret-key-2026-change-in-prod".to_string()),
            server_addr: env::var("SERVER_ADDR").unwrap_or_else(|_| "127.0.0.1:8080".to_string()),
        }
    }
}