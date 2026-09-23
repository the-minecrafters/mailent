use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoreConfig {
    pub host: String,
    pub port: u16,
    pub log_level: String,
    pub environment: String,
    pub policy_path: Option<String>,
    pub database_url: Option<String>,
    pub clickhouse_url: Option<String>,
    pub clickhouse_database: String,
    pub jev_enabled: bool,
    pub jev_base_url: Option<String>,
    pub jev_api_key: Option<String>,
    pub jev_model: Option<String>,
    pub doh_endpoint: Option<String>,
}

impl Default for CoreConfig {
    fn default() -> Self {
        Self {
            host: "127.0.0.1".to_string(),
            port: 8080,
            log_level: "info".to_string(),
            environment: "development".to_string(),
            policy_path: None,
            database_url: None,
            clickhouse_url: None,
            clickhouse_database: "mailent".to_string(),
            jev_enabled: true,
            jev_base_url: None,
            jev_api_key: None,
            jev_model: None,
            doh_endpoint: None,
        }
    }
}

impl CoreConfig {
    pub fn from_env() -> Self {
        let mut config = Self::default();

        if let Ok(host) = std::env::var("MAILENT_CORE_HOST") {
            config.host = host;
        }
        if let Ok(port) = std::env::var("MAILENT_CORE_PORT").or_else(|_| std::env::var("PORT")) {
            config.port = port.parse().expect("MAILENT_CORE_PORT must be a valid u16");
        }
        if let Ok(level) = std::env::var("MAILENT_CORE_LOG_LEVEL") {
            config.log_level = level;
        }
        if let Ok(env) = std::env::var("MAILENT_CORE_ENVIRONMENT") {
            config.environment = env;
        }

        config.policy_path = std::env::var("MAILENT_CORE_POLICY_PATH").ok();
        config.database_url = std::env::var("MAILENT_DATABASE_URL")
            .ok()
            .filter(|s| !s.trim().is_empty());
        config.clickhouse_url = std::env::var("MAILENT_CLICKHOUSE_URL").ok();
        if let Ok(ch_db) = std::env::var("MAILENT_CLICKHOUSE_DATABASE") {
            config.clickhouse_database = ch_db;
        }

        let jev_enabled = std::env::var("MAILENT_JEV_ENABLED")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(true);
        config.jev_enabled = jev_enabled;
        config.jev_base_url = std::env::var("MAILENT_JEV_BASE_URL")
            .or_else(|_| std::env::var("TYPESAFE_BASE_URL"))
            .or_else(|_| std::env::var("JEV_BASE_URL"))
            .ok();
        config.jev_api_key = std::env::var("MAILENT_JEV_API_KEY")
            .or_else(|_| std::env::var("TYPESAFE_API_KEY"))
            .or_else(|_| std::env::var("JEV_API_KEY"))
            .ok();
        config.jev_model = std::env::var("MAILENT_JEV_MODEL")
            .or_else(|_| std::env::var("TYPESAFE_MODEL"))
            .or_else(|_| std::env::var("JEV_MODEL"))
            .ok();
        config.doh_endpoint = std::env::var("MAILENT_DOH_ENDPOINT").ok();

        config
    }

    pub fn socket_addr(&self) -> Result<SocketAddr, std::net::AddrParseError> {
        Ok(SocketAddr::new(self.host.parse()?, self.port))
    }
}
