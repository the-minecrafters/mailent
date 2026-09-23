pub mod agent;
pub mod analyze;
pub mod config;
pub mod error;
pub mod live;
pub mod normalize;
pub mod spool;

pub use agent::SensorAgent;
pub use config::SensorConfig;
pub use error::SensorError;
pub use spool::BoundedSpooler;

/// A collector credential can write observations and heartbeats, never read workspace data.
pub fn auth_headers() -> reqwest::header::HeaderMap {
    let mut headers = reqwest::header::HeaderMap::new();
    if let Ok(token) = std::env::var("MAILENT_COLLECTOR_TOKEN") {
        let mut value = reqwest::header::HeaderValue::from_str(&format!("Bearer {token}"))
            .expect("Invalid MAILENT_COLLECTOR_TOKEN");
        value.set_sensitive(true);
        headers.insert(reqwest::header::AUTHORIZATION, value);
    }
    headers
}
