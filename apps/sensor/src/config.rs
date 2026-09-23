use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SensorConfig {
    pub sensor_id: String,
    pub site_id: String,
    pub interface: String,
    pub buffer_capacity: usize,
    pub core_endpoint: String,
}

impl Default for SensorConfig {
    fn default() -> Self {
        Self {
            sensor_id: "sensor-local-01".to_string(),
            site_id: "site-local-dev".to_string(),
            interface: "any".to_string(),
            buffer_capacity: 1000,
            core_endpoint: "http://127.0.0.1:8080".to_string(),
        }
    }
}

impl SensorConfig {
    pub fn from_env() -> Self {
        let mut config = Self::default();

        if let Ok(id) = std::env::var("MAILENT_SENSOR_ID") {
            config.sensor_id = id;
        }
        if let Ok(site) = std::env::var("MAILENT_SENSOR_SITE_ID") {
            config.site_id = site;
        }
        if let Ok(iface) = std::env::var("MAILENT_SENSOR_INTERFACE") {
            config.interface = iface;
        }
        if let Ok(cap) = std::env::var("MAILENT_SENSOR_BUFFER_SIZE")
            && let Ok(c) = cap.parse::<usize>()
        {
            config.buffer_capacity = c.max(1);
        }
        if let Ok(endpoint) = std::env::var("MAILENT_SENSOR_CORE_ENDPOINT") {
            config.core_endpoint = endpoint;
        }

        config
    }
}
