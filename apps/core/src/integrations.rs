//! Workflow and alerting integration engine.
//!
//! Emits structured notifications to configured webhooks and SIEM / Syslog endpoints
//! on important security events (investigation created, finding confirmed,
//! verification completed, remediation verified, verification failed).
use mailent_domain::{
    IntegrationConfig, IntegrationEventPayload, IntegrationEventType, IntegrationKind,
};
use std::time::Duration;
use time::OffsetDateTime;
use tracing::{error, info, warn};
use uuid::Uuid;

use crate::state::AppState;

#[derive(Debug, Clone)]
pub struct EventNotification {
    pub event_type: IntegrationEventType,
    pub title: String,
    pub summary: String,
    pub asset_id: Option<Uuid>,
    pub asset_name: Option<String>,
    pub investigation_id: Option<Uuid>,
    pub finding_id: Option<Uuid>,
    pub probe_id: Option<Uuid>,
    pub details: serde_json::Value,
}

impl EventNotification {
    pub fn new(
        event_type: IntegrationEventType,
        title: impl Into<String>,
        summary: impl Into<String>,
    ) -> Self {
        Self {
            event_type,
            title: title.into(),
            summary: summary.into(),
            asset_id: None,
            asset_name: None,
            investigation_id: None,
            finding_id: None,
            probe_id: None,
            details: serde_json::Value::Null,
        }
    }

    pub fn with_asset(mut self, asset_id: Uuid, asset_name: Option<String>) -> Self {
        self.asset_id = Some(asset_id);
        self.asset_name = asset_name;
        self
    }

    pub fn with_investigation(mut self, investigation_id: Uuid) -> Self {
        self.investigation_id = Some(investigation_id);
        self
    }

    pub fn with_finding(mut self, finding_id: Uuid) -> Self {
        self.finding_id = Some(finding_id);
        self
    }

    pub fn with_probe(mut self, probe_id: Uuid) -> Self {
        self.probe_id = Some(probe_id);
        self
    }

    pub fn with_details(mut self, details: serde_json::Value) -> Self {
        self.details = details;
        self
    }
}

/// Dispatches an event to all matching enabled integrations in the background.
pub fn notify_event(state: &AppState, event: EventNotification) {
    let state = state.clone();
    tokio::spawn(async move {
        let payload = IntegrationEventPayload {
            event_id: Uuid::new_v4(),
            event_type: event.event_type,
            title: event.title,
            summary: event.summary,
            asset_id: event.asset_id,
            asset_name: event.asset_name,
            investigation_id: event.investigation_id,
            finding_id: event.finding_id,
            probe_id: event.probe_id,
            details: event.details,
            timestamp: OffsetDateTime::now_utc(),
        };

        if let Ok(integrations) = state.integrations.list_all().await {
            for integration in integrations {
                if integration.enabled && integration.event_types.contains(&payload.event_type) {
                    let _ = dispatch_to_destination(&state, &integration, &payload).await;
                }
            }
        }
    });
}

/// Dispatches a single payload to a specific integration and updates delivery status.
pub async fn dispatch_to_destination(
    state: &AppState,
    integration: &IntegrationConfig,
    payload: &IntegrationEventPayload,
) -> Result<u16, String> {
    let now = OffsetDateTime::now_utc();
    match integration.kind {
        IntegrationKind::Webhook => {
            let client = reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .build()
                .map_err(|e| e.to_string())?;

            let mut req = client.post(&integration.destination).json(payload);

            if let Some(ref auth) = integration.auth_header {
                req = req.header("Authorization", auth);
            }

            match req.send().await {
                Ok(resp) => {
                    let status = resp.status().as_u16();
                    let err = if status >= 400 {
                        Some(format!("HTTP status {status}"))
                    } else {
                        None
                    };
                    let _ = state
                        .integrations
                        .update_status(integration.id, Some(status), err.clone(), now)
                        .await;

                    if let Some(e) = err {
                        warn!(
                            integration = %integration.name,
                            destination = %integration.destination,
                            status = status,
                            "Webhook delivery returned error: {e}"
                        );
                        Err(e)
                    } else {
                        info!(
                            integration = %integration.name,
                            destination = %integration.destination,
                            status = status,
                            "Webhook delivered successfully"
                        );
                        Ok(status)
                    }
                }
                Err(e) => {
                    let err_str = e.to_string();
                    let _ = state
                        .integrations
                        .update_status(integration.id, None, Some(err_str.clone()), now)
                        .await;
                    error!(
                        integration = %integration.name,
                        destination = %integration.destination,
                        error = %err_str,
                        "Webhook delivery failed"
                    );
                    Err(err_str)
                }
            }
        }
        IntegrationKind::Syslog => {
            let result = send_syslog(&integration.destination, &payload.to_cef()).await;
            let error = result.as_ref().err().cloned();
            state
                .integrations
                .update_status(integration.id, result.as_ref().ok().copied(), error, now)
                .await
                .map_err(|e| e.to_string())?;
            result
        }
    }
}

async fn send_syslog(destination: &str, cef: &str) -> Result<u16, String> {
    use tokio::io::AsyncWriteExt;
    let url = reqwest::Url::parse(destination)
        .map_err(|_| "Use udp://host:port or tcp://host:port".to_string())?;
    let host = url.host_str().ok_or("Syslog destination requires a host")?;
    let port = url.port().unwrap_or(514);
    let timestamp = OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .map_err(|e| e.to_string())?;
    let message = format!(
        "<134>1 {timestamp} - mailent - - - {}",
        cef.replace(['\n', '\r'], " ")
    );
    tokio::time::timeout(Duration::from_secs(10), async {
        match url.scheme() {
            "udp" => {
                let addr = tokio::net::lookup_host((host, port))
                    .await
                    .map_err(|e| e.to_string())?
                    .next()
                    .ok_or("Syslog host has no address")?;
                let socket = tokio::net::UdpSocket::bind(if addr.is_ipv6() {
                    "[::]:0"
                } else {
                    "0.0.0.0:0"
                })
                .await
                .map_err(|e| e.to_string())?;
                socket
                    .send_to(message.as_bytes(), addr)
                    .await
                    .map_err(|e| e.to_string())?;
            }
            "tcp" => {
                let mut socket = tokio::net::TcpStream::connect((host, port))
                    .await
                    .map_err(|e| e.to_string())?;
                // RFC 6587 octet counting avoids ambiguity when an event contains delimiters.
                socket
                    .write_all(format!("{} {message}", message.len()).as_bytes())
                    .await
                    .map_err(|e| e.to_string())?;
                socket.shutdown().await.map_err(|e| e.to_string())?;
            }
            _ => return Err("Use udp://host:port or tcp://host:port".into()),
        }
        Ok(200)
    })
    .await
    .map_err(|_| "Syslog delivery timed out".to_string())?
}
