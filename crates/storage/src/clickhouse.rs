use async_trait::async_trait;
use mailent_domain::{EmailSession, NormalizedObservation};
use reqwest::Client;
use serde_json::json;
use std::time::Duration;
use uuid::Uuid;

use crate::{
    error::StorageError,
    repository::{ObservationRepository, SessionRepository},
};

#[derive(Clone)]
pub struct ClickHouseStorage {
    client: Client,
    endpoint: String,
    database: String,
}

impl ClickHouseStorage {
    pub async fn connect(endpoint: &str, database: &str) -> Result<Self, StorageError> {
        let client = Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .map_err(|e| StorageError::Backend(format!("Failed to build HTTP client: {e}")))?;

        let storage = Self {
            client,
            endpoint: endpoint.trim_end_matches('/').to_string(),
            database: database.to_string(),
        };

        storage.migrate().await?;
        Ok(storage)
    }

    pub async fn migrate(&self) -> Result<(), StorageError> {
        let migration_sql =
            include_str!("../migrations/clickhouse/20260922000001_initial_schema.sql");
        // Split by statement (semicolon at end of line)
        for stmt in migration_sql.split(';') {
            let trimmed = stmt.trim();
            if trimmed.is_empty() {
                continue;
            }
            self.execute(trimmed).await?;
        }
        Ok(())
    }

    pub async fn execute(&self, query: &str) -> Result<(), StorageError> {
        let url = format!("{}/?database={}", self.endpoint, self.database);
        let res = self
            .client
            .post(&url)
            .body(query.to_string())
            .send()
            .await
            .map_err(|e| StorageError::Backend(format!("ClickHouse query failed: {e}")))?;

        let status = res.status();
        if !status.is_success() {
            let body = res.text().await.unwrap_or_default();
            return Err(StorageError::Backend(format!(
                "ClickHouse returned HTTP {status}: {body} for query: {query}"
            )));
        }
        Ok(())
    }

    async fn execute_with_body(
        &self,
        query_param: &str,
        body: Vec<u8>,
    ) -> Result<(), StorageError> {
        let url = format!(
            "{}/?database={}&query={}",
            self.endpoint,
            self.database,
            urlencoding::encode(query_param)
        );
        let res = self
            .client
            .post(&url)
            .body(body)
            .send()
            .await
            .map_err(|e| StorageError::Backend(format!("ClickHouse insert failed: {e}")))?;

        let status = res.status();
        if !status.is_success() {
            let err = res.text().await.unwrap_or_default();
            return Err(StorageError::Backend(format!(
                "ClickHouse insert HTTP {status}: {err}"
            )));
        }
        Ok(())
    }

    async fn query_rows<T: for<'de> serde::Deserialize<'de>>(
        &self,
        query: &str,
    ) -> Result<Vec<T>, StorageError> {
        let url = format!(
            "{}/?database={}&query={}",
            self.endpoint,
            self.database,
            urlencoding::encode(query)
        );
        let res = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| StorageError::Backend(format!("ClickHouse query failed: {e}")))?;

        let status = res.status();
        if !status.is_success() {
            let err = res.text().await.unwrap_or_default();
            return Err(StorageError::Backend(format!(
                "ClickHouse query HTTP {status}: {err}"
            )));
        }

        let body = res
            .text()
            .await
            .map_err(|e| StorageError::Backend(e.to_string()))?;
        let mut results = Vec::new();
        for line in body.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            let item: T = serde_json::from_str(trimmed).map_err(|e| {
                StorageError::Backend(format!(
                    "JSON deserialization failed: {e} on line: {trimmed}"
                ))
            })?;
            results.push(item);
        }
        Ok(results)
    }
}

#[async_trait]
impl SessionRepository for ClickHouseStorage {
    async fn save(&self, session: EmailSession) -> Result<(), StorageError> {
        let raw_json = serde_json::to_string(&session)
            .map_err(|e| StorageError::Backend(format!("Serialization error: {e}")))?;

        let cert_fp = session
            .certificate
            .as_ref()
            .map(|c| c.reference.sha256_fingerprint.clone());
        let cap_sha = session.capture.as_ref().map(|c| c.capture_sha256.clone());
        let conn_uid = session.capture.as_ref().map(|c| c.connection_uid.clone());

        let row = json!({
            "session_id": session.session_id.to_string(),
            "sensor_id": session.sensor_id,
            "src_ip": session.flow.src_ip,
            "src_port": session.flow.src_port,
            "dst_ip": session.flow.dst_ip,
            "dst_port": session.flow.dst_port,
            "protocol": session.protocol.to_string().to_lowercase(),
            "starttls_state": session.starttls_state.map(|s| format!("{s:?}").to_lowercase()),
            "tls_version": session.tls_version.as_ref().map(|v| v.to_string()),
            "cipher_suite_id": session.cipher_suite.as_ref().and_then(|c| c.id),
            "cipher_suite_name": session.cipher_suite.as_ref().map(|c| c.name.clone()),
            "key_exchange": session.key_exchange.as_ref().map(|k| format!("{k:?}").to_lowercase()),
            "cert_fingerprint": cert_fp,
            "capture_sha256": cap_sha,
            "connection_uid": conn_uid,
            "first_seen": format_clickhouse_datetime(&session.first_seen),
            "last_seen": format_clickhouse_datetime(&session.last_seen),
            "raw_json": raw_json
        });

        let row_line =
            serde_json::to_vec(&row).map_err(|e| StorageError::Backend(e.to_string()))?;
        self.execute_with_body("INSERT INTO email_sessions FORMAT JSONEachRow", row_line)
            .await?;

        // Save timeline events if capture is present
        if let Some(cap) = &session.capture
            && !cap.timeline.is_empty()
        {
            let mut timeline_lines = Vec::new();
            for (idx, ev) in cap.timeline.iter().enumerate() {
                let ev_row = json!({
                    "session_id": session.session_id.to_string(),
                    "timestamp": format_clickhouse_datetime(&ev.timestamp),
                    "kind": ev.kind,
                    "source": ev.source,
                    "event_order": idx as u32
                });
                let mut b = serde_json::to_vec(&ev_row)
                    .map_err(|e| StorageError::Backend(e.to_string()))?;
                b.push(b'\n');
                timeline_lines.extend_from_slice(&b);
            }
            self.execute_with_body(
                "INSERT INTO timeline_events FORMAT JSONEachRow",
                timeline_lines,
            )
            .await?;
        }

        // Save certificate history if present
        if let Some(cert) = &session.certificate {
            let cert_row = json!({
                "fingerprint": cert.reference.sha256_fingerprint,
                "subject": cert.reference.subject,
                "issuer": cert.reference.issuer,
                "sans": cert.san,
                "not_before": format_clickhouse_datetime(&cert.validity.not_before),
                "not_after": format_clickhouse_datetime(&cert.validity.not_after),
                "observed_at": format_clickhouse_datetime(&session.last_seen),
                "asset_ip": session.flow.dst_ip,
                "session_id": session.session_id.to_string()
            });
            let b =
                serde_json::to_vec(&cert_row).map_err(|e| StorageError::Backend(e.to_string()))?;
            self.execute_with_body("INSERT INTO certificate_history FORMAT JSONEachRow", b)
                .await?;
        }

        Ok(())
    }

    async fn list_recent(&self, limit: usize) -> Result<Vec<EmailSession>, StorageError> {
        #[derive(serde::Deserialize)]
        struct Row {
            raw_json: String,
        }
        let query = format!(
            "SELECT raw_json FROM email_sessions FINAL ORDER BY first_seen DESC LIMIT {limit} FORMAT JSONEachRow"
        );
        let rows: Vec<Row> = self.query_rows(&query).await?;
        let mut sessions = Vec::with_capacity(rows.len());
        for r in rows {
            let session: EmailSession = serde_json::from_str(&r.raw_json)
                .map_err(|e| StorageError::Backend(format!("Session deserialize error: {e}")))?;
            sessions.push(session);
        }
        Ok(sessions)
    }

    async fn find_by_id(&self, id: Uuid) -> Result<Option<EmailSession>, StorageError> {
        #[derive(serde::Deserialize)]
        struct Row {
            raw_json: String,
        }
        let query = format!(
            "SELECT raw_json FROM email_sessions FINAL WHERE session_id = '{id}' LIMIT 1 FORMAT JSONEachRow"
        );
        let rows: Vec<Row> = self.query_rows(&query).await?;
        if let Some(r) = rows.into_iter().next() {
            let session: EmailSession = serde_json::from_str(&r.raw_json)
                .map_err(|e| StorageError::Backend(format!("Session deserialize error: {e}")))?;
            Ok(Some(session))
        } else {
            Ok(None)
        }
    }

    async fn list_for_asset(
        &self,
        asset_ip: &str,
        limit: usize,
    ) -> Result<Vec<EmailSession>, StorageError> {
        #[derive(serde::Deserialize)]
        struct Row {
            raw_json: String,
        }
        let query = format!(
            "SELECT raw_json FROM email_sessions FINAL WHERE src_ip = '{asset_ip}' OR dst_ip = '{asset_ip}' ORDER BY first_seen DESC LIMIT {limit} FORMAT JSONEachRow"
        );
        let rows: Vec<Row> = self.query_rows(&query).await?;
        let mut sessions = Vec::with_capacity(rows.len());
        for r in rows {
            let session: EmailSession = serde_json::from_str(&r.raw_json)
                .map_err(|e| StorageError::Backend(format!("Session deserialize error: {e}")))?;
            sessions.push(session);
        }
        Ok(sessions)
    }
}

#[async_trait]
impl ObservationRepository for ClickHouseStorage {
    async fn save(&self, observation: NormalizedObservation) -> Result<(), StorageError> {
        let raw_json = serde_json::to_string(&observation)
            .map_err(|e| StorageError::Backend(format!("Serialization error: {e}")))?;

        let cert_fp = observation
            .certificate
            .as_ref()
            .map(|c| c.reference.sha256_fingerprint.clone());
        let cap_sha = observation
            .capture
            .as_ref()
            .map(|c| c.capture_sha256.clone());
        let conn_uid = observation
            .capture
            .as_ref()
            .map(|c| c.connection_uid.clone());

        let row = json!({
            "observation_id": observation.observation_id.to_string(),
            "timestamp": format_clickhouse_datetime(&observation.timestamp),
            "sensor_id": observation.sensor_id,
            "source": observation.provenance.source,
            "parser": observation.provenance.parser,
            "parser_version": observation.provenance.parser_version,
            "src_ip": observation.flow.src_ip,
            "src_port": observation.flow.src_port,
            "dst_ip": observation.flow.dst_ip,
            "dst_port": observation.flow.dst_port,
            "protocol": observation.protocol.to_string().to_lowercase(),
            "starttls_state": observation.starttls_state.map(|s| format!("{s:?}").to_lowercase()),
            "tls_version": observation.tls_version.as_ref().map(|v| v.to_string()),
            "cipher_suite_id": observation.cipher_suite.as_ref().and_then(|c| c.id),
            "cipher_suite_name": observation.cipher_suite.as_ref().map(|c| c.name.clone()),
            "key_exchange": observation.key_exchange.as_ref().map(|k| format!("{k:?}").to_lowercase()),
            "cert_fingerprint": cert_fp,
            "capture_sha256": cap_sha,
            "connection_uid": conn_uid,
            "raw_json": raw_json
        });

        let row_line =
            serde_json::to_vec(&row).map_err(|e| StorageError::Backend(e.to_string()))?;
        self.execute_with_body(
            "INSERT INTO normalized_observations FORMAT JSONEachRow",
            row_line,
        )
        .await?;
        Ok(())
    }

    async fn find_by_id(&self, id: Uuid) -> Result<Option<NormalizedObservation>, StorageError> {
        #[derive(serde::Deserialize)]
        struct Row {
            raw_json: String,
        }
        let query = format!(
            "SELECT raw_json FROM normalized_observations FINAL WHERE observation_id = '{id}' LIMIT 1 FORMAT JSONEachRow"
        );
        let rows: Vec<Row> = self.query_rows(&query).await?;
        if let Some(r) = rows.into_iter().next() {
            let obs: NormalizedObservation = serde_json::from_str(&r.raw_json).map_err(|e| {
                StorageError::Backend(format!("Observation deserialize error: {e}"))
            })?;
            Ok(Some(obs))
        } else {
            Ok(None)
        }
    }

    async fn list_recent(&self, limit: usize) -> Result<Vec<NormalizedObservation>, StorageError> {
        #[derive(serde::Deserialize)]
        struct Row {
            raw_json: String,
        }
        let query = format!(
            "SELECT raw_json FROM normalized_observations FINAL ORDER BY timestamp DESC LIMIT {limit} FORMAT JSONEachRow"
        );
        let rows: Vec<Row> = self.query_rows(&query).await?;
        let mut obs_list = Vec::with_capacity(rows.len());
        for r in rows {
            let obs: NormalizedObservation = serde_json::from_str(&r.raw_json).map_err(|e| {
                StorageError::Backend(format!("Observation deserialize error: {e}"))
            })?;
            obs_list.push(obs);
        }
        Ok(obs_list)
    }
}

mod urlencoding {
    pub fn encode(s: &str) -> String {
        let mut result = String::with_capacity(s.len());
        for b in s.bytes() {
            match b {
                b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                    result.push(b as char);
                }
                b' ' => result.push('+'),
                _ => {
                    result.push_str(&format!("%{:02X}", b));
                }
            }
        }
        result
    }
}

fn format_clickhouse_datetime(dt: &time::OffsetDateTime) -> String {
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}.{:06}",
        dt.year(),
        dt.month() as u8,
        dt.day(),
        dt.hour(),
        dt.minute(),
        dt.second(),
        dt.microsecond()
    )
}
