//! PostgreSQL evidence storage for single-database deployments.
use crate::{ObservationRepository, PostgresStorage, SessionRepository, StorageError};
use async_trait::async_trait;
use mailent_domain::{EmailSession, NormalizedObservation};
use sqlx::Row;
use uuid::Uuid;

fn backend(error: impl std::fmt::Display) -> StorageError {
    StorageError::Backend(error.to_string())
}
fn decode<T: serde::de::DeserializeOwned>(row: sqlx::postgres::PgRow) -> Result<T, StorageError> {
    serde_json::from_value(row.try_get("data").map_err(backend)?).map_err(backend)
}
#[async_trait]
impl SessionRepository for PostgresStorage {
    async fn save(&self, session: EmailSession) -> Result<(), StorageError> {
        let data = serde_json::to_value(&session).map_err(backend)?;
        // Compare the complete evidence except its observation window. Never overwrite conflicting evidence.
        let saved = sqlx::query("INSERT INTO mail_sessions (session_id, src_ip, dst_ip, last_seen, data) VALUES ($1,$2,$3,$4,$5) ON CONFLICT (session_id) DO UPDATE SET last_seen = GREATEST(mail_sessions.last_seen, EXCLUDED.last_seen), data = jsonb_set(mail_sessions.data, '{last_seen}', to_jsonb(GREATEST(mail_sessions.last_seen, EXCLUDED.last_seen))) WHERE (mail_sessions.data - 'last_seen') = (EXCLUDED.data - 'last_seen')")
            .bind(session.session_id).bind(&session.flow.src_ip).bind(&session.flow.dst_ip).bind(session.last_seen).bind(data).execute(self.pool()).await.map_err(backend)?;
        if saved.rows_affected() == 0 {
            return Err(StorageError::Conflict(
                "Session ID already has different evidence".into(),
            ));
        }
        Ok(())
    }
    async fn list_recent(&self, limit: usize) -> Result<Vec<EmailSession>, StorageError> {
        sqlx::query("SELECT data FROM mail_sessions ORDER BY last_seen DESC, session_id LIMIT $1")
            .bind(limit.min(10000) as i64)
            .fetch_all(self.pool())
            .await
            .map_err(backend)?
            .into_iter()
            .map(decode)
            .collect()
    }
    async fn find_by_id(&self, id: Uuid) -> Result<Option<EmailSession>, StorageError> {
        sqlx::query("SELECT data FROM mail_sessions WHERE session_id=$1")
            .bind(id)
            .fetch_optional(self.pool())
            .await
            .map_err(backend)?
            .map(decode)
            .transpose()
    }
    async fn list_for_asset(
        &self,
        asset_ip: &str,
        limit: usize,
    ) -> Result<Vec<EmailSession>, StorageError> {
        sqlx::query("SELECT data FROM mail_sessions WHERE src_ip=$1 OR dst_ip=$1 ORDER BY last_seen DESC, session_id LIMIT $2").bind(asset_ip).bind(limit.min(10000) as i64).fetch_all(self.pool()).await.map_err(backend)?.into_iter().map(decode).collect()
    }
}
#[async_trait]
impl ObservationRepository for PostgresStorage {
    async fn save(&self, observation: NormalizedObservation) -> Result<(), StorageError> {
        let data = serde_json::to_value(&observation).map_err(backend)?;
        let saved = sqlx::query("INSERT INTO mail_observations (observation_id, observed_at, data) VALUES ($1,$2,$3) ON CONFLICT (observation_id) DO UPDATE SET data = mail_observations.data WHERE mail_observations.data = EXCLUDED.data")
            .bind(observation.observation_id).bind(observation.timestamp).bind(data).execute(self.pool()).await.map_err(backend)?;
        if saved.rows_affected() == 0 {
            return Err(StorageError::Conflict(
                "Observation ID already has different evidence".into(),
            ));
        }
        Ok(())
    }
    async fn find_by_id(&self, id: Uuid) -> Result<Option<NormalizedObservation>, StorageError> {
        sqlx::query("SELECT data FROM mail_observations WHERE observation_id=$1")
            .bind(id)
            .fetch_optional(self.pool())
            .await
            .map_err(backend)?
            .map(decode)
            .transpose()
    }
    async fn list_recent(&self, limit: usize) -> Result<Vec<NormalizedObservation>, StorageError> {
        sqlx::query(
            "SELECT data FROM mail_observations ORDER BY observed_at DESC, observation_id LIMIT $1",
        )
        .bind(limit.min(10000) as i64)
        .fetch_all(self.pool())
        .await
        .map_err(backend)?
        .into_iter()
        .map(decode)
        .collect()
    }
}
