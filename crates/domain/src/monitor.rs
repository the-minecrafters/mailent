use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

/// Execution target for a scheduled infrastructure monitor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "agent_id", rename_all = "snake_case")]
pub enum MonitorExecutionTarget {
    Cloud,
    Agent(Uuid),
}

/// Supported recurring cadences for infrastructure monitoring.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MonitorCadence {
    Hourly,
    Every6Hours,
    Every12Hours,
    Daily,
    Weekly,
}

impl MonitorCadence {
    pub fn interval_duration(&self) -> time::Duration {
        match self {
            Self::Hourly => time::Duration::hours(1),
            Self::Every6Hours => time::Duration::hours(6),
            Self::Every12Hours => time::Duration::hours(12),
            Self::Daily => time::Duration::days(1),
            Self::Weekly => time::Duration::days(7),
        }
    }

    pub fn next_run_after(&self, from: OffsetDateTime) -> OffsetDateTime {
        from + self.interval_duration()
    }
}

/// First-class persistent monitoring configuration for domain mail infrastructure.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct InfrastructureMonitor {
    pub id: Uuid,
    pub organization_id: Uuid,
    pub domain: String,
    pub enabled: bool,
    pub execution_target: MonitorExecutionTarget,
    pub cadence: MonitorCadence,
    #[serde(with = "time::serde::rfc3339")]
    pub next_run_at: OffsetDateTime,
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub last_run_at: Option<OffsetDateTime>,
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub last_success_at: Option<OffsetDateTime>,
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub last_failure_at: Option<OffsetDateTime>,
    #[serde(default)]
    pub last_assessment_id: Option<Uuid>,
    #[serde(default)]
    pub last_error: Option<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
}

impl InfrastructureMonitor {
    pub fn new(
        organization_id: Uuid,
        domain: String,
        execution_target: MonitorExecutionTarget,
        cadence: MonitorCadence,
        start_immediately: bool,
    ) -> Self {
        let now = OffsetDateTime::now_utc();
        let next_run_at = if start_immediately {
            now
        } else {
            cadence.next_run_after(now)
        };

        Self {
            id: Uuid::new_v4(),
            organization_id,
            domain,
            enabled: true,
            execution_target,
            cadence,
            next_run_at,
            last_run_at: None,
            last_success_at: None,
            last_failure_at: None,
            last_assessment_id: None,
            last_error: None,
            created_at: now,
            updated_at: now,
        }
    }
}
