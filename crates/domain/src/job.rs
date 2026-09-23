use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

/// Target for job execution: Cloud core node or a specific registered agent device.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "agent_id", rename_all = "snake_case")]
pub enum JobExecutionTarget {
    Cloud,
    Agent(Uuid),
}

/// Strongly-typed job payload. No shell strings, arbitrary scripts or commands allowed.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AgentJobType {
    InfrastructureAssessment {
        domain: String,
        timeout_seconds: u64,
    },
    ActiveVerification {
        endpoint: String,
    },
}

/// Lifecycle state of an agent job.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JobState {
    Pending,
    Leased,
    Running,
    Completed,
    Failed,
    Canceled,
}

/// Persistent job record representing remote work dispatched by the control plane.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AgentJob {
    pub id: Uuid,
    pub organization_id: Uuid,
    pub target_agent_id: Option<Uuid>,
    pub execution_target: JobExecutionTarget,
    pub job_type: AgentJobType,
    pub state: JobState,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub available_at: OffsetDateTime,
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub leased_at: Option<OffsetDateTime>,
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub lease_expires_at: Option<OffsetDateTime>,
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub started_at: Option<OffsetDateTime>,
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub completed_at: Option<OffsetDateTime>,
    #[serde(default)]
    pub attempt: u32,
    #[serde(default = "default_max_attempts")]
    pub max_attempts: u32,
    #[serde(default)]
    pub result_assessment_id: Option<Uuid>,
    #[serde(default)]
    pub last_error: Option<String>,
    #[serde(default)]
    pub idempotency_key: Option<String>,
    #[serde(default)]
    pub monitor_id: Option<Uuid>,
}

fn default_max_attempts() -> u32 {
    3
}

impl AgentJob {
    pub fn new_infrastructure_assessment(
        organization_id: Uuid,
        domain: String,
        timeout_seconds: u64,
        target_agent_id: Option<Uuid>,
        idempotency_key: Option<String>,
        monitor_id: Option<Uuid>,
    ) -> Self {
        let now = OffsetDateTime::now_utc();
        let execution_target = match target_agent_id {
            Some(agent_id) => JobExecutionTarget::Agent(agent_id),
            None => JobExecutionTarget::Cloud,
        };

        Self {
            id: Uuid::new_v4(),
            organization_id,
            target_agent_id,
            execution_target,
            job_type: AgentJobType::InfrastructureAssessment {
                domain,
                timeout_seconds,
            },
            state: JobState::Pending,
            created_at: now,
            available_at: now,
            leased_at: None,
            lease_expires_at: None,
            started_at: None,
            completed_at: None,
            attempt: 0,
            max_attempts: default_max_attempts(),
            result_assessment_id: None,
            last_error: None,
            idempotency_key,
            monitor_id,
        }
    }

    pub fn is_lease_expired(&self, now: OffsetDateTime) -> bool {
        if (self.state == JobState::Leased || self.state == JobState::Running)
            && let Some(expires_at) = self.lease_expires_at
        {
            return now > expires_at;
        }
        false
    }
}
