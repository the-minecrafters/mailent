-- Agent Jobs table for dispatching tasks to registered local agents or cloud
CREATE TABLE IF NOT EXISTS agent_jobs (
    id UUID PRIMARY KEY,
    organization_id UUID NOT NULL REFERENCES organizations(id),
    target_agent_id UUID REFERENCES devices(id),
    execution_target JSONB NOT NULL,
    job_type JSONB NOT NULL,
    state VARCHAR(50) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    available_at TIMESTAMPTZ NOT NULL,
    leased_at TIMESTAMPTZ,
    lease_expires_at TIMESTAMPTZ,
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    attempt INT NOT NULL DEFAULT 0,
    max_attempts INT NOT NULL DEFAULT 3,
    result_assessment_id UUID REFERENCES assessments(id),
    last_error TEXT,
    idempotency_key VARCHAR(255),
    monitor_id UUID
);

CREATE INDEX IF NOT EXISTS idx_agent_jobs_org_state ON agent_jobs(organization_id, state);
CREATE INDEX IF NOT EXISTS idx_agent_jobs_target ON agent_jobs(target_agent_id, state);
CREATE INDEX IF NOT EXISTS idx_agent_jobs_idempotency ON agent_jobs(organization_id, idempotency_key);
CREATE INDEX IF NOT EXISTS idx_agent_jobs_lease_exp ON agent_jobs(state, lease_expires_at);

-- Infrastructure Monitors table for persistent domain monitoring configuration
CREATE TABLE IF NOT EXISTS infrastructure_monitors (
    id UUID PRIMARY KEY,
    organization_id UUID NOT NULL REFERENCES organizations(id),
    domain VARCHAR(255) NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    execution_target JSONB NOT NULL,
    cadence VARCHAR(50) NOT NULL,
    next_run_at TIMESTAMPTZ NOT NULL,
    last_run_at TIMESTAMPTZ,
    last_success_at TIMESTAMPTZ,
    last_failure_at TIMESTAMPTZ,
    last_assessment_id UUID REFERENCES assessments(id),
    last_error TEXT,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    UNIQUE(organization_id, domain)
);

CREATE INDEX IF NOT EXISTS idx_infra_monitors_due ON infrastructure_monitors(enabled, next_run_at);
CREATE INDEX IF NOT EXISTS idx_infra_monitors_org ON infrastructure_monitors(organization_id);

-- Update devices table with agent operational tracking fields
ALTER TABLE devices ADD COLUMN IF NOT EXISTS version VARCHAR(50);
ALTER TABLE devices ADD COLUMN IF NOT EXISTS agent_enabled BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE devices ADD COLUMN IF NOT EXISTS agent_status VARCHAR(50);
ALTER TABLE devices ADD COLUMN IF NOT EXISTS current_job_id UUID REFERENCES agent_jobs(id);
ALTER TABLE devices ADD COLUMN IF NOT EXISTS completed_jobs_count INT NOT NULL DEFAULT 0;
