-- Posture snapshots for tracking historical security posture transitions over time
CREATE TABLE IF NOT EXISTS posture_snapshots (
    id UUID PRIMARY KEY,
    asset_id UUID NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    score REAL NOT NULL,
    grade VARCHAR(32) NOT NULL,
    score_capped BOOLEAN NOT NULL DEFAULT FALSE,
    pre_cap_score REAL NOT NULL,
    findings_considered INTEGER NOT NULL DEFAULT 0,
    worst_findings JSONB NOT NULL DEFAULT '[]'::jsonb,
    categories JSONB NOT NULL DEFAULT '[]'::jsonb,
    deductions JSONB NOT NULL DEFAULT '[]'::jsonb,
    change_reason TEXT,
    score_delta REAL,
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_posture_snapshots_asset ON posture_snapshots(asset_id, recorded_at DESC);

-- Workflow and outbound alert integrations (Webhooks, Syslog/CEF)
CREATE TABLE IF NOT EXISTS integrations (
    id UUID PRIMARY KEY,
    name VARCHAR(128) NOT NULL,
    kind VARCHAR(32) NOT NULL,
    destination TEXT NOT NULL,
    event_types JSONB NOT NULL DEFAULT '[]'::jsonb,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    auth_header TEXT,
    last_delivery_at TIMESTAMPTZ,
    last_status_code INTEGER,
    last_error TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Immutable archived forensic report snapshots
CREATE TABLE IF NOT EXISTS archived_reports (
    id UUID PRIMARY KEY,
    report_id VARCHAR(128) NOT NULL,
    subject_kind VARCHAR(32) NOT NULL,
    subject_id UUID NOT NULL,
    title TEXT NOT NULL,
    fingerprint VARCHAR(64) NOT NULL,
    generated_at TIMESTAMPTZ NOT NULL,
    archived_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    archived_by VARCHAR(128) NOT NULL DEFAULT 'analyst',
    notes TEXT,
    raw_json TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_archived_reports_subject ON archived_reports(subject_id, archived_at DESC);
