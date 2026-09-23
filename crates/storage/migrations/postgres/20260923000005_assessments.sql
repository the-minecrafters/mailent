-- First-class persistent forensic assessment records
CREATE TABLE IF NOT EXISTS assessments (
    id UUID PRIMARY KEY,
    title TEXT NOT NULL,
    capture_name TEXT NOT NULL,
    capture_hash VARCHAR(64) NOT NULL,
    capture_size_bytes BIGINT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    time_range_start TIMESTAMPTZ,
    time_range_end TIMESTAMPTZ,
    protocols_identified JSONB NOT NULL DEFAULT '[]'::jsonb,
    protocol_evidence JSONB NOT NULL DEFAULT '[]'::jsonb,
    session_ids JSONB NOT NULL DEFAULT '[]'::jsonb,
    asset_ids JSONB NOT NULL DEFAULT '[]'::jsonb,
    finding_ids JSONB NOT NULL DEFAULT '[]'::jsonb,
    posture_score REAL NOT NULL DEFAULT 100.0,
    posture_grade VARCHAR(8) NOT NULL DEFAULT 'A',
    evidence_gaps JSONB NOT NULL DEFAULT '[]'::jsonb,
    ai_risk_classification VARCHAR(32) NOT NULL DEFAULT 'LOW',
    ai_risk_rationale TEXT NOT NULL DEFAULT '',
    ai_confidence REAL NOT NULL DEFAULT 1.0,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS idx_assessments_created_at ON assessments(created_at DESC);
