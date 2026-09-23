CREATE SCHEMA IF NOT EXISTS mailent;
REVOKE ALL ON SCHEMA mailent FROM PUBLIC, anon, authenticated;
SET search_path TO mailent;


-- 20260922000001_initial_schema.sql
-- PostgreSQL schema for Mailent control & mutable state

CREATE TABLE IF NOT EXISTS sites (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS sensors (
    id TEXT PRIMARY KEY,
    site_id TEXT NOT NULL,
    hostname TEXT NOT NULL,
    version TEXT NOT NULL,
    mode TEXT NOT NULL DEFAULT 'pcap',
    interface TEXT,
    status TEXT NOT NULL DEFAULT 'online',
    last_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    registered_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS assets (
    id UUID PRIMARY KEY,
    primary_name TEXT,
    addresses TEXT[] NOT NULL DEFAULT '{}',
    hostnames TEXT[] NOT NULL DEFAULT '{}',
    tls_versions TEXT[] NOT NULL DEFAULT '{}',
    cipher_suites TEXT[] NOT NULL DEFAULT '{}',
    certificate_fingerprints TEXT[] NOT NULL DEFAULT '{}',
    active_findings_count INT NOT NULL DEFAULT 0,
    first_seen TIMESTAMPTZ NOT NULL,
    last_seen TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS asset_identities (
    id UUID PRIMARY KEY,
    asset_id UUID NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    kind TEXT NOT NULL,
    value TEXT NOT NULL,
    first_seen TIMESTAMPTZ NOT NULL,
    last_seen TIMESTAMPTZ NOT NULL,
    CONSTRAINT uq_asset_identity UNIQUE (asset_id, kind, value)
);

CREATE INDEX IF NOT EXISTS idx_asset_identities_lookup ON asset_identities (value);

CREATE TABLE IF NOT EXISTS asset_endpoints (
    id UUID PRIMARY KEY,
    asset_id UUID NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    protocol TEXT NOT NULL,
    port INT NOT NULL,
    tls_versions TEXT[] NOT NULL DEFAULT '{}',
    cipher_suites TEXT[] NOT NULL DEFAULT '{}',
    first_seen TIMESTAMPTZ NOT NULL,
    last_seen TIMESTAMPTZ NOT NULL,
    CONSTRAINT uq_asset_endpoint UNIQUE (asset_id, protocol, port)
);

CREATE TABLE IF NOT EXISTS certificates (
    sha256_fingerprint TEXT PRIMARY KEY,
    subject TEXT NOT NULL,
    issuer TEXT NOT NULL,
    sans TEXT[] NOT NULL DEFAULT '{}',
    not_before TIMESTAMPTZ NOT NULL,
    not_after TIMESTAMPTZ NOT NULL,
    first_seen TIMESTAMPTZ NOT NULL,
    last_seen TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS asset_certificates (
    asset_id UUID NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    certificate_fingerprint TEXT NOT NULL REFERENCES certificates(sha256_fingerprint) ON DELETE CASCADE,
    first_seen TIMESTAMPTZ NOT NULL,
    last_seen TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (asset_id, certificate_fingerprint)
);

CREATE TABLE IF NOT EXISTS findings (
    id UUID PRIMARY KEY,
    rule_id TEXT NOT NULL,
    policy_name TEXT NOT NULL,
    policy_version TEXT NOT NULL,
    reference TEXT NOT NULL,
    severity TEXT NOT NULL,
    category TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    remediation TEXT NOT NULL,
    affected_count INT NOT NULL DEFAULT 1,
    first_seen TIMESTAMPTZ NOT NULL,
    last_seen TIMESTAMPTZ NOT NULL,
    status TEXT NOT NULL DEFAULT 'active',
    asset_id UUID REFERENCES assets(id)
);

CREATE INDEX IF NOT EXISTS idx_findings_rule_id ON findings (rule_id);
CREATE INDEX IF NOT EXISTS idx_findings_asset_id ON findings (asset_id);

CREATE TABLE IF NOT EXISTS finding_evidence (
    id UUID PRIMARY KEY,
    finding_id UUID NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    session_id UUID,
    observation_id UUID,
    description TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_finding_evidence_session_id ON finding_evidence (session_id);

CREATE TABLE IF NOT EXISTS drift_events (
    id UUID PRIMARY KEY,
    asset_id UUID NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    kind TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    previous_value TEXT,
    new_value TEXT NOT NULL,
    observed_at TIMESTAMPTZ NOT NULL,
    session_id UUID
);

CREATE INDEX IF NOT EXISTS idx_drift_events_asset_id ON drift_events (asset_id, observed_at DESC);


-- 20260922000002_intelligence_and_investigations.sql
-- Migration 02: External Intelligence, Baselines, Anomalies, Investigations, Decisions

CREATE TABLE IF NOT EXISTS mx_records (
    id UUID PRIMARY KEY,
    domain TEXT NOT NULL,
    hostname TEXT NOT NULL,
    priority INT NOT NULL,
    resolved_ips TEXT[] NOT NULL DEFAULT '{}',
    dnssec TEXT NOT NULL,
    first_seen TIMESTAMPTZ NOT NULL,
    last_checked TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_mx_records_domain ON mx_records (domain);

CREATE TABLE IF NOT EXISTS tlsa_records (
    id UUID PRIMARY KEY,
    domain TEXT NOT NULL,
    mx_host TEXT NOT NULL,
    port INT NOT NULL,
    usage INT NOT NULL,
    selector INT NOT NULL,
    matching_type INT NOT NULL,
    cert_association_data TEXT NOT NULL,
    dnssec TEXT NOT NULL,
    checked_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_tlsa_records_domain ON tlsa_records (domain);

CREATE TABLE IF NOT EXISTS mta_sts_policies (
    domain TEXT PRIMARY KEY,
    version TEXT NOT NULL,
    mode TEXT NOT NULL,
    mx_patterns TEXT[] NOT NULL DEFAULT '{}',
    max_age_seconds INT NOT NULL,
    dnssec TEXT NOT NULL,
    checked_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS tls_rpt_policies (
    domain TEXT PRIMARY KEY,
    rua TEXT[] NOT NULL DEFAULT '{}',
    checked_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS tls_rpt_reports (
    id UUID PRIMARY KEY,
    organization_name TEXT NOT NULL,
    policy_domain TEXT NOT NULL,
    start_date TIMESTAMPTZ NOT NULL,
    end_date TIMESTAMPTZ NOT NULL,
    successful_sessions BIGINT NOT NULL,
    failed_sessions BIGINT NOT NULL,
    raw_json TEXT NOT NULL,
    imported_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_tls_rpt_policy_domain ON tls_rpt_reports (policy_domain);

CREATE TABLE IF NOT EXISTS ct_certificates (
    sha256_fingerprint TEXT PRIMARY KEY,
    domain TEXT NOT NULL,
    names TEXT[] NOT NULL DEFAULT '{}',
    issuer TEXT NOT NULL,
    not_before TIMESTAMPTZ NOT NULL,
    not_after TIMESTAMPTZ NOT NULL,
    ct_first_seen TIMESTAMPTZ NOT NULL,
    observed_on_network BOOLEAN NOT NULL DEFAULT FALSE,
    first_network_observation TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_ct_certificates_domain ON ct_certificates (domain);

CREATE TABLE IF NOT EXISTS ct_events (
    id UUID PRIMARY KEY,
    domain TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    kind TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    observed_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_ct_events_domain ON ct_events (domain);

CREATE TABLE IF NOT EXISTS intelligence_refresh_status (
    domain TEXT PRIMARY KEY,
    last_checked TIMESTAMPTZ,
    next_check TIMESTAMPTZ,
    last_success TIMESTAMPTZ,
    last_error TEXT
);

CREATE TABLE IF NOT EXISTS asset_baselines (
    asset_id UUID PRIMARY KEY REFERENCES assets(id) ON DELETE CASCADE,
    sample_count BIGINT NOT NULL,
    window_start TIMESTAMPTZ NOT NULL,
    window_end TIMESTAMPTZ NOT NULL,
    generated_at TIMESTAMPTZ NOT NULL,
    coverage REAL NOT NULL,
    tls_version_distribution JSONB NOT NULL DEFAULT '{}',
    cipher_distribution JSONB NOT NULL DEFAULT '{}',
    key_exchange_distribution JSONB NOT NULL DEFAULT '{}',
    certificate_fingerprints TEXT[] NOT NULL DEFAULT '{}',
    certificate_issuers TEXT[] NOT NULL DEFAULT '{}',
    starttls_success_rate REAL NOT NULL,
    handshake_failure_rate REAL NOT NULL,
    peer_set TEXT[] NOT NULL DEFAULT '{}',
    ports INT[] NOT NULL DEFAULT '{}',
    session_frequency_per_hour REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS anomaly_signals (
    id UUID PRIMARY KEY,
    asset_id UUID NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    signal TEXT NOT NULL,
    title TEXT NOT NULL,
    current_value TEXT NOT NULL,
    baseline_value TEXT NOT NULL,
    deviation REAL NOT NULL,
    confidence REAL NOT NULL,
    evidence TEXT NOT NULL,
    observed_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_anomaly_signals_asset_id ON anomaly_signals (asset_id);

CREATE TABLE IF NOT EXISTS investigations (
    id UUID PRIMARY KEY,
    asset_id UUID NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    title TEXT NOT NULL,
    summary TEXT NOT NULL,
    status TEXT NOT NULL,
    risk TEXT NOT NULL,
    priority TEXT NOT NULL,
    finding_ids TEXT[] NOT NULL DEFAULT '{}',
    drift_event_ids UUID[] NOT NULL DEFAULT '{}',
    anomaly_ids UUID[] NOT NULL DEFAULT '{}',
    external_intelligence JSONB NOT NULL DEFAULT '{}',
    jev_decision JSONB,
    first_observed TIMESTAMPTZ NOT NULL,
    last_observed TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_investigations_asset_id ON investigations (asset_id);
CREATE INDEX IF NOT EXISTS idx_investigations_status ON investigations (status);

CREATE TABLE IF NOT EXISTS decision_records (
    id UUID PRIMARY KEY,
    session_id UUID,
    asset_id UUID,
    provider TEXT NOT NULL,
    model TEXT NOT NULL,
    risk TEXT NOT NULL,
    anomalous BOOLEAN NOT NULL,
    human_review BOOLEAN NOT NULL,
    priority TEXT NOT NULL,
    confidence REAL NOT NULL,
    reasons TEXT[] NOT NULL DEFAULT '{}',
    provider_info TEXT NOT NULL,
    latency_ms BIGINT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL
);


-- 20260922000003_probe_runs.sql
-- Migration: probe_runs table for active SMTP/TLS verification runs
-- Target: PostgreSQL 18+

CREATE TABLE IF NOT EXISTS probe_runs (
    id              UUID PRIMARY KEY,
    asset_id        UUID NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    target          TEXT NOT NULL,
    protocol        TEXT NOT NULL DEFAULT 'smtp',
    port            SMALLINT NOT NULL,
    trigger         TEXT NOT NULL,
    investigation_id UUID REFERENCES investigations(id) ON DELETE SET NULL,
    started_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    finished_at     TIMESTAMPTZ,
    outcome         TEXT NOT NULL DEFAULT 'internal_error',
    result          JSONB,
    perspective_mismatches JSONB NOT NULL DEFAULT '[]',
    has_mismatch    BOOLEAN NOT NULL DEFAULT false
);

CREATE INDEX IF NOT EXISTS probe_runs_asset_id_idx      ON probe_runs (asset_id, started_at DESC);
CREATE INDEX IF NOT EXISTS probe_runs_investigation_idx  ON probe_runs (investigation_id) WHERE investigation_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS probe_runs_has_mismatch_idx  ON probe_runs (has_mismatch) WHERE has_mismatch = true;
CREATE INDEX IF NOT EXISTS probe_runs_target_idx        ON probe_runs (asset_id, target, started_at DESC);


-- 20260923000001_probe_port.sql
-- Full TCP port range; do not alter the already shipped probe migration.
ALTER TABLE probe_runs ALTER COLUMN port TYPE INTEGER USING (CASE WHEN port < 0 THEN port::integer + 65536 ELSE port::integer END);
ALTER TABLE probe_runs ADD CONSTRAINT probe_port_range CHECK (port BETWEEN 1 AND 65535);
CREATE INDEX idx_probe_target_time ON probe_runs(target, started_at DESC);
CREATE INDEX idx_probe_unfinished ON probe_runs(started_at) WHERE finished_at IS NULL;


-- 20260923000002_training_records.sql
-- Migration: versioned training/diagnostic record snapshots captured at decision time
-- Target: PostgreSQL 18+

CREATE TABLE IF NOT EXISTS training_records (
    id                     UUID PRIMARY KEY,
    investigation_id       UUID NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
    asset_id               UUID NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    feature_schema_version INTEGER NOT NULL,
    captured_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    features               JSONB NOT NULL,
    automated_label        JSONB,
    analyst_label          JSONB,
    labeled_at             TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS training_records_investigation_idx ON training_records (investigation_id, captured_at DESC);
CREATE INDEX IF NOT EXISTS training_records_asset_idx          ON training_records (asset_id, captured_at DESC);
CREATE INDEX IF NOT EXISTS training_records_unlabeled_idx      ON training_records (captured_at DESC) WHERE analyst_label IS NULL;
CREATE INDEX IF NOT EXISTS training_records_schema_version_idx ON training_records (feature_schema_version);

-- 20260923000003_remediation.sql
-- Immutable before-evidence and append-only verification attempts in one canonical domain record.
CREATE TABLE remediations (
    id UUID PRIMARY KEY,
    asset_id UUID NOT NULL REFERENCES assets(id),
    investigation_id UUID REFERENCES investigations(id),
    finding_id UUID NOT NULL REFERENCES findings(id),
    data JSONB NOT NULL
);
CREATE INDEX remediation_asset_idx ON remediations(asset_id);
CREATE INDEX remediation_investigation_idx ON remediations(investigation_id) WHERE investigation_id IS NOT NULL;
CREATE INDEX remediation_verifying_idx ON remediations(id) WHERE data->>'state' = 'verifying';
ALTER TABLE probe_runs ADD COLUMN remediation_id UUID REFERENCES remediations(id);
ALTER TABLE probe_runs ADD COLUMN verification_condition JSONB;
CREATE INDEX probe_remediation_idx ON probe_runs(remediation_id) WHERE remediation_id IS NOT NULL;
ALTER TABLE training_records ADD COLUMN remediation_outcomes JSONB NOT NULL DEFAULT '{}';


-- 20260923000004_posture_and_workflow.sql
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


-- 20260923000005_assessments.sql
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


-- 20260923134728_mailent_cloud_storage.sql
-- Durable analytical evidence for deployments using PostgreSQL without ClickHouse.
CREATE TABLE IF NOT EXISTS mail_sessions (
    session_id UUID PRIMARY KEY,
    src_ip TEXT NOT NULL,
    dst_ip TEXT NOT NULL,
    last_seen TIMESTAMPTZ NOT NULL,
    data JSONB NOT NULL
);
CREATE INDEX IF NOT EXISTS mail_sessions_recent ON mail_sessions (last_seen DESC, session_id);
CREATE INDEX IF NOT EXISTS mail_sessions_src ON mail_sessions (src_ip, last_seen DESC);
CREATE INDEX IF NOT EXISTS mail_sessions_dst ON mail_sessions (dst_ip, last_seen DESC);
CREATE TABLE IF NOT EXISTS mail_observations (
    observation_id UUID PRIMARY KEY,
    observed_at TIMESTAMPTZ NOT NULL,
    data JSONB NOT NULL
);
CREATE INDEX IF NOT EXISTS mail_observations_recent ON mail_observations (observed_at DESC, observation_id);


DO $$ DECLARE item RECORD; BEGIN
    FOR item IN SELECT tablename FROM pg_tables WHERE schemaname = 'mailent' LOOP
        EXECUTE format('ALTER TABLE mailent.%I ENABLE ROW LEVEL SECURITY', item.tablename);
        EXECUTE format('REVOKE ALL ON mailent.%I FROM PUBLIC, anon, authenticated', item.tablename);
    END LOOP;
END $$;
ALTER DEFAULT PRIVILEGES IN SCHEMA mailent REVOKE ALL ON TABLES FROM PUBLIC, anon, authenticated;
RESET search_path;
