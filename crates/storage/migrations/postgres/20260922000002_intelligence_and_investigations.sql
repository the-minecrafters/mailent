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
