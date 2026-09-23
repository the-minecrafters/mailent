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
