-- ClickHouse analytical storage schema for high-volume observation/session telemetry

CREATE DATABASE IF NOT EXISTS mailent;

CREATE TABLE IF NOT EXISTS mailent.normalized_observations (
    observation_id UUID,
    timestamp DateTime64(6, 'UTC'),
    sensor_id LowCardinality(String),
    source LowCardinality(String),
    parser LowCardinality(String),
    parser_version LowCardinality(String),
    src_ip String,
    src_port UInt16,
    dst_ip String,
    dst_port UInt16,
    protocol LowCardinality(String),
    starttls_state LowCardinality(Nullable(String)),
    tls_version LowCardinality(Nullable(String)),
    cipher_suite_id Nullable(UInt16),
    cipher_suite_name Nullable(String),
    key_exchange LowCardinality(Nullable(String)),
    cert_fingerprint Nullable(String),
    capture_sha256 Nullable(String),
    connection_uid Nullable(String),
    raw_json String
) ENGINE = ReplacingMergeTree()
ORDER BY (protocol, timestamp, observation_id);

CREATE TABLE IF NOT EXISTS mailent.email_sessions (
    session_id UUID,
    sensor_id LowCardinality(String),
    src_ip String,
    src_port UInt16,
    dst_ip String,
    dst_port UInt16,
    protocol LowCardinality(String),
    starttls_state LowCardinality(Nullable(String)),
    tls_version LowCardinality(Nullable(String)),
    cipher_suite_id Nullable(UInt16),
    cipher_suite_name Nullable(String),
    key_exchange LowCardinality(Nullable(String)),
    cert_fingerprint Nullable(String),
    capture_sha256 Nullable(String),
    connection_uid Nullable(String),
    first_seen DateTime64(6, 'UTC'),
    last_seen DateTime64(6, 'UTC'),
    raw_json String
) ENGINE = ReplacingMergeTree(last_seen)
ORDER BY (protocol, first_seen, session_id);

CREATE TABLE IF NOT EXISTS mailent.timeline_events (
    session_id UUID,
    timestamp DateTime64(6, 'UTC'),
    kind LowCardinality(String),
    source String,
    event_order UInt32
) ENGINE = ReplacingMergeTree()
ORDER BY (session_id, event_order, timestamp);

CREATE TABLE IF NOT EXISTS mailent.certificate_history (
    fingerprint String,
    subject String,
    issuer String,
    sans Array(String),
    not_before DateTime64(3, 'UTC'),
    not_after DateTime64(3, 'UTC'),
    observed_at DateTime64(6, 'UTC'),
    asset_ip String,
    session_id UUID
) ENGINE = MergeTree()
ORDER BY (fingerprint, observed_at, session_id);

CREATE TABLE IF NOT EXISTS mailent.finding_events (
    finding_id UUID,
    rule_id LowCardinality(String),
    severity LowCardinality(String),
    session_id UUID,
    observed_at DateTime64(6, 'UTC')
) ENGINE = MergeTree()
ORDER BY (rule_id, observed_at, finding_id);
