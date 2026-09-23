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
