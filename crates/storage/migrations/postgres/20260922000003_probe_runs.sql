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
