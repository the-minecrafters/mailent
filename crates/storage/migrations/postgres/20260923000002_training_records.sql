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