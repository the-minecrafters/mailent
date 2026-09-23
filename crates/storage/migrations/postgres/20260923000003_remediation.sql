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
