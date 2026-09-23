-- Migration: Add organizations and devices for multi-tenancy and CLI connectivity

-- 1. Organizations table
CREATE TABLE IF NOT EXISTS organizations (
    id UUID PRIMARY KEY,
    name TEXT NOT NULL,
    slug TEXT NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Seed default organization "Acme Inc"
INSERT INTO organizations (id, name, slug, created_at)
VALUES ('00000000-0000-0000-0000-000000000001', 'Acme Inc', 'acme-inc', NOW())
ON CONFLICT (id) DO NOTHING;

-- 2. Organization members table
CREATE TABLE IF NOT EXISTS organization_members (
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'member',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (organization_id, user_id)
);

CREATE INDEX IF NOT EXISTS idx_org_members_user ON organization_members(user_id);

-- 3. Devices table
CREATE TABLE IF NOT EXISTS devices (
    id UUID PRIMARY KEY,
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    registered_by_user_id TEXT,
    name TEXT NOT NULL,
    hostname TEXT NOT NULL,
    platform TEXT NOT NULL,
    architecture TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_at TIMESTAMPTZ,
    capabilities TEXT[] NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_devices_org_id ON devices (organization_id);

-- 4. Device tokens table (SHA-256 hashed tokens)
CREATE TABLE IF NOT EXISTS device_tokens (
    token_hash VARCHAR(64) PRIMARY KEY,
    device_id UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_device_tokens_device_id ON device_tokens (device_id);

-- 5. Device authorization challenges table
CREATE TABLE IF NOT EXISTS device_challenges (
    code VARCHAR(32) PRIMARY KEY,
    device_name TEXT NOT NULL,
    hostname TEXT NOT NULL,
    platform TEXT NOT NULL,
    architecture TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    authorized_at TIMESTAMPTZ,
    authorized_by_user_id TEXT,
    organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    issued_token TEXT,
    device_id UUID REFERENCES devices(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_device_challenges_expires ON device_challenges (expires_at);

-- 6. Add organization_id column to workspace records & backfill to default organization
ALTER TABLE assessments ADD COLUMN IF NOT EXISTS organization_id UUID REFERENCES organizations(id);
UPDATE assessments SET organization_id = '00000000-0000-0000-0000-000000000001' WHERE organization_id IS NULL;
CREATE INDEX IF NOT EXISTS idx_assessments_org_id ON assessments (organization_id);

ALTER TABLE assets ADD COLUMN IF NOT EXISTS organization_id UUID REFERENCES organizations(id);
UPDATE assets SET organization_id = '00000000-0000-0000-0000-000000000001' WHERE organization_id IS NULL;
CREATE INDEX IF NOT EXISTS idx_assets_org_id ON assets (organization_id);

ALTER TABLE findings ADD COLUMN IF NOT EXISTS organization_id UUID REFERENCES organizations(id);
UPDATE findings SET organization_id = '00000000-0000-0000-0000-000000000001' WHERE organization_id IS NULL;
CREATE INDEX IF NOT EXISTS idx_findings_org_id ON findings (organization_id);

ALTER TABLE investigations ADD COLUMN IF NOT EXISTS organization_id UUID REFERENCES organizations(id);
UPDATE investigations SET organization_id = '00000000-0000-0000-0000-000000000001' WHERE organization_id IS NULL;
CREATE INDEX IF NOT EXISTS idx_investigations_org_id ON investigations (organization_id);

ALTER TABLE remediations ADD COLUMN IF NOT EXISTS organization_id UUID REFERENCES organizations(id);
UPDATE remediations SET organization_id = '00000000-0000-0000-0000-000000000001' WHERE organization_id IS NULL;

ALTER TABLE probe_runs ADD COLUMN IF NOT EXISTS organization_id UUID REFERENCES organizations(id);
UPDATE probe_runs SET organization_id = '00000000-0000-0000-0000-000000000001' WHERE organization_id IS NULL;

ALTER TABLE anomaly_signals ADD COLUMN IF NOT EXISTS organization_id UUID REFERENCES organizations(id);
UPDATE anomaly_signals SET organization_id = '00000000-0000-0000-0000-000000000001' WHERE organization_id IS NULL;

ALTER TABLE drift_events ADD COLUMN IF NOT EXISTS organization_id UUID REFERENCES organizations(id);
UPDATE drift_events SET organization_id = '00000000-0000-0000-0000-000000000001' WHERE organization_id IS NULL;

ALTER TABLE archived_reports ADD COLUMN IF NOT EXISTS organization_id UUID REFERENCES organizations(id);
UPDATE archived_reports SET organization_id = '00000000-0000-0000-0000-000000000001' WHERE organization_id IS NULL;
