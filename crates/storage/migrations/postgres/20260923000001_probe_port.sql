-- Full TCP port range; do not alter the already shipped probe migration.
ALTER TABLE probe_runs ALTER COLUMN port TYPE INTEGER USING (CASE WHEN port < 0 THEN port::integer + 65536 ELSE port::integer END);
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'probe_port_range'
    ) THEN
        ALTER TABLE probe_runs ADD CONSTRAINT probe_port_range CHECK (port BETWEEN 1 AND 65535);
    END IF;
END $$;
CREATE INDEX IF NOT EXISTS idx_probe_target_time ON probe_runs(target, started_at DESC);
CREATE INDEX IF NOT EXISTS idx_probe_unfinished ON probe_runs(started_at) WHERE finished_at IS NULL;
