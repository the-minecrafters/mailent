-- Full TCP port range; do not alter the already shipped probe migration.
ALTER TABLE probe_runs ALTER COLUMN port TYPE INTEGER USING (CASE WHEN port < 0 THEN port::integer + 65536 ELSE port::integer END);
ALTER TABLE probe_runs ADD CONSTRAINT probe_port_range CHECK (port BETWEEN 1 AND 65535);
CREATE INDEX idx_probe_target_time ON probe_runs(target, started_at DESC);
CREATE INDEX idx_probe_unfinished ON probe_runs(started_at) WHERE finished_at IS NULL;
