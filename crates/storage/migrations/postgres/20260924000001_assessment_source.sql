-- Migration: Add generalized source column to assessments
ALTER TABLE assessments ADD COLUMN IF NOT EXISTS source JSONB;

-- Backfill legacy records to AssessmentSource::Capture
UPDATE assessments
SET source = jsonb_build_object(
    'type', 'capture',
    'capture_name', capture_name,
    'capture_hash', capture_hash,
    'capture_size_bytes', capture_size_bytes,
    'time_range_start', time_range_start,
    'time_range_end', time_range_end
)
WHERE source IS NULL;
