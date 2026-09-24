-- Widen posture_grade to avoid character varying length restrictions
ALTER TABLE assessments ALTER COLUMN posture_grade TYPE VARCHAR(32);
