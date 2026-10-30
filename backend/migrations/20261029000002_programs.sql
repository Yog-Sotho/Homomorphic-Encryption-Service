-- Jobs that run a program of several steps (operation = 'program') keep it
-- here as JSON, as submitted and checked.
ALTER TABLE jobs ADD COLUMN program TEXT;
