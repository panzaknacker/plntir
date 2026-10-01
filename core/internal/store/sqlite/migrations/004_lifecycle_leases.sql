ALTER TABLE outbox ADD COLUMN available_at TEXT;
ALTER TABLE outbox ADD COLUMN lease_owner TEXT;
ALTER TABLE outbox ADD COLUMN lease_expires_at TEXT;

ALTER TABLE wipe_jobs ADD COLUMN mdm_command_id TEXT;

ALTER TABLE files ADD COLUMN deletion_prior_state TEXT
    CHECK (deletion_prior_state IS NULL OR deletion_prior_state IN ('active', 'trashed'));

PRAGMA user_version = 4;
