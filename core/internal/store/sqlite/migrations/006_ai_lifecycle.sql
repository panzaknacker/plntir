ALTER TABLE ai_records ADD COLUMN client_deduplication_id TEXT;
ALTER TABLE ai_records ADD COLUMN capture_id TEXT;
ALTER TABLE ai_records ADD COLUMN segment_index INTEGER
    CHECK (segment_index IS NULL OR segment_index >= 0);
ALTER TABLE ai_records ADD COLUMN final_segment INTEGER
    CHECK (final_segment IS NULL OR final_segment IN (0, 1));
ALTER TABLE ai_records ADD COLUMN previous_segment_sha256 BLOB
    CHECK (previous_segment_sha256 IS NULL OR length(previous_segment_sha256) = 32);
ALTER TABLE ai_records ADD COLUMN capture_version INTEGER NOT NULL DEFAULT 1
    CHECK (capture_version = 1);
ALTER TABLE ai_records ADD COLUMN analysis_state TEXT NOT NULL DEFAULT 'queued'
    CHECK (analysis_state IN ('queued', 'analyzing', 'complete', 'purged'));
ALTER TABLE ai_records ADD COLUMN ingested_at TEXT;
ALTER TABLE ai_records ADD COLUMN analyzed_at TEXT;
ALTER TABLE ai_records ADD COLUMN purge_queued_at TEXT;
ALTER TABLE ai_records ADD COLUMN history_retain_until TEXT;
ALTER TABLE ai_records ADD COLUMN analysis_result_sha256 BLOB
    CHECK (analysis_result_sha256 IS NULL OR length(analysis_result_sha256) = 32);

CREATE UNIQUE INDEX ai_records_client_dedupe_idx
ON ai_records(client_deduplication_id)
WHERE client_deduplication_id IS NOT NULL;

CREATE UNIQUE INDEX ai_records_capture_segment_idx
ON ai_records(device_id, capture_id, segment_index)
WHERE capture_id IS NOT NULL AND segment_index IS NOT NULL;

CREATE INDEX ai_records_raw_purge_idx
ON ai_records(wraps_destroyed_at, purge_after);

CREATE INDEX ai_records_history_purge_idx
ON ai_records(history_retain_until);

CREATE TABLE ai_action_holds (
    id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE RESTRICT,
    device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE RESTRICT,
    record_id TEXT NOT NULL REFERENCES ai_records(id) ON DELETE RESTRICT,
    finding_id TEXT NOT NULL UNIQUE REFERENCES ai_findings(id) ON DELETE RESTRICT,
    state TEXT NOT NULL CHECK (state IN ('pending', 'confirmed')),
    created_at TEXT NOT NULL,
    confirmed_at TEXT,
    confirmed_by TEXT
) STRICT;

CREATE INDEX ai_action_holds_pending_idx
ON ai_action_holds(account_id, device_id, state, created_at);

PRAGMA user_version = 6;
