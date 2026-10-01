CREATE TABLE ingested_envelopes (
    source TEXT NOT NULL,
    sequence INTEGER NOT NULL CHECK (sequence > 0),
    deduplication_id TEXT NOT NULL UNIQUE,
    kind TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    payload_sha256 BLOB NOT NULL CHECK (length(payload_sha256) = 32),
    received_at TEXT NOT NULL,
    PRIMARY KEY (source, sequence)
) STRICT;

CREATE INDEX ingested_envelopes_received_idx ON ingested_envelopes(received_at);

PRAGMA user_version = 2;
