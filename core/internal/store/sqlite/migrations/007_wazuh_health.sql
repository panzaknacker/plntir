CREATE TABLE wazuh_health_projection (
    source TEXT PRIMARY KEY CHECK (source = 'plntir-siem-01'),
    schema_version INTEGER NOT NULL CHECK (schema_version = 1),
    state TEXT NOT NULL CHECK (state = 'available'),
    observed_at TEXT NOT NULL,
    last_event_at TEXT NOT NULL,
    last_sequence INTEGER NOT NULL CHECK (last_sequence > 0),
    chain_hash TEXT NOT NULL CHECK (length(chain_hash) = 43),
    agent_id TEXT,
    rule_level INTEGER NOT NULL CHECK (rule_level BETWEEN 0 AND 16),
    severity TEXT NOT NULL CHECK (severity IN ('info', 'low', 'medium', 'high', 'critical')),
    envelope_deduplication_id TEXT NOT NULL UNIQUE,
    received_at TEXT NOT NULL
) STRICT;

CREATE TRIGGER wazuh_health_sequence_monotonic
BEFORE UPDATE OF last_sequence ON wazuh_health_projection
WHEN NEW.last_sequence <= OLD.last_sequence
BEGIN
    SELECT RAISE(ABORT, 'Wazuh health sequence must increase');
END;

PRAGMA user_version = 7;
