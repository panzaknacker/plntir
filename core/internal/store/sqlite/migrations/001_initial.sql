PRAGMA foreign_keys = ON;

CREATE TABLE accounts (
    id TEXT PRIMARY KEY,
    username_display TEXT NOT NULL,
    username_canonical TEXT NOT NULL UNIQUE,
    state TEXT NOT NULL CHECK (state IN ('active', 'deletion_pending', 'tombstoned')),
    version INTEGER NOT NULL CHECK (version >= 1),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    deletion_requested_at TEXT,
    purge_after TEXT
) STRICT;

CREATE TABLE reserved_usernames (
    username_canonical TEXT PRIMARY KEY,
    username_display TEXT NOT NULL,
    owner_account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE RESTRICT,
    reserved_at TEXT NOT NULL
) STRICT;

CREATE TRIGGER reserved_username_owner_immutable
BEFORE UPDATE OF owner_account_id ON reserved_usernames
BEGIN
    SELECT RAISE(ABORT, 'reserved username ownership is immutable');
END;

CREATE TRIGGER account_limit
BEFORE INSERT ON accounts
WHEN (SELECT count(*) FROM accounts WHERE state != 'tombstoned') >= 10
BEGIN
    SELECT RAISE(ABORT, 'account limit reached');
END;

CREATE TABLE devices (
    id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE RESTRICT,
    display_name TEXT NOT NULL,
    platform TEXT NOT NULL CHECK (platform IN ('macos', 'ios', 'linux')),
    serial_number TEXT NOT NULL,
    serial_fingerprint BLOB NOT NULL UNIQUE CHECK (length(serial_fingerprint) = 32),
    warp_device_id TEXT UNIQUE,
    management_state TEXT NOT NULL CHECK (management_state IN ('verified', 'partial', 'unavailable')),
    enrollment_type TEXT,
    posture_state TEXT NOT NULL CHECK (posture_state IN ('passing', 'degraded', 'failing', 'unknown')),
    wipe_state TEXT NOT NULL CHECK (wipe_state IN ('verified', 'unverified', 'unavailable')),
    reassignment_blocked INTEGER NOT NULL DEFAULT 0 CHECK (reassignment_blocked IN (0, 1)),
    state TEXT NOT NULL CHECK (state IN ('pending', 'active', 'suspended', 'retired')),
    version INTEGER NOT NULL CHECK (version >= 1),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
) STRICT;

CREATE TRIGGER device_limit
BEFORE INSERT ON devices
WHEN (SELECT count(*) FROM devices WHERE state != 'retired') >= 25
BEGIN
    SELECT RAISE(ABORT, 'device limit reached');
END;

CREATE TABLE passkeys (
    id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE RESTRICT,
    device_id TEXT REFERENCES devices(id) ON DELETE RESTRICT,
    credential_id BLOB NOT NULL UNIQUE,
    public_key BLOB NOT NULL,
    sign_count INTEGER NOT NULL DEFAULT 0 CHECK (sign_count >= 0),
    transports_json TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(transports_json)),
    backup_eligible INTEGER NOT NULL DEFAULT 0 CHECK (backup_eligible IN (0, 1)),
    backup_state INTEGER NOT NULL DEFAULT 0 CHECK (backup_state IN (0, 1)),
    created_at TEXT NOT NULL,
    last_used_at TEXT,
    revoked_at TEXT
) STRICT;

CREATE TABLE sessions (
    token_hash BLOB PRIMARY KEY CHECK (length(token_hash) = 32),
    account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE RESTRICT,
    device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE RESTRICT,
    warp_identity_hash BLOB NOT NULL CHECK (length(warp_identity_hash) = 32),
    user_agent_hash BLOB NOT NULL CHECK (length(user_agent_hash) = 32),
    csrf_hash BLOB NOT NULL CHECK (length(csrf_hash) = 32),
    created_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    idle_expires_at TEXT NOT NULL,
    absolute_expires_at TEXT NOT NULL,
    step_up_expires_at TEXT,
    revoked_at TEXT
) STRICT;

CREATE INDEX sessions_account_idx ON sessions(account_id, revoked_at, absolute_expires_at);

CREATE TABLE lockouts (
    scope TEXT NOT NULL CHECK (scope IN ('identity', 'device', 'ip')),
    subject_hash BLOB NOT NULL CHECK (length(subject_hash) = 32),
    reason TEXT NOT NULL,
    failure_count INTEGER NOT NULL CHECK (failure_count >= 1),
    first_failure_at TEXT NOT NULL,
    blocked_until TEXT NOT NULL,
    PRIMARY KEY (scope, subject_hash)
) STRICT;

CREATE TABLE auth_challenges (
    id TEXT PRIMARY KEY,
    kind TEXT NOT NULL CHECK (kind IN ('registration', 'login', 'step_up', 'recovery')),
    account_id TEXT REFERENCES accounts(id) ON DELETE RESTRICT,
    device_id TEXT REFERENCES devices(id) ON DELETE RESTRICT,
    challenge_hash BLOB NOT NULL UNIQUE CHECK (length(challenge_hash) = 32),
    state_json TEXT NOT NULL CHECK (json_valid(state_json)),
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    consumed_at TEXT
) STRICT;

CREATE TABLE enrollment_invites (
    id TEXT PRIMARY KEY,
    account_id TEXT REFERENCES accounts(id) ON DELETE RESTRICT,
    token_hash BLOB NOT NULL UNIQUE CHECK (length(token_hash) = 32),
    warp_service_token_id TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    consumed_at TEXT,
    revoked_at TEXT,
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL
) STRICT;

CREATE TABLE contact_invites (
    id TEXT PRIMARY KEY,
    issuer_account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE RESTRICT,
    token_hash BLOB NOT NULL UNIQUE CHECK (length(token_hash) = 32),
    expires_at TEXT NOT NULL,
    consumed_by_account_id TEXT REFERENCES accounts(id) ON DELETE RESTRICT,
    consumed_at TEXT,
    revoked_at TEXT,
    created_at TEXT NOT NULL
) STRICT;

CREATE TABLE contacts (
    id TEXT PRIMARY KEY,
    account_low_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE RESTRICT,
    account_high_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE RESTRICT,
    low_confirmed_at TEXT,
    high_confirmed_at TEXT,
    state TEXT NOT NULL CHECK (state IN ('pending', 'active', 'removed')),
    version INTEGER NOT NULL CHECK (version >= 1),
    created_at TEXT NOT NULL,
    removed_at TEXT,
    CHECK (account_low_id < account_high_id),
    UNIQUE (account_low_id, account_high_id)
) STRICT;

CREATE TABLE files (
    id TEXT PRIMARY KEY,
    owner_account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE RESTRICT,
    filename TEXT NOT NULL,
    media_kind TEXT NOT NULL CHECK (media_kind IN ('standard', 'image', 'video')),
    logical_size_bytes INTEGER NOT NULL CHECK (logical_size_bytes >= 0),
    state TEXT NOT NULL CHECK (state IN ('uploading', 'active', 'trashed', 'deletion_pending', 'purged')),
    version INTEGER NOT NULL CHECK (version >= 1),
    current_version_id TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    trashed_at TEXT,
    purge_after TEXT
) STRICT;

CREATE INDEX files_owner_state_idx ON files(owner_account_id, state, updated_at);

CREATE TABLE file_versions (
    id TEXT PRIMARY KEY,
    file_id TEXT NOT NULL REFERENCES files(id) ON DELETE RESTRICT,
    version_number INTEGER NOT NULL CHECK (version_number >= 1),
    object_key TEXT NOT NULL UNIQUE,
    ciphertext_size_bytes INTEGER NOT NULL CHECK (ciphertext_size_bytes >= 0),
    plaintext_size_bytes INTEGER NOT NULL CHECK (plaintext_size_bytes >= 0),
    chunk_size_bytes INTEGER NOT NULL CHECK (chunk_size_bytes > 0),
    plaintext_sha256 BLOB CHECK (plaintext_sha256 IS NULL OR length(plaintext_sha256) = 32),
    ciphertext_sha256 BLOB CHECK (ciphertext_sha256 IS NULL OR length(ciphertext_sha256) = 32),
    scan_state TEXT NOT NULL CHECK (scan_state IN ('pending_upload', 'queued', 'scanning', 'clean', 'malware', 'unscannable', 'failed')),
    scan_version INTEGER NOT NULL DEFAULT 0 CHECK (scan_version >= 0),
    immutable_until TEXT NOT NULL,
    created_at TEXT NOT NULL,
    completed_at TEXT,
    UNIQUE (file_id, version_number)
) STRICT;

CREATE TRIGGER file_version_object_key_immutable
BEFORE UPDATE OF object_key ON file_versions
BEGIN
    SELECT RAISE(ABORT, 'object keys are immutable');
END;

CREATE TABLE key_envelopes (
    file_version_id TEXT NOT NULL REFERENCES file_versions(id) ON DELETE RESTRICT,
    provider TEXT NOT NULL CHECK (provider IN ('aws-kms', 'offline-recovery')),
    algorithm TEXT NOT NULL,
    key_reference TEXT NOT NULL,
    ciphertext BLOB NOT NULL,
    created_at TEXT NOT NULL,
    destroyed_at TEXT,
    PRIMARY KEY (file_version_id, provider)
) STRICT;

CREATE TABLE quota_reservations (
    id TEXT PRIMARY KEY,
    owner_account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE RESTRICT,
    file_id TEXT NOT NULL REFERENCES files(id) ON DELETE RESTRICT,
    bytes INTEGER NOT NULL CHECK (bytes > 0),
    state TEXT NOT NULL CHECK (state IN ('active', 'committed', 'released', 'expired')),
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    released_at TEXT,
    UNIQUE (file_id)
) STRICT;

CREATE INDEX quota_active_idx ON quota_reservations(state, expires_at);

CREATE TABLE upload_sessions (
    id TEXT PRIMARY KEY,
    file_version_id TEXT NOT NULL REFERENCES file_versions(id) ON DELETE RESTRICT,
    r2_upload_id TEXT,
    expected_parts INTEGER NOT NULL CHECK (expected_parts >= 1),
    part_size_bytes INTEGER NOT NULL CHECK (part_size_bytes > 0),
    next_part INTEGER NOT NULL DEFAULT 1 CHECK (next_part >= 1),
    state TEXT NOT NULL CHECK (state IN ('starting', 'uploading', 'completing', 'complete', 'aborted', 'expired')),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    UNIQUE (file_version_id)
) STRICT;

CREATE TABLE upload_parts (
    upload_session_id TEXT NOT NULL REFERENCES upload_sessions(id) ON DELETE RESTRICT,
    part_number INTEGER NOT NULL CHECK (part_number BETWEEN 1 AND 10000),
    size_bytes INTEGER NOT NULL CHECK (size_bytes > 0),
    ciphertext_sha256 BLOB NOT NULL CHECK (length(ciphertext_sha256) = 32),
    etag TEXT,
    confirmed_at TEXT,
    PRIMARY KEY (upload_session_id, part_number)
) STRICT;

CREATE TABLE shares (
    id TEXT PRIMARY KEY,
    file_id TEXT NOT NULL REFERENCES files(id) ON DELETE RESTRICT,
    owner_account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE RESTRICT,
    recipient_account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE RESTRICT,
    contact_id TEXT NOT NULL REFERENCES contacts(id) ON DELETE RESTRICT,
    state TEXT NOT NULL CHECK (state IN ('active', 'revoked')),
    version INTEGER NOT NULL CHECK (version >= 1),
    created_at TEXT NOT NULL,
    revoked_at TEXT,
    CHECK (owner_account_id != recipient_account_id),
    UNIQUE (file_id, recipient_account_id)
) STRICT;

CREATE INDEX shares_recipient_state_idx ON shares(recipient_account_id, state);

CREATE TABLE scan_jobs (
    id TEXT PRIMARY KEY,
    deduplication_id TEXT NOT NULL UNIQUE,
    file_version_id TEXT NOT NULL REFERENCES file_versions(id) ON DELETE RESTRICT,
    object_key TEXT NOT NULL,
    expected_size_bytes INTEGER NOT NULL CHECK (expected_size_bytes >= 0),
    expected_etag TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('queued', 'leased', 'clean', 'malware', 'unscannable', 'failed')),
    attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    lease_owner TEXT,
    lease_expires_at TEXT,
    engine_version TEXT,
    rules_version TEXT,
    verdict_sha256 BLOB CHECK (verdict_sha256 IS NULL OR length(verdict_sha256) = 32),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    completed_at TEXT
) STRICT;

CREATE TABLE durable_jobs (
    id TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    deduplication_id TEXT NOT NULL UNIQUE,
    payload_json TEXT NOT NULL CHECK (json_valid(payload_json)),
    state TEXT NOT NULL CHECK (state IN ('ready', 'leased', 'succeeded', 'failed', 'cancelled')),
    available_at TEXT NOT NULL,
    lease_owner TEXT,
    lease_expires_at TEXT,
    heartbeat_at TEXT,
    attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    last_error TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
) STRICT;

CREATE INDEX durable_jobs_poll_idx ON durable_jobs(state, available_at, lease_expires_at);

CREATE TABLE outbox (
    id TEXT PRIMARY KEY,
    topic TEXT NOT NULL,
    deduplication_id TEXT NOT NULL UNIQUE,
    payload_json TEXT NOT NULL CHECK (json_valid(payload_json)),
    created_at TEXT NOT NULL,
    published_at TEXT,
    attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    last_error TEXT
) STRICT;

CREATE INDEX outbox_unpublished_idx ON outbox(published_at, created_at);

CREATE TABLE service_projections (
    id TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    state TEXT NOT NULL,
    source TEXT NOT NULL,
    source_sequence INTEGER NOT NULL CHECK (source_sequence >= 0),
    payload_json TEXT NOT NULL CHECK (json_valid(payload_json)),
    observed_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
) STRICT;

CREATE TABLE device_projections (
    device_id TEXT PRIMARY KEY REFERENCES devices(id) ON DELETE RESTRICT,
    source_sequence INTEGER NOT NULL CHECK (source_sequence >= 0),
    status_json TEXT NOT NULL CHECK (json_valid(status_json)),
    observed_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
) STRICT;

CREATE TABLE incidents (
    id TEXT PRIMARY KEY,
    device_id TEXT REFERENCES devices(id) ON DELETE RESTRICT,
    kind TEXT NOT NULL,
    severity TEXT NOT NULL CHECK (severity IN ('info', 'low', 'medium', 'high', 'critical')),
    state TEXT NOT NULL CHECK (state IN ('open', 'acknowledged', 'resolved')),
    summary TEXT NOT NULL,
    source TEXT NOT NULL,
    source_event_id TEXT NOT NULL,
    occurred_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE (source, source_event_id)
) STRICT;

CREATE TABLE wipe_jobs (
    id TEXT PRIMARY KEY,
    device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE RESTRICT,
    requested_by TEXT NOT NULL,
    typed_device_id TEXT NOT NULL,
    typed_serial_number TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('pending_local', 'handed_to_mdm', 'acknowledged', 'executed', 'cancelled', 'failed')),
    requested_at TEXT NOT NULL,
    handed_to_mdm_at TEXT,
    completed_at TEXT,
    last_error TEXT
) STRICT;

CREATE UNIQUE INDEX one_live_wipe_per_device
ON wipe_jobs(device_id)
WHERE state IN ('pending_local', 'handed_to_mdm', 'acknowledged');

CREATE TABLE ai_records (
    id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE RESTRICT,
    device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE RESTRICT,
    source TEXT NOT NULL CHECK (source IN ('codex-cli', 'claude-code-cli', 'safari', 'chatgpt-native', 'claude-native', 'cowork-native')),
    coverage TEXT NOT NULL CHECK (coverage IN ('full', 'partial', 'content-unavailable')),
    ciphertext_object_key TEXT NOT NULL UNIQUE,
    kms_envelope BLOB NOT NULL,
    offline_envelope BLOB NOT NULL,
    content_sha256 BLOB NOT NULL CHECK (length(content_sha256) = 32),
    occurred_at TEXT NOT NULL,
    purge_after TEXT NOT NULL,
    wraps_destroyed_at TEXT
) STRICT;

CREATE TABLE ai_findings (
    id TEXT PRIMARY KEY,
    record_id TEXT NOT NULL REFERENCES ai_records(id) ON DELETE RESTRICT,
    kind TEXT NOT NULL,
    severity TEXT NOT NULL CHECK (severity IN ('info', 'low', 'medium', 'high', 'critical')),
    classifier_version TEXT NOT NULL,
    rules_version TEXT NOT NULL,
    finding_hash BLOB NOT NULL CHECK (length(finding_hash) = 32),
    summary TEXT NOT NULL,
    created_at TEXT NOT NULL,
    retain_until TEXT NOT NULL
) STRICT;

CREATE TABLE idempotency_records (
    principal_id TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    method TEXT NOT NULL,
    path TEXT NOT NULL,
    request_hash BLOB NOT NULL CHECK (length(request_hash) = 32),
    response_status INTEGER NOT NULL CHECK (response_status BETWEEN 100 AND 599),
    response_headers_json TEXT NOT NULL CHECK (json_valid(response_headers_json)),
    response_body BLOB NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    PRIMARY KEY (principal_id, idempotency_key)
) STRICT;

CREATE TABLE audit_log (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    id TEXT NOT NULL UNIQUE,
    occurred_at TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    action TEXT NOT NULL,
    target_id TEXT NOT NULL,
    success INTEGER NOT NULL CHECK (success IN (0, 1)),
    details_json TEXT NOT NULL CHECK (json_valid(details_json)),
    previous_hash BLOB NOT NULL CHECK (length(previous_hash) = 32),
    entry_hash BLOB NOT NULL UNIQUE CHECK (length(entry_hash) = 32)
) STRICT;

CREATE TABLE hash_anchors (
    anchor_date TEXT PRIMARY KEY,
    last_sequence INTEGER NOT NULL REFERENCES audit_log(sequence) ON DELETE RESTRICT,
    chain_hash BLOB NOT NULL CHECK (length(chain_hash) = 32),
    cloudflare_object_key TEXT,
    anchored_at TEXT
) STRICT;

CREATE TABLE schema_migrations (
    version INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    sha256 BLOB NOT NULL CHECK (length(sha256) = 32),
    applied_at TEXT NOT NULL
) STRICT;

PRAGMA user_version = 1;
