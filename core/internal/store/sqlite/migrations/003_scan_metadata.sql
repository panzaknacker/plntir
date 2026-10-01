ALTER TABLE file_versions ADD COLUMN manifest_sha256 BLOB
    CHECK (manifest_sha256 IS NULL OR length(manifest_sha256) = 32);

ALTER TABLE file_versions ADD COLUMN nonce_prefix BLOB
    CHECK (nonce_prefix IS NULL OR length(nonce_prefix) = 4);

PRAGMA user_version = 3;
