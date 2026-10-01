ALTER TABLE scan_jobs ADD COLUMN content_sha256 BLOB
    CHECK (content_sha256 IS NULL OR length(content_sha256) = 32);
ALTER TABLE scan_jobs ADD COLUMN detected_type TEXT;
ALTER TABLE scan_jobs ADD COLUMN verdict_reason TEXT;
ALTER TABLE scan_jobs ADD COLUMN scanned_at TEXT;
ALTER TABLE scan_jobs ADD COLUMN retain_until TEXT;

PRAGMA user_version = 5;
