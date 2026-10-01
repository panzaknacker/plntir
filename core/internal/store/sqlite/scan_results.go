package sqlite

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"time"

	"plntir/core/internal/envelope"
	"plntir/core/internal/scanresult"
)

const scanFindingRetention = 180 * 24 * time.Hour

func (s *Store) IngestSignedScanResult(ctx context.Context, value envelope.Envelope, scannerVerifyKey ed25519.PublicKey, now time.Time) (bool, error) {
	now = normalizedTime(now)
	payload, err := scanresult.Verify(value, scannerVerifyKey, now)
	if err != nil {
		return false, err
	}
	payloadHash := scanresult.PayloadSHA256(value)
	verdictHash := scanresult.VerdictSHA256(value)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()

	var source, kind, timestamp string
	var sequence uint64
	var storedHash []byte
	err = tx.QueryRowContext(ctx, `SELECT source, sequence, kind, timestamp, payload_sha256
		FROM ingested_envelopes WHERE deduplication_id = ?`, value.DeduplicationID).
		Scan(&source, &sequence, &kind, &timestamp, &storedHash)
	if err == nil {
		if source == value.Source && sequence == value.Sequence && kind == value.Kind && timestamp == value.Timestamp &&
			len(storedHash) == sha256.Size && string(storedHash) == string(payloadHash[:]) {
			if err := tx.Commit(); err != nil {
				return false, err
			}
			return true, nil
		}
		return false, ErrVersionConflict
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return false, err
	}
	var lastSequence uint64
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE(max(sequence), 0) FROM ingested_envelopes WHERE source = ?`, value.Source).Scan(&lastSequence); err != nil {
		return false, err
	}
	if value.Sequence <= lastSequence {
		return false, ErrVersionConflict
	}

	var storedVersionID, storedObjectKey, state string
	var plaintextHash []byte
	err = tx.QueryRowContext(ctx, `SELECT sj.file_version_id, sj.object_key, sj.state, fv.plaintext_sha256
		FROM scan_jobs sj JOIN file_versions fv ON fv.id = sj.file_version_id WHERE sj.id = ?`, payload.ScanJobID).
		Scan(&storedVersionID, &storedObjectKey, &state, &plaintextHash)
	if errors.Is(err, sql.ErrNoRows) {
		return false, ErrResourceNotFound
	}
	if err != nil {
		return false, err
	}
	if storedVersionID != payload.FileVersionID || storedObjectKey != payload.ObjectKey {
		return false, ErrResourceNotFound
	}
	if state != "queued" && state != "leased" {
		return false, ErrInvalidState
	}
	var contentHash []byte
	if payload.ContentSHA256 != "" {
		contentHash, _ = hex.DecodeString(payload.ContentSHA256)
		if len(plaintextHash) != sha256.Size || string(contentHash) != string(plaintextHash) {
			return false, errors.New("scanner content hash does not match completed upload")
		}
	}
	stamp := now.Format(time.RFC3339Nano)
	retainUntil := now.Add(scanFindingRetention).Format(time.RFC3339Nano)
	result, err := tx.ExecContext(ctx, `UPDATE scan_jobs SET state = ?, engine_version = ?, rules_version = ?,
		verdict_sha256 = ?, content_sha256 = ?, detected_type = NULLIF(?, ''), verdict_reason = NULLIF(?, ''),
		scanned_at = ?, retain_until = ?, updated_at = ?, completed_at = ?, lease_owner = NULL, lease_expires_at = NULL
		WHERE id = ? AND state IN ('queued', 'leased')`, payload.Verdict, payload.EngineVersion,
		payload.RuleVersion, verdictHash[:], contentHash, payload.DetectedType, payload.Reason,
		payload.ScannedAt, retainUntil, stamp, stamp, payload.ScanJobID)
	if err != nil {
		return false, err
	}
	if changed, _ := result.RowsAffected(); changed != 1 {
		return false, ErrVersionConflict
	}
	if _, err := tx.ExecContext(ctx, `UPDATE file_versions SET scan_state = ?, scan_version = scan_version + 1
		WHERE id = ? AND scan_state IN ('queued', 'scanning')`, payload.Verdict, payload.FileVersionID); err != nil {
		return false, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO ingested_envelopes
		(source, sequence, deduplication_id, kind, timestamp, payload_sha256, received_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)`, value.Source, value.Sequence, value.DeduplicationID,
		value.Kind, value.Timestamp, payloadHash[:], stamp); err != nil {
		return false, err
	}
	if _, err := appendAuditTx(ctx, tx, "scanner", "scan.verdict", payload.FileVersionID, true,
		map[string]any{"scan_job_id": payload.ScanJobID, "verdict": payload.Verdict}, now); err != nil {
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	return false, nil
}
