package sqlite

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"plntir/core/internal/idgen"
)

var (
	ErrResourceNotFound = errors.New("resource not found")
	ErrInvalidState     = errors.New("resource state does not allow this operation")
	ErrUploadExpired    = errors.New("upload session has expired")
	ErrIncompleteUpload = errors.New("upload does not have every confirmed part")
	ErrPartConflict     = errors.New("upload part conflicts with its prior confirmation")

	opaqueID = regexp.MustCompile(`^[a-z][a-z0-9]{0,15}_[0-9a-hjkmnp-tv-z]{32}$`)
	safeETag = regexp.MustCompile(`^[A-Za-z0-9!#$%&'*+.^_` + "`" + `|~-]{1,256}$`)
)

type UploadPartRequest struct {
	OwnerAccountID  string
	UploadSessionID string
	PartNumber      int64
	SizeBytes       int64
	CiphertextHash  [sha256.Size]byte
	ETag            string
	Now             time.Time
}

type ConfirmedUploadPart struct {
	PartNumber     int64
	SizeBytes      int64
	CiphertextHash [sha256.Size]byte
	ETag           string
	ConfirmedAt    time.Time
}

type UploadStatus struct {
	UploadSessionID         string
	FileID                  string
	FileVersionID           string
	ObjectKey               string
	ProviderUploadID        string
	State                   string
	ExpectedParts           int64
	PartSizeBytes           int64
	PlaintextBytes          int64
	ExpectedCiphertextBytes int64
	NextPart                int64
	ExpiresAt               time.Time
	Parts                   []ConfirmedUploadPart
}

type CompleteUploadRequest struct {
	OwnerAccountID  string
	UploadSessionID string
	CiphertextBytes int64
	PlaintextHash   [sha256.Size]byte
	CiphertextHash  [sha256.Size]byte
	R2ETag          string
	Now             time.Time
}

type UploadCompletion struct {
	FileID        string
	FileVersionID string
	ObjectKey     string
	ScanJobID     string
	ScanState     string
}

type ScanVerdictRequest struct {
	ScanJobID     string
	FileVersionID string
	Verdict       string
	EngineVersion string
	RulesVersion  string
	VerdictSHA256 [sha256.Size]byte
	Now           time.Time
}

func (s *Store) AttachProviderUpload(ctx context.Context, ownerAccountID, uploadSessionID, providerUploadID string, now time.Time) error {
	if providerUploadID == "" || len(providerUploadID) > 1024 || strings.ContainsAny(providerUploadID, "\x00\r\n") {
		return errors.New("provider upload id is invalid")
	}
	now = normalizedTime(now)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var state, expiresAt, fileID string
	var existing sql.NullString
	err = tx.QueryRowContext(ctx, `SELECT us.state, us.expires_at, us.r2_upload_id, f.id
		FROM upload_sessions us
		JOIN file_versions fv ON fv.id = us.file_version_id
		JOIN files f ON f.id = fv.file_id
		WHERE us.id = ? AND f.owner_account_id = ?`, uploadSessionID, ownerAccountID).
		Scan(&state, &expiresAt, &existing, &fileID)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrResourceNotFound
	}
	if err != nil {
		return err
	}
	if uploadExpired(expiresAt, now) {
		return ErrUploadExpired
	}
	if state == "uploading" && existing.Valid && existing.String == providerUploadID {
		return nil
	}
	if state != "starting" || existing.Valid {
		return ErrInvalidState
	}
	result, err := tx.ExecContext(ctx, `UPDATE upload_sessions
		SET r2_upload_id = ?, state = 'uploading', updated_at = ?
		WHERE id = ? AND state = 'starting' AND r2_upload_id IS NULL`,
		providerUploadID, now.Format(time.RFC3339Nano), uploadSessionID)
	if err != nil {
		return err
	}
	if changed, _ := result.RowsAffected(); changed != 1 {
		return ErrVersionConflict
	}
	if _, err := appendAuditTx(ctx, tx, ownerAccountID, "upload.provider.attach", fileID, true,
		map[string]any{"upload_session_id": uploadSessionID}, now); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) ConfirmUploadPart(ctx context.Context, request UploadPartRequest) (UploadStatus, error) {
	request.Now = normalizedTime(request.Now)
	request.ETag = strings.Trim(request.ETag, `"`)
	if request.PartNumber < 1 || request.PartNumber > 10000 || request.SizeBytes < 1 || !safeETag.MatchString(request.ETag) {
		return UploadStatus{}, errors.New("upload part metadata is invalid")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return UploadStatus{}, err
	}
	defer tx.Rollback()
	status, err := uploadStatusTx(ctx, tx, request.OwnerAccountID, request.UploadSessionID)
	if err != nil {
		return UploadStatus{}, err
	}
	if uploadExpired(status.ExpiresAt.Format(time.RFC3339Nano), request.Now) {
		return UploadStatus{}, ErrUploadExpired
	}
	if status.State != "uploading" || status.ProviderUploadID == "" || request.PartNumber > status.ExpectedParts {
		return UploadStatus{}, ErrInvalidState
	}
	expectedPartSize := status.PartSizeBytes + ChunkTagBytes
	if request.PartNumber == status.ExpectedParts {
		remaining := status.PlaintextBytes - status.PartSizeBytes*(status.ExpectedParts-1)
		expectedPartSize = remaining + ChunkTagBytes
	}
	if request.SizeBytes != expectedPartSize {
		return UploadStatus{}, errors.New("upload part size does not match the AES-GCM chunk plan")
	}
	for _, part := range status.Parts {
		if part.PartNumber != request.PartNumber {
			continue
		}
		if part.SizeBytes != request.SizeBytes || part.CiphertextHash != request.CiphertextHash || part.ETag != request.ETag {
			return UploadStatus{}, ErrPartConflict
		}
		return status, nil
	}
	stamp := request.Now.Format(time.RFC3339Nano)
	if _, err := tx.ExecContext(ctx, `INSERT INTO upload_parts
		(upload_session_id, part_number, size_bytes, ciphertext_sha256, etag, confirmed_at)
		VALUES (?, ?, ?, ?, ?, ?)`, request.UploadSessionID, request.PartNumber,
		request.SizeBytes, request.CiphertextHash[:], request.ETag, stamp); err != nil {
		if constraintContains(err, "upload_parts.upload_session_id, upload_parts.part_number") {
			return UploadStatus{}, ErrPartConflict
		}
		return UploadStatus{}, err
	}
	status.Parts = append(status.Parts, ConfirmedUploadPart{
		PartNumber: request.PartNumber, SizeBytes: request.SizeBytes,
		CiphertextHash: request.CiphertextHash, ETag: request.ETag, ConfirmedAt: request.Now,
	})
	status.NextPart = firstMissingPart(status.Parts, status.ExpectedParts)
	if _, err := tx.ExecContext(ctx, "UPDATE upload_sessions SET next_part = ?, updated_at = ? WHERE id = ?",
		status.NextPart, stamp, request.UploadSessionID); err != nil {
		return UploadStatus{}, err
	}
	if err := tx.Commit(); err != nil {
		return UploadStatus{}, err
	}
	return status, nil
}

func (s *Store) ResumeUpload(ctx context.Context, ownerAccountID, uploadSessionID string, now time.Time) (UploadStatus, error) {
	now = normalizedTime(now)
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return UploadStatus{}, err
	}
	defer tx.Rollback()
	status, err := uploadStatusTx(ctx, tx, ownerAccountID, uploadSessionID)
	if err != nil {
		return UploadStatus{}, err
	}
	if uploadExpired(status.ExpiresAt.Format(time.RFC3339Nano), now) {
		return UploadStatus{}, ErrUploadExpired
	}
	if err := tx.Commit(); err != nil {
		return UploadStatus{}, err
	}
	return status, nil
}

func (s *Store) CompleteUpload(ctx context.Context, request CompleteUploadRequest) (UploadCompletion, error) {
	request.Now = normalizedTime(request.Now)
	request.R2ETag = strings.Trim(request.R2ETag, `"`)
	if request.CiphertextBytes < 1 || !safeETag.MatchString(request.R2ETag) {
		return UploadCompletion{}, errors.New("completed object metadata is invalid")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return UploadCompletion{}, err
	}
	defer tx.Rollback()
	status, err := uploadStatusTx(ctx, tx, request.OwnerAccountID, request.UploadSessionID)
	if err != nil {
		return UploadCompletion{}, err
	}
	if status.State == "complete" {
		return completedUploadTx(ctx, tx, status, request)
	}
	if uploadExpired(status.ExpiresAt.Format(time.RFC3339Nano), request.Now) {
		return UploadCompletion{}, ErrUploadExpired
	}
	if status.State != "uploading" || status.ProviderUploadID == "" || int64(len(status.Parts)) != status.ExpectedParts || status.NextPart != status.ExpectedParts+1 {
		return UploadCompletion{}, ErrIncompleteUpload
	}
	var total int64
	for _, part := range status.Parts {
		total += part.SizeBytes
		if part.ETag == "" || part.ConfirmedAt.IsZero() {
			return UploadCompletion{}, ErrIncompleteUpload
		}
	}
	if total != request.CiphertextBytes {
		return UploadCompletion{}, errors.New("completed ciphertext size does not equal confirmed parts")
	}
	if request.CiphertextBytes != status.ExpectedCiphertextBytes {
		return UploadCompletion{}, errors.New("completed ciphertext size does not match the signed AES-GCM plan")
	}
	scanJobID, err := idgen.New("scan")
	if err != nil {
		return UploadCompletion{}, err
	}
	outboxID, err := idgen.New("out")
	if err != nil {
		return UploadCompletion{}, err
	}
	stamp := request.Now.Format(time.RFC3339Nano)
	if _, err := tx.ExecContext(ctx, `UPDATE file_versions SET ciphertext_size_bytes = ?,
		plaintext_sha256 = ?, ciphertext_sha256 = ?, scan_state = 'queued', scan_version = scan_version + 1,
		completed_at = ? WHERE id = ? AND scan_state = 'pending_upload'`, request.CiphertextBytes,
		request.PlaintextHash[:], request.CiphertextHash[:], stamp, status.FileVersionID); err != nil {
		return UploadCompletion{}, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE upload_sessions SET state = 'complete', updated_at = ?
		WHERE id = ? AND state = 'uploading'`, stamp, request.UploadSessionID); err != nil {
		return UploadCompletion{}, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE quota_reservations SET state = 'committed'
		WHERE file_id = ? AND state = 'active'`, status.FileID); err != nil {
		return UploadCompletion{}, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE files SET state = 'active', version = version + 1, updated_at = ?
		WHERE id = ? AND state = 'uploading'`, stamp, status.FileID); err != nil {
		return UploadCompletion{}, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO scan_jobs
		(id, deduplication_id, file_version_id, object_key, expected_size_bytes, expected_etag, state, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, 'queued', ?, ?)`, scanJobID, scanJobID, status.FileVersionID,
		status.ObjectKey, request.CiphertextBytes, request.R2ETag, stamp, stamp); err != nil {
		return UploadCompletion{}, err
	}
	payload, err := json.Marshal(map[string]any{
		"envelope_version": 1, "scan_job_id": scanJobID, "file_version_id": status.FileVersionID,
		"object_key": status.ObjectKey, "ciphertext_size_bytes": request.CiphertextBytes,
		"expected_etag": request.R2ETag,
	})
	if err != nil {
		return UploadCompletion{}, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO outbox
		(id, topic, deduplication_id, payload_json, created_at)
		VALUES (?, 'scan.requested', ?, ?, ?)`, outboxID, "scan.requested:"+scanJobID, string(payload), stamp); err != nil {
		return UploadCompletion{}, err
	}
	if _, err := appendAuditTx(ctx, tx, request.OwnerAccountID, "upload.complete", status.FileID, true,
		map[string]any{"file_version_id": status.FileVersionID, "scan_job_id": scanJobID}, request.Now); err != nil {
		return UploadCompletion{}, err
	}
	if err := tx.Commit(); err != nil {
		return UploadCompletion{}, err
	}
	return UploadCompletion{FileID: status.FileID, FileVersionID: status.FileVersionID, ObjectKey: status.ObjectKey, ScanJobID: scanJobID, ScanState: "queued"}, nil
}

func completedUploadTx(ctx context.Context, tx *sql.Tx, status UploadStatus, request CompleteUploadRequest) (UploadCompletion, error) {
	var completion UploadCompletion
	completion.FileID, completion.FileVersionID, completion.ObjectKey = status.FileID, status.FileVersionID, status.ObjectKey
	var storedBytes int64
	var plaintextHash, ciphertextHash []byte
	err := tx.QueryRowContext(ctx, `SELECT sj.id, sj.state, fv.ciphertext_size_bytes,
		fv.plaintext_sha256, fv.ciphertext_sha256
		FROM scan_jobs sj JOIN file_versions fv ON fv.id = sj.file_version_id
		WHERE sj.file_version_id = ? AND sj.expected_etag = ?`, status.FileVersionID, request.R2ETag).
		Scan(&completion.ScanJobID, &completion.ScanState, &storedBytes, &plaintextHash, &ciphertextHash)
	if errors.Is(err, sql.ErrNoRows) {
		return UploadCompletion{}, ErrPartConflict
	}
	if err != nil {
		return UploadCompletion{}, err
	}
	if storedBytes != request.CiphertextBytes || !equalHash(plaintextHash, request.PlaintextHash) || !equalHash(ciphertextHash, request.CiphertextHash) {
		return UploadCompletion{}, ErrPartConflict
	}
	if err := tx.Commit(); err != nil {
		return UploadCompletion{}, err
	}
	return completion, nil
}

func (s *Store) AbortUpload(ctx context.Context, ownerAccountID, uploadSessionID string, now time.Time) error {
	now = normalizedTime(now)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	status, err := uploadStatusTx(ctx, tx, ownerAccountID, uploadSessionID)
	if err != nil {
		return err
	}
	if status.State == "aborted" || status.State == "expired" {
		return nil
	}
	if status.State == "complete" || status.State == "completing" {
		return ErrInvalidState
	}
	stamp := now.Format(time.RFC3339Nano)
	if _, err := tx.ExecContext(ctx, "UPDATE upload_sessions SET state = 'aborted', updated_at = ? WHERE id = ?", stamp, uploadSessionID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE quota_reservations SET state = 'released', released_at = ?
		WHERE file_id = ? AND state = 'active'`, stamp, status.FileID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE files SET state = 'purged', logical_size_bytes = 0,
		version = version + 1, updated_at = ? WHERE id = ? AND state = 'uploading'`, stamp, status.FileID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE key_envelopes SET ciphertext = zeroblob(length(ciphertext)), destroyed_at = ?
		WHERE file_version_id = ? AND destroyed_at IS NULL`, stamp, status.FileVersionID); err != nil {
		return err
	}
	if status.ProviderUploadID != "" {
		outboxID, err := idgen.New("out")
		if err != nil {
			return err
		}
		payload, _ := json.Marshal(map[string]any{"upload_session_id": uploadSessionID, "object_key": status.ObjectKey, "provider_upload_id": status.ProviderUploadID})
		if _, err := tx.ExecContext(ctx, `INSERT INTO outbox
			(id, topic, deduplication_id, payload_json, created_at) VALUES (?, 'upload.abort', ?, ?, ?)`,
			outboxID, "upload.abort:"+uploadSessionID, string(payload), stamp); err != nil {
			return err
		}
	}
	if _, err := appendAuditTx(ctx, tx, ownerAccountID, "upload.abort", status.FileID, true,
		map[string]any{"upload_session_id": uploadSessionID}, now); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) applyTrustedScanVerdict(ctx context.Context, request ScanVerdictRequest) error {
	request.Now = normalizedTime(request.Now)
	if !opaqueID.MatchString(request.ScanJobID) || !strings.HasPrefix(request.ScanJobID, "scan_") ||
		!opaqueID.MatchString(request.FileVersionID) || !strings.HasPrefix(request.FileVersionID, "fver_") ||
		(request.Verdict != "clean" && request.Verdict != "malware" && request.Verdict != "unscannable" && request.Verdict != "failed") ||
		request.EngineVersion == "" || len(request.EngineVersion) > 256 || len(request.RulesVersion) > 256 {
		return errors.New("scan verdict is invalid")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var state, versionID string
	var storedHash []byte
	err = tx.QueryRowContext(ctx, "SELECT state, file_version_id, verdict_sha256 FROM scan_jobs WHERE id = ?", request.ScanJobID).
		Scan(&state, &versionID, &storedHash)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrResourceNotFound
	}
	if err != nil {
		return err
	}
	if versionID != request.FileVersionID {
		return ErrResourceNotFound
	}
	if state == request.Verdict {
		if equalHash(storedHash, request.VerdictSHA256) {
			return nil
		}
		return ErrVersionConflict
	}
	if state != "queued" && state != "leased" {
		return ErrInvalidState
	}
	stamp := request.Now.Format(time.RFC3339Nano)
	if _, err := tx.ExecContext(ctx, `UPDATE scan_jobs SET state = ?, engine_version = ?, rules_version = ?,
		verdict_sha256 = ?, updated_at = ?, completed_at = ?, lease_owner = NULL, lease_expires_at = NULL
		WHERE id = ? AND state IN ('queued', 'leased')`, request.Verdict, request.EngineVersion,
		request.RulesVersion, request.VerdictSHA256[:], stamp, stamp, request.ScanJobID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE file_versions SET scan_state = ?, scan_version = scan_version + 1
		WHERE id = ? AND scan_state IN ('queued', 'scanning')`, request.Verdict, request.FileVersionID); err != nil {
		return err
	}
	if _, err := appendAuditTx(ctx, tx, "scanner", "scan.verdict", request.FileVersionID, true,
		map[string]any{"scan_job_id": request.ScanJobID, "verdict": request.Verdict}, request.Now); err != nil {
		return err
	}
	return tx.Commit()
}

func uploadStatusTx(ctx context.Context, tx *sql.Tx, ownerAccountID, uploadSessionID string) (UploadStatus, error) {
	var status UploadStatus
	var providerID sql.NullString
	var expiresAt string
	err := tx.QueryRowContext(ctx, `SELECT us.id, f.id, fv.id, fv.object_key, us.r2_upload_id,
		us.state, us.expected_parts, us.part_size_bytes, fv.plaintext_size_bytes,
		fv.ciphertext_size_bytes, us.next_part, us.expires_at
		FROM upload_sessions us
		JOIN file_versions fv ON fv.id = us.file_version_id
		JOIN files f ON f.id = fv.file_id
		WHERE us.id = ? AND f.owner_account_id = ?`, uploadSessionID, ownerAccountID).
		Scan(&status.UploadSessionID, &status.FileID, &status.FileVersionID, &status.ObjectKey,
			&providerID, &status.State, &status.ExpectedParts, &status.PartSizeBytes, &status.PlaintextBytes,
			&status.ExpectedCiphertextBytes, &status.NextPart, &expiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return UploadStatus{}, ErrResourceNotFound
	}
	if err != nil {
		return UploadStatus{}, err
	}
	status.ProviderUploadID = providerID.String
	status.ExpiresAt, err = time.Parse(time.RFC3339Nano, expiresAt)
	if err != nil {
		return UploadStatus{}, fmt.Errorf("invalid upload expiration: %w", err)
	}
	rows, err := tx.QueryContext(ctx, `SELECT part_number, size_bytes, ciphertext_sha256, etag, confirmed_at
		FROM upload_parts WHERE upload_session_id = ? ORDER BY part_number`, uploadSessionID)
	if err != nil {
		return UploadStatus{}, err
	}
	defer rows.Close()
	for rows.Next() {
		var part ConfirmedUploadPart
		var digest []byte
		var stamp string
		if err := rows.Scan(&part.PartNumber, &part.SizeBytes, &digest, &part.ETag, &stamp); err != nil {
			return UploadStatus{}, err
		}
		if len(digest) != sha256.Size {
			return UploadStatus{}, errors.New("stored upload part hash is invalid")
		}
		copy(part.CiphertextHash[:], digest)
		part.ConfirmedAt, err = time.Parse(time.RFC3339Nano, stamp)
		if err != nil {
			return UploadStatus{}, err
		}
		status.Parts = append(status.Parts, part)
	}
	if err := rows.Err(); err != nil {
		return UploadStatus{}, err
	}
	status.NextPart = firstMissingPart(status.Parts, status.ExpectedParts)
	return status, nil
}

func firstMissingPart(parts []ConfirmedUploadPart, expectedParts int64) int64 {
	confirmed := make(map[int64]struct{}, len(parts))
	for _, part := range parts {
		confirmed[part.PartNumber] = struct{}{}
	}
	for next := int64(1); next <= expectedParts; next++ {
		if _, ok := confirmed[next]; !ok {
			return next
		}
	}
	return expectedParts + 1
}

func normalizedTime(value time.Time) time.Time {
	if value.IsZero() {
		value = time.Now()
	}
	return value.UTC()
}

func uploadExpired(encoded string, now time.Time) bool {
	expiresAt, err := time.Parse(time.RFC3339Nano, encoded)
	return err != nil || !now.Before(expiresAt)
}

func equalHash(stored []byte, expected [sha256.Size]byte) bool {
	return len(stored) == sha256.Size && string(stored) == string(expected[:])
}
