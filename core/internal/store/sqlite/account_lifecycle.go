package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

const accountDeletionWindow = 30 * 24 * time.Hour

type AccountDeletionWindow struct {
	AccountID      string
	AccountVersion int64
	PurgeAfter     time.Time
	FilesLocked    int64
}

type AccountTransfer struct {
	SourceAccountID      string
	RecipientAccountID   string
	SourceAccountVersion int64
	FilesTransferred     int64
}

type PurgedAccount struct {
	AccountID      string
	FilesPurged    int64
	ObjectsQueued  int64
	RecordsPurged  int64
	AccountVersion int64
}

// RecordAccountDeletionRequest records user intent only. The account remains
// active and no session, file, share, key envelope, or device is changed.
func (s *Store) RecordAccountDeletionRequest(ctx context.Context, accountID string, expectedVersion int64, now time.Time) (Account, error) {
	now = normalizedTime(now)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Account{}, err
	}
	defer tx.Rollback()
	account, err := accountByIDTx(ctx, tx, accountID)
	if errors.Is(err, sql.ErrNoRows) {
		return Account{}, ErrResourceNotFound
	}
	if err != nil {
		return Account{}, err
	}
	if account.State != "active" || account.Version != expectedVersion {
		return Account{}, ErrVersionConflict
	}
	var prior sql.NullString
	if err := tx.QueryRowContext(ctx, "SELECT deletion_requested_at FROM accounts WHERE id = ?", accountID).Scan(&prior); err != nil {
		return Account{}, err
	}
	if prior.Valid {
		return Account{}, ErrInvalidState
	}
	stamp := now.Format(time.RFC3339Nano)
	result, err := tx.ExecContext(ctx, `UPDATE accounts SET deletion_requested_at = ?, version = version + 1,
		updated_at = ? WHERE id = ? AND state = 'active' AND version = ? AND deletion_requested_at IS NULL`,
		stamp, stamp, accountID, expectedVersion)
	if err != nil {
		return Account{}, err
	}
	if changed, _ := result.RowsAffected(); changed != 1 {
		return Account{}, ErrVersionConflict
	}
	if _, err := appendAuditTx(ctx, tx, accountID, "account.deletion.request", accountID, true,
		map[string]any{"data_changed": false}, now); err != nil {
		return Account{}, err
	}
	if err := tx.Commit(); err != nil {
		return Account{}, err
	}
	account.Version++
	account.UpdatedAt = now
	return account, nil
}

// ExecuteAccountDeletion is the separate admin action that starts the transfer
// window and immediately blocks account and share access.
func (s *Store) ExecuteAccountDeletion(ctx context.Context, adminActor, accountID string, expectedVersion int64, now time.Time) (AccountDeletionWindow, error) {
	now = normalizedTime(now)
	if strings.TrimSpace(adminActor) == "" {
		return AccountDeletionWindow{}, errors.New("admin actor is required")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return AccountDeletionWindow{}, err
	}
	defer tx.Rollback()
	var state string
	var version int64
	var requestedAt sql.NullString
	err = tx.QueryRowContext(ctx, `SELECT state, version, deletion_requested_at FROM accounts WHERE id = ?`, accountID).
		Scan(&state, &version, &requestedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return AccountDeletionWindow{}, ErrResourceNotFound
	}
	if err != nil {
		return AccountDeletionWindow{}, err
	}
	if state != "active" || version != expectedVersion {
		return AccountDeletionWindow{}, ErrVersionConflict
	}
	if !requestedAt.Valid {
		return AccountDeletionWindow{}, ErrInvalidState
	}
	requestStamp, err := time.Parse(time.RFC3339Nano, requestedAt.String)
	if err != nil || requestStamp.After(now) {
		return AccountDeletionWindow{}, errors.New("stored deletion request timestamp is invalid")
	}

	stamp := now.Format(time.RFC3339Nano)
	purgeAfter := now.Add(accountDeletionWindow)
	purgeStamp := purgeAfter.Format(time.RFC3339Nano)

	type providerUpload struct{ sessionID, objectKey, providerID string }
	rows, err := tx.QueryContext(ctx, `SELECT us.id, fv.object_key, us.r2_upload_id
		FROM upload_sessions us JOIN file_versions fv ON fv.id = us.file_version_id
		JOIN files f ON f.id = fv.file_id
		WHERE f.owner_account_id = ? AND f.state = 'uploading' AND us.r2_upload_id IS NOT NULL
		AND us.state IN ('starting', 'uploading')`, accountID)
	if err != nil {
		return AccountDeletionWindow{}, err
	}
	var providerUploads []providerUpload
	for rows.Next() {
		var upload providerUpload
		if err := rows.Scan(&upload.sessionID, &upload.objectKey, &upload.providerID); err != nil {
			rows.Close()
			return AccountDeletionWindow{}, err
		}
		providerUploads = append(providerUploads, upload)
	}
	if err := rows.Close(); err != nil {
		return AccountDeletionWindow{}, err
	}
	if err := rows.Err(); err != nil {
		return AccountDeletionWindow{}, err
	}
	for _, upload := range providerUploads {
		payload, _ := json.Marshal(map[string]any{
			"upload_session_id": upload.sessionID, "object_key": upload.objectKey, "provider_upload_id": upload.providerID,
		})
		if _, err := enqueueOutboxTx(ctx, tx, "upload.abort", "upload:abort:"+upload.sessionID, payload, now); err != nil {
			return AccountDeletionWindow{}, err
		}
	}

	if _, err := tx.ExecContext(ctx, `UPDATE upload_sessions SET state = 'aborted', updated_at = ?
		WHERE file_version_id IN (SELECT fv.id FROM file_versions fv JOIN files f ON f.id = fv.file_id
		WHERE f.owner_account_id = ? AND f.state = 'uploading') AND state IN ('starting', 'uploading')`, stamp, accountID); err != nil {
		return AccountDeletionWindow{}, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE quota_reservations SET state = 'released', released_at = ?
		WHERE owner_account_id = ? AND state = 'active'`, stamp, accountID); err != nil {
		return AccountDeletionWindow{}, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE key_envelopes SET ciphertext = zeroblob(length(ciphertext)), destroyed_at = ?
		WHERE destroyed_at IS NULL AND file_version_id IN
		(SELECT fv.id FROM file_versions fv JOIN files f ON f.id = fv.file_id
		 WHERE f.owner_account_id = ? AND f.state = 'uploading')`, stamp, accountID); err != nil {
		return AccountDeletionWindow{}, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE files SET state = 'purged', logical_size_bytes = 0,
		version = version + 1, updated_at = ?, purge_after = ?, deletion_prior_state = NULL
		WHERE owner_account_id = ? AND state = 'uploading'`, stamp, stamp, accountID); err != nil {
		return AccountDeletionWindow{}, err
	}
	lockedResult, err := tx.ExecContext(ctx, `UPDATE files SET deletion_prior_state = state,
		state = 'deletion_pending', purge_after = ?, version = version + 1, updated_at = ?
		WHERE owner_account_id = ? AND state IN ('active', 'trashed')`, purgeStamp, stamp, accountID)
	if err != nil {
		return AccountDeletionWindow{}, err
	}
	filesLocked, _ := lockedResult.RowsAffected()
	if _, err := tx.ExecContext(ctx, `UPDATE shares SET state = 'revoked', version = version + 1, revoked_at = ?
		WHERE state = 'active' AND (owner_account_id = ? OR recipient_account_id = ?)`, stamp, accountID, accountID); err != nil {
		return AccountDeletionWindow{}, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE contacts SET state = 'removed', version = version + 1, removed_at = ?
		WHERE state != 'removed' AND (account_low_id = ? OR account_high_id = ?)`, stamp, accountID, accountID); err != nil {
		return AccountDeletionWindow{}, err
	}
	if _, err := tx.ExecContext(ctx, "UPDATE sessions SET revoked_at = ? WHERE account_id = ? AND revoked_at IS NULL", stamp, accountID); err != nil {
		return AccountDeletionWindow{}, err
	}
	if _, err := tx.ExecContext(ctx, "UPDATE passkeys SET revoked_at = ? WHERE account_id = ? AND revoked_at IS NULL", stamp, accountID); err != nil {
		return AccountDeletionWindow{}, err
	}
	if _, err := tx.ExecContext(ctx, "UPDATE enrollment_invites SET revoked_at = ? WHERE account_id = ? AND consumed_at IS NULL AND revoked_at IS NULL", stamp, accountID); err != nil {
		return AccountDeletionWindow{}, err
	}
	if _, err := tx.ExecContext(ctx, "UPDATE contact_invites SET revoked_at = ? WHERE issuer_account_id = ? AND consumed_at IS NULL AND revoked_at IS NULL", stamp, accountID); err != nil {
		return AccountDeletionWindow{}, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE devices SET state = 'suspended', version = version + 1,
		updated_at = ? WHERE account_id = ? AND state IN ('pending', 'active')`, stamp, accountID); err != nil {
		return AccountDeletionWindow{}, err
	}
	result, err := tx.ExecContext(ctx, `UPDATE accounts SET state = 'deletion_pending', purge_after = ?,
		version = version + 1, updated_at = ? WHERE id = ? AND state = 'active' AND version = ?`,
		purgeStamp, stamp, accountID, expectedVersion)
	if err != nil {
		return AccountDeletionWindow{}, err
	}
	if changed, _ := result.RowsAffected(); changed != 1 {
		return AccountDeletionWindow{}, ErrVersionConflict
	}
	payload, _ := json.Marshal(map[string]any{"account_id": accountID, "purge_after": purgeStamp})
	if _, err := enqueueOutboxTx(ctx, tx, "account.deletion.started", "account:deletion:"+accountID+fmt.Sprintf(":%d", expectedVersion), payload, now); err != nil {
		return AccountDeletionWindow{}, err
	}
	if _, err := appendAuditTx(ctx, tx, adminActor, "account.deletion.execute", accountID, true,
		map[string]any{"files_locked": filesLocked, "purge_after": purgeStamp}, now); err != nil {
		return AccountDeletionWindow{}, err
	}
	if err := tx.Commit(); err != nil {
		return AccountDeletionWindow{}, err
	}
	return AccountDeletionWindow{AccountID: accountID, AccountVersion: expectedVersion + 1, PurgeAfter: purgeAfter, FilesLocked: filesLocked}, nil
}

func (s *Store) TransferDeletedAccountFiles(ctx context.Context, adminActor, sourceAccountID, recipientAccountID string, expectedSourceVersion int64, reason string, now time.Time) (AccountTransfer, error) {
	now = normalizedTime(now)
	reason = sanitizeJobError(reason)
	if strings.TrimSpace(adminActor) == "" || sourceAccountID == recipientAccountID || len(reason) < 8 || len(reason) > 500 {
		return AccountTransfer{}, errors.New("account transfer request is invalid")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return AccountTransfer{}, err
	}
	defer tx.Rollback()
	var sourceState, purgeAfter string
	var sourceVersion int64
	err = tx.QueryRowContext(ctx, `SELECT state, version, purge_after FROM accounts WHERE id = ?`, sourceAccountID).
		Scan(&sourceState, &sourceVersion, &purgeAfter)
	if errors.Is(err, sql.ErrNoRows) {
		return AccountTransfer{}, ErrResourceNotFound
	}
	if err != nil {
		return AccountTransfer{}, err
	}
	if sourceState != "deletion_pending" || sourceVersion != expectedSourceVersion {
		return AccountTransfer{}, ErrVersionConflict
	}
	deadline, err := time.Parse(time.RFC3339Nano, purgeAfter)
	if err != nil || !now.Before(deadline) {
		return AccountTransfer{}, ErrInvalidState
	}
	var recipientState string
	if err := tx.QueryRowContext(ctx, "SELECT state FROM accounts WHERE id = ?", recipientAccountID).Scan(&recipientState); errors.Is(err, sql.ErrNoRows) {
		return AccountTransfer{}, ErrResourceNotFound
	} else if err != nil {
		return AccountTransfer{}, err
	}
	if recipientState != "active" {
		return AccountTransfer{}, ErrInvalidState
	}
	stamp := now.Format(time.RFC3339Nano)
	if _, err := tx.ExecContext(ctx, `UPDATE shares SET state = 'revoked', version = version + 1,
		revoked_at = ? WHERE state = 'active' AND file_id IN
		(SELECT id FROM files WHERE owner_account_id = ? AND state = 'deletion_pending')`, stamp, sourceAccountID); err != nil {
		return AccountTransfer{}, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE quota_reservations SET owner_account_id = ?
		WHERE owner_account_id = ? AND file_id IN
		(SELECT id FROM files WHERE owner_account_id = ? AND state = 'deletion_pending')`,
		recipientAccountID, sourceAccountID, sourceAccountID); err != nil {
		return AccountTransfer{}, err
	}
	result, err := tx.ExecContext(ctx, `UPDATE files SET owner_account_id = ?,
		state = CASE deletion_prior_state WHEN 'trashed' THEN 'trashed' ELSE 'active' END,
		deletion_prior_state = NULL, purge_after = NULL, version = version + 1, updated_at = ?
		WHERE owner_account_id = ? AND state = 'deletion_pending'`, recipientAccountID, stamp, sourceAccountID)
	if err != nil {
		return AccountTransfer{}, err
	}
	transferred, _ := result.RowsAffected()
	result, err = tx.ExecContext(ctx, `UPDATE accounts SET version = version + 1, updated_at = ?
		WHERE id = ? AND state = 'deletion_pending' AND version = ?`, stamp, sourceAccountID, expectedSourceVersion)
	if err != nil {
		return AccountTransfer{}, err
	}
	if changed, _ := result.RowsAffected(); changed != 1 {
		return AccountTransfer{}, ErrVersionConflict
	}
	if _, err := appendAuditTx(ctx, tx, adminActor, "account.files.transfer", sourceAccountID, true,
		map[string]any{"recipient_account_id": recipientAccountID, "files_transferred": transferred, "reason": reason}, now); err != nil {
		return AccountTransfer{}, err
	}
	if err := tx.Commit(); err != nil {
		return AccountTransfer{}, err
	}
	return AccountTransfer{SourceAccountID: sourceAccountID, RecipientAccountID: recipientAccountID,
		SourceAccountVersion: expectedSourceVersion + 1, FilesTransferred: transferred}, nil
}

func (s *Store) PurgeExpiredAccounts(ctx context.Context, now time.Time) ([]PurgedAccount, error) {
	now = normalizedTime(now)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	stamp := now.Format(time.RFC3339Nano)
	rows, err := tx.QueryContext(ctx, `SELECT id, version FROM accounts
		WHERE state = 'deletion_pending' AND purge_after <= ? ORDER BY id`, stamp)
	if err != nil {
		return nil, err
	}
	var accounts []struct {
		id      string
		version int64
	}
	for rows.Next() {
		var account struct {
			id      string
			version int64
		}
		if err := rows.Scan(&account.id, &account.version); err != nil {
			rows.Close()
			return nil, err
		}
		accounts = append(accounts, account)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	results := make([]PurgedAccount, 0, len(accounts))
	for _, account := range accounts {
		versionRows, err := tx.QueryContext(ctx, `SELECT fv.id, fv.object_key, fv.immutable_until
			FROM file_versions fv JOIN files f ON f.id = fv.file_id
			WHERE f.owner_account_id = ? AND f.state = 'deletion_pending' ORDER BY fv.id`, account.id)
		if err != nil {
			return nil, err
		}
		type objectVersion struct{ id, key, immutableUntil string }
		var objects []objectVersion
		for versionRows.Next() {
			var object objectVersion
			if err := versionRows.Scan(&object.id, &object.key, &object.immutableUntil); err != nil {
				versionRows.Close()
				return nil, err
			}
			objects = append(objects, object)
		}
		if err := versionRows.Close(); err != nil {
			return nil, err
		}
		if err := versionRows.Err(); err != nil {
			return nil, err
		}
		for _, object := range objects {
			notBefore := now
			if immutableUntil, parseErr := time.Parse(time.RFC3339Nano, object.immutableUntil); parseErr != nil {
				return nil, fmt.Errorf("invalid immutable_until for %s: %w", object.id, parseErr)
			} else if immutableUntil.After(notBefore) {
				notBefore = immutableUntil
			}
			payload, _ := json.Marshal(map[string]any{"file_version_id": object.id, "object_key": object.key, "not_before": notBefore.Format(time.RFC3339Nano)})
			message, err := enqueueOutboxTx(ctx, tx, "file.delete", "file:purge:"+object.id, payload, now)
			if err != nil {
				return nil, err
			}
			if _, err := tx.ExecContext(ctx, "UPDATE outbox SET available_at = ? WHERE id = ? AND published_at IS NULL",
				notBefore.Format(time.RFC3339Nano), message.ID); err != nil {
				return nil, err
			}
		}
		if _, err := tx.ExecContext(ctx, `UPDATE key_envelopes SET ciphertext = zeroblob(length(ciphertext)), destroyed_at = ?
			WHERE destroyed_at IS NULL AND file_version_id IN (SELECT fv.id FROM file_versions fv JOIN files f ON f.id = fv.file_id
			WHERE f.owner_account_id = ? AND f.state = 'deletion_pending')`, stamp, account.id); err != nil {
			return nil, err
		}
		fileResult, err := tx.ExecContext(ctx, `UPDATE files SET state = 'purged', logical_size_bytes = 0,
			filename = 'deleted', deletion_prior_state = NULL, version = version + 1, updated_at = ?
			WHERE owner_account_id = ? AND state = 'deletion_pending'`, stamp, account.id)
		if err != nil {
			return nil, err
		}
		filesPurged, _ := fileResult.RowsAffected()
		if _, err := tx.ExecContext(ctx, `UPDATE quota_reservations SET state = 'released', released_at = ?
			WHERE owner_account_id = ? AND state IN ('active', 'committed')`, stamp, account.id); err != nil {
			return nil, err
		}
		aiResult, err := tx.ExecContext(ctx, `UPDATE ai_records SET kms_envelope = zeroblob(length(kms_envelope)),
			offline_envelope = zeroblob(length(offline_envelope)), wraps_destroyed_at = ?
			WHERE account_id = ? AND wraps_destroyed_at IS NULL`, stamp, account.id)
		if err != nil {
			return nil, err
		}
		recordsPurged, _ := aiResult.RowsAffected()
		if _, err := tx.ExecContext(ctx, `UPDATE devices SET state = 'retired', reassignment_blocked = 0,
			version = version + 1, updated_at = ? WHERE account_id = ? AND state != 'retired'`, stamp, account.id); err != nil {
			return nil, err
		}
		result, err := tx.ExecContext(ctx, `UPDATE accounts SET state = 'tombstoned', version = version + 1,
			updated_at = ? WHERE id = ? AND state = 'deletion_pending' AND version = ?`, stamp, account.id, account.version)
		if err != nil {
			return nil, err
		}
		if changed, _ := result.RowsAffected(); changed != 1 {
			return nil, ErrVersionConflict
		}
		if _, err := appendAuditTx(ctx, tx, "system", "account.crypto-purge", account.id, true,
			map[string]any{"files_purged": filesPurged, "objects_queued": len(objects), "ai_records_purged": recordsPurged}, now); err != nil {
			return nil, err
		}
		results = append(results, PurgedAccount{AccountID: account.id, FilesPurged: filesPurged,
			ObjectsQueued: int64(len(objects)), RecordsPurged: recordsPurged, AccountVersion: account.version + 1})
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return results, nil
}

func accountByIDTx(ctx context.Context, tx *sql.Tx, accountID string) (Account, error) {
	var account Account
	var createdAt, updatedAt string
	err := tx.QueryRowContext(ctx, `SELECT id, username_display, username_canonical, state, version, created_at, updated_at
		FROM accounts WHERE id = ?`, accountID).Scan(&account.ID, &account.UsernameDisplay, &account.UsernameCanonical,
		&account.State, &account.Version, &createdAt, &updatedAt)
	if err != nil {
		return Account{}, err
	}
	account.CreatedAt, err = time.Parse(time.RFC3339Nano, createdAt)
	if err != nil {
		return Account{}, err
	}
	account.UpdatedAt, err = time.Parse(time.RFC3339Nano, updatedAt)
	return account, err
}
