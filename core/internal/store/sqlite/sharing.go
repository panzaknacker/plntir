package sqlite

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"time"

	"plntir/core/internal/idgen"
)

var ErrScanLocked = errors.New("file access is locked until a clean scan")

type ContactInvite struct {
	ID        string
	ExpiresAt time.Time
}

type Contact struct {
	ID            string
	AccountLowID  string
	AccountHighID string
	LowConfirmed  bool
	HighConfirmed bool
	State         string
	Version       int64
	CreatedAt     time.Time
	RemovedAt     *time.Time
}

type Share struct {
	ID                 string
	FileID             string
	OwnerAccountID     string
	RecipientAccountID string
	ContactID          string
	State              string
	Version            int64
	CreatedAt          time.Time
}

func (s *Store) CreateContactInvite(ctx context.Context, issuerAccountID string, issuerVersion int64, tokenHash [sha256.Size]byte, now time.Time) (ContactInvite, error) {
	now = normalizedTime(now)
	id, err := idgen.New("cinv")
	if err != nil {
		return ContactInvite{}, err
	}
	expiresAt := now.Add(15 * time.Minute)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return ContactInvite{}, err
	}
	defer tx.Rollback()
	var state string
	var version int64
	err = tx.QueryRowContext(ctx, "SELECT state, version FROM accounts WHERE id = ?", issuerAccountID).Scan(&state, &version)
	if errors.Is(err, sql.ErrNoRows) {
		return ContactInvite{}, ErrResourceNotFound
	}
	if err != nil {
		return ContactInvite{}, err
	}
	if state != "active" || version != issuerVersion {
		return ContactInvite{}, ErrVersionConflict
	}
	stamp := now.Format(time.RFC3339Nano)
	if _, err := tx.ExecContext(ctx, `INSERT INTO contact_invites
		(id, issuer_account_id, token_hash, expires_at, created_at) VALUES (?, ?, ?, ?, ?)`,
		id, issuerAccountID, tokenHash[:], expiresAt.Format(time.RFC3339Nano), stamp); err != nil {
		return ContactInvite{}, err
	}
	if _, err := appendAuditTx(ctx, tx, issuerAccountID, "contact.invite.create", id, true, nil, now); err != nil {
		return ContactInvite{}, err
	}
	if err := tx.Commit(); err != nil {
		return ContactInvite{}, err
	}
	return ContactInvite{ID: id, ExpiresAt: expiresAt}, nil
}

func (s *Store) AcceptContactInvite(ctx context.Context, accepterAccountID string, accepterVersion int64, tokenHash [sha256.Size]byte, now time.Time) (Contact, error) {
	now = normalizedTime(now)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Contact{}, err
	}
	defer tx.Rollback()
	var accepterState string
	var storedVersion int64
	if err := tx.QueryRowContext(ctx, "SELECT state, version FROM accounts WHERE id = ?", accepterAccountID).Scan(&accepterState, &storedVersion); errors.Is(err, sql.ErrNoRows) {
		return Contact{}, ErrResourceNotFound
	} else if err != nil {
		return Contact{}, err
	}
	if accepterState != "active" || storedVersion != accepterVersion {
		return Contact{}, ErrVersionConflict
	}
	var inviteID, issuerID, expiresAt string
	err = tx.QueryRowContext(ctx, `SELECT id, issuer_account_id, expires_at FROM contact_invites
		WHERE token_hash = ? AND consumed_at IS NULL AND revoked_at IS NULL`, tokenHash[:]).
		Scan(&inviteID, &issuerID, &expiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Contact{}, ErrResourceNotFound
	}
	if err != nil {
		return Contact{}, err
	}
	if issuerID == accepterAccountID || uploadExpired(expiresAt, now) {
		return Contact{}, ErrResourceNotFound
	}
	var issuerState string
	if err := tx.QueryRowContext(ctx, "SELECT state FROM accounts WHERE id = ?", issuerID).Scan(&issuerState); err != nil || issuerState != "active" {
		return Contact{}, ErrResourceNotFound
	}
	stamp := now.Format(time.RFC3339Nano)
	result, err := tx.ExecContext(ctx, `UPDATE contact_invites SET consumed_by_account_id = ?, consumed_at = ?
		WHERE id = ? AND consumed_at IS NULL AND revoked_at IS NULL`, accepterAccountID, stamp, inviteID)
	if err != nil {
		return Contact{}, err
	}
	if changed, _ := result.RowsAffected(); changed != 1 {
		return Contact{}, ErrVersionConflict
	}
	ids := []string{issuerID, accepterAccountID}
	sort.Strings(ids)
	contact, err := contactByPairTx(ctx, tx, ids[0], ids[1])
	switch {
	case errors.Is(err, sql.ErrNoRows):
		contactID, generateErr := idgen.New("ctc")
		if generateErr != nil {
			return Contact{}, generateErr
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO contacts
			(id, account_low_id, account_high_id, state, version, created_at)
			VALUES (?, ?, ?, 'pending', 1, ?)`, contactID, ids[0], ids[1], stamp); err != nil {
			return Contact{}, err
		}
		contact = Contact{ID: contactID, AccountLowID: ids[0], AccountHighID: ids[1], State: "pending", Version: 1, CreatedAt: now}
	case err != nil:
		return Contact{}, err
	case contact.State == "removed":
		result, err := tx.ExecContext(ctx, `UPDATE contacts SET low_confirmed_at = NULL, high_confirmed_at = NULL,
			state = 'pending', version = version + 1, created_at = ?, removed_at = NULL
			WHERE id = ? AND state = 'removed' AND version = ?`, stamp, contact.ID, contact.Version)
		if err != nil {
			return Contact{}, err
		}
		if changed, _ := result.RowsAffected(); changed != 1 {
			return Contact{}, ErrVersionConflict
		}
		contact.State, contact.LowConfirmed, contact.HighConfirmed, contact.RemovedAt = "pending", false, false, nil
		contact.Version++
		contact.CreatedAt = now
	}
	if _, err := appendAuditTx(ctx, tx, accepterAccountID, "contact.invite.accept", contact.ID, true,
		map[string]any{"invite_id": inviteID}, now); err != nil {
		return Contact{}, err
	}
	if err := tx.Commit(); err != nil {
		return Contact{}, err
	}
	return contact, nil
}

func (s *Store) ConfirmContact(ctx context.Context, actorAccountID, contactID string, expectedVersion int64, now time.Time) (Contact, error) {
	now = normalizedTime(now)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Contact{}, err
	}
	defer tx.Rollback()
	contact, err := contactForMemberTx(ctx, tx, contactID, actorAccountID)
	if err != nil {
		return Contact{}, err
	}
	if contact.Version != expectedVersion {
		return Contact{}, ErrVersionConflict
	}
	if contact.State == "removed" {
		return Contact{}, ErrInvalidState
	}
	isLow := actorAccountID == contact.AccountLowID
	if (isLow && contact.LowConfirmed) || (!isLow && contact.HighConfirmed) {
		return contact, nil
	}
	if isLow {
		contact.LowConfirmed = true
	} else {
		contact.HighConfirmed = true
	}
	if contact.LowConfirmed && contact.HighConfirmed {
		contact.State = "active"
	}
	stamp := now.Format(time.RFC3339Nano)
	lowStamp, highStamp := any(nil), any(nil)
	if contact.LowConfirmed {
		lowStamp = stamp
	}
	if contact.HighConfirmed {
		highStamp = stamp
	}
	result, err := tx.ExecContext(ctx, `UPDATE contacts SET low_confirmed_at = COALESCE(low_confirmed_at, ?),
		high_confirmed_at = COALESCE(high_confirmed_at, ?), state = ?, version = version + 1
		WHERE id = ? AND version = ? AND state != 'removed'`, lowStamp, highStamp, contact.State, contact.ID, expectedVersion)
	if err != nil {
		return Contact{}, err
	}
	if changed, _ := result.RowsAffected(); changed != 1 {
		return Contact{}, ErrVersionConflict
	}
	contact.Version++
	if _, err := appendAuditTx(ctx, tx, actorAccountID, "contact.confirm", contact.ID, true,
		map[string]any{"active": contact.State == "active"}, now); err != nil {
		return Contact{}, err
	}
	if err := tx.Commit(); err != nil {
		return Contact{}, err
	}
	return contact, nil
}

func (s *Store) RemoveContact(ctx context.Context, actorAccountID, contactID string, expectedVersion int64, now time.Time) error {
	now = normalizedTime(now)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	contact, err := contactForMemberTx(ctx, tx, contactID, actorAccountID)
	if err != nil {
		return err
	}
	if contact.Version != expectedVersion {
		return ErrVersionConflict
	}
	if contact.State == "removed" {
		return nil
	}
	stamp := now.Format(time.RFC3339Nano)
	if _, err := tx.ExecContext(ctx, `UPDATE contacts SET state = 'removed', version = version + 1, removed_at = ?
		WHERE id = ? AND version = ? AND state != 'removed'`, stamp, contactID, expectedVersion); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE shares SET state = 'revoked', version = version + 1, revoked_at = ?
		WHERE contact_id = ? AND state = 'active'`, stamp, contactID); err != nil {
		return err
	}
	if _, err := appendAuditTx(ctx, tx, actorAccountID, "contact.remove", contactID, true,
		map[string]any{"shares_revoked": true}, now); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) CreateShare(ctx context.Context, ownerAccountID, fileID, contactID string, expectedFileVersion int64, now time.Time) (Share, error) {
	now = normalizedTime(now)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Share{}, err
	}
	defer tx.Rollback()
	contact, err := contactForMemberTx(ctx, tx, contactID, ownerAccountID)
	if err != nil {
		return Share{}, err
	}
	if contact.State != "active" {
		return Share{}, ErrResourceNotFound
	}
	recipientID := contact.AccountLowID
	if recipientID == ownerAccountID {
		recipientID = contact.AccountHighID
	}
	var fileState, scanState string
	var fileVersion int64
	var intactWraps int
	err = tx.QueryRowContext(ctx, `SELECT f.state, f.version, fv.scan_state,
		(SELECT count(*) FROM key_envelopes ke WHERE ke.file_version_id = fv.id AND ke.destroyed_at IS NULL)
		FROM files f JOIN file_versions fv ON fv.id = f.current_version_id
		WHERE f.id = ? AND f.owner_account_id = ?`, fileID, ownerAccountID).
		Scan(&fileState, &fileVersion, &scanState, &intactWraps)
	if errors.Is(err, sql.ErrNoRows) {
		return Share{}, ErrResourceNotFound
	}
	if err != nil {
		return Share{}, err
	}
	if fileVersion != expectedFileVersion {
		return Share{}, ErrVersionConflict
	}
	if fileState != "active" || scanState != "clean" || intactWraps != 2 {
		return Share{}, ErrScanLocked
	}
	var recipientState string
	if err := tx.QueryRowContext(ctx, "SELECT state FROM accounts WHERE id = ?", recipientID).Scan(&recipientState); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Share{}, ErrResourceNotFound
		}
		return Share{}, err
	}
	if recipientState != "active" {
		return Share{}, ErrResourceNotFound
	}
	share, err := shareByFileRecipientTx(ctx, tx, fileID, recipientID)
	stamp := now.Format(time.RFC3339Nano)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		shareID, generateErr := idgen.New("shr")
		if generateErr != nil {
			return Share{}, generateErr
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO shares
			(id, file_id, owner_account_id, recipient_account_id, contact_id, state, version, created_at)
			VALUES (?, ?, ?, ?, ?, 'active', 1, ?)`, shareID, fileID, ownerAccountID, recipientID, contactID, stamp); err != nil {
			return Share{}, err
		}
		share = Share{ID: shareID, FileID: fileID, OwnerAccountID: ownerAccountID, RecipientAccountID: recipientID, ContactID: contactID, State: "active", Version: 1, CreatedAt: now}
	case err != nil:
		return Share{}, err
	case share.State == "active":
		return share, nil
	default:
		if _, err := tx.ExecContext(ctx, `UPDATE shares SET contact_id = ?, state = 'active',
			version = version + 1, created_at = ?, revoked_at = NULL WHERE id = ? AND state = 'revoked'`,
			contactID, stamp, share.ID); err != nil {
			return Share{}, err
		}
		share.ContactID, share.State, share.CreatedAt = contactID, "active", now
		share.Version++
	}
	if _, err := appendAuditTx(ctx, tx, ownerAccountID, "share.create", share.ID, true,
		map[string]any{"file_id": fileID, "recipient_account_id": recipientID}, now); err != nil {
		return Share{}, err
	}
	if err := tx.Commit(); err != nil {
		return Share{}, err
	}
	return share, nil
}

func (s *Store) RevokeShare(ctx context.Context, ownerAccountID, shareID string, expectedVersion int64, now time.Time) error {
	now = normalizedTime(now)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var state, fileID string
	var version int64
	err = tx.QueryRowContext(ctx, `SELECT state, version, file_id FROM shares WHERE id = ? AND owner_account_id = ?`, shareID, ownerAccountID).
		Scan(&state, &version, &fileID)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrResourceNotFound
	}
	if err != nil {
		return err
	}
	if version != expectedVersion {
		return ErrVersionConflict
	}
	if state == "revoked" {
		return nil
	}
	stamp := now.Format(time.RFC3339Nano)
	if _, err := tx.ExecContext(ctx, `UPDATE shares SET state = 'revoked', version = version + 1, revoked_at = ?
		WHERE id = ? AND owner_account_id = ? AND version = ? AND state = 'active'`, stamp, shareID, ownerAccountID, expectedVersion); err != nil {
		return err
	}
	if _, err := appendAuditTx(ctx, tx, ownerAccountID, "share.revoke", shareID, true, map[string]any{"file_id": fileID}, now); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) AuthorizeCleanDownload(ctx context.Context, requesterAccountID, fileID string) error {
	var ownerID, fileState, scanState, fileVersionID string
	var intactWraps int
	err := s.db.QueryRowContext(ctx, `SELECT f.owner_account_id, f.state, fv.scan_state, fv.id,
		(SELECT count(*) FROM key_envelopes ke WHERE ke.file_version_id = fv.id AND ke.destroyed_at IS NULL)
		FROM files f JOIN file_versions fv ON fv.id = f.current_version_id WHERE f.id = ?`, fileID).
		Scan(&ownerID, &fileState, &scanState, &fileVersionID, &intactWraps)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrResourceNotFound
	}
	if err != nil {
		return err
	}
	if requesterAccountID != ownerID {
		var count int
		err = s.db.QueryRowContext(ctx, `SELECT count(*) FROM shares sh
			JOIN contacts c ON c.id = sh.contact_id
			WHERE sh.file_id = ? AND sh.recipient_account_id = ? AND sh.state = 'active' AND c.state = 'active'`,
			fileID, requesterAccountID).Scan(&count)
		if err != nil {
			return err
		}
		if count != 1 {
			return ErrResourceNotFound
		}
	}
	if fileState != "active" || scanState != "clean" || intactWraps != 2 {
		return ErrScanLocked
	}
	return nil
}

func (s *Store) TrashFile(ctx context.Context, ownerAccountID, fileID string, expectedVersion int64, now time.Time) (int64, error) {
	return s.setTrashState(ctx, ownerAccountID, fileID, expectedVersion, true, now)
}

func (s *Store) RestoreFile(ctx context.Context, ownerAccountID, fileID string, expectedVersion int64, now time.Time) (int64, error) {
	return s.setTrashState(ctx, ownerAccountID, fileID, expectedVersion, false, now)
}

func (s *Store) setTrashState(ctx context.Context, ownerAccountID, fileID string, expectedVersion int64, trash bool, now time.Time) (int64, error) {
	now = normalizedTime(now)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	var state string
	var version int64
	var purgeAfter sql.NullString
	err = tx.QueryRowContext(ctx, `SELECT state, version, purge_after FROM files WHERE id = ? AND owner_account_id = ?`, fileID, ownerAccountID).
		Scan(&state, &version, &purgeAfter)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, ErrResourceNotFound
	}
	if err != nil {
		return 0, err
	}
	if version != expectedVersion {
		return 0, ErrVersionConflict
	}
	stamp := now.Format(time.RFC3339Nano)
	if trash {
		if state != "active" {
			return 0, ErrInvalidState
		}
		purge := now.Add(30 * 24 * time.Hour).Format(time.RFC3339Nano)
		if _, err := tx.ExecContext(ctx, `UPDATE files SET state = 'trashed', version = version + 1,
			updated_at = ?, trashed_at = ?, purge_after = ? WHERE id = ? AND version = ? AND state = 'active'`,
			stamp, stamp, purge, fileID, expectedVersion); err != nil {
			return 0, err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE shares SET state = 'revoked', version = version + 1, revoked_at = ?
			WHERE file_id = ? AND state = 'active'`, stamp, fileID); err != nil {
			return 0, err
		}
		if _, err := appendAuditTx(ctx, tx, ownerAccountID, "file.trash", fileID, true,
			map[string]any{"purge_after": purge}, now); err != nil {
			return 0, err
		}
	} else {
		if state != "trashed" || !purgeAfter.Valid || uploadExpired(purgeAfter.String, now) {
			return 0, ErrInvalidState
		}
		if _, err := tx.ExecContext(ctx, `UPDATE files SET state = 'active', version = version + 1,
			updated_at = ?, trashed_at = NULL, purge_after = NULL WHERE id = ? AND version = ? AND state = 'trashed'`,
			stamp, fileID, expectedVersion); err != nil {
			return 0, err
		}
		if _, err := appendAuditTx(ctx, tx, ownerAccountID, "file.restore", fileID, true,
			map[string]any{"shares_restored": false}, now); err != nil {
			return 0, err
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return expectedVersion + 1, nil
}

func contactByPairTx(ctx context.Context, tx *sql.Tx, lowID, highID string) (Contact, error) {
	return scanContact(tx.QueryRowContext(ctx, `SELECT id, account_low_id, account_high_id,
		low_confirmed_at, high_confirmed_at, state, version, created_at, removed_at
		FROM contacts WHERE account_low_id = ? AND account_high_id = ?`, lowID, highID))
}

func contactForMemberTx(ctx context.Context, tx *sql.Tx, contactID, accountID string) (Contact, error) {
	contact, err := scanContact(tx.QueryRowContext(ctx, `SELECT id, account_low_id, account_high_id,
		low_confirmed_at, high_confirmed_at, state, version, created_at, removed_at
		FROM contacts WHERE id = ? AND (account_low_id = ? OR account_high_id = ?)`, contactID, accountID, accountID))
	if errors.Is(err, sql.ErrNoRows) {
		return Contact{}, ErrResourceNotFound
	}
	return contact, err
}

type rowScanner interface {
	Scan(...any) error
}

func scanContact(row rowScanner) (Contact, error) {
	var contact Contact
	var low, high, created, removed sql.NullString
	if err := row.Scan(&contact.ID, &contact.AccountLowID, &contact.AccountHighID, &low, &high,
		&contact.State, &contact.Version, &created, &removed); err != nil {
		return Contact{}, err
	}
	contact.LowConfirmed, contact.HighConfirmed = low.Valid, high.Valid
	var err error
	contact.CreatedAt, err = time.Parse(time.RFC3339Nano, created.String)
	if err != nil {
		return Contact{}, fmt.Errorf("invalid contact creation time: %w", err)
	}
	if removed.Valid {
		stamp, err := time.Parse(time.RFC3339Nano, removed.String)
		if err != nil {
			return Contact{}, err
		}
		contact.RemovedAt = &stamp
	}
	return contact, nil
}

func shareByFileRecipientTx(ctx context.Context, tx *sql.Tx, fileID, recipientID string) (Share, error) {
	var share Share
	var created string
	err := tx.QueryRowContext(ctx, `SELECT id, file_id, owner_account_id, recipient_account_id,
		contact_id, state, version, created_at FROM shares WHERE file_id = ? AND recipient_account_id = ?`,
		fileID, recipientID).Scan(&share.ID, &share.FileID, &share.OwnerAccountID, &share.RecipientAccountID,
		&share.ContactID, &share.State, &share.Version, &created)
	if err != nil {
		return Share{}, err
	}
	share.CreatedAt, err = time.Parse(time.RFC3339Nano, created)
	return share, err
}
