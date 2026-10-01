package sqlite

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestAccountDeletionRequestExecuteAndShareFreeTransfer(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t)
	now := time.Date(2026, 9, 4, 18, 0, 0, 0, time.UTC)
	owner, _ := store.CreateAccount(ctx, "Delete me", now)
	recipient, _ := store.CreateAccount(ctx, "Keep files", now)
	contact := createActiveContact(t, store, owner, recipient, now.Add(time.Minute))
	upload, _ := completeTestFile(t, store, owner.ID, now.Add(10*time.Minute), true)
	share, err := store.CreateShare(ctx, owner.ID, upload.FileID, contact.ID, 2, now.Add(20*time.Minute))
	if err != nil {
		t.Fatal(err)
	}

	requested, err := store.RecordAccountDeletionRequest(ctx, owner.ID, owner.Version, now.Add(21*time.Minute))
	if err != nil || requested.State != "active" || requested.Version != owner.Version+1 {
		t.Fatalf("request altered account access: %+v %v", requested, err)
	}
	if err := store.AuthorizeCleanDownload(ctx, recipient.ID, upload.FileID); err != nil {
		t.Fatalf("user request changed data before admin action: %v", err)
	}
	var wrapsBefore int
	if err := store.db.QueryRow("SELECT count(*) FROM key_envelopes WHERE file_version_id = ? AND destroyed_at IS NULL", upload.FileVersionID).Scan(&wrapsBefore); err != nil || wrapsBefore != 2 {
		t.Fatalf("request destroyed key wraps: count=%d err=%v", wrapsBefore, err)
	}

	window, err := store.ExecuteAccountDeletion(ctx, "masteradmin", owner.ID, requested.Version, now.Add(22*time.Minute))
	if err != nil || window.FilesLocked != 1 || !window.PurgeAfter.Equal(now.Add(22*time.Minute+accountDeletionWindow)) {
		t.Fatalf("execute failed: %+v %v", window, err)
	}
	if err := store.AuthorizeCleanDownload(ctx, recipient.ID, upload.FileID); !errors.Is(err, ErrResourceNotFound) {
		t.Fatalf("share remained active after account lock: %v", err)
	}
	var shareState, fileState string
	if err := store.db.QueryRow("SELECT state FROM shares WHERE id = ?", share.ID).Scan(&shareState); err != nil {
		t.Fatal(err)
	}
	if err := store.db.QueryRow("SELECT state FROM files WHERE id = ?", upload.FileID).Scan(&fileState); err != nil {
		t.Fatal(err)
	}
	if shareState != "revoked" || fileState != "deletion_pending" {
		t.Fatalf("lock was incomplete: share=%s file=%s", shareState, fileState)
	}

	transfer, err := store.TransferDeletedAccountFiles(ctx, "masteradmin", owner.ID, recipient.ID,
		window.AccountVersion, "Owner requested continuity transfer", now.Add(23*time.Minute))
	if err != nil || transfer.FilesTransferred != 1 {
		t.Fatalf("transfer failed: %+v %v", transfer, err)
	}
	if err := store.AuthorizeCleanDownload(ctx, recipient.ID, upload.FileID); err != nil {
		t.Fatalf("new owner cannot access transferred clean file: %v", err)
	}
	var activeShares int
	if err := store.db.QueryRow("SELECT count(*) FROM shares WHERE file_id = ? AND state = 'active'", upload.FileID).Scan(&activeShares); err != nil {
		t.Fatal(err)
	}
	if activeShares != 0 {
		t.Fatal("transfer carried an old share")
	}
	if purged, err := store.PurgeExpiredAccounts(ctx, window.PurgeAfter); err != nil || len(purged) != 1 || purged[0].FilesPurged != 0 {
		t.Fatalf("source tombstone purge touched transferred files: %+v %v", purged, err)
	}
	if err := store.AuthorizeCleanDownload(ctx, recipient.ID, upload.FileID); err != nil {
		t.Fatalf("source purge destroyed transferred file: %v", err)
	}
	if err := store.VerifyAuditChain(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestAccountCryptoPurgeWaitsThirtyDaysAndRetainsNameTombstone(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t)
	now := time.Date(2026, 9, 4, 19, 0, 0, 0, time.UTC)
	owner, _ := store.CreateAccount(ctx, "Forever reserved", now)
	upload, _ := completeTestFile(t, store, owner.ID, now.Add(time.Minute), true)
	requested, err := store.RecordAccountDeletionRequest(ctx, owner.ID, owner.Version, now.Add(10*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	window, err := store.ExecuteAccountDeletion(ctx, "masteradmin", owner.ID, requested.Version, now.Add(11*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if purged, err := store.PurgeExpiredAccounts(ctx, window.PurgeAfter.Add(-time.Nanosecond)); err != nil || len(purged) != 0 {
		t.Fatalf("purged before deadline: %+v %v", purged, err)
	}
	var intact int
	if err := store.db.QueryRow("SELECT count(*) FROM key_envelopes WHERE file_version_id = ? AND destroyed_at IS NULL", upload.FileVersionID).Scan(&intact); err != nil || intact != 2 {
		t.Fatalf("wraps did not survive transfer window: %d %v", intact, err)
	}
	purged, err := store.PurgeExpiredAccounts(ctx, window.PurgeAfter)
	if err != nil || len(purged) != 1 || purged[0].FilesPurged != 1 || purged[0].ObjectsQueued != 1 {
		t.Fatalf("crypto purge failed: %+v %v", purged, err)
	}
	var accountState, fileState, filename string
	var bytes, intactWraps, deleteMessages int64
	if err := store.db.QueryRow("SELECT state FROM accounts WHERE id = ?", owner.ID).Scan(&accountState); err != nil {
		t.Fatal(err)
	}
	if err := store.db.QueryRow("SELECT state, filename, logical_size_bytes FROM files WHERE id = ?", upload.FileID).Scan(&fileState, &filename, &bytes); err != nil {
		t.Fatal(err)
	}
	if err := store.db.QueryRow("SELECT count(*) FROM key_envelopes WHERE file_version_id = ? AND destroyed_at IS NULL", upload.FileVersionID).Scan(&intactWraps); err != nil {
		t.Fatal(err)
	}
	if err := store.db.QueryRow("SELECT count(*) FROM outbox WHERE topic = 'file.delete' AND published_at IS NULL").Scan(&deleteMessages); err != nil {
		t.Fatal(err)
	}
	if accountState != "tombstoned" || fileState != "purged" || filename != "deleted" || bytes != 0 || intactWraps != 0 || deleteMessages != 1 {
		t.Fatalf("purge incomplete: account=%s file=%s name=%s bytes=%d wraps=%d delete=%d", accountState, fileState, filename, bytes, intactWraps, deleteMessages)
	}
	if _, err := store.CreateAccount(ctx, "FOREVER RESERVED", window.PurgeAfter.Add(time.Minute)); !errors.Is(err, ErrUsernameTaken) {
		t.Fatalf("tombstoned name was reusable: %v", err)
	}
}

func TestAccountDeletionAbortsUnfinishedProviderUpload(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t)
	now := time.Date(2026, 9, 4, 20, 0, 0, 0, time.UTC)
	owner, _ := store.CreateAccount(ctx, "Interrupted upload", now)
	upload := startTestUpload(t, store, owner.ID, 1024, now.Add(time.Minute))
	if err := store.AttachProviderUpload(ctx, owner.ID, upload.UploadSessionID, "provider-upload-delete", now.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	requested, _ := store.RecordAccountDeletionRequest(ctx, owner.ID, owner.Version, now.Add(3*time.Minute))
	if _, err := store.ExecuteAccountDeletion(ctx, "masteradmin", owner.ID, requested.Version, now.Add(4*time.Minute)); err != nil {
		t.Fatal(err)
	}
	var uploadState, reservationState, fileState string
	var intactWraps, abortMessages int
	if err := store.db.QueryRow("SELECT state FROM upload_sessions WHERE id = ?", upload.UploadSessionID).Scan(&uploadState); err != nil {
		t.Fatal(err)
	}
	if err := store.db.QueryRow("SELECT state FROM quota_reservations WHERE id = ?", upload.ReservationID).Scan(&reservationState); err != nil {
		t.Fatal(err)
	}
	if err := store.db.QueryRow("SELECT state FROM files WHERE id = ?", upload.FileID).Scan(&fileState); err != nil {
		t.Fatal(err)
	}
	if err := store.db.QueryRow("SELECT count(*) FROM key_envelopes WHERE file_version_id = ? AND destroyed_at IS NULL", upload.FileVersionID).Scan(&intactWraps); err != nil {
		t.Fatal(err)
	}
	if err := store.db.QueryRow("SELECT count(*) FROM outbox WHERE topic = 'upload.abort'").Scan(&abortMessages); err != nil {
		t.Fatal(err)
	}
	if uploadState != "aborted" || reservationState != "released" || fileState != "purged" || intactWraps != 0 || abortMessages != 1 {
		t.Fatalf("unfinished upload not safely aborted: upload=%s reservation=%s file=%s wraps=%d messages=%d", uploadState, reservationState, fileState, intactWraps, abortMessages)
	}
}
