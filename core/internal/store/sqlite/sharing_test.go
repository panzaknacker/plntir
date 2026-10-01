package sqlite

import (
	"context"
	"crypto/sha256"
	"errors"
	"testing"
	"time"
)

func completeTestFile(t *testing.T, store *Store, ownerID string, now time.Time, clean bool) (Upload, UploadCompletion) {
	t.Helper()
	ctx := context.Background()
	upload := startTestUpload(t, store, ownerID, 1024, now)
	if err := store.AttachProviderUpload(ctx, ownerID, upload.UploadSessionID, "r2-complete-id", now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	partHash := sha256.Sum256([]byte("ciphertext part"))
	if _, err := store.ConfirmUploadPart(ctx, UploadPartRequest{
		OwnerAccountID: ownerID, UploadSessionID: upload.UploadSessionID,
		PartNumber: 1, SizeBytes: 1024 + ChunkTagBytes, CiphertextHash: partHash,
		ETag: "part-one", Now: now.Add(2 * time.Minute),
	}); err != nil {
		t.Fatal(err)
	}
	completion, err := store.CompleteUpload(ctx, CompleteUploadRequest{
		OwnerAccountID: ownerID, UploadSessionID: upload.UploadSessionID,
		CiphertextBytes: upload.ExpectedCiphertextBytes,
		PlaintextHash:   sha256.Sum256([]byte("plain")), CiphertextHash: sha256.Sum256([]byte("cipher")),
		R2ETag: "final-one", Now: now.Add(3 * time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
	if clean {
		if err := store.applyTrustedScanVerdict(ctx, ScanVerdictRequest{
			ScanJobID: completion.ScanJobID, FileVersionID: completion.FileVersionID,
			Verdict: "clean", EngineVersion: "qualified-test", RulesVersion: "rules-test",
			VerdictSHA256: sha256.Sum256([]byte("verdict")), Now: now.Add(4 * time.Minute),
		}); err != nil {
			t.Fatal(err)
		}
	}
	return upload, completion
}

func createActiveContact(t *testing.T, store *Store, first, second Account, now time.Time) Contact {
	t.Helper()
	ctx := context.Background()
	tokenHash := sha256.Sum256([]byte("unguessable one-time contact token"))
	if _, err := store.CreateContactInvite(ctx, first.ID, first.Version, tokenHash, now); err != nil {
		t.Fatal(err)
	}
	contact, err := store.AcceptContactInvite(ctx, second.ID, second.Version, tokenHash, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if contact.State != "pending" || contact.LowConfirmed || contact.HighConfirmed {
		t.Fatalf("contact skipped bilateral confirmation: %+v", contact)
	}
	if _, err := store.AcceptContactInvite(ctx, second.ID, second.Version, tokenHash, now.Add(time.Minute)); !errors.Is(err, ErrResourceNotFound) {
		t.Fatalf("one-time contact token was replayable: %v", err)
	}
	contact, err = store.ConfirmContact(ctx, first.ID, contact.ID, contact.Version, now.Add(2*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if contact.State != "pending" {
		t.Fatal("one confirmation activated a contact")
	}
	contact, err = store.ConfirmContact(ctx, second.ID, contact.ID, contact.Version, now.Add(3*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if contact.State != "active" || !contact.LowConfirmed || !contact.HighConfirmed {
		t.Fatalf("bilateral contact did not activate: %+v", contact)
	}
	return contact
}

func TestContactShareRevokeTrashAndRestoreIsolation(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t)
	now := time.Date(2026, 9, 4, 13, 0, 0, 0, time.UTC)
	owner, err := store.CreateAccount(ctx, "File owner", now)
	if err != nil {
		t.Fatal(err)
	}
	recipient, err := store.CreateAccount(ctx, "Recipient", now)
	if err != nil {
		t.Fatal(err)
	}
	stranger, err := store.CreateAccount(ctx, "Stranger", now)
	if err != nil {
		t.Fatal(err)
	}
	contact := createActiveContact(t, store, owner, recipient, now)
	upload, _ := completeTestFile(t, store, owner.ID, now.Add(10*time.Minute), true)

	share, err := store.CreateShare(ctx, owner.ID, upload.FileID, contact.ID, 2, now.Add(20*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.AuthorizeCleanDownload(ctx, recipient.ID, upload.FileID); err != nil {
		t.Fatalf("recipient did not receive clean file: %v", err)
	}
	if err := store.AuthorizeCleanDownload(ctx, stranger.ID, upload.FileID); !errors.Is(err, ErrResourceNotFound) {
		t.Fatalf("unrelated account learned or received file: %v", err)
	}
	if _, err := store.CreateShare(ctx, recipient.ID, upload.FileID, contact.ID, 2, now.Add(21*time.Minute)); !errors.Is(err, ErrResourceNotFound) {
		t.Fatalf("recipient could reshare owner file: %v", err)
	}

	if err := store.RevokeShare(ctx, owner.ID, share.ID, share.Version, now.Add(22*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := store.AuthorizeCleanDownload(ctx, recipient.ID, upload.FileID); !errors.Is(err, ErrResourceNotFound) {
		t.Fatalf("revoked recipient retained access: %v", err)
	}
	share, err = store.CreateShare(ctx, owner.ID, upload.FileID, contact.ID, 2, now.Add(23*time.Minute))
	if err != nil || share.State != "active" {
		t.Fatalf("explicit reshare failed: %+v %v", share, err)
	}

	fileVersion, err := store.TrashFile(ctx, owner.ID, upload.FileID, 2, now.Add(24*time.Minute))
	if err != nil || fileVersion != 3 {
		t.Fatalf("trash failed: version=%d err=%v", fileVersion, err)
	}
	if err := store.AuthorizeCleanDownload(ctx, recipient.ID, upload.FileID); !errors.Is(err, ErrResourceNotFound) {
		t.Fatalf("trashed file remained downloadable: %v", err)
	}
	fileVersion, err = store.RestoreFile(ctx, owner.ID, upload.FileID, fileVersion, now.Add(25*time.Minute))
	if err != nil || fileVersion != 4 {
		t.Fatalf("restore failed: version=%d err=%v", fileVersion, err)
	}
	if err := store.AuthorizeCleanDownload(ctx, owner.ID, upload.FileID); err != nil {
		t.Fatalf("owner could not download restored clean file: %v", err)
	}
	if err := store.AuthorizeCleanDownload(ctx, recipient.ID, upload.FileID); !errors.Is(err, ErrResourceNotFound) {
		t.Fatalf("restore resurrected a revoked share: %v", err)
	}
	share, err = store.CreateShare(ctx, owner.ID, upload.FileID, contact.ID, fileVersion, now.Add(26*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.RemoveContact(ctx, recipient.ID, contact.ID, contact.Version, now.Add(27*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := store.AuthorizeCleanDownload(ctx, recipient.ID, upload.FileID); !errors.Is(err, ErrResourceNotFound) {
		t.Fatalf("removed contact retained share access: %v", err)
	}
	if err := store.VerifyAuditChain(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestSharingIsLockedUntilCleanVerdict(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t)
	now := time.Date(2026, 9, 4, 14, 0, 0, 0, time.UTC)
	owner, err := store.CreateAccount(ctx, "Pending owner", now)
	if err != nil {
		t.Fatal(err)
	}
	recipient, err := store.CreateAccount(ctx, "Pending recipient", now)
	if err != nil {
		t.Fatal(err)
	}
	contact := createActiveContact(t, store, owner, recipient, now)
	upload, _ := completeTestFile(t, store, owner.ID, now.Add(10*time.Minute), false)
	if _, err := store.CreateShare(ctx, owner.ID, upload.FileID, contact.ID, 2, now.Add(20*time.Minute)); !errors.Is(err, ErrScanLocked) {
		t.Fatalf("unscanned file was shareable: %v", err)
	}
	if err := store.AuthorizeCleanDownload(ctx, owner.ID, upload.FileID); !errors.Is(err, ErrScanLocked) {
		t.Fatalf("unscanned file was downloadable: %v", err)
	}
}

func TestNonMemberCannotConfirmContact(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t)
	now := time.Date(2026, 9, 4, 15, 0, 0, 0, time.UTC)
	first, _ := store.CreateAccount(ctx, "One", now)
	second, _ := store.CreateAccount(ctx, "Two", now)
	third, _ := store.CreateAccount(ctx, "Three", now)
	tokenHash := sha256.Sum256([]byte("contact token two"))
	if _, err := store.CreateContactInvite(ctx, first.ID, first.Version, tokenHash, now); err != nil {
		t.Fatal(err)
	}
	contact, err := store.AcceptContactInvite(ctx, second.ID, second.Version, tokenHash, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.ConfirmContact(ctx, third.ID, contact.ID, contact.Version, now); !errors.Is(err, ErrResourceNotFound) {
		t.Fatalf("non-member contact confirmation leaked existence: %v", err)
	}
}
