package sqlite

import (
	"context"
	"crypto/sha256"
	"errors"
	"strings"
	"testing"
	"time"
)

func startTestUpload(t *testing.T, store *Store, ownerID string, size int64, now time.Time) Upload {
	t.Helper()
	upload, err := store.StartUpload(context.Background(), UploadRequest{
		OwnerAccountID: ownerID,
		Filename:       "resume.bin",
		MediaKind:      "standard",
		PlaintextBytes: size,
		ManifestSHA256: sha256.Sum256([]byte("manifest-v1")),
		NoncePrefix:    [4]byte{1, 3, 3, 7},
		KMSEnvelope: KeyEnvelopeInput{
			Algorithm: "SYMMETRIC_DEFAULT", KeyReference: "arn:aws:kms:eu-central-1:123456789012:key/test",
			Ciphertext: []byte{1, 2, 3, 4},
		},
		OfflineEnvelope: KeyEnvelopeInput{
			Algorithm: "X25519-HKDF-SHA256-AES-256-GCM", KeyReference: "offline-recovery-v1",
			Ciphertext: make([]byte, 80),
		},
		Now: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	return upload
}

func TestMultipartResumeCompleteAndVerdictAreAtomic(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t)
	now := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	owner, err := store.CreateAccount(ctx, "Owner", now)
	if err != nil {
		t.Fatal(err)
	}
	other, err := store.CreateAccount(ctx, "Other", now)
	if err != nil {
		t.Fatal(err)
	}
	upload := startTestUpload(t, store, owner.ID, StandardPartBytes+7, now)
	if upload.ExpectedParts != 2 || upload.ExpectedCiphertextBytes != StandardPartBytes+7+2*ChunkTagBytes {
		t.Fatalf("unexpected chunk plan: %+v", upload)
	}
	if err := store.AttachProviderUpload(ctx, owner.ID, upload.UploadSessionID, "r2-multipart-opaque", now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := store.AttachProviderUpload(ctx, owner.ID, upload.UploadSessionID, "r2-multipart-opaque", now.Add(time.Minute)); err != nil {
		t.Fatalf("idempotent provider attach failed: %v", err)
	}
	if _, err := store.ResumeUpload(ctx, other.ID, upload.UploadSessionID, now.Add(time.Minute)); !errors.Is(err, ErrResourceNotFound) {
		t.Fatalf("cross-account upload lookup leaked existence: %v", err)
	}

	secondHash := sha256.Sum256([]byte("second ciphertext part"))
	status, err := store.ConfirmUploadPart(ctx, UploadPartRequest{
		OwnerAccountID: owner.ID, UploadSessionID: upload.UploadSessionID,
		PartNumber: 2, SizeBytes: 7 + ChunkTagBytes, CiphertextHash: secondHash,
		ETag: `"part-two"`, Now: now.Add(2 * time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
	if status.NextPart != 1 {
		t.Fatalf("out-of-order resume next part = %d, want 1", status.NextPart)
	}
	resumed, err := store.ResumeUpload(ctx, owner.ID, upload.UploadSessionID, now.Add(3*time.Minute))
	if err != nil || resumed.NextPart != 1 || len(resumed.Parts) != 1 || resumed.Parts[0].PartNumber != 2 {
		t.Fatalf("resume lost confirmed state: %+v %v", resumed, err)
	}

	firstHash := sha256.Sum256([]byte("first ciphertext part"))
	status, err = store.ConfirmUploadPart(ctx, UploadPartRequest{
		OwnerAccountID: owner.ID, UploadSessionID: upload.UploadSessionID,
		PartNumber: 1, SizeBytes: StandardPartBytes + ChunkTagBytes, CiphertextHash: firstHash,
		ETag: "part-one", Now: now.Add(4 * time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
	if status.NextPart != 3 {
		t.Fatalf("complete part set next part = %d, want 3", status.NextPart)
	}
	if _, err := store.ConfirmUploadPart(ctx, UploadPartRequest{
		OwnerAccountID: owner.ID, UploadSessionID: upload.UploadSessionID,
		PartNumber: 1, SizeBytes: StandardPartBytes + ChunkTagBytes,
		CiphertextHash: sha256.Sum256([]byte("changed")), ETag: "part-one", Now: now.Add(5 * time.Minute),
	}); !errors.Is(err, ErrPartConflict) {
		t.Fatalf("changed checksum was not rejected: %v", err)
	}

	plainHash := sha256.Sum256([]byte("plaintext"))
	cipherHash := sha256.Sum256([]byte("complete ciphertext"))
	completeRequest := CompleteUploadRequest{
		OwnerAccountID: owner.ID, UploadSessionID: upload.UploadSessionID,
		CiphertextBytes: upload.ExpectedCiphertextBytes, PlaintextHash: plainHash,
		CiphertextHash: cipherHash, R2ETag: `"final-etag-2"`, Now: now.Add(6 * time.Minute),
	}
	completion, err := store.CompleteUpload(ctx, completeRequest)
	if err != nil {
		t.Fatal(err)
	}
	if completion.ScanState != "queued" || !strings.HasPrefix(completion.ScanJobID, "scan_") {
		t.Fatalf("unexpected completion: %+v", completion)
	}
	repeated, err := store.CompleteUpload(ctx, completeRequest)
	if err != nil || repeated.ScanJobID != completion.ScanJobID {
		t.Fatalf("idempotent completion changed job: %+v %v", repeated, err)
	}
	var reservationState, fileState, scanState string
	var outboxCount int
	if err := store.db.QueryRow("SELECT state FROM quota_reservations WHERE id = ?", upload.ReservationID).Scan(&reservationState); err != nil {
		t.Fatal(err)
	}
	if err := store.db.QueryRow("SELECT state FROM files WHERE id = ?", upload.FileID).Scan(&fileState); err != nil {
		t.Fatal(err)
	}
	if err := store.db.QueryRow("SELECT count(*) FROM outbox WHERE topic = 'scan.requested'").Scan(&outboxCount); err != nil {
		t.Fatal(err)
	}
	if reservationState != "committed" || fileState != "active" || outboxCount != 1 {
		t.Fatalf("completion transaction split: reservation=%s file=%s outbox=%d", reservationState, fileState, outboxCount)
	}

	verdictHash := sha256.Sum256([]byte("signed clean result"))
	verdict := ScanVerdictRequest{
		ScanJobID: completion.ScanJobID, FileVersionID: completion.FileVersionID,
		Verdict: "clean", EngineVersion: "clamav-test", RulesVersion: "corpus-test",
		VerdictSHA256: verdictHash, Now: now.Add(7 * time.Minute),
	}
	if err := store.applyTrustedScanVerdict(ctx, verdict); err != nil {
		t.Fatal(err)
	}
	if err := store.applyTrustedScanVerdict(ctx, verdict); err != nil {
		t.Fatalf("idempotent scan result failed: %v", err)
	}
	if err := store.db.QueryRow("SELECT scan_state FROM file_versions WHERE id = ?", completion.FileVersionID).Scan(&scanState); err != nil {
		t.Fatal(err)
	}
	if scanState != "clean" {
		t.Fatalf("file version scan state = %s", scanState)
	}
	verdict.VerdictSHA256 = sha256.Sum256([]byte("different result"))
	if err := store.applyTrustedScanVerdict(ctx, verdict); !errors.Is(err, ErrVersionConflict) {
		t.Fatalf("conflicting duplicate verdict was accepted: %v", err)
	}
	if err := store.VerifyAuditChain(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestAbortReleasesQuotaDestroysWrapsAndQueuesProviderAbort(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t)
	now := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	owner, err := store.CreateAccount(ctx, "Abort owner", now)
	if err != nil {
		t.Fatal(err)
	}
	upload := startTestUpload(t, store, owner.ID, 1024, now)
	if err := store.AttachProviderUpload(ctx, owner.ID, upload.UploadSessionID, "r2-abort-id", now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := store.AbortUpload(ctx, owner.ID, upload.UploadSessionID, now.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := store.AbortUpload(ctx, owner.ID, upload.UploadSessionID, now.Add(3*time.Minute)); err != nil {
		t.Fatalf("idempotent abort failed: %v", err)
	}
	var reservationState, fileState string
	var logicalSize, intactWraps, abortMessages int64
	if err := store.db.QueryRow("SELECT state FROM quota_reservations WHERE id = ?", upload.ReservationID).Scan(&reservationState); err != nil {
		t.Fatal(err)
	}
	if err := store.db.QueryRow("SELECT state, logical_size_bytes FROM files WHERE id = ?", upload.FileID).Scan(&fileState, &logicalSize); err != nil {
		t.Fatal(err)
	}
	if err := store.db.QueryRow("SELECT count(*) FROM key_envelopes WHERE file_version_id = ? AND destroyed_at IS NULL", upload.FileVersionID).Scan(&intactWraps); err != nil {
		t.Fatal(err)
	}
	if err := store.db.QueryRow("SELECT count(*) FROM outbox WHERE topic = 'upload.abort'").Scan(&abortMessages); err != nil {
		t.Fatal(err)
	}
	if reservationState != "released" || fileState != "purged" || logicalSize != 0 || intactWraps != 0 || abortMessages != 1 {
		t.Fatalf("abort transaction incomplete: reservation=%s file=%s bytes=%d wraps=%d outbox=%d",
			reservationState, fileState, logicalSize, intactWraps, abortMessages)
	}
}

func TestIncompleteAndExpiredUploadsFailClosed(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t)
	now := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	owner, err := store.CreateAccount(ctx, "Expiry owner", now)
	if err != nil {
		t.Fatal(err)
	}
	upload := startTestUpload(t, store, owner.ID, StandardPartBytes+1, now)
	if err := store.AttachProviderUpload(ctx, owner.ID, upload.UploadSessionID, "r2-expiry-id", now); err != nil {
		t.Fatal(err)
	}
	_, err = store.CompleteUpload(ctx, CompleteUploadRequest{
		OwnerAccountID: owner.ID, UploadSessionID: upload.UploadSessionID,
		CiphertextBytes: upload.ExpectedCiphertextBytes, PlaintextHash: sha256.Sum256(nil),
		CiphertextHash: sha256.Sum256([]byte("cipher")), R2ETag: "final", Now: now.Add(time.Hour),
	})
	if !errors.Is(err, ErrIncompleteUpload) {
		t.Fatalf("incomplete upload returned %v", err)
	}
	if _, err := store.ResumeUpload(ctx, owner.ID, upload.UploadSessionID, now.Add(24*time.Hour)); !errors.Is(err, ErrUploadExpired) {
		t.Fatalf("expired upload returned %v", err)
	}
}
