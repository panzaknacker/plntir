package sqlite

import (
	"context"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func openTestStore(t *testing.T) *Store {
	t.Helper()
	store, err := Open(context.Background(), filepath.Join(t.TempDir(), "core.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func TestOpenUsesWALAndProtectedFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "core.db")
	store, err := Open(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.QuickCheck(context.Background()); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("database mode = %04o, want 0600", got)
	}
	var mode string
	if err := store.db.QueryRow("PRAGMA journal_mode").Scan(&mode); err != nil {
		t.Fatal(err)
	}
	if mode != "wal" {
		t.Fatalf("journal mode %q, want wal", mode)
	}
}

func TestHistoricUsernameRemainsReservedForOwner(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t)
	now := time.Date(2026, 9, 4, 10, 0, 0, 0, time.UTC)
	first, err := store.CreateAccount(ctx, "Mira", now)
	if err != nil {
		t.Fatal(err)
	}
	renamed, err := store.RenameAccount(ctx, first.ID, "Nova", first.Version, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if renamed.Version != 2 {
		t.Fatalf("version = %d, want 2", renamed.Version)
	}
	if _, err := store.CreateAccount(ctx, "MIRA", now.Add(2*time.Minute)); !errors.Is(err, ErrUsernameTaken) {
		t.Fatalf("old username was not retained: %v", err)
	}
	back, err := store.RenameAccount(ctx, first.ID, "mira", renamed.Version, now.Add(3*time.Minute))
	if err != nil {
		t.Fatalf("owner could not reclaim historic name: %v", err)
	}
	if back.UsernameCanonical != "mira" {
		t.Fatalf("unexpected canonical %q", back.UsernameCanonical)
	}
	if _, err := store.RenameAccount(ctx, first.ID, "Again", 1, now); !errors.Is(err, ErrVersionConflict) {
		t.Fatalf("stale version unexpectedly accepted: %v", err)
	}
}

func TestStartUploadReservesFullSizeAndUsesOpaqueObjectKey(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t)
	now := time.Date(2026, 9, 4, 10, 0, 0, 0, time.UTC)
	account, err := store.CreateAccount(ctx, "Uploader \U0001F680", now)
	if err != nil {
		t.Fatal(err)
	}
	upload, err := store.StartUpload(ctx, UploadRequest{
		OwnerAccountID:  account.ID,
		Filename:        "private-name.txt",
		MediaKind:       "standard",
		PlaintextBytes:  4_000_000_000,
		ManifestSHA256:  sha256.Sum256([]byte("manifest")),
		NoncePrefix:     [4]byte{1, 2, 3, 4},
		KMSEnvelope:     KeyEnvelopeInput{Algorithm: "SYMMETRIC_DEFAULT", KeyReference: "alias/plntir-files", Ciphertext: []byte{1, 2, 3}},
		OfflineEnvelope: KeyEnvelopeInput{Algorithm: "X25519-HKDF-SHA256-AES-256-GCM", KeyReference: "offline-v1", Ciphertext: make([]byte, 80)},
		Now:             now,
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(upload.ObjectKey, "private-name") || strings.Contains(upload.ObjectKey, account.ID) {
		t.Fatalf("object key leaks metadata: %q", upload.ObjectKey)
	}
	var reserved int64
	if err := store.db.QueryRow("SELECT bytes FROM quota_reservations WHERE id = ?", upload.ReservationID).Scan(&reserved); err != nil {
		t.Fatal(err)
	}
	if reserved != 4_000_000_000 {
		t.Fatalf("reserved %d bytes", reserved)
	}
}

func TestLargeMediaRequiresBothGrantAndManagedMac(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t)
	now := time.Date(2026, 9, 4, 10, 0, 0, 0, time.UTC)
	account, err := store.CreateAccount(ctx, "Media owner", now)
	if err != nil {
		t.Fatal(err)
	}
	request := UploadRequest{
		OwnerAccountID:  account.ID,
		Filename:        "large.mov",
		MediaKind:       "video",
		PlaintextBytes:  MaxStandardFileBytes + 1,
		ManifestSHA256:  sha256.Sum256([]byte("large manifest")),
		NoncePrefix:     [4]byte{4, 3, 2, 1},
		KMSEnvelope:     KeyEnvelopeInput{Algorithm: "SYMMETRIC_DEFAULT", KeyReference: "alias/plntir-files", Ciphertext: []byte{1, 2, 3}},
		OfflineEnvelope: KeyEnvelopeInput{Algorithm: "X25519-HKDF-SHA256-AES-256-GCM", KeyReference: "offline-v1", Ciphertext: make([]byte, 80)},
		Now:             now,
	}
	if _, err := store.StartUpload(ctx, request); !errors.Is(err, ErrMediaPermission) {
		t.Fatalf("ungranted media unexpectedly accepted: %v", err)
	}
	request.ManagedMac = true
	request.LargeMediaGrant = true
	upload, err := store.StartUpload(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	if upload.PartSizeBytes < MediaPartBytes {
		t.Fatalf("large-media part size %d is below 64 MiB", upload.PartSizeBytes)
	}
}

func TestAuditChainDetectsTampering(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t)
	now := time.Date(2026, 9, 4, 10, 0, 0, 0, time.UTC)
	if _, err := store.AppendAudit(ctx, "operator", "device.inspect", "device-1", true, map[string]any{"reason": "test"}, now); err != nil {
		t.Fatal(err)
	}
	if _, err := store.AppendAudit(ctx, "operator", "device.action", "device-1", false, map[string]any{"action": "isolate"}, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := store.VerifyAuditChain(ctx); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("tampered"))
	if _, err := store.db.Exec("UPDATE audit_log SET entry_hash = ? WHERE sequence = 1", digest[:]); err != nil {
		t.Fatal(err)
	}
	if err := store.VerifyAuditChain(ctx); err == nil {
		t.Fatal("tampered audit chain unexpectedly verified")
	}
}

func TestOpenRejectsTamperedMigrationRecord(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "core.db")
	store, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.Exec("UPDATE schema_migrations SET sha256 = zeroblob(32) WHERE version = 2"); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if reopened, err := Open(ctx, path); err == nil {
		_ = reopened.Close()
		t.Fatal("tampered migration record was accepted")
	}
}
