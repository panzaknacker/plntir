package sqlite

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"plntir/core/internal/envelope"
	"plntir/core/internal/wazuhintegrity"
)

func TestWazuhProjectionIsMonotonicIdempotentAndSanitized(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t)
	now := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	publicKey, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	record, projection, signed := sqliteWazuhProjection(t, 1, [sha256.Size]byte{}, now, privateKey)
	created, err := store.AcceptWazuhProjection(ctx, signed, projection, publicKey, now)
	if err != nil || !created {
		t.Fatalf("first projection was not created: %t %v", created, err)
	}
	created, err = store.AcceptWazuhProjection(ctx, signed, projection, publicKey, now.Add(24*time.Hour))
	if err != nil || created {
		t.Fatalf("identical retry was not idempotent: %t %v", created, err)
	}
	var count int
	var sequence int64
	var agentID, chainHash string
	if err := store.db.QueryRow(`
		SELECT count(*), last_sequence, coalesce(agent_id, ''), chain_hash
		FROM wazuh_health_projection`).Scan(&count, &sequence, &agentID, &chainHash); err != nil {
		t.Fatal(err)
	}
	if count != 1 || sequence != 1 || agentID != "001" || chainHash != record.EntryHash {
		t.Fatalf("stored projection drifted: count=%d sequence=%d agent=%q hash=%q", count, sequence, agentID, chainHash)
	}
	previous, _ := record.Hash()
	_, nextProjection, nextSigned := sqliteWazuhProjection(t, 2, previous, now.Add(2*time.Second), privateKey)
	created, err = store.AcceptWazuhProjection(ctx, nextSigned, nextProjection, publicKey, now.Add(2*time.Second))
	if err != nil || !created {
		t.Fatalf("next monotonic projection failed: %t %v", created, err)
	}
	if err := store.db.QueryRow(`SELECT count(*) FROM ingested_envelopes WHERE source = 'plntir-siem-01'`).Scan(&count); err != nil || count != 2 {
		t.Fatalf("projection envelope ledger count=%d err=%v", count, err)
	}
}

func TestWazuhProjectionRejectsSequenceDeduplicationAndSignatureConflicts(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t)
	now := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	publicKey, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	_, firstProjection, firstSigned := sqliteWazuhProjection(t, 1, [sha256.Size]byte{}, now, privateKey)
	if _, err := store.AcceptWazuhProjection(ctx, firstSigned, firstProjection, publicKey, now); err != nil {
		t.Fatal(err)
	}

	_, conflictingProjection, conflictingSigned := sqliteWazuhProjection(t, 1, [sha256.Size]byte{}, now.Add(time.Second), privateKey)
	if _, err := store.AcceptWazuhProjection(ctx, conflictingSigned, conflictingProjection, publicKey, now.Add(time.Second)); !errors.Is(err, wazuhintegrity.ErrProjectionStoreConflict) {
		t.Fatalf("same sequence conflict was accepted: %v", err)
	}

	_, nextProjection, nextSigned := sqliteWazuhProjection(t, 2, [sha256.Size]byte{}, now.Add(2*time.Second), privateKey)
	nextSigned.DeduplicationID = firstSigned.DeduplicationID
	if err := envelope.Sign(&nextSigned, privateKey); err != nil {
		t.Fatal(err)
	}
	if _, err := store.AcceptWazuhProjection(ctx, nextSigned, nextProjection, publicKey, now.Add(2*time.Second)); !errors.Is(err, wazuhintegrity.ErrProjectionStoreConflict) {
		t.Fatalf("deduplication conflict was accepted: %v", err)
	}

	wrongPublic, _, _ := ed25519.GenerateKey(rand.Reader)
	_, validProjection, validSigned := sqliteWazuhProjection(t, 2, [sha256.Size]byte{}, now.Add(3*time.Second), privateKey)
	if _, err := store.AcceptWazuhProjection(ctx, validSigned, validProjection, wrongPublic, now.Add(3*time.Second)); !errors.Is(err, wazuhintegrity.ErrProjectionAuthentication) {
		t.Fatalf("wrong signing key was accepted: %v", err)
	}

	_, gapProjection, gapSigned := sqliteWazuhProjection(t, 3, [sha256.Size]byte{}, now.Add(4*time.Second), privateKey)
	if _, err := store.AcceptWazuhProjection(ctx, gapSigned, gapProjection, publicKey, now.Add(4*time.Second)); !errors.Is(err, wazuhintegrity.ErrProjectionStoreConflict) {
		t.Fatalf("sequence gap was accepted: %v", err)
	}
}

func TestWazuhProjectionSchemaRejectsSequenceDowngrade(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t)
	now := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	publicKey, privateKey, _ := ed25519.GenerateKey(rand.Reader)

	record, firstProjection, firstSigned := sqliteWazuhProjection(t, 1, [sha256.Size]byte{}, now, privateKey)
	if _, err := store.AcceptWazuhProjection(ctx, firstSigned, firstProjection, publicKey, now); err != nil {
		t.Fatal(err)
	}
	previous, err := record.Hash()
	if err != nil {
		t.Fatal(err)
	}
	_, secondProjection, secondSigned := sqliteWazuhProjection(t, 2, previous, now.Add(time.Second), privateKey)
	if _, err := store.AcceptWazuhProjection(ctx, secondSigned, secondProjection, publicKey, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}

	if _, err := store.db.ExecContext(ctx, `
		UPDATE wazuh_health_projection
		SET last_sequence = 1
		WHERE source = 'plntir-siem-01'`); err == nil {
		t.Fatal("schema accepted a direct Wazuh sequence downgrade")
	}
}

func sqliteWazuhProjection(
	t *testing.T,
	sequence uint64,
	previous [sha256.Size]byte,
	now time.Time,
	privateKey ed25519.PrivateKey,
) (wazuhintegrity.Record, wazuhintegrity.HealthProjection, envelope.Envelope) {
	t.Helper()
	raw, _ := json.Marshal(map[string]any{
		"timestamp": now.Format(time.RFC3339Nano),
		"rule":      map[string]any{"id": "5710", "level": 13, "description": "raw-only"},
		"agent":     map[string]any{"id": "001", "name": "mac-secret-name"},
		"data":      map[string]any{"password": "never-store-in-core"},
	})
	record, err := wazuhintegrity.NewRecord(sequence, previous, raw, now)
	if err != nil {
		t.Fatal(err)
	}
	projection, err := wazuhintegrity.ProjectionFromRecord(record, now)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := wazuhintegrity.SignProjection(projection, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	return record, projection, signed
}
