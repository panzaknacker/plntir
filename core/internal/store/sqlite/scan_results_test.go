package sqlite

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"plntir/core/internal/scanresult"
)

func TestSignedScanResultIsVerifiedAndAppliedAtomically(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t)
	now := time.Date(2026, 9, 5, 0, 0, 0, 0, time.UTC)
	owner, _ := store.CreateAccount(ctx, "Signed scan owner", now.Add(-time.Hour))
	upload, completion := completeTestFile(t, store, owner.ID, now.Add(-30*time.Minute), false)
	publicKey, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	plainHash := sha256.Sum256([]byte("plain"))
	payload := scanresult.Payload{
		ScanJobID: completion.ScanJobID, FileVersionID: completion.FileVersionID, ObjectKey: upload.ObjectKey,
		EventTime: now.Add(-20 * time.Minute).Format(time.RFC3339Nano), Verdict: "clean",
		EngineVersion: "clamav-qualified-1", RuleVersion: "rules-20260905",
		ContentSHA256: hex.EncodeToString(plainHash[:]), DetectedType: "application/octet-stream",
		ScannedAt: now.Format(time.RFC3339Nano),
	}
	result, err := scanresult.NewEnvelope(payload, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	duplicate, err := store.IngestSignedScanResult(ctx, result, publicKey, now)
	if err != nil || duplicate {
		t.Fatalf("valid result failed: duplicate=%v err=%v", duplicate, err)
	}
	duplicate, err = store.IngestSignedScanResult(ctx, result, publicKey, now.Add(time.Minute))
	if err != nil || !duplicate {
		t.Fatalf("identical delivery was not idempotent: duplicate=%v err=%v", duplicate, err)
	}
	var state, scanState, engine, detected string
	var retained string
	if err := store.db.QueryRow(`SELECT sj.state, fv.scan_state, sj.engine_version, sj.detected_type, sj.retain_until
		FROM scan_jobs sj JOIN file_versions fv ON fv.id = sj.file_version_id WHERE sj.id = ?`, completion.ScanJobID).
		Scan(&state, &scanState, &engine, &detected, &retained); err != nil {
		t.Fatal(err)
	}
	if state != "clean" || scanState != "clean" || engine != payload.EngineVersion || detected != payload.DetectedType || retained == "" {
		t.Fatalf("result projection incomplete: state=%s file=%s engine=%s detected=%s retained=%s", state, scanState, engine, detected, retained)
	}
}

func TestSignedScanResultRejectsTamperWrongObjectAndContentHash(t *testing.T) {
	for name, testCase := range map[string]struct {
		mutate func(*scanresult.Payload)
		tamper bool
	}{
		"content hash": {mutate: func(value *scanresult.Payload) { value.ContentSHA256 = strings.Repeat("b", 64) }},
		"object":       {mutate: func(value *scanresult.Payload) { value.ObjectKey = "objects/obj_1123456789abcdefghjkmnpqrstvwxyz" }},
		"signature":    {mutate: func(*scanresult.Payload) {}, tamper: true},
	} {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			store := openTestStore(t)
			now := time.Date(2026, 9, 5, 1, 0, 0, 0, time.UTC)
			owner, _ := store.CreateAccount(ctx, "Rejected "+name, now.Add(-time.Hour))
			upload, completion := completeTestFile(t, store, owner.ID, now.Add(-30*time.Minute), false)
			publicKey, privateKey, _ := ed25519.GenerateKey(rand.Reader)
			plainHash := sha256.Sum256([]byte("plain"))
			payload := scanresult.Payload{ScanJobID: completion.ScanJobID, FileVersionID: completion.FileVersionID,
				ObjectKey: upload.ObjectKey, EventTime: now.Add(-20 * time.Minute).Format(time.RFC3339Nano),
				Verdict: "clean", EngineVersion: "scanner", RuleVersion: "rules",
				ContentSHA256: hex.EncodeToString(plainHash[:]), ScannedAt: now.Format(time.RFC3339Nano)}
			testCase.mutate(&payload)
			result, err := scanresult.NewEnvelope(payload, privateKey)
			if err != nil {
				t.Fatal(err)
			}
			if testCase.tamper {
				replacement := "A"
				if result.Signature[0] == 'A' {
					replacement = "B"
				}
				result.Signature = replacement + result.Signature[1:]
			}
			if _, err := store.IngestSignedScanResult(ctx, result, publicKey, now); err == nil {
				t.Fatal("invalid result was accepted")
			}
			var state string
			var ingested int
			if err := store.db.QueryRow("SELECT state FROM scan_jobs WHERE id = ?", completion.ScanJobID).Scan(&state); err != nil {
				t.Fatal(err)
			}
			if err := store.db.QueryRow("SELECT count(*) FROM ingested_envelopes").Scan(&ingested); err != nil {
				t.Fatal(err)
			}
			if state != "queued" || ingested != 0 {
				t.Fatalf("invalid result changed state: state=%s ingested=%d", state, ingested)
			}
		})
	}
}

func TestUnsignedVerdictEntryPointIsNotExposed(t *testing.T) {
	// the production transition is IngestSignedScanResult. a replay with a
	// different signing key must not be accepted even when all payload fields match.
	ctx := context.Background()
	store := openTestStore(t)
	now := time.Date(2026, 9, 5, 2, 0, 0, 0, time.UTC)
	owner, _ := store.CreateAccount(ctx, "Key mismatch", now.Add(-time.Hour))
	upload, completion := completeTestFile(t, store, owner.ID, now.Add(-30*time.Minute), false)
	_, signingKey, _ := ed25519.GenerateKey(rand.Reader)
	wrongPublic, _, _ := ed25519.GenerateKey(rand.Reader)
	plainHash := sha256.Sum256([]byte("plain"))
	value, _ := scanresult.NewEnvelope(scanresult.Payload{ScanJobID: completion.ScanJobID, FileVersionID: completion.FileVersionID,
		ObjectKey: upload.ObjectKey, EventTime: now.Add(-time.Minute).Format(time.RFC3339Nano), Verdict: "clean",
		EngineVersion: "scanner", ContentSHA256: hex.EncodeToString(plainHash[:]), ScannedAt: now.Format(time.RFC3339Nano)}, signingKey)
	if _, err := store.IngestSignedScanResult(ctx, value, wrongPublic, now); err == nil || errors.Is(err, ErrResourceNotFound) {
		t.Fatalf("wrong signer was not cryptographically rejected: %v", err)
	}
}
