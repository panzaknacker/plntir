package scanresult

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
	"time"
)

func TestResultEnvelopeBindsEverySecurityField(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	payload := Payload{
		ScanJobID: "scan_0123456789abcdefghjkmnpqrstvwxyz", FileVersionID: "fver_0123456789abcdefghjkmnpqrstvwxyz",
		ObjectKey: "objects/obj_0123456789abcdefghjkmnpqrstvwxyz", EventTime: now.Add(-time.Minute).Format(time.RFC3339Nano),
		Verdict: "clean", EngineVersion: "clamav-1", RuleVersion: "rules-1", ContentSHA256: strings.Repeat("a", 64),
		DetectedType: "application/pdf", ScannedAt: now.Format(time.RFC3339Nano),
	}
	result, err := NewEnvelope(payload, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	if verified, err := Verify(result, publicKey, now); err != nil || verified != payload {
		t.Fatalf("signed result did not verify: %+v %v", verified, err)
	}
	result.Payload[10] ^= 1
	if _, err := Verify(result, publicKey, now); err == nil {
		t.Fatal("tampered result verified")
	}
}

func TestResultEnvelopeRejectsStaleAndIncompleteVerdicts(t *testing.T) {
	publicKey, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	payload := Payload{
		ScanJobID: "scan_0123456789abcdefghjkmnpqrstvwxyz", FileVersionID: "fver_0123456789abcdefghjkmnpqrstvwxyz",
		ObjectKey: "objects/obj_0123456789abcdefghjkmnpqrstvwxyz", EventTime: now.Add(-time.Hour).Format(time.RFC3339Nano),
		Verdict: "clean", EngineVersion: "clamav-1", ScannedAt: now.Add(-31 * time.Minute).Format(time.RFC3339Nano),
	}
	if _, err := NewEnvelope(payload, privateKey); err == nil {
		t.Fatal("clean result without full hash was signed")
	}
	payload.Verdict, payload.ContentSHA256 = "unscannable", ""
	result, err := NewEnvelope(payload, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(result, publicKey, now); err == nil {
		t.Fatal("stale result verified")
	}
}
