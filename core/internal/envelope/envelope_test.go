package envelope

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"testing"
	"time"
)

func TestSignedEnvelopeRejectsTamperReplayAndStaleTimestamp(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 4, 10, 0, 0, 0, time.UTC)
	value := Envelope{
		Version:         Version,
		Kind:            "device-status",
		Source:          "agent-mac-01",
		Sequence:        7,
		Timestamp:       now.Format(time.RFC3339Nano),
		DeduplicationID: "evt_01k4aabbccddeeff",
		Payload:         json.RawMessage(`{"state":"verified"}`),
	}
	if err := Sign(&value, privateKey); err != nil {
		t.Fatal(err)
	}
	if err := Verify(value, publicKey, VerifyOptions{Now: now, LastSequence: 6}); err != nil {
		t.Fatal(err)
	}

	tampered := value
	tampered.Payload = json.RawMessage(`{"state":"unavailable"}`)
	if err := Verify(tampered, publicKey, VerifyOptions{Now: now, LastSequence: 6}); err == nil {
		t.Fatal("tampered payload unexpectedly verified")
	}
	if err := Verify(value, publicKey, VerifyOptions{Now: now, LastSequence: 7}); err == nil {
		t.Fatal("replayed sequence unexpectedly verified")
	}
	if err := Verify(value, publicKey, VerifyOptions{Now: now.Add(6 * time.Minute), LastSequence: 6}); err == nil {
		t.Fatal("stale timestamp unexpectedly verified")
	}
	if err := Verify(value, publicKey, VerifyOptions{
		Now: now, LastSequence: 6, Seen: func(string) (bool, error) { return true, nil },
	}); err == nil {
		t.Fatal("duplicate id unexpectedly verified")
	}
}
