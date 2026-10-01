package wazuhintegrity

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDailyAnchorSignatureAndCanonicalBody(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	for index := range seed {
		seed[index] = byte(index)
	}
	privateKey := ed25519.NewKeyFromSeed(seed)
	chain := sha256.Sum256([]byte("chain"))
	anchor, err := SignDailyAnchor(17, chain, time.Date(2026, 9, 4, 12, 0, 0, 999, time.UTC), privateKey)
	if err != nil {
		t.Fatal(err)
	}
	signature, _ := base64.RawURLEncoding.DecodeString(anchor.Signature)
	if !ed25519.Verify(privateKey.Public().(ed25519.PublicKey), CanonicalAnchor(anchor), signature) {
		t.Fatal("anchor signature did not verify")
	}
	body, err := anchor.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if body[len(body)-1] != '\n' || anchor.CreatedAt != "2026-09-04T12:00:00Z" || anchor.Date != "2026-09-04" {
		t.Fatalf("anchor is not canonical: %s", body)
	}
	fixtureBytes, err := os.ReadFile(filepath.Join("..", "..", "..", "testdata", "wazuh-anchor-golden.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		SchemaVersion int    `json:"schema_version"`
		PublicKey     string `json:"public_key"`
		Body          string `json:"body"`
	}
	if err := json.Unmarshal(fixtureBytes, &fixture); err != nil {
		t.Fatal(err)
	}
	if fixture.SchemaVersion != 1 || fixture.PublicKey != base64.RawURLEncoding.EncodeToString(privateKey.Public().(ed25519.PublicKey)) || fixture.Body != string(body) {
		t.Fatal("Go anchor drifted from the cross-runtime golden fixture")
	}
}
