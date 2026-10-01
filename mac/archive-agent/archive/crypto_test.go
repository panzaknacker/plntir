package archive

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"strings"
	"testing"
)

func TestChunkAuthenticationAndRecordRoundTrip(t *testing.T) {
	t.Parallel()
	key := bytes.Repeat([]byte{0x31}, DEKBytes)
	prefix := [NoncePrefixBytes]byte{1, 2, 3, 4}
	aad := ChunkAAD{DeviceID: "device-1", ArchiveID: "archive-1", WorkID: strings.Repeat("a", 64), ObjectID: "object-1"}
	plaintext := []byte("mail, browser, and application state")
	chunk, err := SealChunk(key, prefix, 7, aad, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	record, err := EncodeCipherChunk(chunk)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeCipherChunk(record)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := OpenChunk(key, prefix, aad, decoded)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(opened, plaintext) {
		t.Fatal("opened plaintext differs")
	}
	decoded.Ciphertext[0] ^= 0x80
	if _, err := OpenChunk(key, prefix, aad, decoded); err == nil {
		t.Fatal("tampered ciphertext was accepted")
	}
	record[len(record)-1] ^= 0x40
	if _, err := DecodeCipherChunk(record); err == nil {
		t.Fatal("tampered record was accepted")
	}
	if _, err := OpenChunk(key, prefix, ChunkAAD{DeviceID: "other", ArchiveID: aad.ArchiveID, WorkID: aad.WorkID, ObjectID: aad.ObjectID}, chunk); err == nil {
		t.Fatal("wrong AAD was accepted")
	}
}

func TestNonceLeaseIsUniqueAndRejectsZeroSource(t *testing.T) {
	t.Parallel()
	prefix := [NoncePrefixBytes]byte{9, 8, 7, 6}
	seen := make(map[[NonceBytes]byte]struct{})
	for counter := uint64(1); counter <= 10_000; counter++ {
		nonce := nonceFor(prefix, counter)
		if _, exists := seen[nonce]; exists {
			t.Fatalf("nonce repeated at counter %d", counter)
		}
		seen[nonce] = struct{}{}
	}
	if _, err := GenerateNoncePrefix(bytes.NewReader(make([]byte, 8*NoncePrefixBytes))); err == nil {
		t.Fatal("repeated all-zero nonce prefix was accepted")
	}
}

func TestDualWrapAndOfflineRecovery(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		t.Fatal(err)
	}
	key := bytes.Repeat([]byte{0x5a}, DEKBytes)
	wrapper := fakeKMS{key: key}
	wrapContext := WrapContext{DeviceID: "mac-test", ArchiveKeyID: "archive-key-1"}
	envelopes, err := WrapArchiveDEK(context.Background(), wrapper, &privateKey.PublicKey, wrapContext, key, nil)
	if err != nil {
		t.Fatal(err)
	}
	fromKMS, err := UnwrapArchiveDEK(context.Background(), wrapper, wrapContext, envelopes)
	if err != nil {
		t.Fatal(err)
	}
	defer Zero(fromKMS)
	fromOffline, err := UnwrapOffline(privateKey, wrapContext, envelopes)
	if err != nil {
		t.Fatal(err)
	}
	defer Zero(fromOffline)
	if !bytes.Equal(fromKMS, key) || !bytes.Equal(fromOffline, key) {
		t.Fatal("recovered archive key differs")
	}
	if _, err := UnwrapOffline(privateKey, WrapContext{DeviceID: "other", ArchiveKeyID: wrapContext.ArchiveKeyID}, envelopes); err == nil {
		t.Fatal("offline wrap accepted the wrong context")
	}
	tampered := envelopes
	tampered.OfflineFingerprint = strings.Repeat("b", 64)
	if _, err := UnwrapOffline(privateKey, wrapContext, tampered); err == nil {
		t.Fatal("offline wrap accepted the wrong key fingerprint")
	}
}
