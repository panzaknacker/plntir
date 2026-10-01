package scanmeta

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

type goldenVector struct {
	AccountID, Bucket, ObjectKey           string
	CiphertextSize                         int64
	JobID, FileVersionID, MediaKind        string
	ManifestSHA256, KMSCiphertext          string
	KMSCiphertextSHA256                    string
	PlaintextSize, ChunkSize               int64
	NoncePrefix, SignedAt, Seed, PublicKey string
	Canonical, Signature                   string
}

func readGoldenVector(t *testing.T) goldenVector {
	t.Helper()
	encoded, err := os.ReadFile("../../../testdata/scanmeta-golden.json")
	if err != nil {
		t.Fatal(err)
	}
	var vector goldenVector
	if err := json.Unmarshal(encoded, &vector); err != nil {
		t.Fatal(err)
	}
	return vector
}

func fixture(t *testing.T) (Input, ed25519.PublicKey) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return Input{
		AccountID:         "0123456789abcdef0123456789abcdef",
		Bucket:            "plntir-files",
		ObjectKey:         "objects/obj_0123456789abcdefghjkmnpqrstvwxyz",
		CiphertextSize:    80_000_000,
		JobID:             "scan_0123456789abcdefghjkmnpqrstvwxyz",
		FileVersionID:     "fver_0123456789abcdefghjkmnpqrstvwxyz",
		MediaKind:         "image",
		ManifestSHA256:    strings.Repeat("a", 64),
		KMSCiphertext:     []byte{1, 2, 3, 4, 5, 6},
		PlaintextSize:     79_999_968,
		ChunkSize:         MinMediaChunkBytes,
		NoncePrefix:       [4]byte{9, 8, 7, 6},
		SignedAt:          time.Date(2026, 9, 4, 11, 55, 0, 0, time.UTC),
		MetadataSignerKey: privateKey,
	}, publicKey
}

func TestSignAndVerifyMetadata(t *testing.T) {
	input, publicKey := fixture(t)
	metadata, err := Sign(input)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(input.AccountID, input.Bucket, input.ObjectKey, input.CiphertextSize, metadata, publicKey); err != nil {
		t.Fatal(err)
	}
	if len(metadata.R2CustomMetadata()) != 11 {
		t.Fatal("R2 custom metadata is incomplete")
	}

	metadata.ManifestSHA256 = strings.Repeat("b", 64)
	if err := Verify(input.AccountID, input.Bucket, input.ObjectKey, input.CiphertextSize, metadata, publicKey); err == nil {
		t.Fatal("tampered manifest unexpectedly verified")
	}
	metadata, err = Sign(input)
	if err != nil {
		t.Fatal(err)
	}
	metadata.NoncePrefix = "AAAA"
	if err := Verify(input.AccountID, input.Bucket, input.ObjectKey, input.CiphertextSize, metadata, publicKey); err == nil {
		t.Fatal("malformed nonce prefix unexpectedly verified")
	}
}

func TestCanonicalFormatIsStable(t *testing.T) {
	input, _ := fixture(t)
	metadata, err := Sign(input)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := Canonical(input.AccountID, input.Bucket, input.ObjectKey, input.CiphertextSize, metadata)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(canonical, []byte("plntir-r2-scan-v1\n0123456789abcdef0123456789abcdef\nplntir-files\nobjects/obj_")) || canonical[len(canonical)-1] != '\n' {
		t.Fatalf("unexpected canonical encoding %q", canonical)
	}
}

func TestLargeMediaAndOpaqueKeyConstraints(t *testing.T) {
	input, _ := fixture(t)
	input.PlaintextSize = 6_000_000_000
	input.ChunkSize = 8 << 20
	if _, err := Sign(input); err == nil {
		t.Fatal("undersized media chunks unexpectedly accepted")
	}
	input.ChunkSize = MinMediaChunkBytes
	input.ObjectKey = "objects/Alice/tax.pdf"
	if _, err := Sign(input); err == nil {
		t.Fatal("user-derived object key unexpectedly accepted")
	}
}

func TestSharedGoldenVector(t *testing.T) {
	vector := readGoldenVector(t)
	decode := func(label, value string) []byte {
		t.Helper()
		decoded, err := base64.RawURLEncoding.Strict().DecodeString(value)
		if err != nil {
			t.Fatalf("decode %s: %v", label, err)
		}
		return decoded
	}
	seed := decode("seed", vector.Seed)
	if len(seed) != ed25519.SeedSize {
		t.Fatal("golden seed has an invalid length")
	}
	privateKey := ed25519.NewKeyFromSeed(seed)
	publicKey := privateKey.Public().(ed25519.PublicKey)
	if got := base64.RawURLEncoding.EncodeToString(publicKey); got != vector.PublicKey {
		t.Fatalf("public key mismatch: %s", got)
	}
	nonce := decode("nonce prefix", vector.NoncePrefix)
	var noncePrefix [4]byte
	copy(noncePrefix[:], nonce)
	signedAt, err := time.Parse(time.RFC3339, vector.SignedAt)
	if err != nil {
		t.Fatal(err)
	}
	metadata, err := Sign(Input{
		AccountID: vector.AccountID, Bucket: vector.Bucket, ObjectKey: vector.ObjectKey,
		CiphertextSize: vector.CiphertextSize, JobID: vector.JobID,
		FileVersionID: vector.FileVersionID, MediaKind: vector.MediaKind,
		ManifestSHA256: vector.ManifestSHA256, KMSCiphertext: decode("KMS ciphertext", vector.KMSCiphertext),
		PlaintextSize: vector.PlaintextSize, ChunkSize: vector.ChunkSize,
		NoncePrefix: noncePrefix, SignedAt: signedAt, MetadataSignerKey: privateKey,
	})
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := Canonical(vector.AccountID, vector.Bucket, vector.ObjectKey, vector.CiphertextSize, metadata)
	if err != nil {
		t.Fatal(err)
	}
	if string(canonical) != vector.Canonical || metadata.Signature != vector.Signature || metadata.KMSCiphertextSHA256 != vector.KMSCiphertextSHA256 {
		t.Fatal("Go scan metadata no longer matches the shared golden vector")
	}
	if err := Verify(vector.AccountID, vector.Bucket, vector.ObjectKey, vector.CiphertextSize, metadata, publicKey); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyRejectsInvalidExternalBinding(t *testing.T) {
	input, publicKey := fixture(t)
	metadata, err := Sign(input)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify("not-an-account", input.Bucket, input.ObjectKey, input.CiphertextSize, metadata, publicKey); err == nil {
		t.Fatal("invalid external account unexpectedly verified")
	}
	if err := Verify(input.AccountID, "Invalid_Bucket", input.ObjectKey, input.CiphertextSize, metadata, publicKey); err == nil {
		t.Fatal("invalid external bucket unexpectedly verified")
	}
}
