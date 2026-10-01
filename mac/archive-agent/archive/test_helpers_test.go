package archive

import (
	"context"
	"encoding/base64"
	"os"
	"strings"
	"testing"
	"time"
)

var testNow = time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)

type fakeKMS struct {
	key []byte
}

func privateTempDir(t *testing.T) string {
	t.Helper()
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	return directory
}

func (kms fakeKMS) Wrap(_ context.Context, plaintext []byte, encryptionContext map[string]string) ([]byte, string, string, error) {
	return append([]byte("kms:"), plaintext...), "arn:aws:kms:eu-central-1:111122223333:key/test", "SYMMETRIC_DEFAULT", nil
}

func (kms fakeKMS) Unwrap(_ context.Context, ciphertext []byte, keyReference, algorithm string, encryptionContext map[string]string) ([]byte, error) {
	return append([]byte(nil), kms.key...), nil
}

func testEnvelopes() KeyEnvelopes {
	return KeyEnvelopes{
		KMSCiphertextB64:     base64.RawStdEncoding.EncodeToString([]byte("kms-wrapped-dek")),
		KMSKeyReference:      "arn:aws:kms:eu-central-1:111122223333:key/test",
		KMSAlgorithm:         "SYMMETRIC_DEFAULT",
		OfflineCiphertextB64: base64.RawStdEncoding.EncodeToString([]byte("offline-wrapped-dek")),
		OfflineFingerprint:   strings.Repeat("a", 64),
		OfflineAlgorithm:     "RSA-OAEP-SHA256",
	}
}

func readyPolicy() PolicySnapshot {
	return PolicySnapshot{
		ObservedAt:               testNow,
		OnACPower:                true,
		BatteryPercent:           100,
		CPUPercent:               10,
		Thermal:                  ThermalNominal,
		FreeBytes:                MinimumFreeBytes + 1,
		Network:                  NetworkUnmetered,
		ConsecutiveNetworkErrors: 0,
	}
}
