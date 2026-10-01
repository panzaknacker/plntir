package envelope

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

const Version = 1

type Envelope struct {
	Version         int             `json:"version"`
	Kind            string          `json:"kind"`
	Source          string          `json:"source"`
	Sequence        uint64          `json:"sequence"`
	Timestamp       string          `json:"timestamp"`
	DeduplicationID string          `json:"deduplication_id"`
	Payload         json.RawMessage `json:"payload"`
	Signature       string          `json:"signature"`
}

type VerifyOptions struct {
	Now           time.Time
	MaximumAge    time.Duration
	MaximumFuture time.Duration
	LastSequence  uint64
	Seen          func(string) (bool, error)
}

func Sign(value *Envelope, privateKey ed25519.PrivateKey) error {
	if len(privateKey) != ed25519.PrivateKeySize {
		return errors.New("invalid Ed25519 private key")
	}
	if err := validateUnsigned(*value); err != nil {
		return err
	}
	value.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, canonical(*value)))
	return nil
}

func Verify(value Envelope, publicKey ed25519.PublicKey, options VerifyOptions) error {
	if len(publicKey) != ed25519.PublicKeySize {
		return errors.New("invalid Ed25519 public key")
	}
	if err := validateUnsigned(value); err != nil {
		return err
	}
	signature, err := base64.RawURLEncoding.DecodeString(value.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return errors.New("invalid envelope signature encoding")
	}
	if !ed25519.Verify(publicKey, canonical(value), signature) {
		return errors.New("invalid envelope signature")
	}
	stamp, _ := time.Parse(time.RFC3339Nano, value.Timestamp)
	if options.Now.IsZero() {
		options.Now = time.Now().UTC()
	}
	if options.MaximumAge <= 0 {
		options.MaximumAge = 5 * time.Minute
	}
	if options.MaximumFuture <= 0 {
		options.MaximumFuture = 30 * time.Second
	}
	if stamp.Before(options.Now.Add(-options.MaximumAge)) {
		return errors.New("envelope is stale")
	}
	if stamp.After(options.Now.Add(options.MaximumFuture)) {
		return errors.New("envelope timestamp is in the future")
	}
	if value.Sequence <= options.LastSequence {
		return errors.New("envelope sequence is not monotonic")
	}
	if options.Seen != nil {
		seen, err := options.Seen(value.DeduplicationID)
		if err != nil {
			return fmt.Errorf("check envelope deduplication id: %w", err)
		}
		if seen {
			return errors.New("envelope is a duplicate")
		}
	}
	return nil
}

func validateUnsigned(value Envelope) error {
	if value.Version != Version {
		return fmt.Errorf("unsupported envelope version %d", value.Version)
	}
	for name, field := range map[string]string{
		"kind": value.Kind, "source": value.Source, "deduplication_id": value.DeduplicationID,
	} {
		if !validToken(field) {
			return fmt.Errorf("invalid envelope %s", name)
		}
	}
	if value.Sequence == 0 {
		return errors.New("envelope sequence must be positive")
	}
	if _, err := time.Parse(time.RFC3339Nano, value.Timestamp); err != nil {
		return errors.New("invalid envelope timestamp")
	}
	if len(value.Payload) == 0 || len(value.Payload) > 1<<20 || !json.Valid(value.Payload) {
		return errors.New("invalid or oversized envelope payload")
	}
	return nil
}

func canonical(value Envelope) []byte {
	result := make([]byte, 0, len(value.Payload)+256)
	result = append(result, []byte("plntir-internal-envelope-v1\x00")...)
	var version [8]byte
	binary.BigEndian.PutUint64(version[:], uint64(value.Version))
	result = append(result, version[:]...)
	for _, field := range []string{value.Kind, value.Source} {
		result = appendField(result, []byte(field))
	}
	var sequence [8]byte
	binary.BigEndian.PutUint64(sequence[:], value.Sequence)
	result = append(result, sequence[:]...)
	for _, field := range []string{value.Timestamp, value.DeduplicationID} {
		result = appendField(result, []byte(field))
	}
	result = appendField(result, value.Payload)
	return result
}

func appendField(target, field []byte) []byte {
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(len(field)))
	target = append(target, length[:]...)
	return append(target, field...)
}

func validToken(value string) bool {
	if value == "" || len(value) > 128 || strings.HasPrefix(value, "-") || strings.HasSuffix(value, "-") {
		return false
	}
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.' {
			continue
		}
		return false
	}
	return true
}
