package scanmeta

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	MaxCiphertextBytes = int64(500_200_000_000)
	MaxPlaintextBytes  = int64(500_000_000_000)
	MaxStandardBytes   = int64(5_000_000_000)
	MinMediaChunkBytes = int64(64 << 20)
	MaxChunks          = int64(10_000)
)

var (
	accountIDPattern = regexp.MustCompile(`^[a-f0-9]{32}$`)
	bucketPattern    = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$`)
	safeID           = regexp.MustCompile(`^[a-z][a-z0-9]{0,15}_[0-9a-hjkmnp-tv-z]{32}$`)
	objectKey        = regexp.MustCompile(`^objects/obj_[0-9a-hjkmnp-tv-z]{32}$`)
	hexHash          = regexp.MustCompile(`^[a-f0-9]{64}$`)
)

type Input struct {
	AccountID         string
	Bucket            string
	ObjectKey         string
	CiphertextSize    int64
	JobID             string
	FileVersionID     string
	MediaKind         string
	ManifestSHA256    string
	KMSCiphertext     []byte
	PlaintextSize     int64
	ChunkSize         int64
	NoncePrefix       [4]byte
	SignedAt          time.Time
	MetadataSignerKey ed25519.PrivateKey
}

type Metadata struct {
	JobID               string
	FileVersionID       string
	MediaKind           string
	ManifestSHA256      string
	KMSCiphertext       string
	KMSCiphertextSHA256 string
	PlaintextSize       int64
	ChunkSize           int64
	NoncePrefix         string
	SignedAt            string
	Signature           string
}

func Sign(input Input) (Metadata, error) {
	if err := validateInput(input); err != nil {
		return Metadata{}, err
	}
	kmsHash := sha256.Sum256(input.KMSCiphertext)
	metadata := Metadata{
		JobID:               input.JobID,
		FileVersionID:       input.FileVersionID,
		MediaKind:           input.MediaKind,
		ManifestSHA256:      input.ManifestSHA256,
		KMSCiphertext:       base64.RawURLEncoding.EncodeToString(input.KMSCiphertext),
		KMSCiphertextSHA256: hex.EncodeToString(kmsHash[:]),
		PlaintextSize:       input.PlaintextSize,
		ChunkSize:           input.ChunkSize,
		NoncePrefix:         base64.RawURLEncoding.EncodeToString(input.NoncePrefix[:]),
		SignedAt:            input.SignedAt.UTC().Truncate(time.Second).Format(time.RFC3339),
	}
	canonical, err := Canonical(input.AccountID, input.Bucket, input.ObjectKey, input.CiphertextSize, metadata)
	if err != nil {
		return Metadata{}, err
	}
	metadata.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(input.MetadataSignerKey, canonical))
	return metadata, nil
}

func Verify(accountID, bucket, key string, ciphertextSize int64, metadata Metadata, publicKey ed25519.PublicKey) error {
	if len(publicKey) != ed25519.PublicKeySize {
		return errors.New("scan metadata public key has an invalid length")
	}
	if err := validateMetadata(metadata); err != nil {
		return err
	}
	if err := validateBinding(accountID, bucket, key, ciphertextSize, metadata.PlaintextSize); err != nil {
		return err
	}
	nonce, err := base64.RawURLEncoding.Strict().DecodeString(metadata.NoncePrefix)
	if err != nil || len(nonce) != 4 {
		return errors.New("nonce prefix is not canonical four-byte base64url")
	}
	signedAt, err := time.Parse(time.RFC3339, metadata.SignedAt)
	if err != nil || signedAt.UTC().Format(time.RFC3339) != metadata.SignedAt {
		return errors.New("scan metadata signing time is invalid")
	}
	canonical, err := Canonical(accountID, bucket, key, ciphertextSize, metadata)
	if err != nil {
		return err
	}
	signature, err := base64.RawURLEncoding.Strict().DecodeString(metadata.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return errors.New("scan metadata signature is invalid")
	}
	if !ed25519.Verify(publicKey, canonical, signature) {
		return errors.New("scan metadata signature is invalid")
	}
	kmsCiphertext, err := base64.RawURLEncoding.Strict().DecodeString(metadata.KMSCiphertext)
	if err != nil {
		return errors.New("KMS ciphertext is not canonical base64url")
	}
	hash := sha256.Sum256(kmsCiphertext)
	if hex.EncodeToString(hash[:]) != metadata.KMSCiphertextSHA256 {
		return errors.New("KMS ciphertext hash does not match")
	}
	return nil
}

func Canonical(accountID, bucket, key string, ciphertextSize int64, metadata Metadata) ([]byte, error) {
	fields := []string{
		"plntir-r2-scan-v1",
		accountID,
		bucket,
		key,
		strconv.FormatInt(ciphertextSize, 10),
		metadata.JobID,
		metadata.FileVersionID,
		metadata.MediaKind,
		metadata.ManifestSHA256,
		metadata.KMSCiphertextSHA256,
		strconv.FormatInt(metadata.PlaintextSize, 10),
		strconv.FormatInt(metadata.ChunkSize, 10),
		metadata.NoncePrefix,
		metadata.SignedAt,
	}
	for _, field := range fields {
		if field == "" || strings.ContainsAny(field, "\r\n") {
			return nil, errors.New("scan metadata canonical field is empty or contains a line break")
		}
	}
	return []byte(strings.Join(fields, "\n") + "\n"), nil
}

func (m Metadata) R2CustomMetadata() map[string]string {
	return map[string]string{
		"plntir-job-id":                m.JobID,
		"plntir-file-version-id":       m.FileVersionID,
		"plntir-media-kind":            m.MediaKind,
		"plntir-manifest-sha256":       m.ManifestSHA256,
		"plntir-kms-ciphertext":        m.KMSCiphertext,
		"plntir-kms-ciphertext-sha256": m.KMSCiphertextSHA256,
		"plntir-plaintext-size":        strconv.FormatInt(m.PlaintextSize, 10),
		"plntir-chunk-size":            strconv.FormatInt(m.ChunkSize, 10),
		"plntir-nonce-prefix":          m.NoncePrefix,
		"plntir-signed-at":             m.SignedAt,
		"plntir-signature":             m.Signature,
	}
}

func validateInput(input Input) error {
	if err := validateBinding(input.AccountID, input.Bucket, input.ObjectKey, input.CiphertextSize, input.PlaintextSize); err != nil {
		return err
	}
	if input.SignedAt.IsZero() || len(input.MetadataSignerKey) != ed25519.PrivateKeySize {
		return errors.New("metadata signing time or private key is invalid")
	}
	if len(input.KMSCiphertext) == 0 || len(input.KMSCiphertext) > 6144 {
		return errors.New("KMS ciphertext length is invalid")
	}
	metadata := Metadata{
		JobID: input.JobID, FileVersionID: input.FileVersionID, MediaKind: input.MediaKind,
		ManifestSHA256: input.ManifestSHA256, PlaintextSize: input.PlaintextSize,
		ChunkSize: input.ChunkSize,
	}
	return validateMetadata(metadata)
}

func validateBinding(accountID, bucket, key string, ciphertextSize, plaintextSize int64) error {
	if !accountIDPattern.MatchString(accountID) {
		return errors.New("Cloudflare account id is invalid")
	}
	if !bucketPattern.MatchString(bucket) {
		return errors.New("R2 bucket name is invalid")
	}
	if !objectKey.MatchString(key) {
		return errors.New("opaque R2 object key is invalid")
	}
	if ciphertextSize < plaintextSize || ciphertextSize > MaxCiphertextBytes {
		return errors.New("ciphertext size is invalid")
	}
	return nil
}

func validateMetadata(metadata Metadata) error {
	if !safeID.MatchString(metadata.JobID) || !strings.HasPrefix(metadata.JobID, "scan_") {
		return errors.New("scan job id is invalid")
	}
	if !safeID.MatchString(metadata.FileVersionID) || !strings.HasPrefix(metadata.FileVersionID, "fver_") {
		return errors.New("file version id is invalid")
	}
	if metadata.MediaKind != "standard" && metadata.MediaKind != "image" && metadata.MediaKind != "video" {
		return errors.New("media kind is invalid")
	}
	if !hexHash.MatchString(metadata.ManifestSHA256) {
		return errors.New("manifest SHA-256 is invalid")
	}
	if metadata.KMSCiphertextSHA256 != "" && !hexHash.MatchString(metadata.KMSCiphertextSHA256) {
		return errors.New("KMS ciphertext SHA-256 is invalid")
	}
	if metadata.PlaintextSize < 1 || metadata.PlaintextSize > MaxPlaintextBytes {
		return errors.New("plaintext size is invalid")
	}
	if metadata.MediaKind == "standard" && metadata.PlaintextSize > MaxStandardBytes {
		return errors.New("standard files are limited to 5 GB")
	}
	if metadata.ChunkSize < 1 || metadata.ChunkSize > 1<<30 {
		return errors.New("chunk size is invalid")
	}
	if metadata.PlaintextSize > MaxStandardBytes && metadata.ChunkSize < MinMediaChunkBytes {
		return errors.New("large media chunks must be at least 64 MiB")
	}
	parts := (metadata.PlaintextSize + metadata.ChunkSize - 1) / metadata.ChunkSize
	if parts > MaxChunks {
		return fmt.Errorf("file requires %d chunks; maximum is %d", parts, MaxChunks)
	}
	return nil
}
