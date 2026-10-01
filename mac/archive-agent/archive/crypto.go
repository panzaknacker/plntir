package archive

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"runtime"
)

const (
	DEKBytes         = 32
	NoncePrefixBytes = 4
	NonceBytes       = 12
	GCMTagBytes      = 16
)

type ChunkAAD struct {
	DeviceID  string
	ArchiveID string
	WorkID    string
	ObjectID  string
}

type CipherChunk struct {
	Counter          uint64
	Nonce            [NonceBytes]byte
	PlaintextSHA256  [sha256.Size]byte
	CiphertextSHA256 [sha256.Size]byte
	Ciphertext       []byte
}

func GenerateDEK(source io.Reader) ([]byte, error) {
	if source == nil {
		source = rand.Reader
	}
	key := make([]byte, DEKBytes)
	if _, err := io.ReadFull(source, key); err != nil {
		return nil, fmt.Errorf("generate archive DEK: %w", err)
	}
	return key, nil
}

func GenerateNoncePrefix(source io.Reader) ([NoncePrefixBytes]byte, error) {
	var prefix [NoncePrefixBytes]byte
	if source == nil {
		source = rand.Reader
	}
	for attempts := 0; attempts < 8; attempts++ {
		if _, err := io.ReadFull(source, prefix[:]); err != nil {
			return prefix, fmt.Errorf("generate archive nonce prefix: %w", err)
		}
		if prefix != [NoncePrefixBytes]byte{} {
			return prefix, nil
		}
	}
	return prefix, errors.New("archive nonce source repeatedly returned an all-zero prefix")
}

func SealChunk(key []byte, prefix [NoncePrefixBytes]byte, counter uint64, aad ChunkAAD, plaintext []byte) (CipherChunk, error) {
	if len(key) != DEKBytes {
		return CipherChunk{}, fmt.Errorf("archive DEK must contain %d bytes", DEKBytes)
	}
	if counter == 0 {
		return CipherChunk{}, errors.New("nonce counter zero is reserved")
	}
	if int64(len(plaintext)) > MaximumPlaintextBytes {
		return CipherChunk{}, errors.New("archive plaintext chunk exceeds 64 MiB")
	}
	encodedAAD, err := marshalChunkAAD(aad, counter)
	if err != nil {
		return CipherChunk{}, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return CipherChunk{}, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return CipherChunk{}, err
	}
	nonce := nonceFor(prefix, counter)
	plaintextHash := sha256.Sum256(plaintext)
	ciphertext := aead.Seal(nil, nonce[:], plaintext, encodedAAD)
	return CipherChunk{
		Counter:          counter,
		Nonce:            nonce,
		PlaintextSHA256:  plaintextHash,
		CiphertextSHA256: sha256.Sum256(ciphertext),
		Ciphertext:       ciphertext,
	}, nil
}

func OpenChunk(key []byte, prefix [NoncePrefixBytes]byte, aad ChunkAAD, chunk CipherChunk) ([]byte, error) {
	if len(key) != DEKBytes {
		return nil, errors.New("invalid archive DEK length")
	}
	wantNonce := nonceFor(prefix, chunk.Counter)
	if chunk.Nonce != wantNonce {
		return nil, errors.New("archive chunk nonce does not match its leased counter")
	}
	if sha256.Sum256(chunk.Ciphertext) != chunk.CiphertextSHA256 {
		return nil, errors.New("archive ciphertext hash mismatch")
	}
	encodedAAD, err := marshalChunkAAD(aad, chunk.Counter)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	plaintext, err := aead.Open(nil, chunk.Nonce[:], chunk.Ciphertext, encodedAAD)
	if err != nil {
		return nil, errors.New("archive chunk authentication failed")
	}
	if sha256.Sum256(plaintext) != chunk.PlaintextSHA256 {
		return nil, errors.New("archive plaintext hash mismatch")
	}
	return plaintext, nil
}

func nonceFor(prefix [NoncePrefixBytes]byte, counter uint64) [NonceBytes]byte {
	var nonce [NonceBytes]byte
	copy(nonce[:NoncePrefixBytes], prefix[:])
	binary.BigEndian.PutUint64(nonce[NoncePrefixBytes:], counter)
	return nonce
}

func marshalChunkAAD(aad ChunkAAD, counter uint64) ([]byte, error) {
	fields := []string{aad.DeviceID, aad.ArchiveID, aad.WorkID, aad.ObjectID}
	var output bytes.Buffer
	output.WriteString("PLNTIR-ARCHIVE-AAD-V1\x00")
	for _, field := range fields {
		if field == "" || len(field) > 1024 {
			return nil, errors.New("archive chunk AAD field is empty or oversized")
		}
		if err := binary.Write(&output, binary.BigEndian, uint16(len(field))); err != nil {
			return nil, err
		}
		output.WriteString(field)
	}
	if err := binary.Write(&output, binary.BigEndian, counter); err != nil {
		return nil, err
	}
	return output.Bytes(), nil
}

type WrapContext struct {
	DeviceID     string
	ArchiveKeyID string
}

func (c WrapContext) EncryptionContext() (map[string]string, error) {
	if c.DeviceID == "" || c.ArchiveKeyID == "" || len(c.DeviceID) > 128 || len(c.ArchiveKeyID) > 128 {
		return nil, errors.New("archive wrap context is invalid")
	}
	return map[string]string{
		"plntir-purpose":        "mac-archive-dek",
		"plntir-device-id":      c.DeviceID,
		"plntir-archive-key-id": c.ArchiveKeyID,
	}, nil
}

type KMSWrapper interface {
	Wrap(context.Context, []byte, map[string]string) (ciphertext []byte, keyReference, algorithm string, err error)
	Unwrap(context.Context, []byte, string, string, map[string]string) ([]byte, error)
}

type KeyEnvelopes struct {
	KMSCiphertextB64     string `json:"kms_ciphertext_b64"`
	KMSKeyReference      string `json:"kms_key_reference"`
	KMSAlgorithm         string `json:"kms_algorithm"`
	OfflineCiphertextB64 string `json:"offline_ciphertext_b64"`
	OfflineFingerprint   string `json:"offline_public_key_sha256"`
	OfflineAlgorithm     string `json:"offline_algorithm"`
}

func WrapArchiveDEK(ctx context.Context, wrapper KMSWrapper, offline *rsa.PublicKey, wrapContext WrapContext, key []byte, source io.Reader) (KeyEnvelopes, error) {
	if wrapper == nil || offline == nil || len(key) != DEKBytes {
		return KeyEnvelopes{}, errors.New("both key wrappers and a 256-bit DEK are required")
	}
	encryptionContext, err := wrapContext.EncryptionContext()
	if err != nil {
		return KeyEnvelopes{}, err
	}
	kmsCiphertext, keyReference, algorithm, err := wrapper.Wrap(ctx, key, encryptionContext)
	if err != nil {
		return KeyEnvelopes{}, fmt.Errorf("KMS-wrap archive DEK: %w", err)
	}
	if len(kmsCiphertext) == 0 || keyReference == "" || algorithm == "" {
		return KeyEnvelopes{}, errors.New("KMS wrapper returned an incomplete envelope")
	}
	offlineCiphertext, fingerprint, err := wrapOffline(offline, wrapContext, key, source)
	if err != nil {
		return KeyEnvelopes{}, err
	}
	return KeyEnvelopes{
		KMSCiphertextB64:     base64.RawStdEncoding.EncodeToString(kmsCiphertext),
		KMSKeyReference:      keyReference,
		KMSAlgorithm:         algorithm,
		OfflineCiphertextB64: base64.RawStdEncoding.EncodeToString(offlineCiphertext),
		OfflineFingerprint:   fingerprint,
		OfflineAlgorithm:     "RSA-OAEP-SHA256",
	}, nil
}

func UnwrapArchiveDEK(ctx context.Context, wrapper KMSWrapper, wrapContext WrapContext, envelopes KeyEnvelopes) ([]byte, error) {
	if wrapper == nil {
		return nil, errors.New("KMS archive wrapper is required")
	}
	if err := validateEnvelopes(envelopes); err != nil {
		return nil, err
	}
	encryptionContext, err := wrapContext.EncryptionContext()
	if err != nil {
		return nil, err
	}
	ciphertext, err := base64.RawStdEncoding.DecodeString(envelopes.KMSCiphertextB64)
	if err != nil || len(ciphertext) == 0 {
		return nil, errors.New("invalid KMS archive envelope")
	}
	key, err := wrapper.Unwrap(ctx, ciphertext, envelopes.KMSKeyReference, envelopes.KMSAlgorithm, encryptionContext)
	if err != nil {
		return nil, fmt.Errorf("KMS-unwrap archive DEK: %w", err)
	}
	if len(key) != DEKBytes {
		Zero(key)
		return nil, errors.New("KMS returned an invalid archive DEK")
	}
	return key, nil
}

func wrapOffline(publicKey *rsa.PublicKey, context WrapContext, key []byte, source io.Reader) ([]byte, string, error) {
	if publicKey.N.BitLen() < 3072 {
		return nil, "", errors.New("offline recovery RSA key must be at least 3072 bits")
	}
	if source == nil {
		source = rand.Reader
	}
	label := []byte("plntir-mac-archive-v1\x00" + context.DeviceID + "\x00" + context.ArchiveKeyID)
	ciphertext, err := rsa.EncryptOAEP(sha256.New(), source, publicKey, key, label)
	if err != nil {
		return nil, "", fmt.Errorf("offline-wrap archive DEK: %w", err)
	}
	der, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, "", err
	}
	fingerprint := sha256.Sum256(der)
	return ciphertext, hex.EncodeToString(fingerprint[:]), nil
}

func UnwrapOffline(privateKey *rsa.PrivateKey, context WrapContext, envelope KeyEnvelopes) ([]byte, error) {
	if privateKey == nil || privateKey.N.BitLen() < 3072 || envelope.OfflineAlgorithm != "RSA-OAEP-SHA256" {
		return nil, errors.New("offline recovery key or algorithm is invalid")
	}
	ciphertext, err := base64.RawStdEncoding.DecodeString(envelope.OfflineCiphertextB64)
	if err != nil {
		return nil, errors.New("offline archive envelope is not canonical base64")
	}
	der, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return nil, errors.New("marshal offline recovery public key")
	}
	fingerprint := sha256.Sum256(der)
	if hex.EncodeToString(fingerprint[:]) != envelope.OfflineFingerprint {
		return nil, errors.New("offline recovery key fingerprint does not match the envelope")
	}
	label := []byte("plntir-mac-archive-v1\x00" + context.DeviceID + "\x00" + context.ArchiveKeyID)
	key, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privateKey, ciphertext, label)
	if err != nil {
		return nil, errors.New("offline archive envelope authentication failed")
	}
	if len(key) != DEKBytes {
		Zero(key)
		return nil, errors.New("offline archive envelope contained an invalid DEK")
	}
	return key, nil
}

func Zero(value []byte) {
	clear(value)
	runtime.KeepAlive(value)
}
