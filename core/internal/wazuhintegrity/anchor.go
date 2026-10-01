package wazuhintegrity

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"strconv"
	"time"
)

type DailyAnchor struct {
	ChainHash       string `json:"chain_hash"`
	CreatedAt       string `json:"created_at"`
	Date            string `json:"date"`
	DeduplicationID string `json:"deduplication_id"`
	Kind            string `json:"kind"`
	Sequence        uint64 `json:"sequence"`
	Signature       string `json:"signature"`
	Source          string `json:"source"`
	Version         int    `json:"version"`
}

func SignDailyAnchor(sequence uint64, chainHash [sha256.Size]byte, now time.Time, privateKey ed25519.PrivateKey) (DailyAnchor, error) {
	if sequence == 0 || now.IsZero() || len(privateKey) != ed25519.PrivateKeySize {
		return DailyAnchor{}, errors.New("daily anchor inputs are invalid")
	}
	stamp := now.UTC().Truncate(time.Second)
	anchor := DailyAnchor{
		ChainHash:       base64.RawURLEncoding.EncodeToString(chainHash[:]),
		CreatedAt:       stamp.Format(time.RFC3339),
		Date:            stamp.Format(time.DateOnly),
		DeduplicationID: "anchor-" + stamp.Format(time.DateOnly) + "-" + strconv.FormatUint(sequence, 10),
		Kind:            "wazuh-daily-hash-anchor",
		Sequence:        sequence,
		Source:          "plntir-siem-01",
		Version:         1,
	}
	anchor.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, CanonicalAnchor(anchor)))
	return anchor, nil
}

func CanonicalAnchor(anchor DailyAnchor) []byte {
	result := append([]byte(nil), []byte("plntir-wazuh-hash-anchor-v1\x00")...)
	var version [8]byte
	binary.BigEndian.PutUint64(version[:], uint64(anchor.Version))
	result = append(result, version[:]...)
	for _, field := range []string{
		anchor.Kind,
		anchor.Source,
		anchor.Date,
		strconv.FormatUint(anchor.Sequence, 10),
		anchor.ChainHash,
		anchor.CreatedAt,
		anchor.DeduplicationID,
	} {
		var length [8]byte
		binary.BigEndian.PutUint64(length[:], uint64(len(field)))
		result = append(result, length[:]...)
		result = append(result, field...)
	}
	return result
}

func (anchor DailyAnchor) Marshal() ([]byte, error) {
	if anchor.Version != 1 || anchor.Kind != "wazuh-daily-hash-anchor" || anchor.Source != "plntir-siem-01" || anchor.Sequence == 0 {
		return nil, errors.New("daily anchor is invalid")
	}
	if _, err := decodeHash(anchor.ChainHash); err != nil {
		return nil, err
	}
	if _, err := time.Parse(time.RFC3339, anchor.CreatedAt); err != nil || anchor.Date != anchor.CreatedAt[:10] {
		return nil, errors.New("daily anchor time is invalid")
	}
	if anchor.DeduplicationID != "anchor-"+anchor.Date+"-"+strconv.FormatUint(anchor.Sequence, 10) {
		return nil, errors.New("daily anchor deduplication identity is invalid")
	}
	signature, err := base64.RawURLEncoding.DecodeString(anchor.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize || base64.RawURLEncoding.EncodeToString(signature) != anchor.Signature {
		return nil, errors.New("daily anchor signature encoding is invalid")
	}
	encoded, err := json.Marshal(anchor)
	if err != nil {
		return nil, err
	}
	return append(encoded, '\n'), nil
}

func VerifyDailyAnchor(anchor DailyAnchor, publicKey ed25519.PublicKey) error {
	if len(publicKey) != ed25519.PublicKeySize {
		return errors.New("daily anchor public key is invalid")
	}
	if _, err := anchor.Marshal(); err != nil {
		return err
	}
	signature, _ := base64.RawURLEncoding.DecodeString(anchor.Signature)
	if !ed25519.Verify(publicKey, CanonicalAnchor(anchor), signature) {
		return errors.New("daily anchor signature is invalid")
	}
	return nil
}
