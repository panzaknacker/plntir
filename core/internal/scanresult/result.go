package scanresult

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"strings"
	"time"

	"plntir/core/internal/envelope"
)

const (
	MaximumDeliveryAge = 30 * time.Minute
	MaximumFutureSkew  = time.Minute
)

var (
	safeID    = regexp.MustCompile(`^[a-z][a-z0-9]{0,15}_[0-9a-hjkmnp-tv-z]{32}$`)
	objectKey = regexp.MustCompile(`^objects/obj_[0-9a-hjkmnp-tv-z]{32}$`)
	hexHash   = regexp.MustCompile(`^[a-f0-9]{64}$`)
)

type Payload struct {
	ScanJobID     string `json:"scan_job_id"`
	FileVersionID string `json:"file_version_id"`
	ObjectKey     string `json:"object_key"`
	EventTime     string `json:"event_time"`
	Verdict       string `json:"verdict"`
	EngineVersion string `json:"engine_version"`
	RuleVersion   string `json:"rule_version"`
	ContentSHA256 string `json:"content_sha256"`
	DetectedType  string `json:"detected_type"`
	Reason        string `json:"reason"`
	ScannedAt     string `json:"scanned_at"`
}

func NewEnvelope(payload Payload, privateKey ed25519.PrivateKey) (envelope.Envelope, error) {
	if err := validatePayload(payload); err != nil {
		return envelope.Envelope{}, err
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return envelope.Envelope{}, err
	}
	result := envelope.Envelope{
		Version:         envelope.Version,
		Kind:            "scan-result",
		Source:          "scanner-" + payload.ScanJobID,
		Sequence:        1,
		Timestamp:       payload.ScannedAt,
		DeduplicationID: payload.ScanJobID,
		Payload:         encoded,
	}
	if err := envelope.Sign(&result, privateKey); err != nil {
		return envelope.Envelope{}, err
	}
	return result, nil
}

func Verify(value envelope.Envelope, publicKey ed25519.PublicKey, now time.Time) (Payload, error) {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if err := envelope.Verify(value, publicKey, envelope.VerifyOptions{
		Now: now.UTC(), MaximumAge: MaximumDeliveryAge, MaximumFuture: MaximumFutureSkew,
	}); err != nil {
		return Payload{}, err
	}
	var payload Payload
	decoder := json.NewDecoder(strings.NewReader(string(value.Payload)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&payload); err != nil {
		return Payload{}, errors.New("scan result payload is invalid")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return Payload{}, errors.New("scan result payload has trailing data")
	}
	if err := validatePayload(payload); err != nil {
		return Payload{}, err
	}
	if value.Kind != "scan-result" || value.Source != "scanner-"+payload.ScanJobID || value.Sequence != 1 ||
		value.DeduplicationID != payload.ScanJobID || value.Timestamp != payload.ScannedAt {
		return Payload{}, errors.New("scan result envelope binding is invalid")
	}
	return payload, nil
}

func PayloadSHA256(value envelope.Envelope) [sha256.Size]byte {
	return sha256.Sum256(value.Payload)
}

func VerdictSHA256(value envelope.Envelope) [sha256.Size]byte {
	return sha256.Sum256(append([]byte("plntir-scan-verdict-v1\x00"), value.Payload...))
}

func validatePayload(payload Payload) error {
	if !safeID.MatchString(payload.ScanJobID) || !strings.HasPrefix(payload.ScanJobID, "scan_") ||
		!safeID.MatchString(payload.FileVersionID) || !strings.HasPrefix(payload.FileVersionID, "fver_") ||
		!objectKey.MatchString(payload.ObjectKey) {
		return errors.New("scan result identity is invalid")
	}
	if payload.Verdict != "clean" && payload.Verdict != "malware" && payload.Verdict != "unscannable" && payload.Verdict != "failed" {
		return errors.New("scan result verdict is invalid")
	}
	if payload.EngineVersion == "" || len(payload.EngineVersion) > 256 || len(payload.RuleVersion) > 256 ||
		len(payload.DetectedType) > 256 || len(payload.Reason) > 1024 || strings.ContainsAny(payload.EngineVersion+payload.RuleVersion+payload.DetectedType+payload.Reason, "\x00\r\n") {
		return errors.New("scan result metadata is invalid")
	}
	if (payload.Verdict == "clean" || payload.Verdict == "malware") && !hexHash.MatchString(payload.ContentSHA256) {
		return errors.New("complete scan verdict requires a content SHA-256")
	}
	if payload.ContentSHA256 != "" {
		decoded, err := hex.DecodeString(payload.ContentSHA256)
		if err != nil || len(decoded) != sha256.Size || hex.EncodeToString(decoded) != payload.ContentSHA256 {
			return errors.New("scan result content SHA-256 is invalid")
		}
	}
	eventAt, err := time.Parse(time.RFC3339Nano, payload.EventTime)
	if err != nil || eventAt.Year() < 2020 {
		return errors.New("scan result event time is invalid")
	}
	scannedAt, err := time.Parse(time.RFC3339Nano, payload.ScannedAt)
	if err != nil || scannedAt.Before(eventAt.Add(-MaximumFutureSkew)) || scannedAt.Sub(eventAt) > 8*24*time.Hour {
		return errors.New("scan result time binding is invalid")
	}
	return nil
}
