package wazuhintegrity

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"plntir/core/internal/envelope"
)

type HealthProjection struct {
	SchemaVersion int    `json:"schema_version"`
	State         string `json:"state"`
	ObservedAt    string `json:"observed_at"`
	LastEventAt   string `json:"last_event_at"`
	LastSequence  uint64 `json:"last_sequence"`
	ChainHash     string `json:"chain_hash"`
	AgentID       string `json:"agent_id,omitempty"`
	RuleLevel     int    `json:"rule_level"`
	Severity      string `json:"severity"`
}

const (
	ProjectionMaximumAge    = 31 * 24 * time.Hour
	ProjectionMaximumFuture = 5 * time.Minute
)

func ProjectionFromRecord(record Record, observedAt time.Time) (HealthProjection, error) {
	if err := record.Validate(); err != nil || observedAt.IsZero() {
		return HealthProjection{}, errors.New("cannot project invalid Wazuh record")
	}
	return HealthProjection{
		SchemaVersion: 1,
		State:         "available",
		ObservedAt:    observedAt.UTC().Format(time.RFC3339Nano),
		LastEventAt:   record.Summary.OccurredAt,
		LastSequence:  record.Sequence,
		ChainHash:     record.EntryHash,
		AgentID:       record.Summary.AgentID,
		RuleLevel:     record.Summary.RuleLevel,
		Severity:      record.Summary.Severity,
	}, nil
}

func SignProjection(projection HealthProjection, privateKey ed25519.PrivateKey) (envelope.Envelope, error) {
	if ValidateHealthProjection(projection) != nil || len(privateKey) != ed25519.PrivateKeySize {
		return envelope.Envelope{}, errors.New("Wazuh health projection is invalid")
	}
	payload, err := json.Marshal(projection)
	if err != nil {
		return envelope.Envelope{}, err
	}
	payloadHash := sha256.Sum256(payload)
	result := envelope.Envelope{
		Version:         envelope.Version,
		Kind:            "wazuh-health-v1",
		Source:          "plntir-siem-01",
		Sequence:        projection.LastSequence,
		Timestamp:       projection.ObservedAt,
		DeduplicationID: fmt.Sprintf("wazuh-health-%d-%s", projection.LastSequence, hex.EncodeToString(payloadHash[:12])),
		Payload:         payload,
	}
	if err := envelope.Sign(&result, privateKey); err != nil {
		return envelope.Envelope{}, err
	}
	return result, nil
}

func ValidateHealthProjection(projection HealthProjection) error {
	if projection.SchemaVersion != 1 || projection.State != "available" || projection.LastSequence == 0 {
		return errors.New("projection schema, state, or sequence is invalid")
	}
	if _, err := time.Parse(time.RFC3339Nano, projection.ObservedAt); err != nil {
		return errors.New("projection observation time is invalid")
	}
	if _, err := time.Parse(time.RFC3339Nano, projection.LastEventAt); err != nil {
		return errors.New("projection event time is invalid")
	}
	if _, err := decodeHash(projection.ChainHash); err != nil {
		return errors.New("projection chain hash is invalid")
	}
	if projection.RuleLevel < 0 || projection.RuleLevel > 16 ||
		severity(projection.RuleLevel) != projection.Severity {
		return errors.New("projection rule level or severity is invalid")
	}
	if projection.AgentID != "" && !agentIDPattern.MatchString(projection.AgentID) {
		return errors.New("projection agent is invalid")
	}
	return nil
}
