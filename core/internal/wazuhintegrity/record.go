package wazuhintegrity

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"time"
)

const (
	SchemaVersion    = 1
	MaximumAlertSize = 1 << 20
)

var (
	ruleIDPattern  = regexp.MustCompile(`^[0-9]{1,16}$`)
	agentIDPattern = regexp.MustCompile(`^[0-9]{1,16}$`)
)

type AlertSummary struct {
	EventSHA256 string `json:"event_sha256"`
	OccurredAt  string `json:"occurred_at"`
	RuleID      string `json:"rule_id"`
	RuleLevel   int    `json:"rule_level"`
	Severity    string `json:"severity"`
	AgentID     string `json:"agent_id,omitempty"`
}

type Record struct {
	SchemaVersion int             `json:"schema_version"`
	Sequence      uint64          `json:"sequence"`
	ReceivedAt    string          `json:"received_at"`
	PreviousHash  string          `json:"previous_hash"`
	SourceSHA256  string          `json:"source_sha256"`
	EntryHash     string          `json:"entry_hash"`
	Summary       AlertSummary    `json:"summary"`
	Alert         json.RawMessage `json:"alert"`
}

type wazuhAlert struct {
	Timestamp string `json:"timestamp"`
	Rule      struct {
		Level int             `json:"level"`
		ID    json.RawMessage `json:"id"`
	} `json:"rule"`
	Agent *struct {
		ID string `json:"id"`
	} `json:"agent,omitempty"`
}

func NewRecord(sequence uint64, previousHash [sha256.Size]byte, raw []byte, receivedAt time.Time) (Record, error) {
	if sequence == 0 || receivedAt.IsZero() {
		return Record{}, errors.New("record sequence and received time are required")
	}
	if err := validateJSONNoDuplicateKeys(raw); err != nil {
		return Record{}, err
	}
	var source wazuhAlert
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if err := decoder.Decode(&source); err != nil {
		return Record{}, errors.New("decode Wazuh alert")
	}
	if err := ensureEOF(decoder); err != nil {
		return Record{}, err
	}
	occurredAt, err := parseWazuhTime(source.Timestamp)
	if err != nil {
		return Record{}, err
	}
	ruleID, err := parseRuleID(source.Rule.ID)
	if err != nil || source.Rule.Level < 0 || source.Rule.Level > 16 {
		return Record{}, errors.New("Wazuh rule identity or level is invalid")
	}
	agentID := ""
	if source.Agent != nil {
		agentID = source.Agent.ID
		if !agentIDPattern.MatchString(agentID) {
			return Record{}, errors.New("Wazuh agent ID is invalid")
		}
	}
	sourceHash := sha256.Sum256(raw)
	record := Record{
		SchemaVersion: SchemaVersion,
		Sequence:      sequence,
		ReceivedAt:    receivedAt.UTC().Format(time.RFC3339Nano),
		PreviousHash:  base64.RawURLEncoding.EncodeToString(previousHash[:]),
		SourceSHA256:  base64.RawURLEncoding.EncodeToString(sourceHash[:]),
		Summary: AlertSummary{
			EventSHA256: base64.RawURLEncoding.EncodeToString(sourceHash[:]),
			OccurredAt:  occurredAt.UTC().Format(time.RFC3339Nano),
			RuleID:      ruleID,
			RuleLevel:   source.Rule.Level,
			Severity:    severity(source.Rule.Level),
			AgentID:     agentID,
		},
		Alert: append(json.RawMessage(nil), raw...),
	}
	entryHash := recordHash(record)
	record.EntryHash = base64.RawURLEncoding.EncodeToString(entryHash[:])
	return record, nil
}

func (record Record) Validate() error {
	if record.SchemaVersion != SchemaVersion || record.Sequence == 0 {
		return errors.New("record schema or sequence is invalid")
	}
	if _, err := time.Parse(time.RFC3339Nano, record.ReceivedAt); err != nil {
		return errors.New("record received time is invalid")
	}
	previous, err := decodeHash(record.PreviousHash)
	if err != nil {
		return errors.New("record previous hash is invalid")
	}
	rebuilt, err := NewRecord(record.Sequence, previous, record.Alert, mustParseTime(record.ReceivedAt))
	if err != nil {
		return err
	}
	if rebuilt.SourceSHA256 != record.SourceSHA256 || rebuilt.EntryHash != record.EntryHash || rebuilt.Summary != record.Summary {
		return errors.New("record content or hash chain is inconsistent")
	}
	return nil
}

func (record Record) Marshal() ([]byte, error) {
	if err := record.Validate(); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(record)
	if err != nil {
		return nil, err
	}
	return append(encoded, '\n'), nil
}

func (record Record) Hash() ([sha256.Size]byte, error) {
	return decodeHash(record.EntryHash)
}

func (record Record) ObjectKey() (string, error) {
	stamp, err := time.Parse(time.RFC3339Nano, record.ReceivedAt)
	if err != nil || record.Sequence == 0 {
		return "", errors.New("record cannot form an object key")
	}
	return fmt.Sprintf(
		"objects/%04d/%02d/%02d/%020d-%s.json",
		stamp.Year(), stamp.Month(), stamp.Day(), record.Sequence, record.EntryHash,
	), nil
}

func recordHash(record Record) [sha256.Size]byte {
	hash := sha256.New()
	hash.Write([]byte("plntir-wazuh-record-v1\x00"))
	var sequence [8]byte
	binary.BigEndian.PutUint64(sequence[:], record.Sequence)
	hash.Write(sequence[:])
	appendHashField(hash, []byte(record.ReceivedAt))
	previous, _ := base64.RawURLEncoding.DecodeString(record.PreviousHash)
	source, _ := base64.RawURLEncoding.DecodeString(record.SourceSHA256)
	appendHashField(hash, previous)
	appendHashField(hash, source)
	appendHashField(hash, record.Alert)
	var result [sha256.Size]byte
	copy(result[:], hash.Sum(nil))
	return result
}

type hashWriter interface {
	Write([]byte) (int, error)
}

func appendHashField(target hashWriter, value []byte) {
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(len(value)))
	_, _ = target.Write(length[:])
	_, _ = target.Write(value)
}

func severity(level int) string {
	switch {
	case level >= 13:
		return "critical"
	case level >= 10:
		return "high"
	case level >= 7:
		return "medium"
	case level >= 4:
		return "low"
	default:
		return "info"
	}
}

func parseRuleID(raw json.RawMessage) (string, error) {
	var text string
	if err := json.Unmarshal(raw, &text); err == nil && ruleIDPattern.MatchString(text) {
		return text, nil
	}
	var number json.Number
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&number); err == nil && ruleIDPattern.MatchString(string(number)) {
		return string(number), nil
	}
	return "", errors.New("invalid Wazuh rule ID")
}

func parseWazuhTime(value string) (time.Time, error) {
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02T15:04:05.999999999-0700"} {
		if result, err := time.Parse(layout, value); err == nil {
			return result, nil
		}
	}
	return time.Time{}, errors.New("Wazuh alert timestamp is invalid")
}

func decodeHash(value string) ([sha256.Size]byte, error) {
	var result [sha256.Size]byte
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(decoded) != sha256.Size || base64.RawURLEncoding.EncodeToString(decoded) != value {
		return result, errors.New("invalid canonical SHA-256")
	}
	copy(result[:], decoded)
	return result, nil
}

func mustParseTime(value string) time.Time {
	result, _ := time.Parse(time.RFC3339Nano, value)
	return result
}

func validateJSONNoDuplicateKeys(raw []byte) error {
	if len(raw) == 0 || len(raw) > MaximumAlertSize || !json.Valid(raw) {
		return errors.New("Wazuh alert JSON is empty, oversized, or invalid")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := walkJSON(decoder); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("Wazuh alert contains trailing data")
	}
	return nil
}

func walkJSON(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return errors.New("decode Wazuh alert token")
	}
	delimiter, composite := token.(json.Delim)
	if !composite {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return errors.New("decode Wazuh alert object key")
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("Wazuh alert object key is not a string")
			}
			if _, duplicate := seen[key]; duplicate {
				return errors.New("Wazuh alert contains a duplicate object key")
			}
			seen[key] = struct{}{}
			if err := walkJSON(decoder); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim('}') {
			return errors.New("Wazuh alert object is unterminated")
		}
	case '[':
		for decoder.More() {
			if err := walkJSON(decoder); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim(']') {
			return errors.New("Wazuh alert array is unterminated")
		}
	default:
		return errors.New("Wazuh alert has an unexpected delimiter")
	}
	return nil
}

func ensureEOF(decoder *json.Decoder) error {
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("JSON contains trailing data")
	}
	return nil
}
