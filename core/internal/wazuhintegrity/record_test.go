package wazuhintegrity

import (
	"bytes"
	"crypto/sha256"
	"strconv"
	"strings"
	"testing"
	"time"
)

func alertAtLevel(level int) []byte {
	return []byte(strings.Replace(
		`{"timestamp":"2026-09-04T11:59:58.123+0000","rule":{"level":LEVEL,"description":"password=never-project-this","id":"100001"},"agent":{"id":"007","name":"mac-secret-name"},"data":{"secret":"raw-only"}}`,
		"LEVEL", strconv.Itoa(level), 1,
	))
}

func TestRecordPreservesRawAlertButSanitizesSummary(t *testing.T) {
	raw := alertAtLevel(13)
	record, err := NewRecord(1, [sha256.Size]byte{}, raw, time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(record.Alert, raw) || record.Summary.Severity != "critical" || record.Summary.AgentID != "007" {
		t.Fatalf("unexpected record: %#v", record)
	}
	summary := strings.Join([]string{record.Summary.EventSHA256, record.Summary.OccurredAt, record.Summary.RuleID, record.Summary.Severity, record.Summary.AgentID}, " ")
	for _, secret := range []string{"password", "raw-only", "mac-secret-name"} {
		if strings.Contains(summary, secret) {
			t.Fatalf("summary leaked %q", secret)
		}
	}
	if err := record.Validate(); err != nil {
		t.Fatal(err)
	}
	key, err := record.ObjectKey()
	if err != nil || !strings.HasPrefix(key, "objects/2026/09/04/00000000000000000001-") {
		t.Fatalf("unexpected object key %q: %v", key, err)
	}
}

func TestHashChainBindsPreviousRecordAndRawBytes(t *testing.T) {
	first, err := NewRecord(1, [sha256.Size]byte{}, alertAtLevel(10), time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	firstHash, _ := first.Hash()
	second, err := NewRecord(2, firstHash, alertAtLevel(11), time.Date(2026, 9, 4, 12, 0, 1, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	tampered := second
	tampered.Alert = append([]byte(nil), second.Alert...)
	tampered.Alert[bytes.Index(tampered.Alert, []byte("raw-only"))] = 'x'
	if err := tampered.Validate(); err == nil {
		t.Fatal("tampered record validated")
	}
	wrongPrevious := second
	wrongPrevious.PreviousHash = first.PreviousHash
	if err := wrongPrevious.Validate(); err == nil {
		t.Fatal("record with replaced previous hash validated")
	}
}

func TestRejectsDuplicateCriticalJSONKey(t *testing.T) {
	raw := []byte(`{"timestamp":"2026-09-04T12:00:00Z","rule":{"level":10,"level":1,"id":"1"}}`)
	if _, err := NewRecord(1, [sha256.Size]byte{}, raw, time.Now()); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("duplicate JSON key was not rejected: %v", err)
	}
}

func TestRecordAcceptsHighestDocumentedWazuhRuleLevel(t *testing.T) {
	record, err := NewRecord(1, [sha256.Size]byte{}, alertAtLevel(16), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if record.Summary.RuleLevel != 16 || record.Summary.Severity != "critical" {
		t.Fatalf("level 16 mapping drifted: %#v", record.Summary)
	}
}
