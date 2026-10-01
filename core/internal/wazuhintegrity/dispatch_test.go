package wazuhintegrity

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"plntir/core/internal/envelope"
)

type archiveRecorder struct {
	called bool
	calls  int
	body   []byte
	err    error
}

func (sink *archiveRecorder) AppendRecord(_ context.Context, _ string, body []byte, _ string) error {
	sink.called = true
	sink.calls++
	sink.body = append([]byte(nil), body...)
	return sink.err
}

type alertRecorder struct {
	called  bool
	calls   int
	summary AlertSummary
	err     error
}

func (sink *alertRecorder) PublishAlert(_ context.Context, summary AlertSummary) error {
	sink.called = true
	sink.calls++
	sink.summary = summary
	return sink.err
}

type projectionRecorder struct {
	called     bool
	calls      int
	projection HealthProjection
	err        error
}

func (sink *projectionRecorder) PublishHealth(_ context.Context, projection HealthProjection) error {
	sink.called = true
	sink.calls++
	sink.projection = projection
	return sink.err
}

func TestCoreProjectionFailureDoesNotSkipArchiveOrIndependentAlert(t *testing.T) {
	record, err := NewRecord(1, [sha256.Size]byte{}, alertAtLevel(13), time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	archive := &archiveRecorder{}
	alerts := &alertRecorder{}
	projections := &projectionRecorder{err: errors.New("core unavailable")}
	err = (Dispatcher{Archive: archive, Alerts: alerts, Projections: projections}).Deliver(context.Background(), record)
	if err == nil || !strings.Contains(err.Error(), "core unavailable") {
		t.Fatalf("projection failure not returned: %v", err)
	}
	if !archive.called || !alerts.called || !projections.called {
		t.Fatal("a sink was skipped after independent failure")
	}
	if !bytesContains(archive.body, []byte("password=never-project-this")) {
		t.Fatal("full archival record lost the raw Wazuh event")
	}
	encodedSummary, _ := json.Marshal(alerts.summary)
	encodedProjection, _ := json.Marshal(projections.projection)
	for _, value := range [][]byte{encodedSummary, encodedProjection} {
		if bytesContains(value, []byte("password")) || bytesContains(value, []byte("raw-only")) || bytesContains(value, []byte("mac-secret-name")) {
			t.Fatalf("sanitized sink leaked raw alert content: %s", value)
		}
	}
}

func TestSignedHealthProjectionUsesVersionedInternalEnvelope(t *testing.T) {
	record, _ := NewRecord(9, [sha256.Size]byte{}, alertAtLevel(10), time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC))
	projection, err := ProjectionFromRecord(record, time.Date(2026, 9, 4, 12, 0, 1, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	publicKey, privateKey, _ := ed25519.GenerateKey(nil)
	signed, err := SignProjection(projection, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	if signed.Kind != "wazuh-health-v1" || signed.Source != "plntir-siem-01" || signed.Sequence != 9 {
		t.Fatalf("wrong projection envelope: %#v", signed)
	}
	if err := envelope.Verify(signed, publicKey, envelope.VerifyOptions{
		Now:          time.Date(2026, 9, 4, 12, 0, 1, 0, time.UTC),
		MaximumAge:   time.Minute,
		LastSequence: 8,
	}); err != nil {
		t.Fatalf("signed projection did not verify: %v", err)
	}
}

func bytesContains(haystack, needle []byte) bool {
	return strings.Contains(string(haystack), string(needle))
}
