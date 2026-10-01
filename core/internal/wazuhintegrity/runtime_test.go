package wazuhintegrity

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type anchorRecorder struct {
	anchors []DailyAnchor
	err     error
}

func (sink *anchorRecorder) PublishAnchor(_ context.Context, anchor DailyAnchor) error {
	sink.anchors = append(sink.anchors, anchor)
	return sink.err
}

func runtimeJournal(t *testing.T, now time.Time) *Journal {
	t.Helper()
	root := filepath.Join(t.TempDir(), "journal")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	journal, err := OpenJournal(root, now)
	if err != nil {
		t.Fatal(err)
	}
	return journal
}

func TestRuntimeKeepsIndependentSinksMovingWhileCoreIsDown(t *testing.T) {
	now := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	journal := runtimeJournal(t, now)
	archive := &archiveRecorder{}
	alerts := &alertRecorder{}
	projections := &projectionRecorder{err: errors.New("core unavailable")}
	anchors := &anchorRecorder{}
	_, signingKey, _ := ed25519.GenerateKey(rand.Reader)
	runtime := Runtime{
		Journal: journal, Archive: archive, Alerts: alerts, Projections: projections,
		Anchors: anchors, SigningKey: signingKey,
	}
	if _, err := runtime.Ingest(context.Background(), alertAtLevel(13), now); err == nil {
		t.Fatal("Core outage was not reported")
	}
	if !archive.called || !alerts.called || !projections.called {
		t.Fatal("an independent sink stopped when Core failed")
	}
	if _, err := runtime.Ingest(context.Background(), alertAtLevel(13), now.Add(time.Second)); err == nil {
		t.Fatal("pending projection outage was not reported")
	}
	if archive.calls != 2 || alerts.calls != 2 {
		t.Fatalf("archive and alert must advance exactly once per new record: archive=%d alerts=%d", archive.calls, alerts.calls)
	}
	if projections.calls != 2 {
		t.Fatalf("only the oldest Core projection should be retried: %d calls", projections.calls)
	}
	items, err := journal.Pending()
	if err != nil || len(items) != 2 {
		t.Fatalf("both durable records must remain pending: %d %v", len(items), err)
	}
	for _, item := range items {
		if ready, _ := journal.HasReceipt(item.Record, ArchiveReceipt); !ready {
			t.Fatalf("archive receipt missing for sequence %d", item.Record.Sequence)
		}
		if ready, _ := journal.HasReceipt(item.Record, AlertReceipt); !ready {
			t.Fatalf("alert receipt missing for sequence %d", item.Record.Sequence)
		}
	}
	if ready, _ := journal.HasReceipt(items[1].Record, ProjectionReceipt); ready {
		t.Fatal("later Core projection bypassed the failed sequence")
	}

	projections.err = nil
	if err := runtime.Drain(context.Background()); err != nil {
		t.Fatal(err)
	}
	items, err = journal.Pending()
	if err != nil || len(items) != 0 {
		t.Fatalf("pending records did not drain: %d %v", len(items), err)
	}
}

func TestRuntimeTreatsConditionalS3RetryAsDelivered(t *testing.T) {
	now := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	journal := runtimeJournal(t, now)
	item, err := journal.Append(alertAtLevel(3), now)
	if err != nil {
		t.Fatal(err)
	}
	archive := &archiveRecorder{err: ErrAlreadyArchived}
	alerts := &alertRecorder{}
	projections := &projectionRecorder{}
	anchors := &anchorRecorder{}
	_, signingKey, _ := ed25519.GenerateKey(rand.Reader)
	runtime := Runtime{
		Journal: journal, Archive: archive, Alerts: alerts, Projections: projections,
		Anchors: anchors, SigningKey: signingKey,
	}
	if err := runtime.Drain(context.Background()); err != nil {
		t.Fatal(err)
	}
	if pending, _ := journal.Pending(); len(pending) != 0 {
		t.Fatal("idempotent S3 retry prevented delivery completion")
	}
	if alerts.called {
		t.Fatal("low-severity event unexpectedly reached SNS")
	}
	if ready, err := journal.HasReceipt(item.Record, ArchiveReceipt); err == nil || ready {
		t.Fatal("receipt inspection must fail after the pending link is completed")
	}
}

func TestDailyAnchorIsDurableAndByteStableAcrossRetry(t *testing.T) {
	now := time.Date(2026, 9, 4, 23, 55, 0, 0, time.UTC)
	journal := runtimeJournal(t, now)
	archive := &archiveRecorder{}
	alerts := &alertRecorder{}
	projections := &projectionRecorder{}
	anchors := &anchorRecorder{err: errors.New("Cloudflare unavailable")}
	publicKey, signingKey, _ := ed25519.GenerateKey(rand.Reader)
	runtime := Runtime{
		Journal: journal, Archive: archive, Alerts: alerts, Projections: projections,
		Anchors: anchors, SigningKey: signingKey,
	}
	if _, err := runtime.Ingest(context.Background(), alertAtLevel(3), now); err != nil {
		t.Fatal(err)
	}
	if err := runtime.PublishDailyAnchor(context.Background(), now); err == nil {
		t.Fatal("anchor outage was not returned")
	}
	if len(anchors.anchors) != 1 {
		t.Fatal("first anchor was not attempted")
	}
	anchors.err = nil
	if err := runtime.PublishDailyAnchor(context.Background(), now.Add(3*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if len(anchors.anchors) != 2 || anchors.anchors[0] != anchors.anchors[1] {
		t.Fatal("daily anchor retry changed its signed bytes")
	}
	if err := VerifyDailyAnchor(anchors.anchors[1], publicKey); err != nil {
		t.Fatal(err)
	}
}
