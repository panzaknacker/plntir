package sqlite

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

func TestDurableJobLeaseHeartbeatRetryAndRecovery(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t)
	now := time.Date(2026, 9, 4, 15, 0, 0, 0, time.UTC)
	job, err := store.EnqueueDurableJob(ctx, "backup.retry", "device:backup:0001", json.RawMessage(`{"device_id":"dev_1","attempt":1}`), now, now)
	if err != nil {
		t.Fatal(err)
	}
	repeated, err := store.EnqueueDurableJob(ctx, "backup.retry", "device:backup:0001", json.RawMessage(`{"attempt":1,"device_id":"dev_1"}`), now.Add(time.Hour), now)
	if err != nil || repeated.ID != job.ID {
		t.Fatalf("idempotent enqueue failed: %+v %v", repeated, err)
	}
	if _, err := store.EnqueueDurableJob(ctx, "backup.retry", "device:backup:0001", json.RawMessage(`{"attempt":2}`), now, now); !errors.Is(err, ErrVersionConflict) {
		t.Fatalf("conflicting dedupe payload accepted: %v", err)
	}
	leased, err := store.LeaseNextDurableJob(ctx, "worker-a", 30*time.Second, now)
	if err != nil || leased.ID != job.ID || leased.Attempts != 1 || leased.LeaseOwner != "worker-a" {
		t.Fatalf("lease failed: %+v %v", leased, err)
	}
	if _, err := store.LeaseNextDurableJob(ctx, "worker-b", 30*time.Second, now.Add(10*time.Second)); !errors.Is(err, ErrNoWork) {
		t.Fatalf("active lease was stolen: %v", err)
	}
	if _, err := store.HeartbeatDurableJob(ctx, job.ID, "worker-a", time.Minute, now.Add(10*time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := store.LeaseNextDurableJob(ctx, "worker-b", 30*time.Second, now.Add(35*time.Second)); !errors.Is(err, ErrNoWork) {
		t.Fatalf("heartbeat extension was ignored: %v", err)
	}
	if err := store.RetryDurableJob(ctx, job.ID, "worker-a", "temporary\nnetwork\terror", now.Add(2*time.Minute), now.Add(20*time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := store.LeaseNextDurableJob(ctx, "worker-b", time.Minute, now.Add(time.Minute)); !errors.Is(err, ErrNoWork) {
		t.Fatalf("backoff was ignored: %v", err)
	}
	leased, err = store.LeaseNextDurableJob(ctx, "worker-b", time.Minute, now.Add(2*time.Minute))
	if err != nil || leased.Attempts != 2 || leased.LastError != "temporary network error" {
		t.Fatalf("retry lease failed: %+v %v", leased, err)
	}
	if err := store.SucceedDurableJob(ctx, job.ID, "worker-a", now.Add(2*time.Minute)); !errors.Is(err, ErrResourceNotFound) {
		t.Fatalf("old worker completed new lease: %v", err)
	}
	if err := store.SucceedDurableJob(ctx, job.ID, "worker-b", now.Add(2*time.Minute+time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := store.LeaseNextDurableJob(ctx, "worker-c", time.Minute, now.Add(10*time.Minute)); !errors.Is(err, ErrNoWork) {
		t.Fatalf("completed job was leased: %v", err)
	}
}

func TestExpiredDurableLeaseCanBeRecovered(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t)
	now := time.Date(2026, 9, 4, 16, 0, 0, 0, time.UTC)
	job, err := store.EnqueueDurableJob(ctx, "device.refresh", "device:refresh:0001", json.RawMessage(`{"device_id":"dev_1"}`), now, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.LeaseNextDurableJob(ctx, "dead-worker", 5*time.Second, now); err != nil {
		t.Fatal(err)
	}
	recovered, err := store.LeaseNextDurableJob(ctx, "recovery-worker", time.Minute, now.Add(6*time.Second))
	if err != nil || recovered.ID != job.ID || recovered.Attempts != 2 {
		t.Fatalf("expired lease was not recovered: %+v %v", recovered, err)
	}
}

func TestTransactionalOutboxLeaseDedupeAndBackoff(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t)
	now := time.Date(2026, 9, 4, 17, 0, 0, 0, time.UTC)
	message, err := store.EnqueueOutbox(ctx, "security.alert", "security:alert:0001", json.RawMessage(`{"severity":"high","event":"wipe"}`), now)
	if err != nil {
		t.Fatal(err)
	}
	repeated, err := store.EnqueueOutbox(ctx, "security.alert", "security:alert:0001", json.RawMessage(`{"event":"wipe","severity":"high"}`), now)
	if err != nil || repeated.ID != message.ID {
		t.Fatalf("outbox dedupe failed: %+v %v", repeated, err)
	}
	leased, err := store.LeaseOutbox(ctx, "publisher-a", 10, 30*time.Second, now)
	if err != nil || len(leased) != 1 || leased[0].ID != message.ID || leased[0].Attempts != 1 {
		t.Fatalf("outbox lease failed: %+v %v", leased, err)
	}
	second, err := store.LeaseOutbox(ctx, "publisher-b", 10, 30*time.Second, now)
	if err != nil || len(second) != 0 {
		t.Fatalf("outbox active lease was duplicated: %+v %v", second, err)
	}
	if err := store.RetryOutbox(ctx, message.ID, "publisher-a", "SNS\nrate limited", now.Add(time.Minute), now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	second, err = store.LeaseOutbox(ctx, "publisher-b", 10, 30*time.Second, now.Add(30*time.Second))
	if err != nil || len(second) != 0 {
		t.Fatalf("outbox backoff was ignored: %+v %v", second, err)
	}
	second, err = store.LeaseOutbox(ctx, "publisher-b", 10, 30*time.Second, now.Add(time.Minute))
	if err != nil || len(second) != 1 || second[0].Attempts != 2 {
		t.Fatalf("outbox retry was not leased: %+v %v", second, err)
	}
	if err := store.MarkOutboxPublished(ctx, message.ID, "publisher-a", now.Add(time.Minute)); !errors.Is(err, ErrResourceNotFound) {
		t.Fatalf("old publisher completed a new lease: %v", err)
	}
	if err := store.MarkOutboxPublished(ctx, message.ID, "publisher-b", now.Add(time.Minute+time.Second)); err != nil {
		t.Fatal(err)
	}
	remaining, err := store.LeaseOutbox(ctx, "publisher-c", 10, time.Minute, now.Add(2*time.Minute))
	if err != nil || len(remaining) != 0 {
		t.Fatalf("published message was leased again: %+v %v", remaining, err)
	}
}

func TestJobPayloadRejectsDuplicateKeysAtEveryDepth(t *testing.T) {
	store := openTestStore(t)
	now := time.Date(2026, 9, 5, 6, 0, 0, 0, time.UTC)
	for name, payload := range map[string]json.RawMessage{
		"root":   json.RawMessage(`{"record_id":"one","record_id":"two"}`),
		"nested": json.RawMessage(`{"record":{"id":"one","id":"two"}}`),
		"array":  json.RawMessage(`{"records":[{"id":"one","id":"two"}]}`),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := store.EnqueueDurableJob(context.Background(), "ai.analyze", "ai:duplicate:"+name,
				payload, now, now); err == nil {
				t.Fatal("job payload with duplicate keys was accepted")
			}
		})
	}
}
