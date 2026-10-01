package scanresultconsumer

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/aws/aws-sdk-go-v2/service/sqs/types"

	"plntir/core/internal/envelope"
	"plntir/core/internal/scanresult"
)

type fakeQueue struct {
	messages    []types.Message
	receiveErr  error
	deleteErr   error
	receive     *sqs.ReceiveMessageInput
	delete      *sqs.DeleteMessageInput
	deleteCalls int
}

func (queue *fakeQueue) ReceiveMessage(_ context.Context, input *sqs.ReceiveMessageInput, _ ...func(*sqs.Options)) (*sqs.ReceiveMessageOutput, error) {
	queue.receive = input
	if queue.receiveErr != nil {
		return nil, queue.receiveErr
	}
	return &sqs.ReceiveMessageOutput{Messages: queue.messages}, nil
}

func (queue *fakeQueue) DeleteMessage(_ context.Context, input *sqs.DeleteMessageInput, _ ...func(*sqs.Options)) (*sqs.DeleteMessageOutput, error) {
	queue.deleteCalls++
	queue.delete = input
	if queue.deleteErr != nil {
		return nil, queue.deleteErr
	}
	return &sqs.DeleteMessageOutput{}, nil
}

type fakeStore struct {
	calls     int
	duplicate bool
	err       error
	verify    bool
	value     envelope.Envelope
}

func (store *fakeStore) IngestSignedScanResult(_ context.Context, value envelope.Envelope, key ed25519.PublicKey, now time.Time) (bool, error) {
	store.calls++
	store.value = value
	if store.verify {
		if _, err := scanresult.Verify(value, key, now); err != nil {
			return false, err
		}
	}
	return store.duplicate, store.err
}

type fixture struct {
	consumer *Consumer
	queue    *fakeQueue
	store    *fakeStore
	value    envelope.Envelope
	body     string
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	now := time.Date(2026, 9, 5, 5, 0, 0, 0, time.UTC)
	publicKey, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	value, err := scanresult.NewEnvelope(scanresult.Payload{
		ScanJobID: "scan_0123456789abcdefghjkmnpqrstvwxyz", FileVersionID: "fver_0123456789abcdefghjkmnpqrstvwxyz",
		ObjectKey: "objects/obj_0123456789abcdefghjkmnpqrstvwxyz", EventTime: now.Add(-time.Minute).Format(time.RFC3339Nano),
		Verdict: "clean", EngineVersion: "scanner-qualified", RuleVersion: "rules-1", ContentSHA256: strings.Repeat("a", 64),
		DetectedType: "application/pdf", ScannedAt: now.Format(time.RFC3339Nano),
	}, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(value)
	queue := &fakeQueue{messages: []types.Message{{Body: aws.String(string(encoded)), ReceiptHandle: aws.String("receipt-1")}}}
	store := &fakeStore{verify: true}
	consumer, err := New(queue, store, Configuration{
		AWSAccountID: "123456789012", QueueURL: "https://sqs.eu-central-1.amazonaws.com/123456789012/plntir-scan-results.fifo",
		ScannerVerifyKey: publicKey,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	consumer.now = func() time.Time { return now }
	return fixture{consumer: consumer, queue: queue, store: store, value: value, body: string(encoded)}
}

func TestPollCommitsBeforeDeleting(t *testing.T) {
	fixture := newFixture(t)
	result, err := fixture.consumer.PollOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if result.Received != 1 || result.Committed != 1 || result.Rejected != 0 || fixture.store.calls != 1 || fixture.queue.deleteCalls != 1 {
		t.Fatalf("unexpected poll result: %+v store=%d deletes=%d", result, fixture.store.calls, fixture.queue.deleteCalls)
	}
	if aws.ToString(fixture.queue.receive.QueueUrl) != fixture.consumer.config.QueueURL ||
		fixture.queue.receive.WaitTimeSeconds != longPollSeconds || fixture.queue.receive.VisibilityTimeout != visibilitySeconds ||
		aws.ToString(fixture.queue.delete.ReceiptHandle) != "receipt-1" {
		t.Fatal("queue polling was not pinned and bounded")
	}
}

func TestExactDuplicateIsAcknowledged(t *testing.T) {
	fixture := newFixture(t)
	fixture.store.duplicate = true
	result, err := fixture.consumer.PollOnce(context.Background())
	if err != nil || result.Duplicates != 1 || fixture.queue.deleteCalls != 1 {
		t.Fatalf("duplicate was not safely acknowledged: %+v err=%v", result, err)
	}
}

func TestInvalidOrNonCanonicalMessageRemainsForRedrive(t *testing.T) {
	for name, mutate := range map[string]func(*fixture){
		"non-canonical": func(fixture *fixture) { fixture.queue.messages[0].Body = aws.String(" " + fixture.body) },
		"tampered": func(fixture *fixture) {
			body := strings.Replace(fixture.body, `"verdict":"clean"`, `"verdict":"malware"`, 1)
			fixture.queue.messages[0].Body = aws.String(body)
		},
		"oversized": func(fixture *fixture) {
			fixture.queue.messages[0].Body = aws.String(strings.Repeat("x", maximumMessageBytes+1))
		},
	} {
		t.Run(name, func(t *testing.T) {
			fixture := newFixture(t)
			mutate(&fixture)
			result, err := fixture.consumer.PollOnce(context.Background())
			if err == nil || result.Rejected != 1 || fixture.queue.deleteCalls != 0 {
				t.Fatalf("bad message was acknowledged: %+v err=%v", result, err)
			}
		})
	}
}

func TestStoreOrDeleteFailureIsNeverLost(t *testing.T) {
	fixture := newFixture(t)
	fixture.store.err = errors.New("simulated database outage")
	if result, err := fixture.consumer.PollOnce(context.Background()); err == nil || result.Rejected != 1 || fixture.queue.deleteCalls != 0 {
		t.Fatalf("store outage was acknowledged: %+v err=%v", result, err)
	}

	fixture = newFixture(t)
	fixture.queue.deleteErr = errors.New("simulated SQS outage")
	if result, err := fixture.consumer.PollOnce(context.Background()); err == nil || result.Rejected != 1 || fixture.store.calls != 1 {
		t.Fatalf("delete outage did not leave replayable message: %+v err=%v", result, err)
	}
}

func TestConfigurationPinsRegionAccountAndQueue(t *testing.T) {
	fixture := newFixture(t)
	configuration := fixture.consumer.config
	configuration.QueueURL = "https://sqs.us-east-1.amazonaws.com/123456789012/plntir-scan-results.fifo"
	if err := configuration.Validate(); err == nil {
		t.Fatal("cross-region queue was accepted")
	}
	configuration = fixture.consumer.config
	configuration.QueueURL = "https://sqs.eu-central-1.amazonaws.com/999999999999/plntir-scan-results.fifo"
	if err := configuration.Validate(); err == nil {
		t.Fatal("cross-account queue was accepted")
	}
}
