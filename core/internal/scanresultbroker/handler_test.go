package scanresultbroker

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sqs"

	"plntir/core/internal/scanresult"
)

type fakeQueue struct {
	input *sqs.SendMessageInput
	err   error
	calls int
}

func (queue *fakeQueue) SendMessage(_ context.Context, input *sqs.SendMessageInput, _ ...func(*sqs.Options)) (*sqs.SendMessageOutput, error) {
	queue.calls++
	queue.input = input
	if queue.err != nil {
		return nil, queue.err
	}
	return &sqs.SendMessageOutput{MessageId: aws.String("message-1")}, nil
}

type brokerFixture struct {
	handler *Handler
	queue   *fakeQueue
	request events.APIGatewayV2HTTPRequest
}

func newBrokerFixture(t *testing.T) brokerFixture {
	t.Helper()
	now := time.Date(2026, 9, 5, 3, 0, 0, 0, time.UTC)
	certificatePEM, fingerprint := resultClientCertificate(t, now)
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
	body, _ := json.Marshal(value)
	configuration := Configuration{
		ScannerVerifyKey: publicKey, ClientCertFingerprint: fingerprint,
		ExpectedAPIID: "a1b2c3d4e5", ExpectedDomainName: "result-broker.security.example",
		AWSAccountID: "123456789012", QueueURL: "https://sqs.eu-central-1.amazonaws.com/123456789012/plntir-scan-results.fifo",
	}
	queue := &fakeQueue{}
	handler, err := New(queue, configuration, nil)
	if err != nil {
		t.Fatal(err)
	}
	handler.now = func() time.Time { return now }
	request := events.APIGatewayV2HTTPRequest{
		RawPath: "/v1/results", Body: string(body),
		Headers: map[string]string{"content-type": "application/json", "idempotency-key": value.DeduplicationID},
		RequestContext: events.APIGatewayV2HTTPRequestContext{
			APIID: configuration.ExpectedAPIID, DomainName: configuration.ExpectedDomainName, RequestID: "request-1",
			HTTP: events.APIGatewayV2HTTPRequestContextHTTPDescription{Method: http.MethodPost, Path: "/v1/results"},
			Authentication: events.APIGatewayV2HTTPRequestContextAuthentication{
				ClientCert: events.APIGatewayV2HTTPRequestContextAuthenticationClientCert{ClientCertPem: certificatePEM},
			},
		},
	}
	return brokerFixture{handler: handler, queue: queue, request: request}
}

func resultClientCertificate(t *testing.T, now time.Time) (string, string) {
	t.Helper()
	publicKey, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "plntir-scanner-result"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(der)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), hex.EncodeToString(digest[:])
}

func TestBrokerRequiresMTLSAndSignatureBeforeFIFOQueue(t *testing.T) {
	fixture := newBrokerFixture(t)
	response, err := fixture.handler.Handle(context.Background(), fixture.request)
	if err != nil || response.StatusCode != http.StatusAccepted {
		t.Fatalf("valid result failed: %d %s %v", response.StatusCode, response.Body, err)
	}
	if fixture.queue.calls != 1 || fixture.queue.input == nil || aws.ToString(fixture.queue.input.MessageGroupId) != "scan-results" ||
		aws.ToString(fixture.queue.input.MessageDeduplicationId) != fixture.request.Headers["idempotency-key"] ||
		aws.ToString(fixture.queue.input.QueueUrl) != fixture.handler.config.QueueURL {
		t.Fatalf("FIFO binding is incorrect: %+v", fixture.queue.input)
	}
	if strings.Contains(response.Body, "content_sha256") || strings.Contains(response.Body, "application/pdf") {
		t.Fatal("broker response leaked scan result content")
	}
}

func TestBrokerRejectsWrongCertificateBeforeQueue(t *testing.T) {
	fixture := newBrokerFixture(t)
	fixture.handler.config.ClientCertFingerprint = strings.Repeat("0", 64)
	response, err := fixture.handler.Handle(context.Background(), fixture.request)
	if err != nil || response.StatusCode != http.StatusForbidden || fixture.queue.calls != 0 {
		t.Fatalf("certificate rejection failed: status=%d calls=%d err=%v", response.StatusCode, fixture.queue.calls, err)
	}
}

func TestBrokerRejectsTamperedEnvelopeBeforeQueue(t *testing.T) {
	fixture := newBrokerFixture(t)
	var value map[string]any
	if err := json.Unmarshal([]byte(fixture.request.Body), &value); err != nil {
		t.Fatal(err)
	}
	payload := value["payload"].(map[string]any)
	payload["verdict"] = "malware"
	body, _ := json.Marshal(value)
	fixture.request.Body = string(body)
	response, err := fixture.handler.Handle(context.Background(), fixture.request)
	if err != nil || response.StatusCode != http.StatusBadRequest || fixture.queue.calls != 0 {
		t.Fatalf("tampered result was queued: status=%d calls=%d err=%v", response.StatusCode, fixture.queue.calls, err)
	}
}

func TestBrokerFailsClosedWhenQueueIsUnavailable(t *testing.T) {
	fixture := newBrokerFixture(t)
	fixture.queue.err = errors.New("simulated SQS outage")
	response, err := fixture.handler.Handle(context.Background(), fixture.request)
	if err != nil || response.StatusCode != http.StatusServiceUnavailable || !strings.Contains(response.Body, "result_queue_unavailable") {
		t.Fatalf("queue outage was not fail-closed: %d %s %v", response.StatusCode, response.Body, err)
	}
}

func TestConfigurationPinsExactFIFOQueue(t *testing.T) {
	fixture := newBrokerFixture(t)
	changed := fixture.handler.config
	changed.QueueURL = "https://sqs.eu-central-1.amazonaws.com/999999999999/plntir-scan-results.fifo"
	if err := changed.Validate(); err == nil {
		t.Fatal("cross-account result queue was accepted")
	}
}

func TestConfigurationRejectsPlntirBrokerDomains(t *testing.T) {
	fixture := newBrokerFixture(t)
	for _, domain := range []string{"plntir.example", "scanner.plntir.example"} {
		configuration := fixture.handler.config
		configuration.ExpectedDomainName = domain
		if err := configuration.Validate(); err == nil {
			t.Fatalf("Plntir web domain %q was accepted for the public mTLS broker", domain)
		}
	}
}
