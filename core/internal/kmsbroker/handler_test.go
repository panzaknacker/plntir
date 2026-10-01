package kmsbroker

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go-v2/service/kms"

	"plntir/core/internal/scanmeta"
)

type fakeKMS struct {
	plaintext []byte
	err       error
	input     *kms.DecryptInput
	calls     int
}

func (fake *fakeKMS) Decrypt(_ context.Context, input *kms.DecryptInput, _ ...func(*kms.Options)) (*kms.DecryptOutput, error) {
	fake.calls++
	fake.input = input
	if fake.err != nil {
		return nil, fake.err
	}
	return &kms.DecryptOutput{Plaintext: append([]byte(nil), fake.plaintext...), KeyId: input.KeyId}, nil
}

type brokerFixture struct {
	handler          *Handler
	kms              *fakeKMS
	request          events.APIGatewayV2HTTPRequest
	input            rewrapRequest
	containerPrivate *ecdh.PrivateKey
	dek              []byte
}

func newBrokerFixture(t *testing.T) brokerFixture {
	t.Helper()
	now := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	certificatePEM, fingerprint := clientCertificate(t, now)
	corePublic, corePrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	metadata, err := scanmeta.Sign(scanmeta.Input{
		AccountID:         "0123456789abcdef0123456789abcdef",
		Bucket:            "plntir-files",
		ObjectKey:         "objects/obj_0123456789abcdefghjkmnpqrstvwxyz",
		CiphertextSize:    80_000_000,
		JobID:             "scan_0123456789abcdefghjkmnpqrstvwxyz",
		FileVersionID:     "fver_0123456789abcdefghjkmnpqrstvwxyz",
		MediaKind:         "image",
		ManifestSHA256:    strings.Repeat("a", 64),
		KMSCiphertext:     []byte{1, 2, 3, 4, 5, 6},
		PlaintextSize:     79_999_968,
		ChunkSize:         scanmeta.MinMediaChunkBytes,
		NoncePrefix:       [4]byte{9, 8, 7, 6},
		SignedAt:          now.Add(-time.Minute),
		MetadataSignerKey: corePrivate,
	})
	if err != nil {
		t.Fatal(err)
	}
	containerPrivate, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	input := rewrapRequest{
		EnvelopeVersion:    1,
		ScanSessionID:      "scan_1123456789abcdefghjkmnpqrstvwxyz",
		ContainerPublicKey: base64.RawURLEncoding.EncodeToString(containerPrivate.PublicKey().Bytes()),
		Job: scanJob{
			Account:             "0123456789abcdef0123456789abcdef",
			Action:              "CompleteMultipartUpload",
			Bucket:              "plntir-files",
			ObjectKey:           "objects/obj_0123456789abcdefghjkmnpqrstvwxyz",
			CiphertextSize:      80_000_000,
			ETag:                "0123456789abcdef-2",
			EventTime:           now.Format(time.RFC3339),
			JobID:               metadata.JobID,
			FileVersionID:       metadata.FileVersionID,
			MediaKind:           metadata.MediaKind,
			ManifestSHA256:      metadata.ManifestSHA256,
			KMSCiphertext:       metadata.KMSCiphertext,
			KMSCiphertextSHA256: metadata.KMSCiphertextSHA256,
			PlaintextSize:       metadata.PlaintextSize,
			ChunkSize:           metadata.ChunkSize,
			NoncePrefix:         metadata.NoncePrefix,
			SignedAt:            metadata.SignedAt,
			Signature:           metadata.Signature,
		},
	}
	body, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	configuration := Configuration{
		KMSKeyARN:             "arn:aws:kms:eu-central-1:123456789012:key/01234567-89ab-cdef-0123-456789abcdef",
		CoreVerifyKey:         corePublic,
		ClientCertFingerprint: fingerprint,
		ExpectedAccountID:     input.Job.Account,
		ExpectedBucket:        input.Job.Bucket,
		ExpectedAPIID:         "a1b2c3d4e5",
		ExpectedDomainName:    "kms-broker.security.example",
	}
	dek := []byte("0123456789abcdef0123456789abcdef")
	fake := &fakeKMS{plaintext: dek}
	handler, err := New(fake, configuration, nil)
	if err != nil {
		t.Fatal(err)
	}
	handler.now = func() time.Time { return now }
	request := events.APIGatewayV2HTTPRequest{
		RawPath: "/v1/rewrap",
		Headers: map[string]string{
			"content-type":    "application/json; charset=utf-8",
			"idempotency-key": input.Job.JobID,
		},
		Body: string(body),
		RequestContext: events.APIGatewayV2HTTPRequestContext{
			APIID:      configuration.ExpectedAPIID,
			DomainName: configuration.ExpectedDomainName,
			RequestID:  "request-test",
			HTTP:       events.APIGatewayV2HTTPRequestContextHTTPDescription{Method: http.MethodPost, Path: "/v1/rewrap"},
			Authentication: events.APIGatewayV2HTTPRequestContextAuthentication{
				ClientCert: events.APIGatewayV2HTTPRequestContextAuthenticationClientCert{ClientCertPem: certificatePEM},
			},
		},
	}
	return brokerFixture{handler: handler, kms: fake, request: request, input: input, containerPrivate: containerPrivate, dek: dek}
}

func clientCertificate(t *testing.T, now time.Time) (string, string) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "plntir-scanner-worker"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, public, private)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint := sha256.Sum256(der)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), hex.EncodeToString(fingerprint[:])
}

func TestRewrapValidSignedJob(t *testing.T) {
	fixture := newBrokerFixture(t)
	response, err := fixture.handler.Handle(context.Background(), fixture.request)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("unexpected response %d %s", response.StatusCode, response.Body)
	}
	if fixture.kms.calls != 1 || fixture.kms.input == nil {
		t.Fatal("KMS decrypt was not called exactly once")
	}
	wantedContext := EncryptionContext(fixture.input.Job.FileVersionID, fixture.input.Job.ObjectKey)
	if !reflect.DeepEqual(fixture.kms.input.EncryptionContext, wantedContext) || fixture.kms.input.KeyId == nil || *fixture.kms.input.KeyId != fixture.handler.config.KMSKeyARN {
		t.Fatal("KMS decrypt was not bound to the exact key and encryption context")
	}
	var result rewrapResponse
	if err := json.Unmarshal([]byte(response.Body), &result); err != nil {
		t.Fatal(err)
	}
	brokerPublicBytes, err := decodeCanonicalBase64URL(result.BrokerPublicKey, 32)
	if err != nil {
		t.Fatal(err)
	}
	brokerPublic, err := ecdh.X25519().NewPublicKey(brokerPublicBytes)
	if err != nil {
		t.Fatal(err)
	}
	shared, err := fixture.containerPrivate.ECDH(brokerPublic)
	if err != nil {
		t.Fatal(err)
	}
	salt := wrapSalt(fixture.input.Job.JobID, fixture.input.Job.FileVersionID, fixture.input.Job.ObjectKey, fixture.input.ScanSessionID)
	key, err := hkdf.Key(sha256.New, shared, salt[:], "plntir-scan-dek-wrap-v1", 32)
	if err != nil {
		t.Fatal(err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	nonce, err := decodeCanonicalBase64URL(result.WrapNonce, gcm.NonceSize())
	if err != nil {
		t.Fatal(err)
	}
	wrapped, err := decodeCanonicalBase64URL(result.WrappedDEK, 48)
	if err != nil {
		t.Fatal(err)
	}
	aad := wrapAAD(fixture.input.Job.JobID, fixture.input.Job.FileVersionID, fixture.input.Job.ObjectKey, fixture.input.ScanSessionID, fixture.input.ContainerPublicKey, result.BrokerPublicKey)
	plaintext, err := gcm.Open(nil, nonce, wrapped, aad)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(plaintext, fixture.dek) {
		t.Fatal("rewrapped DEK does not match KMS plaintext")
	}
}

func TestRejectsWrongCertificateBeforeKMS(t *testing.T) {
	fixture := newBrokerFixture(t)
	fixture.handler.config.ClientCertFingerprint = strings.Repeat("0", 64)
	response, err := fixture.handler.Handle(context.Background(), fixture.request)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusForbidden || fixture.kms.calls != 0 {
		t.Fatalf("certificate rejection failed: status=%d calls=%d", response.StatusCode, fixture.kms.calls)
	}
}

func TestRejectsTamperedSignedJobBeforeKMS(t *testing.T) {
	fixture := newBrokerFixture(t)
	fixture.input.Job.ManifestSHA256 = strings.Repeat("b", 64)
	body, err := json.Marshal(fixture.input)
	if err != nil {
		t.Fatal(err)
	}
	fixture.request.Body = string(body)
	response, err := fixture.handler.Handle(context.Background(), fixture.request)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusBadRequest || fixture.kms.calls != 0 || strings.Contains(response.Body, fixture.input.Job.KMSCiphertext) {
		t.Fatalf("tampered job was not safely rejected: %d %s", response.StatusCode, response.Body)
	}
}

func TestKMSFailureIsFailClosed(t *testing.T) {
	fixture := newBrokerFixture(t)
	fixture.kms.err = errors.New("simulated KMS outage")
	response, err := fixture.handler.Handle(context.Background(), fixture.request)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusServiceUnavailable || !strings.Contains(response.Body, "key_service_unavailable") {
		t.Fatalf("KMS failure was not fail-closed: %d %s", response.StatusCode, response.Body)
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
