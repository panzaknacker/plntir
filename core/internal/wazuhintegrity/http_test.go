package wazuhintegrity

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net/http"
	"strings"
	"testing"
	"time"

	"plntir/core/internal/envelope"
)

type recordingDoer struct {
	request *http.Request
	status  int
	err     error
}

func (client *recordingDoer) Do(request *http.Request) (*http.Response, error) {
	client.request = request
	if client.err != nil {
		return nil, client.err
	}
	return &http.Response{StatusCode: client.status, Body: io.NopCloser(strings.NewReader(""))}, nil
}

func TestAnchorHTTPSinkPostsCanonicalBodyAndHandlesIdempotency(t *testing.T) {
	_, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	chainHash := sha256.Sum256([]byte("chain"))
	anchor, err := SignDailyAnchor(17, chainHash, time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC), privateKey)
	if err != nil {
		t.Fatal(err)
	}
	client := &recordingDoer{status: http.StatusCreated}
	sink := AnchorHTTPSink{Client: client, Endpoint: "https://anchor.plntir.invalid/internal/v1/wazuh/hash-anchor"}
	if err := sink.PublishAnchor(context.Background(), anchor); err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(client.request.Body)
	expected, _ := anchor.Marshal()
	if client.request.Method != http.MethodPost || client.request.URL.String() != sink.Endpoint ||
		client.request.ContentLength != int64(len(expected)) || string(body) != string(expected) ||
		client.request.Header.Get("Content-Type") != "application/json" {
		t.Fatal("anchor request was not exact and canonical")
	}
	client.status = http.StatusNoContent
	if err := sink.PublishAnchor(context.Background(), anchor); err != nil {
		t.Fatalf("byte-identical retry was not accepted: %v", err)
	}
	client.status = http.StatusConflict
	if err := sink.PublishAnchor(context.Background(), anchor); !errors.Is(err, ErrAnchorConflict) {
		t.Fatalf("conflicting daily anchor was not surfaced: %v", err)
	}
}

func TestProjectionHTTPSinkSignsOnlySanitizedHealth(t *testing.T) {
	publicKey, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	record, _ := NewRecord(3, [sha256.Size]byte{}, alertAtLevel(13), time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC))
	projection, _ := ProjectionFromRecord(record, time.Date(2026, 9, 4, 12, 0, 1, 0, time.UTC))
	client := &recordingDoer{status: http.StatusCreated}
	sink := ProjectionHTTPSink{
		Client: client, PrivateKey: privateKey,
		Endpoint: "https://plntir-core-01.internal:8443/internal/v1/wazuh/health",
	}
	if err := sink.PublishHealth(context.Background(), projection); err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(client.request.Body)
	for _, secret := range []string{"password=never-project-this", "raw-only", "mac-secret-name"} {
		if strings.Contains(string(body), secret) {
			t.Fatalf("projection transport leaked raw Wazuh content %q", secret)
		}
	}
	var signed envelope.Envelope
	decoder := json.NewDecoder(strings.NewReader(string(body)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&signed); err != nil {
		t.Fatal(err)
	}
	if err := envelope.Verify(signed, publicKey, envelope.VerifyOptions{
		Now: time.Date(2026, 9, 4, 12, 0, 1, 0, time.UTC), LastSequence: 2,
	}); err != nil {
		t.Fatalf("transported projection signature failed: %v", err)
	}
	if signed.Kind != "wazuh-health-v1" || client.request.ContentLength != int64(len(body)) {
		t.Fatal("projection transport identity or length drifted")
	}
}

func TestHTTPSinksRejectAmbiguousEndpointsBeforeNetwork(t *testing.T) {
	_, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	chainHash := sha256.Sum256([]byte("chain"))
	anchor, _ := SignDailyAnchor(1, chainHash, time.Now(), privateKey)
	for _, endpoint := range []string{
		"http://anchor.plntir.invalid/internal/v1/wazuh/hash-anchor",
		"https://user@anchor.plntir.invalid/internal/v1/wazuh/hash-anchor",
		"https://anchor.plntir.invalid/internal/v1/wazuh/hash-anchor?second=true",
		"https://ANCHOR.plntir.invalid/internal/v1/wazuh/hash-anchor",
		"https://127.0.0.1/internal/v1/wazuh/hash-anchor",
		"https://anchor.plntir.invalid/other",
	} {
		client := &recordingDoer{status: http.StatusCreated}
		if err := (AnchorHTTPSink{Client: client, Endpoint: endpoint}).PublishAnchor(context.Background(), anchor); err == nil {
			t.Fatalf("ambiguous endpoint %q was accepted", endpoint)
		}
		if client.request != nil {
			t.Fatalf("network was reached for invalid endpoint %q", endpoint)
		}
	}
}

func TestMTLSClientUsesOnlyExactPrivateRelayAndDisablesRedirects(t *testing.T) {
	now := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	certificate, roots := testClientCertificate(t, now)
	client, err := NewMTLSRelayClient(MTLSRelayClientOptions{
		ProxyURL: "http://10.23.0.7:3128", ServerName: "anchor.plntir.invalid",
		RootCAs: roots, Certificate: certificate, Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	transport, ok := client.Transport.(*http.Transport)
	if !ok || transport.TLSClientConfig.MinVersion != tls.VersionTLS13 ||
		transport.TLSClientConfig.ServerName != "anchor.plntir.invalid" ||
		!transport.DisableCompression || transport.Proxy == nil {
		t.Fatal("mTLS client did not preserve the sealed transport boundary")
	}
	request, _ := http.NewRequest(http.MethodGet, "https://anchor.plntir.invalid/", nil)
	proxy, err := transport.Proxy(request)
	if err != nil || proxy.String() != "http://10.23.0.7:3128" {
		t.Fatalf("unexpected proxy binding: %v %v", proxy, err)
	}
	if client.CheckRedirect(nil, nil) == nil {
		t.Fatal("redirects are not blocked")
	}
	for _, proxyURL := range []string{
		"http://8.8.8.8:3128",
		"http://10.23.0.7:8080",
		"https://10.23.0.7:3128",
		"http://user@10.23.0.7:3128",
		"http://10.23.0.7:3128/",
	} {
		_, err := NewMTLSRelayClient(MTLSRelayClientOptions{
			ProxyURL: proxyURL, ServerName: "anchor.plntir.invalid",
			RootCAs: roots, Certificate: certificate, Now: func() time.Time { return now },
		})
		if err == nil {
			t.Fatalf("unsafe proxy %q was accepted", proxyURL)
		}
	}
}

func testClientCertificate(t *testing.T, now time.Time) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Plntir test CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCertificate, _ := x509.ParseCertificate(caDER)
	clientKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	clientTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "plntir-siem-01"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	clientDER, err := x509.CreateCertificate(rand.Reader, clientTemplate, caCertificate, &clientKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(caCertificate)
	return tls.Certificate{Certificate: [][]byte{clientDER, caDER}, PrivateKey: clientKey}, roots
}
