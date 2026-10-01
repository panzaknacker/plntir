package wazuhintegrity

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"plntir/core/internal/envelope"
)

type projectionAcceptor struct {
	called     int
	created    bool
	err        error
	signed     envelope.Envelope
	projection HealthProjection
}

func (store *projectionAcceptor) AcceptWazuhProjection(
	_ context.Context,
	signed envelope.Envelope,
	projection HealthProjection,
	_ ed25519.PublicKey,
	_ time.Time,
) (bool, error) {
	store.called++
	store.signed = signed
	store.projection = projection
	return store.created, store.err
}

func signedProjectionRequest(t *testing.T, now time.Time) (*http.Request, ed25519.PublicKey, string) {
	t.Helper()
	publicKey, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	record, err := NewRecord(7, [sha256.Size]byte{}, alertAtLevel(13), now)
	if err != nil {
		t.Fatal(err)
	}
	projection, _ := ProjectionFromRecord(record, now)
	signed, err := SignProjection(projection, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(signed)
	body = append(body, '\n')
	request := httptest.NewRequest(http.MethodPost,
		"https://plntir-core-01.internal:8443"+projectionPath, bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	certificate := &x509.Certificate{Raw: []byte("verified-client-certificate")}
	request.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{certificate},
		VerifiedChains:   [][]*x509.Certificate{{certificate}},
	}
	digest := sha256.Sum256(certificate.Raw)
	return request, publicKey, hex.EncodeToString(digest[:])
}

func TestProjectionReceiverRequiresMTLSSignatureAndCanonicalBody(t *testing.T) {
	now := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	request, publicKey, fingerprint := signedProjectionRequest(t, now)
	store := &projectionAcceptor{created: true}
	receiver, err := NewProjectionReceiver(ProjectionReceiverOptions{
		Store: store, VerifyKey: publicKey, ClientCertFingerprint: fingerprint,
		ExpectedAuthority: "plntir-core-01.internal:8443", Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	receiver.ServeHTTP(response, request)
	if response.Code != http.StatusCreated || store.called != 1 ||
		store.signed.Kind != "wazuh-health-v1" || store.projection.LastSequence != 7 {
		t.Fatalf("valid projection rejected: status=%d calls=%d", response.Code, store.called)
	}
	if response.Header().Get("Cache-Control") != "no-store, max-age=0" {
		t.Fatal("internal response lacks no-store boundary")
	}
	encoded, _ := json.Marshal(store.projection)
	if bytes.Contains(encoded, []byte("password=never-project-this")) {
		t.Fatal("raw Wazuh data reached the Core projection")
	}
}

func TestProjectionReceiverConcealsWrongClientCertificate(t *testing.T) {
	now := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	request, publicKey, _ := signedProjectionRequest(t, now)
	store := &projectionAcceptor{created: true}
	receiver, _ := NewProjectionReceiver(ProjectionReceiverOptions{
		Store: store, VerifyKey: publicKey, ClientCertFingerprint: string(bytes.Repeat([]byte{'0'}, 64)),
		ExpectedAuthority: "plntir-core-01.internal:8443", Now: func() time.Time { return now },
	})
	response := httptest.NewRecorder()
	receiver.ServeHTTP(response, request)
	if response.Code != http.StatusNotFound || store.called != 0 {
		t.Fatalf("wrong certificate was not concealed: status=%d calls=%d", response.Code, store.called)
	}
}

func TestProjectionReceiverRejectsSignatureNoncanonicalJSONAndStoreConflict(t *testing.T) {
	now := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	baseRequest, publicKey, fingerprint := signedProjectionRequest(t, now)
	body, _ := io.ReadAll(baseRequest.Body)
	newReceiver := func(store *projectionAcceptor) *ProjectionReceiver {
		receiver, _ := NewProjectionReceiver(ProjectionReceiverOptions{
			Store: store, VerifyKey: publicKey, ClientCertFingerprint: fingerprint,
			ExpectedAuthority: "plntir-core-01.internal:8443", Now: func() time.Time { return now },
		})
		return receiver
	}
	newRequest := func(content []byte) *http.Request {
		request := httptest.NewRequest(http.MethodPost,
			"https://plntir-core-01.internal:8443"+projectionPath, bytes.NewReader(content))
		request.Header.Set("Content-Type", "application/json")
		request.TLS = baseRequest.TLS
		return request
	}

	var signed envelope.Envelope
	_ = json.Unmarshal(body, &signed)
	signed.Signature = string(bytes.Repeat([]byte{'A'}, 86))
	corrupted, _ := json.Marshal(signed)
	corrupted = append(corrupted, '\n')
	response := httptest.NewRecorder()
	newReceiver(&projectionAcceptor{}).ServeHTTP(response, newRequest(corrupted))
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("bad signature status = %d", response.Code)
	}

	response = httptest.NewRecorder()
	newReceiver(&projectionAcceptor{}).ServeHTTP(response, newRequest(bytes.TrimSuffix(body, []byte{'\n'})))
	if response.Code != http.StatusBadRequest {
		t.Fatalf("noncanonical body status = %d", response.Code)
	}

	store := &projectionAcceptor{err: ErrProjectionStoreConflict}
	response = httptest.NewRecorder()
	newReceiver(store).ServeHTTP(response, newRequest(body))
	if response.Code != http.StatusConflict || store.called != 1 {
		t.Fatalf("store conflict status = %d calls=%d", response.Code, store.called)
	}

	store = &projectionAcceptor{err: errors.New("database offline")}
	response = httptest.NewRecorder()
	newReceiver(store).ServeHTTP(response, newRequest(body))
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("store outage status = %d", response.Code)
	}
}
