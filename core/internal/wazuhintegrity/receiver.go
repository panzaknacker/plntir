package wazuhintegrity

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"time"

	"plntir/core/internal/envelope"
)

const maximumProjectionBodyBytes = 64 << 10

var (
	projectionFingerprintPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)
	ErrProjectionStoreConflict   = errors.New("Wazuh projection sequence or deduplication conflict")
	ErrProjectionAuthentication  = errors.New("Wazuh projection authentication failed")
)

type ProjectionAcceptor interface {
	AcceptWazuhProjection(context.Context, envelope.Envelope, HealthProjection, ed25519.PublicKey, time.Time) (bool, error)
}

type ProjectionReceiverOptions struct {
	Store                 ProjectionAcceptor
	VerifyKey             ed25519.PublicKey
	ClientCertFingerprint string
	ExpectedAuthority     string
	Now                   func() time.Time
}

type ProjectionReceiver struct {
	store                 ProjectionAcceptor
	verifyKey             ed25519.PublicKey
	clientCertFingerprint []byte
	expectedAuthority     string
	now                   func() time.Time
}

func NewProjectionReceiver(options ProjectionReceiverOptions) (*ProjectionReceiver, error) {
	if options.Store == nil || len(options.VerifyKey) != ed25519.PublicKeySize ||
		!projectionFingerprintPattern.MatchString(options.ClientCertFingerprint) {
		return nil, errors.New("Wazuh projection receiver identity is incomplete")
	}
	if _, err := exactEndpoint("https://"+options.ExpectedAuthority+projectionPath, projectionPath); err != nil {
		return nil, errors.New("Wazuh projection receiver authority is invalid")
	}
	fingerprint, _ := hex.DecodeString(options.ClientCertFingerprint)
	if options.Now == nil {
		options.Now = time.Now
	}
	return &ProjectionReceiver{
		store: options.Store, verifyKey: append(ed25519.PublicKey(nil), options.VerifyKey...),
		clientCertFingerprint: fingerprint, expectedAuthority: options.ExpectedAuthority, now: options.Now,
	}, nil
}

func (receiver *ProjectionReceiver) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	projectionSecurityHeaders(writer)
	if request.Method != http.MethodPost || request.Host != receiver.expectedAuthority ||
		request.URL.Path != projectionPath || request.URL.RawPath != "" || request.URL.RawQuery != "" || request.URL.ForceQuery {
		writer.WriteHeader(http.StatusNotFound)
		return
	}
	if !receiver.validClientCertificate(request) {
		writer.WriteHeader(http.StatusNotFound)
		return
	}
	if request.Header.Get("Content-Type") != "application/json" {
		writer.WriteHeader(http.StatusUnsupportedMediaType)
		return
	}
	if request.ContentLength < 1 || request.ContentLength > maximumProjectionBodyBytes {
		writer.WriteHeader(http.StatusRequestEntityTooLarge)
		return
	}
	request.Body = http.MaxBytesReader(writer, request.Body, maximumProjectionBodyBytes)
	body, err := io.ReadAll(request.Body)
	if err != nil || int64(len(body)) != request.ContentLength || validateJSONNoDuplicateKeys(body) != nil {
		writer.WriteHeader(http.StatusBadRequest)
		return
	}
	var signed envelope.Envelope
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&signed); err != nil || ensureEOF(decoder) != nil {
		writer.WriteHeader(http.StatusBadRequest)
		return
	}
	canonical, err := json.Marshal(signed)
	canonical = append(canonical, '\n')
	if err != nil || !bytes.Equal(canonical, body) || signed.Kind != "wazuh-health-v1" ||
		signed.Source != "plntir-siem-01" {
		writer.WriteHeader(http.StatusBadRequest)
		return
	}
	now := receiver.now().UTC()
	if err := envelope.Verify(signed, receiver.verifyKey, envelope.VerifyOptions{
		Now: now, MaximumAge: ProjectionMaximumAge, MaximumFuture: ProjectionMaximumFuture,
	}); err != nil {
		writer.WriteHeader(http.StatusUnauthorized)
		return
	}
	if validateJSONNoDuplicateKeys(signed.Payload) != nil {
		writer.WriteHeader(http.StatusBadRequest)
		return
	}
	var projection HealthProjection
	payloadDecoder := json.NewDecoder(bytes.NewReader(signed.Payload))
	payloadDecoder.DisallowUnknownFields()
	if err := payloadDecoder.Decode(&projection); err != nil || ensureEOF(payloadDecoder) != nil ||
		ValidateHealthProjection(projection) != nil || projection.LastSequence != signed.Sequence ||
		projection.ObservedAt != signed.Timestamp {
		writer.WriteHeader(http.StatusBadRequest)
		return
	}
	created, err := receiver.store.AcceptWazuhProjection(request.Context(), signed, projection, receiver.verifyKey, now)
	switch {
	case errors.Is(err, ErrProjectionStoreConflict):
		writer.WriteHeader(http.StatusConflict)
	case errors.Is(err, ErrProjectionAuthentication):
		writer.WriteHeader(http.StatusUnauthorized)
	case err != nil:
		writer.WriteHeader(http.StatusServiceUnavailable)
	case created:
		writer.WriteHeader(http.StatusCreated)
	default:
		writer.WriteHeader(http.StatusNoContent)
	}
}

func (receiver *ProjectionReceiver) validClientCertificate(request *http.Request) bool {
	if request.TLS == nil || len(request.TLS.PeerCertificates) == 0 || len(request.TLS.VerifiedChains) == 0 {
		return false
	}
	digest := sha256.Sum256(request.TLS.PeerCertificates[0].Raw)
	return subtle.ConstantTimeCompare(digest[:], receiver.clientCertFingerprint) == 1
}

func projectionSecurityHeaders(writer http.ResponseWriter) {
	writer.Header().Set("Cache-Control", "no-store, max-age=0")
	writer.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
	writer.Header().Set("Cross-Origin-Resource-Policy", "same-origin")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
}
