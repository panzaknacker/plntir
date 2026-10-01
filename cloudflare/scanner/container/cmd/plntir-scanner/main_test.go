package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func addValidWrappedDEK(t *testing.T, app *server, request *http.Request, prepared prepareResponse) {
	t.Helper()
	stored, ok := app.sessions.Load(prepared.SessionID)
	if !ok {
		t.Fatal("prepared session was not stored")
	}
	current := stored.(session)
	brokerPrivate, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	shared, err := brokerPrivate.ECDH(current.private.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	jobID := request.Header.Get("X-Plntir-Job-ID")
	fileVersionID := "fver_0123456789abcdefghjkmnpqrstvwxyz"
	key := "objects/obj_0123456789abcdefghjkmnpqrstvwxyz"
	containerEncoded := prepared.PublicKey
	brokerEncoded := base64.RawURLEncoding.EncodeToString(brokerPrivate.PublicKey().Bytes())
	salt := wrapSalt(jobID, fileVersionID, key, prepared.SessionID)
	wrappingKey, err := hkdf.Key(sha256.New, shared, salt[:], "plntir-scan-dek-wrap-v1", 32)
	if err != nil {
		t.Fatal(err)
	}
	block, err := aes.NewCipher(wrappingKey)
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, gcm.NonceSize())
	wrapped := gcm.Seal(nil, nonce, []byte("0123456789abcdef0123456789abcdef"), wrapAAD(jobID, fileVersionID, key, prepared.SessionID, containerEncoded, brokerEncoded))
	request.Header.Set("X-Plntir-File-Version-ID", fileVersionID)
	request.Header.Set("X-Plntir-Object-Key", key)
	request.Header.Set("X-Plntir-Broker-Public-Key", brokerEncoded)
	request.Header.Set("X-Plntir-Wrap-Nonce", base64.RawURLEncoding.EncodeToString(nonce))
	request.Header.Set("X-Plntir-Wrapped-DEK", base64.RawURLEncoding.EncodeToString(wrapped))
}

func testServer(now time.Time) *server {
	return &server{
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		now:    func() time.Time { return now },
	}
}

func TestShadowScannerNeverReturnsClean(t *testing.T) {
	now := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	app := testServer(now)
	prepare := httptest.NewRecorder()
	app.prepare(prepare, httptest.NewRequest(http.MethodPost, "/v1/prepare", nil))
	if prepare.Code != http.StatusCreated {
		t.Fatalf("prepare status = %d: %s", prepare.Code, prepare.Body.String())
	}
	var prepared prepareResponse
	if err := json.Unmarshal(prepare.Body.Bytes(), &prepared); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/v1/scan", strings.NewReader("ciphertext"))
	request.Header.Set("X-Plntir-Job-ID", "scan_0123456789abcdefghjkmnpqrstvwxyz")
	request.Header.Set("X-Plntir-Scan-Session", prepared.SessionID)
	addValidWrappedDEK(t, app, request, prepared)
	response := httptest.NewRecorder()
	app.scan(response, request)
	if response.Code != http.StatusServiceUnavailable || strings.Contains(response.Body.String(), `"verdict":"clean"`) {
		t.Fatalf("shadow scan was not fail-closed: %d %s", response.Code, response.Body.String())
	}
	response = httptest.NewRecorder()
	app.scan(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("replayed scan session returned %d", response.Code)
	}
}

func TestTamperedWrappedDEKRejected(t *testing.T) {
	now := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	app := testServer(now)
	prepare := httptest.NewRecorder()
	app.prepare(prepare, httptest.NewRequest(http.MethodPost, "/v1/prepare", nil))
	var prepared prepareResponse
	if err := json.Unmarshal(prepare.Body.Bytes(), &prepared); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/v1/scan", strings.NewReader("ciphertext"))
	request.Header.Set("X-Plntir-Job-ID", "scan_0123456789abcdefghjkmnpqrstvwxyz")
	request.Header.Set("X-Plntir-Scan-Session", prepared.SessionID)
	addValidWrappedDEK(t, app, request, prepared)
	wrapped, err := base64.RawURLEncoding.DecodeString(request.Header.Get("X-Plntir-Wrapped-DEK"))
	if err != nil {
		t.Fatal(err)
	}
	wrapped[len(wrapped)-1] ^= 1
	request.Header.Set("X-Plntir-Wrapped-DEK", base64.RawURLEncoding.EncodeToString(wrapped))
	response := httptest.NewRecorder()
	app.scan(response, request)
	if response.Code != http.StatusUnauthorized || !strings.Contains(response.Body.String(), "invalid_wrapped_key") {
		t.Fatalf("tampered DEK returned %d %s", response.Code, response.Body.String())
	}
}

func TestExpiredSessionRejected(t *testing.T) {
	now := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	app := testServer(now)
	prepare := httptest.NewRecorder()
	app.prepare(prepare, httptest.NewRequest(http.MethodPost, "/v1/prepare", nil))
	var prepared prepareResponse
	if err := json.Unmarshal(prepare.Body.Bytes(), &prepared); err != nil {
		t.Fatal(err)
	}
	app.now = func() time.Time { return now.Add(sessionTTL) }
	request := httptest.NewRequest(http.MethodPost, "/v1/scan", nil)
	request.Header.Set("X-Plntir-Job-ID", "scan_0123456789abcdefghjkmnpqrstvwxyz")
	request.Header.Set("X-Plntir-Scan-Session", prepared.SessionID)
	response := httptest.NewRecorder()
	app.scan(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("expired session returned %d", response.Code)
	}
}
