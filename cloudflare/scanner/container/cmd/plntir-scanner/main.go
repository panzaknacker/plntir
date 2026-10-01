package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

const (
	listenAddress = ":8080"
	sessionTTL    = 10 * time.Minute
)

var (
	safeID    = regexp.MustCompile(`^[a-z][a-z0-9]{0,15}_[0-9a-hjkmnp-tv-z]{32}$`)
	objectKey = regexp.MustCompile(`^objects/obj_[0-9a-hjkmnp-tv-z]{32}$`)
	crockford = base32.NewEncoding("0123456789abcdefghjkmnpqrstvwxyz").WithPadding(base32.NoPadding)
)

type session struct {
	private   *ecdh.PrivateKey
	expiresAt time.Time
}

type server struct {
	logger   *slog.Logger
	now      func() time.Time
	sessions sync.Map
}

type prepareResponse struct {
	SessionID string `json:"session_id"`
	PublicKey string `json:"public_key"`
	ExpiresAt string `json:"expires_at"`
}

type verdictResponse struct {
	Verdict       string `json:"verdict"`
	EngineVersion string `json:"engine_version"`
	Reason        string `json:"reason"`
}

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	app := &server{logger: logger, now: time.Now}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", app.health)
	mux.HandleFunc("POST /v1/prepare", app.prepare)
	mux.HandleFunc("POST /v1/scan", app.scan)
	httpServer := &http.Server{
		Addr:              listenAddress,
		Handler:           secureHeaders(mux),
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    32 << 10,
	}
	logger.Info("scanner container listening", "address", listenAddress, "mode", "shadow-fail-closed")
	if err := httpServer.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
		logger.Error("scanner container stopped", "error", err.Error())
		os.Exit(1)
	}
}

func secureHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Cache-Control", "no-store")
		writer.Header().Set("Content-Security-Policy", "default-src 'none'")
		writer.Header().Set("X-Content-Type-Options", "nosniff")
		next.ServeHTTP(writer, request)
	})
}

func (s *server) health(writer http.ResponseWriter, _ *http.Request) {
	writeJSON(writer, http.StatusServiceUnavailable, map[string]string{
		"state": "not_sealed", "scan_capability": "unavailable",
	})
}

func (s *server) prepare(writer http.ResponseWriter, request *http.Request) {
	if request.ContentLength > 0 {
		writeJSON(writer, http.StatusBadRequest, map[string]string{"error": "body_not_allowed"})
		return
	}
	private, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		writeJSON(writer, http.StatusInternalServerError, map[string]string{"error": "key_generation_failed"})
		return
	}
	idBytes := make([]byte, 20)
	if _, err := rand.Read(idBytes); err != nil {
		writeJSON(writer, http.StatusInternalServerError, map[string]string{"error": "session_generation_failed"})
		return
	}
	sessionID := "scan_" + crockford.EncodeToString(idBytes)
	expiresAt := s.now().UTC().Add(sessionTTL)
	s.sessions.Store(sessionID, session{private: private, expiresAt: expiresAt})
	writeJSON(writer, http.StatusCreated, prepareResponse{
		SessionID: sessionID,
		PublicKey: base64.RawURLEncoding.EncodeToString(private.PublicKey().Bytes()),
		ExpiresAt: expiresAt.Format(time.RFC3339Nano),
	})
}

func (s *server) scan(writer http.ResponseWriter, request *http.Request) {
	jobID := request.Header.Get("X-Plntir-Job-ID")
	sessionID := request.Header.Get("X-Plntir-Scan-Session")
	value, found := s.sessions.LoadAndDelete(sessionID)
	if !found || !safeID.MatchString(jobID) {
		writeJSON(writer, http.StatusUnauthorized, map[string]string{"error": "invalid_scan_session"})
		return
	}
	current, ok := value.(session)
	if !ok || current.private == nil || !s.now().Before(current.expiresAt) {
		writeJSON(writer, http.StatusUnauthorized, map[string]string{"error": "expired_scan_session"})
		return
	}
	dek, err := unwrapDEK(current.private, request)
	if err != nil {
		writeJSON(writer, http.StatusUnauthorized, map[string]string{"error": "invalid_wrapped_key"})
		return
	}
	clear(dek)
	// the transport and ephemeral key protocol are wired, but the malware,
	// archive and media engines are deliberately not certified in this build.
	// returning anything other than unscannable here would unlock downloads.
	s.logger.Warn("scan rejected by shadow engine", "job_id", jobID)
	writeJSON(writer, http.StatusServiceUnavailable, verdictResponse{
		Verdict:       "unscannable",
		EngineVersion: "shadow-not-sealed",
		Reason:        "scanner engines have not passed the qualification corpus",
	})
}

func unwrapDEK(containerPrivate *ecdh.PrivateKey, request *http.Request) ([]byte, error) {
	jobID := request.Header.Get("X-Plntir-Job-ID")
	fileVersionID := request.Header.Get("X-Plntir-File-Version-ID")
	key := request.Header.Get("X-Plntir-Object-Key")
	sessionID := request.Header.Get("X-Plntir-Scan-Session")
	if !safeID.MatchString(jobID) || !strings.HasPrefix(jobID, "scan_") ||
		!safeID.MatchString(fileVersionID) || !strings.HasPrefix(fileVersionID, "fver_") ||
		!safeID.MatchString(sessionID) || !strings.HasPrefix(sessionID, "scan_") || !objectKey.MatchString(key) {
		return nil, errors.New("key wrap identity is invalid")
	}
	brokerEncoded := request.Header.Get("X-Plntir-Broker-Public-Key")
	brokerBytes, err := decodeCanonicalBase64URL(brokerEncoded, 32)
	if err != nil {
		return nil, err
	}
	brokerPublic, err := ecdh.X25519().NewPublicKey(brokerBytes)
	if err != nil {
		return nil, errors.New("broker public key is invalid")
	}
	sharedSecret, err := containerPrivate.ECDH(brokerPublic)
	if err != nil {
		return nil, err
	}
	defer clear(sharedSecret)
	salt := wrapSalt(jobID, fileVersionID, key, sessionID)
	wrappingKey, err := hkdf.Key(sha256.New, sharedSecret, salt[:], "plntir-scan-dek-wrap-v1", 32)
	if err != nil {
		return nil, err
	}
	defer clear(wrappingKey)
	block, err := aes.NewCipher(wrappingKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce, err := decodeCanonicalBase64URL(request.Header.Get("X-Plntir-Wrap-Nonce"), gcm.NonceSize())
	if err != nil {
		return nil, err
	}
	wrapped, err := decodeCanonicalBase64URL(request.Header.Get("X-Plntir-Wrapped-DEK"), 32+gcm.Overhead())
	if err != nil {
		return nil, err
	}
	containerEncoded := base64.RawURLEncoding.EncodeToString(containerPrivate.PublicKey().Bytes())
	aad := wrapAAD(jobID, fileVersionID, key, sessionID, containerEncoded, brokerEncoded)
	plaintext, err := gcm.Open(nil, nonce, wrapped, aad)
	if err != nil || len(plaintext) != 32 {
		clear(plaintext)
		return nil, errors.New("wrapped DEK authentication failed")
	}
	return plaintext, nil
}

func wrapSalt(jobID, fileVersionID, key, sessionID string) [32]byte {
	return sha256.Sum256([]byte(strings.Join([]string{
		"plntir-scan-dek-wrap-salt-v1", jobID, fileVersionID, key, sessionID, "",
	}, "\n")))
}

func wrapAAD(jobID, fileVersionID, key, sessionID, containerPublicKey, brokerPublicKey string) []byte {
	return []byte(strings.Join([]string{
		"plntir-scan-dek-wrap-aad-v1", jobID, fileVersionID, key, sessionID,
		containerPublicKey, brokerPublicKey, "",
	}, "\n"))
}

func decodeCanonicalBase64URL(value string, expectedLength int) ([]byte, error) {
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(value)
	if err != nil || len(decoded) != expectedLength || base64.RawURLEncoding.EncodeToString(decoded) != value {
		return nil, errors.New("value is not canonical base64url")
	}
	return decoded, nil
}

func writeJSON(writer http.ResponseWriter, status int, value any) {
	writer.Header().Set("Content-Type", "application/json; charset=utf-8")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(value)
}
