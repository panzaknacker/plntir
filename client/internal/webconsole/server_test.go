package webconsole

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testDashboardPassword = "this is a separate dashboard password"

func TestServerRequiresHTTPSMeshHostAndAuthentication(t *testing.T) {
	server := newTestServer(t)

	request := secureRequest(http.MethodGet, "/", nil)
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("index status = %d: %s", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Header().Get("Content-Security-Policy"), "frame-ancestors 'none'") {
		t.Fatal("strict CSP is missing")
	}
	if response.Header().Get("Cross-Origin-Opener-Policy") != "same-origin" ||
		response.Header().Get("Cross-Origin-Resource-Policy") != "same-origin" {
		t.Fatal("cross-origin isolation headers are missing")
	}

	request = secureRequest(http.MethodGet, "/api/status", nil)
	response = httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated API status = %d", response.Code)
	}

	request = secureRequest(http.MethodGet, "/", nil)
	request.TLS = nil
	response = httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusUpgradeRequired {
		t.Fatalf("plain HTTP status = %d", response.Code)
	}

	request = secureRequest(http.MethodGet, "/", nil)
	request.RemoteAddr = "203.0.113.10:50000"
	response = httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("non-Mesh client status = %d", response.Code)
	}

	request = secureRequest(http.MethodGet, "/", nil)
	request.Host = "attacker.example"
	response = httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusMisdirectedRequest {
		t.Fatalf("wrong Host status = %d", response.Code)
	}
}

func TestLoginCSRFAndPrivateStepUp(t *testing.T) {
	server := newTestServer(t)
	loginBody := map[string]string{
		"username": "operator",
		"password": testDashboardPassword,
	}
	response := performJSON(t, server, http.MethodPost, "/api/login", loginBody, nil, "")
	if response.Code != http.StatusOK {
		t.Fatalf("login status = %d: %s", response.Code, response.Body.String())
	}
	result := decodeResponse(t, response)
	csrf, _ := result["csrf"].(string)
	if csrf == "" {
		t.Fatal("login response has no CSRF token")
	}
	cookies := response.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != sessionCookieName || !cookies[0].Secure || !cookies[0].HttpOnly {
		t.Fatalf("invalid session cookie: %#v", cookies)
	}
	cookie := cookies[0]

	request := secureRequest(http.MethodGet, "/api/files/list", nil)
	request.AddCookie(cookie)
	response = httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("locked private API status = %d", response.Code)
	}

	response = performJSON(t, server, http.MethodPost, "/api/private/unlock", map[string]string{
		"password": testDashboardPassword,
	}, cookie, "")
	if response.Code != http.StatusForbidden {
		t.Fatalf("missing CSRF unlock status = %d", response.Code)
	}

	response = performJSON(t, server, http.MethodPost, "/api/private/unlock", map[string]string{
		"password": testDashboardPassword,
	}, cookie, csrf)
	if response.Code != http.StatusOK {
		t.Fatalf("private unlock status = %d: %s", response.Code, response.Body.String())
	}
	result = decodeResponse(t, response)
	if active, _ := result["private_active"].(bool); !active {
		t.Fatal("private session was not activated")
	}

	request = secureRequest(http.MethodGet, "/api/audit?limit=20", nil)
	request.AddCookie(cookie)
	response = httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusOK || !bytes.Contains(response.Body.Bytes(), []byte(`"private.unlock"`)) {
		t.Fatalf("private audit status = %d: %s", response.Code, response.Body.String())
	}

	audit, err := os.ReadFile(server.config.AuditFile)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(audit, []byte(testDashboardPassword)) {
		t.Fatal("audit log contains the submitted password")
	}
}

func TestPrivateUnlockHasIndependentRateLimit(t *testing.T) {
	server := newTestServer(t)
	response := performJSON(t, server, http.MethodPost, "/api/login", map[string]string{
		"username": "operator",
		"password": testDashboardPassword,
	}, nil, "")
	if response.Code != http.StatusOK {
		t.Fatalf("login status = %d: %s", response.Code, response.Body.String())
	}
	result := decodeResponse(t, response)
	csrf, _ := result["csrf"].(string)
	cookie := response.Result().Cookies()[0]
	for attempt := 0; attempt < 5; attempt++ {
		response = performJSON(t, server, http.MethodPost, "/api/private/unlock", map[string]string{
			"password": "definitely the wrong dashboard password",
		}, cookie, csrf)
		if response.Code != http.StatusUnauthorized {
			t.Fatalf("wrong unlock attempt %d status = %d", attempt+1, response.Code)
		}
	}
	response = performJSON(t, server, http.MethodPost, "/api/private/unlock", map[string]string{
		"password": testDashboardPassword,
	}, cookie, csrf)
	if response.Code != http.StatusTooManyRequests {
		t.Fatalf("rate-limited unlock status = %d: %s", response.Code, response.Body.String())
	}
}

func newTestServer(t *testing.T) *Server {
	t.Helper()
	root := t.TempDir()
	monitor := filepath.Join(root, "monitor")
	retrieved := filepath.Join(root, "retrieved")
	if err := os.MkdirAll(filepath.Join(monitor, "security"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(retrieved, 0o700); err != nil {
		t.Fatal(err)
	}
	hash, err := HashPassword([]byte(testDashboardPassword), minimumIterations)
	if err != nil {
		t.Fatal(err)
	}
	authPath := filepath.Join(root, "auth.json")
	auth, err := json.Marshal(AuthFile{SchemaVersion: 1, Username: "operator", PasswordHash: hash})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(authPath, auth, 0o600); err != nil {
		t.Fatal(err)
	}
	_, meshNet, err := net.ParseCIDR(defaultMeshCIDR)
	if err != nil {
		t.Fatal(err)
	}
	config := Config{
		Listen:                "100.101.0.5:8443",
		AllowedMeshCIDR:       defaultMeshCIDR,
		AllowedHosts:          []string{"100.101.0.5:8443"},
		AuthFile:              authPath,
		StatusCommand:         []string{"/usr/bin/false"},
		ActionCommand:         []string{"/usr/bin/false"},
		MonitorRoot:           monitor,
		RetrievedRoot:         retrieved,
		AuditFile:             filepath.Join(root, "audit.jsonl"),
		ManagedHome:           "/Users/managed",
		RefreshSeconds:        10,
		SessionMinutes:        60,
		PrivateSessionMinutes: 10,
		MaxResponseBytes:      1 << 20,
		MeshNet:               meshNet,
	}
	server, err := NewServer(config)
	if err != nil {
		t.Fatal(err)
	}
	return server
}

func secureRequest(method, target string, body io.Reader) *http.Request {
	request := httptest.NewRequest(method, "https://100.101.0.5:8443"+target, body)
	request.Host = "100.101.0.5:8443"
	request.RemoteAddr = "100.101.0.10:50000"
	request.Header.Set("User-Agent", "plntir-test-agent")
	return request
}

func performJSON(t *testing.T, server *Server, method, target string, body any, cookie *http.Cookie, csrf string) *httptest.ResponseRecorder {
	t.Helper()
	encoded, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	request := secureRequest(method, target, bytes.NewReader(encoded))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", "https://100.101.0.5:8443")
	if cookie != nil {
		request.AddCookie(cookie)
	}
	if csrf != "" {
		request.Header.Set("X-Plntir-CSRF", csrf)
	}
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	return response
}

func decodeResponse(t *testing.T, response *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var result map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	return result
}
