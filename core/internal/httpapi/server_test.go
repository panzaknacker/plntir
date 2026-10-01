package httpapi

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"plntir/core/internal/access"
	"plntir/core/internal/shadow"
)

type fakeAccess struct {
	principal access.Principal
	err       error
}

func (f fakeAccess) Verify(_ context.Context, token string) (access.Principal, error) {
	if token == "" {
		return access.Principal{}, errors.New("missing assertion")
	}
	return f.principal, f.err
}

type fakeStore struct{ err error }

func (f fakeStore) QuickCheck(context.Context) error { return f.err }

func testServer(t *testing.T) *Server {
	t.Helper()
	path := filepath.Join(t.TempDir(), "status.json")
	data := []byte(`{
		"schema_version":2,
		"collected_at":"2026-09-04T10:00:00Z",
		"node":{"hostname":"watch","warp_service_active":true,"warp_connected":true},
		"mac":{"health":{"timestamp":"2026-09-04T09:59:30Z","state":"online"}},
		"timers":{"control_node":{"active":true},"security":{"active":true}}
	}`)
	if err := os.WriteFile(path, data, 0o640); err != nil {
		t.Fatal(err)
	}
	server, err := New(Options{
		AllowedHosts: []string{"admin.plntir.example"},
		Mode:         "shadow",
		Access:       fakeAccess{principal: access.Principal{Subject: "admin-1", Email: "admin@example.invalid"}},
		Projection:   shadow.New(path),
		Store:        fakeStore{},
		Now: func() time.Time {
			return time.Date(2026, 9, 4, 10, 0, 0, 0, time.UTC)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return server
}

func TestHealthHasSecurityHeadersAndHostBoundary(t *testing.T) {
	server := testServer(t)
	request := httptest.NewRequest(http.MethodGet, "http://admin.plntir.example/health/live", nil)
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", response.Code, response.Body.String())
	}
	if response.Header().Get("Content-Security-Policy") == "" || response.Header().Get("Cache-Control") != "no-store, max-age=0" {
		t.Fatal("security headers are missing")
	}
	request = httptest.NewRequest(http.MethodGet, "http://evil.invalid/health/live", nil)
	response = httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusMisdirectedRequest {
		t.Fatalf("unexpected host status %d", response.Code)
	}
}

func TestAdminHealthRequiresAccessAndReturnsReadOnlyV3(t *testing.T) {
	server := testServer(t)
	request := httptest.NewRequest(http.MethodGet, "http://admin.plntir.example/api/v1/admin/health", nil)
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("missing Access assertion returned %d", response.Code)
	}
	request.Header.Set(access.AssertionHeader, "signed-access-token")
	response = httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"schema_version":3`) ||
		!strings.Contains(response.Body.String(), `"mode":"legacy-read-only"`) {
		t.Fatalf("unexpected response %d: %s", response.Code, response.Body.String())
	}

	server.access = fakeAccess{err: errors.New("invalid")}
	response = httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("invalid Access token returned %d", response.Code)
	}
}

func TestShadowModeFailsClosedForMutations(t *testing.T) {
	server := testServer(t)
	request := httptest.NewRequest(http.MethodPost, "http://admin.plntir.example/api/v1/admin/actions/refresh-device", strings.NewReader(`{}`))
	request.Header.Set(access.AssertionHeader, "signed-access-token")
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("unguarded mutation returned %d: %s", response.Code, response.Body.String())
	}
	request.Header.Set("X-CSRF-Token", strings.Repeat("c", 32))
	request.Header.Set("Idempotency-Key", "request-0123456789")
	request.Header.Set("If-Match", `"1"`)
	response = httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable || !strings.Contains(response.Body.String(), "shadow_mode_read_only") {
		t.Fatalf("guarded shadow mutation returned %d: %s", response.Code, response.Body.String())
	}
	if response.Header().Get("Content-Type") != "application/problem+json" {
		t.Fatalf("problem content type = %q", response.Header().Get("Content-Type"))
	}
}
