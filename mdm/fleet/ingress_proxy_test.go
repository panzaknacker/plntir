package main

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
)

func testPolicy(t *testing.T) ingressPolicy {
	t.Helper()
	policy, err := parsePolicy(embeddedPolicy)
	if err != nil {
		t.Fatal(err)
	}
	return policy
}

func testGate(t *testing.T, backend http.Handler, logOutput io.Writer) (*ingressGate, *httptest.Server) {
	t.Helper()
	server := httptest.NewServer(backend)
	t.Cleanup(server.Close)
	upstream, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.NewJSONHandler(logOutput, nil))
	return newIngressGate(testPolicy(t), upstream, logger), server
}

func TestEmbeddedPolicy(t *testing.T) {
	policy := testPolicy(t)
	if got, want := len(policy.Routes), 15; got != want {
		t.Fatalf("route count = %d, want %d", got, want)
	}
	var methodCount int
	for _, route := range policy.Routes {
		methodCount += len(route.Methods)
	}
	if got, want := methodCount, 17; got != want {
		t.Fatalf("route/method count = %d, want %d", got, want)
	}
}

func TestEveryAllowedRouteReachesFleet(t *testing.T) {
	var calls atomic.Int64
	backend := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		calls.Add(1)
		if request.Host != expectedHostname {
			t.Errorf("upstream Host = %q", request.Host)
		}
		if request.Header.Get("X-Forwarded-Proto") != "https" {
			t.Errorf("X-Forwarded-Proto = %q", request.Header.Get("X-Forwarded-Proto"))
		}
		if strings.Contains(request.Header.Get("X-Forwarded-For"), "attacker") || request.Header.Get("CF-Connecting-IP") != "" {
			t.Error("untrusted forwarding identity reached Fleet")
		}
		writer.WriteHeader(http.StatusNoContent)
	})
	gate, _ := testGate(t, backend, io.Discard)
	for _, route := range testPolicy(t).Routes {
		for _, method := range route.Methods {
			name := route.ID + "/" + method
			t.Run(name, func(t *testing.T) {
				request := httptest.NewRequest(method, route.Path+"?token=never-log-this", strings.NewReader("body"))
				request.Host = expectedHostname
				request.Header.Set("X-Forwarded-For", "attacker")
				request.Header.Set("CF-Connecting-IP", "attacker")
				response := httptest.NewRecorder()
				gate.ServeHTTP(response, request)
				if response.Code != http.StatusNoContent {
					t.Fatalf("status = %d, body = %q", response.Code, response.Body.String())
				}
			})
		}
	}
	if got, want := calls.Load(), int64(17); got != want {
		t.Fatalf("upstream calls = %d, want %d", got, want)
	}
}

func TestDeniedRequestsNeverReachFleet(t *testing.T) {
	var calls atomic.Int64
	gate, _ := testGate(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		calls.Add(1)
	}), io.Discard)
	tests := []struct {
		name   string
		method string
		target string
		host   string
	}{
		{"root", "GET", "/", expectedHostname},
		{"login", "GET", "/login", expectedHostname},
		{"admin users", "POST", "/api/v1/fleet/users", expectedHostname},
		{"admin hosts", "GET", "/api/v1/fleet/hosts", expectedHostname},
		{"ADE enroll", "GET", "/api/mdm/apple/enroll", expectedHostname},
		{"OTA enroll", "POST", "/api/v1/fleet/ota_enrollment", expectedHostname},
		{"service discovery", "GET", "/mdm/apple/service_discovery", expectedHostname},
		{"Fleet Desktop", "HEAD", "/api/fleet/device/ping", expectedHostname},
		{"software install", "POST", "/api/fleet/orbit/software_install/package", expectedHostname},
		{"setup experience", "POST", "/api/fleet/orbit/setup_experience/status", expectedHostname},
		{"carve begin", "POST", "/api/v1/osquery/carve/begin", expectedHostname},
		{"carve block", "POST", "/api/v1/osquery/carve/block", expectedHostname},
		{"YARA", "POST", "/api/v1/osquery/yara/rules", expectedHostname},
		{"wrong method", "GET", "/api/fleet/orbit/config", expectedHostname},
		{"path suffix", "POST", "/api/fleet/orbit/config/extra", expectedHostname},
		{"path prefix", "POST", "/x/api/fleet/orbit/config", expectedHostname},
		{"trailing slash", "POST", "/api/fleet/orbit/config/", expectedHostname},
		{"duplicate slash", "POST", "/api/fleet//orbit/config", expectedHostname},
		{"dot segment", "POST", "/api/fleet/orbit/../orbit/config", expectedHostname},
		{"encoded slash", "POST", "/api/fleet/orbit%2fconfig", expectedHostname},
		{"encoded letter", "POST", "/api/fleet/orbit/%63onfig", expectedHostname},
		{"wrong host", "POST", "/api/fleet/orbit/config", "admin.plntir.example"},
		{"host suffix", "POST", "/api/fleet/orbit/config", "mdm.plntir.example.example"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(test.method, test.target, nil)
			request.Host = test.host
			response := httptest.NewRecorder()
			gate.ServeHTTP(response, request)
			if response.Code != http.StatusNotFound {
				t.Fatalf("status = %d, want 404", response.Code)
			}
		})
	}
	if got := calls.Load(); got != 0 {
		t.Fatalf("denied requests reached upstream %d times", got)
	}
}

func TestQueryIsForwardedButNeverLogged(t *testing.T) {
	const secret = "secret-enrollment-token"
	var query string
	backend := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		query = request.URL.RawQuery
		writer.WriteHeader(http.StatusNoContent)
	})
	var logs bytes.Buffer
	gate, _ := testGate(t, backend, &logs)
	request := httptest.NewRequest(http.MethodGet, "/api/mdm/apple/installer?token="+secret, nil)
	request.Host = expectedHostname
	response := httptest.NewRecorder()
	gate.ServeHTTP(response, request)
	if response.Code != http.StatusNoContent {
		t.Fatalf("status = %d", response.Code)
	}
	if query != "token="+secret {
		t.Fatalf("upstream query = %q", query)
	}
	if strings.Contains(logs.String(), secret) {
		t.Fatal("query secret appeared in ingress log")
	}
}

func TestHealthEndpointRequiresLoopback(t *testing.T) {
	gate, _ := testGate(t, http.NotFoundHandler(), io.Discard)
	for _, test := range []struct {
		remote string
		want   int
	}{
		{"127.0.0.1:12345", http.StatusNoContent},
		{"[::1]:12345", http.StatusNoContent},
		{"192.0.2.10:12345", http.StatusNotFound},
	} {
		request := httptest.NewRequest(http.MethodGet, "http://127.0.0.1/healthz", nil)
		request.RemoteAddr = test.remote
		response := httptest.NewRecorder()
		gate.ServeHTTP(response, request)
		if response.Code != test.want {
			t.Errorf("remote %s: status = %d, want %d", test.remote, response.Code, test.want)
		}
	}
}

func TestMalformedPoliciesFailClosed(t *testing.T) {
	base := testPolicy(t)
	tests := []struct {
		name   string
		mutate func(*ingressPolicy)
	}{
		{"wrong release", func(policy *ingressPolicy) { policy.Release.Tag = "fleet-v4.90.0" }},
		{"wrong hash", func(policy *ingressPolicy) { policy.Release.SourceArchiveSHA256 = strings.Repeat("0", 64) }},
		{"wildcard path", func(policy *ingressPolicy) { policy.Routes[0].Path = "/api/*" }},
		{"duplicate path", func(policy *ingressPolicy) { policy.Routes[1].Path = policy.Routes[0].Path }},
		{"lowercase method", func(policy *ingressPolicy) { policy.Routes[0].Methods = []string{"get"} }},
		{"excluded allowed", func(policy *ingressPolicy) { policy.IntentionallyExcluded[0].Examples[0] = policy.Routes[0].Path }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			encoded, err := json.Marshal(base)
			if err != nil {
				t.Fatal(err)
			}
			var policy ingressPolicy
			if err := json.Unmarshal(encoded, &policy); err != nil {
				t.Fatal(err)
			}
			test.mutate(&policy)
			if err := validatePolicy(policy); err == nil {
				t.Fatal("invalid policy passed validation")
			}
		})
	}
}

func TestValidatedUpstream(t *testing.T) {
	for _, value := range []string{
		"https://fleet:8080",
		"http://user:password@fleet:8080",
		"http://fleet:8080/path",
		"http://fleet:8080?query=yes",
		"http://fleet.example:8080",
		"http://169.254.169.254",
	} {
		if _, err := validatedUpstream(value); err == nil {
			t.Errorf("unsafe upstream %q accepted", value)
		}
	}
	if _, err := validatedUpstream(defaultUpstream); err != nil {
		t.Fatalf("default upstream rejected: %v", err)
	}
}
