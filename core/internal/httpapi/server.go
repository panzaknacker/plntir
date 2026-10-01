package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strings"
	"time"

	"plntir/core/internal/access"
	"plntir/core/internal/idgen"
	"plntir/core/internal/shadow"
)

const maxRequestBodyBytes = 1 << 20

var safeIdempotencyKey = regexp.MustCompile(`^[A-Za-z0-9._~-]{16,128}$`)

type ProjectionSource interface {
	Snapshot(context.Context) (shadow.Projection, error)
}

type HealthStore interface {
	QuickCheck(context.Context) error
}

type Options struct {
	AllowedHosts []string
	Mode         string
	Access       access.Verifier
	Projection   ProjectionSource
	Store        HealthStore
	Now          func() time.Time
}

type Server struct {
	allowedHosts map[string]struct{}
	mode         string
	access       access.Verifier
	projection   ProjectionSource
	store        HealthStore
	now          func() time.Time
	mux          *http.ServeMux
}

type problem struct {
	Type      string `json:"type"`
	Title     string `json:"title"`
	Status    int    `json:"status"`
	Detail    string `json:"detail,omitempty"`
	RequestID string `json:"request_id"`
}

func New(options Options) (*Server, error) {
	if options.Mode != "shadow" {
		return nil, errors.New("HTTP API is not sealed for active mode")
	}
	if options.Access == nil || options.Projection == nil || options.Store == nil {
		return nil, errors.New("Access verifier, projection source and store are required")
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	server := &Server{
		allowedHosts: make(map[string]struct{}, len(options.AllowedHosts)),
		mode:         options.Mode, access: options.Access, projection: options.Projection,
		store: options.Store, now: options.Now, mux: http.NewServeMux(),
	}
	for _, host := range options.AllowedHosts {
		server.allowedHosts[strings.ToLower(host)] = struct{}{}
	}
	server.routes()
	return server, nil
}

func (s *Server) Handler() http.Handler {
	return s.securityHeaders(s.hostBoundary(s.requestLimit(s.mux)))
}

func (s *Server) routes() {
	s.mux.HandleFunc("GET /health/live", s.handleLive)
	s.mux.HandleFunc("GET /health/ready", s.handleReady)
	s.mux.Handle("GET /api/v1/admin/health", s.requireHumanAccess(http.HandlerFunc(s.handleAdminHealth)))
	s.mux.Handle("GET /api/v1/fileshare/status", s.requireHumanAccess(http.HandlerFunc(s.handleFileshareStatus)))
	s.mux.Handle("/api/v1/", s.requireHumanAccess(http.HandlerFunc(s.handleShadowAPI)))
}

func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Cache-Control", "no-store, max-age=0")
		writer.Header().Set("Cross-Origin-Opener-Policy", "same-origin")
		writer.Header().Set("Cross-Origin-Resource-Policy", "same-origin")
		writer.Header().Set("Referrer-Policy", "no-referrer")
		writer.Header().Set("X-Content-Type-Options", "nosniff")
		writer.Header().Set("X-Frame-Options", "DENY")
		writer.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=()")
		writer.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
		writer.Header().Set("Strict-Transport-Security", "max-age=31536000")
		writer.Header().Set("X-Plntir-Mode", s.mode)
		next.ServeHTTP(writer, request)
	})
}

func (s *Server) hostBoundary(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if _, ok := s.allowedHosts[strings.ToLower(request.Host)]; !ok {
			s.writeProblem(writer, http.StatusMisdirectedRequest, "host_not_allowed", "Host is not allowed", "")
			return
		}
		next.ServeHTTP(writer, request)
	})
}

func (s *Server) requestLimit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.ContentLength > maxRequestBodyBytes {
			s.writeProblem(writer, http.StatusRequestEntityTooLarge, "request_too_large", "Request is too large", "")
			return
		}
		request.Body = http.MaxBytesReader(writer, request.Body, maxRequestBodyBytes)
		next.ServeHTTP(writer, request)
	})
}

func (s *Server) requireHumanAccess(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		principal, err := access.FromRequest(request.Context(), request, s.access)
		if err != nil || principal.ServiceAuth {
			s.writeProblem(writer, http.StatusUnauthorized, "access_required", "Cloudflare Access authentication required", "")
			return
		}
		next.ServeHTTP(writer, request)
	})
}

func (s *Server) handleLive(writer http.ResponseWriter, _ *http.Request) {
	s.writeJSON(writer, http.StatusOK, map[string]any{
		"state": "live", "mode": s.mode, "checked_at": s.now().UTC().Format(time.RFC3339Nano),
	})
}

func (s *Server) handleReady(writer http.ResponseWriter, request *http.Request) {
	ctx, cancel := context.WithTimeout(request.Context(), 2*time.Second)
	defer cancel()
	if err := s.store.QuickCheck(ctx); err != nil {
		s.writeProblem(writer, http.StatusServiceUnavailable, "database_not_ready", "Core is not ready", "")
		return
	}
	if _, err := s.projection.Snapshot(ctx); err != nil {
		s.writeProblem(writer, http.StatusServiceUnavailable, "projection_not_ready", "Core is not ready", "")
		return
	}
	s.writeJSON(writer, http.StatusOK, map[string]any{
		"state": "ready", "mode": s.mode, "checked_at": s.now().UTC().Format(time.RFC3339Nano),
	})
}

func (s *Server) handleAdminHealth(writer http.ResponseWriter, request *http.Request) {
	projection, err := s.projection.Snapshot(request.Context())
	if err != nil {
		s.writeProblem(writer, http.StatusServiceUnavailable, "projection_unavailable", "Status projection is unavailable", "")
		return
	}
	s.writeJSON(writer, http.StatusOK, projection)
}

func (s *Server) handleFileshareStatus(writer http.ResponseWriter, _ *http.Request) {
	s.writeJSON(writer, http.StatusOK, map[string]string{
		"state": "unavailable", "reason": "shadow_mode",
	})
}

func (s *Server) handleShadowAPI(writer http.ResponseWriter, request *http.Request) {
	if isUnsafe(request.Method) {
		if !validMutationHeaders(request) {
			s.writeProblem(writer, http.StatusBadRequest, "mutation_guards_required", "CSRF, idempotency and version headers are required", "")
			return
		}
		s.writeProblem(writer, http.StatusServiceUnavailable, "shadow_mode_read_only", "Mutations are disabled in shadow mode", "")
		return
	}
	s.writeProblem(writer, http.StatusNotFound, "route_not_available", "Route is not available in shadow mode", "")
}

func validMutationHeaders(request *http.Request) bool {
	csrf := request.Header.Get("X-CSRF-Token")
	if len(csrf) < 32 || len(csrf) > 256 {
		return false
	}
	if !safeIdempotencyKey.MatchString(request.Header.Get("Idempotency-Key")) {
		return false
	}
	version := request.Header.Get("If-Match")
	create := request.Header.Get("If-None-Match")
	return (version != "" && create == "") || (version == "" && create == "*")
}

func isUnsafe(method string) bool {
	return method != http.MethodGet && method != http.MethodHead && method != http.MethodOptions
}

func (s *Server) writeProblem(writer http.ResponseWriter, status int, code, title, detail string) {
	requestID, err := idgen.New("req")
	if err != nil {
		requestID = "req_unavailable"
	}
	writer.Header().Set("Content-Type", "application/problem+json")
	s.writeJSON(writer, status, problem{
		Type: "https://plntir.example/problems/" + code, Title: title, Status: status,
		Detail: shadow.Sanitize(detail), RequestID: requestID,
	})
}

func (s *Server) writeJSON(writer http.ResponseWriter, status int, value any) {
	if writer.Header().Get("Content-Type") == "" {
		writer.Header().Set("Content-Type", "application/json; charset=utf-8")
	}
	writer.WriteHeader(status)
	encoder := json.NewEncoder(writer)
	encoder.SetEscapeHTML(true)
	_ = encoder.Encode(value)
}
