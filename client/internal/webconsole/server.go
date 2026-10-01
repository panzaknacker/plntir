package webconsole

import (
	"context"
	"crypto/subtle"
	"crypto/tls"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	"plntir/client/internal/status"
)

const sessionCookieName = "__Host-plntir_session"

//go:embed static/*
var embeddedStatic embed.FS

type Server struct {
	config   Config
	verifier *PasswordVerifier
	sessions *SessionStore
	source   *CommandSource
	audit    *AuditLog
	jobs     *ExportJobs
	mux      *http.ServeMux

	loginMu       sync.Mutex
	loginAttempts map[string]loginAttempt
	statusMu      sync.Mutex
	statusAt      time.Time
	statusValue   status.Snapshot
	statusErr     error
}

type loginAttempt struct {
	Failures     []time.Time
	BlockedUntil time.Time
}

type authenticatedHandler func(http.ResponseWriter, *http.Request, Session, string)

func NewServer(config Config) (*Server, error) {
	verifier, err := LoadPasswordVerifier(config.AuthFile)
	if err != nil {
		return nil, fmt.Errorf("load dashboard authentication: %w", err)
	}
	audit, err := NewAuditLog(config.AuditFile)
	if err != nil {
		return nil, fmt.Errorf("open dashboard audit log: %w", err)
	}
	source := NewCommandSource(config)
	server := &Server{
		config:        config,
		verifier:      verifier,
		sessions:      NewSessionStore(time.Duration(config.SessionMinutes) * time.Minute),
		source:        source,
		audit:         audit,
		jobs:          NewExportJobs(source, audit),
		mux:           http.NewServeMux(),
		loginAttempts: make(map[string]loginAttempt),
	}
	server.routes()
	return server, nil
}

func (server *Server) Handler() http.Handler {
	return server.securityMiddleware(server.mux)
}

func (server *Server) Serve(ctx context.Context) error {
	if !server.config.LocalMeshAddressPresent() {
		return fmt.Errorf("configured Mesh listen address %s is not assigned locally", server.config.Listen)
	}
	httpServer := &http.Server{
		Addr:              server.config.Listen,
		Handler:           server.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		IdleTimeout:       90 * time.Second,
		MaxHeaderBytes:    32 << 10,
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS13,
		},
	}
	done := make(chan error, 1)
	go func() {
		done <- httpServer.ListenAndServeTLS(server.config.TLSCertFile, server.config.TLSKeyFile)
	}()
	select {
	case err := <-done:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		shutdownContext, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := httpServer.Shutdown(shutdownContext); err != nil {
			return err
		}
		return nil
	}
}

func (server *Server) routes() {
	server.mux.HandleFunc("/", server.handleIndex)
	server.mux.HandleFunc("/assets/", server.handleAsset)
	server.mux.HandleFunc("/api/login", server.handleLogin)
	server.mux.HandleFunc("/api/session", server.withSession(server.handleSession))
	server.mux.HandleFunc("/api/logout", server.withSession(server.handleLogout))
	server.mux.HandleFunc("/api/private/unlock", server.withSession(server.handlePrivateUnlock))
	server.mux.HandleFunc("/api/private/lock", server.withSession(server.handlePrivateLock))
	server.mux.HandleFunc("/api/status", server.withSession(server.handleStatus))
	server.mux.HandleFunc("/api/health-history", server.withSession(server.handleHealthHistory))
	server.mux.HandleFunc("/api/audit", server.withSession(server.requirePrivate(server.handleAudit)))
	server.mux.HandleFunc("/api/telemetry", server.withSession(server.handleTelemetry))
	server.mux.HandleFunc("/api/telemetry/view", server.withSession(server.handleTelemetryView))
	server.mux.HandleFunc("/api/files/list", server.withSession(server.requirePrivate(server.handleFilesList)))
	server.mux.HandleFunc("/api/files/preview", server.withSession(server.requirePrivate(server.handleFilesPreview)))
	server.mux.HandleFunc("/api/files/probe", server.withSession(server.requirePrivate(server.handleFilesProbe)))
	server.mux.HandleFunc("/api/safari", server.withSession(server.requirePrivate(server.handleSafari)))
	server.mux.HandleFunc("/api/export-jobs", server.withSession(server.requirePrivate(server.handleExportJobs)))
	server.mux.HandleFunc("/api/export-jobs/cancel", server.withSession(server.requirePrivate(server.handleExportJobCancel)))
	server.mux.HandleFunc("/api/archives", server.withSession(server.requirePrivate(server.handleArchives)))
	server.mux.HandleFunc("/api/archives/download", server.withSession(server.requirePrivate(server.handleArchiveDownload)))
	server.mux.HandleFunc("/api/refresh", server.withSession(server.handleRefresh))
}

func (server *Server) securityMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Cache-Control", "no-store, max-age=0")
		writer.Header().Set("Pragma", "no-cache")
		writer.Header().Set("Cross-Origin-Opener-Policy", "same-origin")
		writer.Header().Set("Cross-Origin-Resource-Policy", "same-origin")
		writer.Header().Set("Referrer-Policy", "no-referrer")
		writer.Header().Set("X-Content-Type-Options", "nosniff")
		writer.Header().Set("X-Frame-Options", "DENY")
		writer.Header().Set("X-DNS-Prefetch-Control", "off")
		writer.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=()")
		writer.Header().Set("Strict-Transport-Security", "max-age=31536000")
		writer.Header().Set("Content-Security-Policy", "default-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; object-src 'none'; img-src 'self' data:; style-src 'self'; script-src 'self'; connect-src 'self'")
		if request.TLS == nil {
			writeError(writer, http.StatusUpgradeRequired, "HTTPS is required")
			return
		}
		if !server.config.HostAllowed(request.Host) {
			writeError(writer, http.StatusMisdirectedRequest, "host is not allowed")
			return
		}
		remoteIP, err := requestIP(request)
		if err != nil || !server.config.MeshNet.Contains(remoteIP) {
			writeError(writer, http.StatusForbidden, "Mesh client address required")
			return
		}
		next.ServeHTTP(writer, request)
	})
}

func (server *Server) withSession(next authenticatedHandler) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		cookie, err := request.Cookie(sessionCookieName)
		if err != nil {
			writeError(writer, http.StatusUnauthorized, "authentication required")
			return
		}
		now := time.Now().UTC()
		session, ok := server.sessions.Get(cookie.Value, request.UserAgent(), now)
		if !ok {
			server.clearCookie(writer)
			writeError(writer, http.StatusUnauthorized, "session expired")
			return
		}
		next(writer, request, session, cookie.Value)
	}
}

func (server *Server) requirePrivate(next authenticatedHandler) authenticatedHandler {
	return func(writer http.ResponseWriter, request *http.Request, session Session, token string) {
		if !session.PrivateActive(time.Now().UTC()) {
			writeError(writer, http.StatusForbidden, "private-data session is locked")
			return
		}
		next(writer, request, session, token)
	}
}

func (server *Server) handleIndex(writer http.ResponseWriter, request *http.Request) {
	if request.URL.Path != "/" || request.Method != http.MethodGet {
		if request.URL.Path != "/" {
			http.NotFound(writer, request)
		} else {
			writeError(writer, http.StatusMethodNotAllowed, "method not allowed")
		}
		return
	}
	contents, err := embeddedStatic.ReadFile("static/index.html")
	if err != nil {
		writeError(writer, http.StatusInternalServerError, "dashboard asset unavailable")
		return
	}
	writer.Header().Set("Content-Type", "text/html; charset=utf-8")
	writer.WriteHeader(http.StatusOK)
	_, _ = writer.Write(contents)
}

func (server *Server) handleAsset(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		writeError(writer, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	name := strings.TrimPrefix(path.Clean(request.URL.Path), "/assets/")
	if name == "" || name == "." || strings.Contains(name, "/") {
		http.NotFound(writer, request)
		return
	}
	contents, err := fs.ReadFile(embeddedStatic, "static/"+name)
	if err != nil {
		http.NotFound(writer, request)
		return
	}
	switch path.Ext(name) {
	case ".css":
		writer.Header().Set("Content-Type", "text/css; charset=utf-8")
	case ".js":
		writer.Header().Set("Content-Type", "text/javascript; charset=utf-8")
	case ".svg":
		writer.Header().Set("Content-Type", "image/svg+xml")
	default:
		writer.Header().Set("Content-Type", "application/octet-stream")
	}
	writer.Header().Set("Cache-Control", "private, max-age=3600")
	_, _ = writer.Write(contents)
}

func (server *Server) handleLogin(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		writeError(writer, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if !sameOrigin(request) {
		writeError(writer, http.StatusForbidden, "same-origin request required")
		return
	}
	remote := remoteIPString(request)
	now := time.Now().UTC()
	if !server.loginAllowed(remote, now) {
		_ = server.audit.Write("login.blocked", "", remote, false, nil)
		writeError(writer, http.StatusTooManyRequests, "too many login attempts")
		return
	}
	var input struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := decodeJSON(writer, request, 4096, &input); err != nil {
		writeError(writer, http.StatusBadRequest, "invalid login request")
		return
	}
	password := []byte(input.Password)
	input.Password = ""
	valid := server.verifier.Verify(input.Username, password)
	clearBytes(password)
	if !valid {
		server.recordLoginFailure(remote, now)
		_ = server.audit.Write("login.failed", input.Username, remote, false, nil)
		writeError(writer, http.StatusUnauthorized, "invalid credentials")
		return
	}
	server.clearLoginFailures(remote)
	token, session, err := server.sessions.Create(server.verifier.Username(), request.UserAgent(), now)
	if err != nil {
		writeError(writer, http.StatusServiceUnavailable, "session unavailable")
		return
	}
	http.SetCookie(writer, &http.Cookie{
		Name:     sessionCookieName,
		Value:    token,
		Path:     "/",
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Expires:  session.ExpiresAt,
		MaxAge:   int(time.Until(session.ExpiresAt).Seconds()),
	})
	_ = server.audit.Write("login.success", session.Username, remote, true, nil)
	writeJSON(writer, http.StatusOK, sessionPayload(server.config, session, now))
}

func (server *Server) handleSession(writer http.ResponseWriter, request *http.Request, session Session, _ string) {
	if request.Method != http.MethodGet {
		writeError(writer, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	writeJSON(writer, http.StatusOK, sessionPayload(server.config, session, time.Now().UTC()))
}

func (server *Server) handleLogout(writer http.ResponseWriter, request *http.Request, session Session, token string) {
	if request.Method != http.MethodPost || !server.validUnsafeRequest(request, session) {
		writeError(writer, http.StatusForbidden, "valid CSRF token required")
		return
	}
	server.sessions.Delete(token)
	server.clearCookie(writer)
	_ = server.audit.Write("logout", session.Username, remoteIPString(request), true, nil)
	writeJSON(writer, http.StatusOK, map[string]bool{"ok": true})
}

func (server *Server) handlePrivateUnlock(writer http.ResponseWriter, request *http.Request, session Session, token string) {
	if request.Method != http.MethodPost || !server.validUnsafeRequest(request, session) {
		writeError(writer, http.StatusForbidden, "valid CSRF token required")
		return
	}
	remote := remoteIPString(request)
	now := time.Now().UTC()
	rateKey := "private:" + session.Username + ":" + remote
	if !server.loginAllowed(rateKey, now) {
		_ = server.audit.Write("private.unlock.blocked", session.Username, remote, false, nil)
		writeError(writer, http.StatusTooManyRequests, "too many unlock attempts")
		return
	}
	var input struct {
		Password string `json:"password"`
	}
	if err := decodeJSON(writer, request, 4096, &input); err != nil {
		writeError(writer, http.StatusBadRequest, "invalid unlock request")
		return
	}
	password := []byte(input.Password)
	input.Password = ""
	valid := server.verifier.Verify(session.Username, password)
	clearBytes(password)
	if !valid {
		server.recordLoginFailure(rateKey, now)
		_ = server.audit.Write("private.unlock", session.Username, remote, false, nil)
		writeError(writer, http.StatusUnauthorized, "invalid credentials")
		return
	}
	server.clearLoginFailures(rateKey)
	unlocked, ok := server.sessions.UnlockPrivate(
		token,
		request.UserAgent(),
		now,
		time.Duration(server.config.PrivateSessionMinutes)*time.Minute,
	)
	if !ok {
		writeError(writer, http.StatusUnauthorized, "session expired")
		return
	}
	_ = server.audit.Write("private.unlock", session.Username, remote, true, map[string]any{
		"expires_at": unlocked.PrivateUntil.Format(time.RFC3339),
	})
	writeJSON(writer, http.StatusOK, sessionPayload(server.config, unlocked, time.Now().UTC()))
}

func (server *Server) handlePrivateLock(writer http.ResponseWriter, request *http.Request, session Session, token string) {
	if request.Method != http.MethodPost || !server.validUnsafeRequest(request, session) {
		writeError(writer, http.StatusForbidden, "valid CSRF token required")
		return
	}
	server.sessions.LockPrivate(token)
	_ = server.audit.Write("private.lock", session.Username, remoteIPString(request), true, nil)
	writeJSON(writer, http.StatusOK, map[string]bool{"ok": true})
}

func (server *Server) handleStatus(writer http.ResponseWriter, request *http.Request, _ Session, _ string) {
	if request.Method != http.MethodGet {
		writeError(writer, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	snapshot, err := server.cachedStatus(request.Context())
	if err != nil {
		writeError(writer, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(writer, http.StatusOK, snapshot)
}

func (server *Server) handleHealthHistory(writer http.ResponseWriter, request *http.Request, _ Session, _ string) {
	if request.Method != http.MethodGet {
		writeError(writer, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	limit := queryInteger(request.URL.Query(), "limit", 200, 1, 2000)
	if limit == 0 {
		writeError(writer, http.StatusBadRequest, "invalid history limit")
		return
	}
	history, err := server.source.HealthHistory(limit)
	if err != nil {
		writeError(writer, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{"history": history})
}

func (server *Server) handleAudit(writer http.ResponseWriter, request *http.Request, _ Session, _ string) {
	if request.Method != http.MethodGet {
		writeError(writer, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	limit := queryInteger(request.URL.Query(), "limit", 100, 1, 2000)
	if limit == 0 {
		writeError(writer, http.StatusBadRequest, "invalid audit limit")
		return
	}
	records, err := server.audit.Read(limit)
	if err != nil {
		writeError(writer, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{"records": records})
}

func (server *Server) handleTelemetry(writer http.ResponseWriter, request *http.Request, _ Session, _ string) {
	if request.Method != http.MethodGet {
		writeError(writer, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	captures, err := server.source.TelemetryIndex()
	if err != nil {
		writeError(writer, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{"captures": captures})
}

func (server *Server) handleTelemetryView(writer http.ResponseWriter, request *http.Request, _ Session, _ string) {
	if request.Method != http.MethodGet {
		writeError(writer, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	document, err := server.source.ReadTelemetry(request.URL.Query().Get("id"))
	if err != nil {
		writeError(writer, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(writer, http.StatusOK, document)
}

func (server *Server) handleFilesList(writer http.ResponseWriter, request *http.Request, session Session, _ string) {
	if request.Method != http.MethodGet {
		writeError(writer, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	requested := request.URL.Query().Get("path")
	if requested == "" {
		requested = server.config.ManagedHome
	}
	listing, err := server.source.List(request.Context(), requested)
	remote := remoteIPString(request)
	if err != nil {
		_ = server.audit.Write("files.list", session.Username, remote, false, map[string]any{"path": requested})
		writeError(writer, http.StatusBadGateway, err.Error())
		return
	}
	_ = server.audit.Write("files.list", session.Username, remote, true, map[string]any{
		"path": listing.Path, "entries": listing.EntryCount,
	})
	writeJSON(writer, http.StatusOK, listing)
}

func (server *Server) handleFilesProbe(writer http.ResponseWriter, request *http.Request, session Session, _ string) {
	if request.Method != http.MethodPost || !server.validUnsafeRequest(request, session) {
		writeError(writer, http.StatusForbidden, "valid CSRF token required")
		return
	}
	var input struct {
		Path string `json:"path"`
	}
	if err := decodeJSON(writer, request, 8192, &input); err != nil {
		writeError(writer, http.StatusBadRequest, "invalid probe request")
		return
	}
	result, err := server.source.Probe(request.Context(), input.Path)
	remote := remoteIPString(request)
	if err != nil {
		_ = server.audit.Write("files.probe", session.Username, remote, false, map[string]any{"path": input.Path})
		writeError(writer, http.StatusBadGateway, err.Error())
		return
	}
	_ = server.audit.Write("files.probe", session.Username, remote, true, map[string]any{
		"path": result.Path, "files": result.Files, "bytes": result.Bytes,
	})
	writeJSON(writer, http.StatusOK, result)
}

func (server *Server) handleFilesPreview(writer http.ResponseWriter, request *http.Request, session Session, _ string) {
	if request.Method != http.MethodPost || !server.validUnsafeRequest(request, session) {
		writeError(writer, http.StatusForbidden, "valid CSRF token required")
		return
	}
	var input struct {
		Path string `json:"path"`
	}
	if err := decodeJSON(writer, request, 8192, &input); err != nil {
		writeError(writer, http.StatusBadRequest, "invalid preview request")
		return
	}
	result, err := server.source.Preview(request.Context(), input.Path)
	remote := remoteIPString(request)
	if err != nil {
		_ = server.audit.Write("files.preview", session.Username, remote, false, map[string]any{"path": input.Path})
		writeError(writer, http.StatusBadGateway, err.Error())
		return
	}
	_ = server.audit.Write("files.preview", session.Username, remote, true, map[string]any{
		"path": result.Path, "bytes": result.Bytes, "returned_bytes": result.ReturnedBytes,
		"kind": result.Kind, "truncated": result.Truncated,
	})
	writeJSON(writer, http.StatusOK, result)
}

func (server *Server) handleSafari(writer http.ResponseWriter, request *http.Request, session Session, _ string) {
	if request.Method != http.MethodGet {
		writeError(writer, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	hours := queryInteger(request.URL.Query(), "hours", 24, 1, 8760)
	limit := queryInteger(request.URL.Query(), "limit", 500, 1, 5000)
	if hours == 0 || limit == 0 {
		writeError(writer, http.StatusBadRequest, "invalid Safari query range")
		return
	}
	history, err := server.source.Safari(request.Context(), hours, limit)
	remote := remoteIPString(request)
	if err != nil {
		_ = server.audit.Write("safari.history", session.Username, remote, false, map[string]any{"hours": hours})
		writeError(writer, http.StatusBadGateway, err.Error())
		return
	}
	_ = server.audit.Write("safari.history", session.Username, remote, true, map[string]any{
		"hours": hours, "returned": history.Returned,
	})
	writeJSON(writer, http.StatusOK, history)
}

func (server *Server) handleExportJobs(writer http.ResponseWriter, request *http.Request, session Session, _ string) {
	switch request.Method {
	case http.MethodGet:
		writeJSON(writer, http.StatusOK, map[string]any{"jobs": server.jobs.List(session.Username)})
	case http.MethodPost:
		if !server.validUnsafeRequest(request, session) {
			writeError(writer, http.StatusForbidden, "valid CSRF token required")
			return
		}
		var input struct {
			Paths []string `json:"paths"`
		}
		if err := decodeJSON(writer, request, 128<<10, &input); err != nil {
			writeError(writer, http.StatusBadRequest, "invalid export request")
			return
		}
		job, err := server.jobs.Start(input.Paths, session.Username, remoteIPString(request))
		if err != nil {
			writeError(writer, http.StatusBadRequest, err.Error())
			return
		}
		writeJSON(writer, http.StatusAccepted, job)
	default:
		writeError(writer, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (server *Server) handleExportJobCancel(writer http.ResponseWriter, request *http.Request, session Session, _ string) {
	if request.Method != http.MethodPost || !server.validUnsafeRequest(request, session) {
		writeError(writer, http.StatusForbidden, "valid CSRF token required")
		return
	}
	var input struct {
		ID string `json:"id"`
	}
	if err := decodeJSON(writer, request, 4096, &input); err != nil {
		writeError(writer, http.StatusBadRequest, "invalid cancellation request")
		return
	}
	if err := server.jobs.Cancel(input.ID, session.Username, remoteIPString(request)); err != nil {
		writeError(writer, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(writer, http.StatusOK, map[string]bool{"ok": true})
}

func (server *Server) handleArchives(writer http.ResponseWriter, request *http.Request, _ Session, _ string) {
	if request.Method != http.MethodGet {
		writeError(writer, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	archives, err := server.source.Archives()
	if err != nil {
		writeError(writer, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{"archives": archives})
}

func (server *Server) handleArchiveDownload(writer http.ResponseWriter, request *http.Request, session Session, _ string) {
	if request.Method != http.MethodGet {
		writeError(writer, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	name := request.URL.Query().Get("name")
	file, info, err := server.source.OpenArchive(name)
	if err != nil {
		writeError(writer, http.StatusBadRequest, err.Error())
		return
	}
	defer file.Close()
	writer.Header().Set("Content-Type", "application/octet-stream")
	writer.Header().Set("Content-Disposition", "attachment; filename*=UTF-8''"+url.PathEscape(path.Base(name)))
	_ = server.audit.Write("archive.download", session.Username, remoteIPString(request), true, map[string]any{
		"name": name, "bytes": info.Size(),
	})
	http.ServeContent(writer, request, info.Name(), info.ModTime(), file)
}

func (server *Server) handleRefresh(writer http.ResponseWriter, request *http.Request, session Session, _ string) {
	if request.Method != http.MethodPost || !server.validUnsafeRequest(request, session) {
		writeError(writer, http.StatusForbidden, "valid CSRF token required")
		return
	}
	result, err := server.source.Refresh(request.Context())
	remote := remoteIPString(request)
	if err != nil {
		_ = server.audit.Write("monitor.refresh", session.Username, remote, false, nil)
		writeError(writer, http.StatusBadGateway, err.Error())
		return
	}
	server.statusMu.Lock()
	server.statusAt = time.Time{}
	server.statusMu.Unlock()
	_ = server.audit.Write("monitor.refresh", session.Username, remote, true, nil)
	writeJSON(writer, http.StatusOK, result)
}

func (server *Server) cachedStatus(ctx context.Context) (status.Snapshot, error) {
	server.statusMu.Lock()
	defer server.statusMu.Unlock()
	now := time.Now().UTC()
	if !server.statusAt.IsZero() && now.Sub(server.statusAt) < 2*time.Second {
		return server.statusValue, server.statusErr
	}
	server.statusValue, server.statusErr = server.source.Status(ctx)
	server.statusAt = now
	return server.statusValue, server.statusErr
}

func (server *Server) validUnsafeRequest(request *http.Request, session Session) bool {
	if !sameOrigin(request) {
		return false
	}
	provided := request.Header.Get("X-Plntir-CSRF")
	return len(provided) == len(session.CSRF) && subtle.ConstantTimeCompare([]byte(provided), []byte(session.CSRF)) == 1
}

func (server *Server) clearCookie(writer http.ResponseWriter) {
	http.SetCookie(writer, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
		Expires:  time.Unix(1, 0),
	})
}

func (server *Server) loginAllowed(remote string, now time.Time) bool {
	server.loginMu.Lock()
	defer server.loginMu.Unlock()
	attempt := server.loginAttempts[remote]
	return !now.Before(attempt.BlockedUntil)
}

func (server *Server) recordLoginFailure(remote string, now time.Time) {
	server.loginMu.Lock()
	defer server.loginMu.Unlock()
	attempt := server.loginAttempts[remote]
	cutoff := now.Add(-10 * time.Minute)
	kept := attempt.Failures[:0]
	for _, failure := range attempt.Failures {
		if failure.After(cutoff) {
			kept = append(kept, failure)
		}
	}
	attempt.Failures = append(kept, now)
	if len(attempt.Failures) >= 5 {
		attempt.BlockedUntil = now.Add(15 * time.Minute)
	}
	server.loginAttempts[remote] = attempt
}

func (server *Server) clearLoginFailures(remote string) {
	server.loginMu.Lock()
	defer server.loginMu.Unlock()
	delete(server.loginAttempts, remote)
}

func sessionPayload(config Config, session Session, now time.Time) map[string]any {
	return map[string]any{
		"authenticated":       true,
		"username":            session.Username,
		"csrf":                session.CSRF,
		"expires_at":          session.ExpiresAt.Format(time.RFC3339),
		"private_active":      session.PrivateActive(now),
		"private_until":       optionalTime(session.PrivateUntil),
		"managed_home":        config.ManagedHome,
		"refresh_seconds":     config.RefreshSeconds,
		"private_ttl_minutes": config.PrivateSessionMinutes,
	}
}

func optionalTime(value time.Time) string {
	if value.IsZero() {
		return ""
	}
	return value.Format(time.RFC3339)
}

func sameOrigin(request *http.Request) bool {
	origin := request.Header.Get("Origin")
	if origin == "" {
		return false
	}
	parsed, err := url.Parse(origin)
	return err == nil && parsed.Scheme == "https" && strings.EqualFold(parsed.Host, request.Host) && parsed.Path == ""
}

func requestIP(request *http.Request) (net.IP, error) {
	host, _, err := net.SplitHostPort(request.RemoteAddr)
	if err != nil {
		return nil, err
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return nil, errors.New("invalid remote IP")
	}
	return ip, nil
}

func remoteIPString(request *http.Request) string {
	ip, err := requestIP(request)
	if err != nil {
		return "unknown"
	}
	return ip.String()
}

func queryInteger(values url.Values, name string, fallback, minimum, maximum int) int {
	raw := values.Get(name)
	if raw == "" {
		return fallback
	}
	value, err := strconv.Atoi(raw)
	if err != nil || value < minimum || value > maximum {
		return 0
	}
	return value
}

func decodeJSON(writer http.ResponseWriter, request *http.Request, limit int64, target any) error {
	if mediaType := strings.ToLower(strings.TrimSpace(strings.Split(request.Header.Get("Content-Type"), ";")[0])); mediaType != "application/json" {
		return errors.New("application/json required")
	}
	request.Body = http.MaxBytesReader(writer, request.Body, limit)
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("trailing JSON data")
		}
		return err
	}
	return nil
}

func writeJSON(writer http.ResponseWriter, code int, value any) {
	writer.Header().Set("Content-Type", "application/json; charset=utf-8")
	writer.WriteHeader(code)
	encoder := json.NewEncoder(writer)
	encoder.SetEscapeHTML(true)
	_ = encoder.Encode(value)
}

func writeError(writer http.ResponseWriter, code int, message string) {
	writeJSON(writer, code, map[string]any{
		"ok":    false,
		"error": message,
	})
}
