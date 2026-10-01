package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"syscall"
	"time"
)

const (
	expectedHostname  = "mdm.plntir.example"
	expectedTag       = "fleet-v4.89.2"
	expectedSourceSHA = "1fb267b8a0b997b201bc833e13794d773c3dd75b5117101345219b63e1ff27e9"
	defaultListen     = ":8080"
	defaultUpstream   = "http://fleet:8080"
)

var (
	//go:embed public-routes-v4.89.2.json
	embeddedPolicy []byte

	pathPattern      = regexp.MustCompile(`^/[A-Za-z0-9._/-]+$`)
	idPattern        = regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+)*$`)
	imagePattern     = regexp.MustCompile(`^fleetdm/fleet:v4\.89\.2@sha256:[0-9a-f]{64}$`)
	logMethodPattern = regexp.MustCompile(`^[A-Z]{1,12}$`)
)

type releasePolicy struct {
	Tag                 string `json:"tag"`
	SourceArchive       string `json:"source_archive"`
	SourceArchiveSHA256 string `json:"source_archive_sha256"`
	ContainerImage      string `json:"container_image"`
}

type routePolicy struct {
	ID      string   `json:"id"`
	Path    string   `json:"path"`
	Methods []string `json:"methods"`
	Purpose string   `json:"purpose"`
	Sources []string `json:"sources"`
}

type excludedPolicy struct {
	Feature  string   `json:"feature"`
	Examples []string `json:"examples"`
}

type ingressPolicy struct {
	SchemaVersion         int              `json:"schema_version"`
	Hostname              string           `json:"hostname"`
	Release               releasePolicy    `json:"release"`
	Routes                []routePolicy    `json:"routes"`
	IntentionallyExcluded []excludedPolicy `json:"intentionally_excluded"`
}

func parsePolicy(data []byte) (ingressPolicy, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var policy ingressPolicy
	if err := decoder.Decode(&policy); err != nil {
		return ingressPolicy{}, fmt.Errorf("decode policy: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return ingressPolicy{}, errors.New("decode policy: trailing JSON data")
	}
	if err := validatePolicy(policy); err != nil {
		return ingressPolicy{}, err
	}
	return policy, nil
}

func validatePolicy(policy ingressPolicy) error {
	if policy.SchemaVersion != 1 {
		return errors.New("policy schema_version must be 1")
	}
	if policy.Hostname != expectedHostname {
		return fmt.Errorf("policy hostname must be exactly %q", expectedHostname)
	}
	if policy.Release.Tag != expectedTag {
		return fmt.Errorf("policy release must be exactly %q", expectedTag)
	}
	if policy.Release.SourceArchive == "" || policy.Release.SourceArchiveSHA256 != expectedSourceSHA {
		return errors.New("policy Fleet source archive is not the reviewed release")
	}
	if !imagePattern.MatchString(policy.Release.ContainerImage) {
		return errors.New("policy Fleet image is not pinned to the reviewed tag and digest")
	}
	if len(policy.Routes) == 0 {
		return errors.New("policy has no routes")
	}
	allowedMethods := map[string]bool{"GET": true, "HEAD": true, "POST": true, "PUT": true}
	ids := make(map[string]bool, len(policy.Routes))
	paths := make(map[string]bool, len(policy.Routes))
	for index, route := range policy.Routes {
		if !idPattern.MatchString(route.ID) || ids[route.ID] {
			return fmt.Errorf("route %d has an invalid or duplicate id", index)
		}
		if !canonicalPolicyPath(route.Path) || paths[route.Path] {
			return fmt.Errorf("route %d has a non-canonical or duplicate path", index)
		}
		if route.Purpose == "" || len(route.Sources) == 0 {
			return fmt.Errorf("route %d lacks purpose or reviewed sources", index)
		}
		for _, source := range route.Sources {
			if source == "" {
				return fmt.Errorf("route %d contains an empty source", index)
			}
		}
		if len(route.Methods) == 0 {
			return fmt.Errorf("route %d has no methods", index)
		}
		methods := make(map[string]bool, len(route.Methods))
		for _, method := range route.Methods {
			if !allowedMethods[method] || methods[method] {
				return fmt.Errorf("route %d has an invalid or duplicate method", index)
			}
			methods[method] = true
		}
		ids[route.ID] = true
		paths[route.Path] = true
	}
	if len(policy.IntentionallyExcluded) == 0 {
		return errors.New("policy does not document excluded feature families")
	}
	for index, group := range policy.IntentionallyExcluded {
		if group.Feature == "" || len(group.Examples) == 0 {
			return fmt.Errorf("excluded group %d is incomplete", index)
		}
		for _, example := range group.Examples {
			if !strings.HasPrefix(example, "/") || paths[example] {
				return fmt.Errorf("excluded group %d has an invalid or allowed example", index)
			}
		}
	}
	return nil
}

func canonicalPolicyPath(value string) bool {
	if value == "/" || strings.HasSuffix(value, "/") || strings.Contains(value, "//") || !pathPattern.MatchString(value) {
		return false
	}
	for _, part := range strings.Split(value, "/") {
		if part == "." || part == ".." {
			return false
		}
	}
	return true
}

type routeKey struct {
	method string
	path   string
}

type ingressGate struct {
	hostname string
	routes   map[routeKey]string
	proxy    *httputil.ReverseProxy
	logger   *slog.Logger
}

func newIngressGate(policy ingressPolicy, upstream *url.URL, logger *slog.Logger) *ingressGate {
	routes := make(map[routeKey]string)
	for _, route := range policy.Routes {
		for _, method := range route.Methods {
			routes[routeKey{method: method, path: route.Path}] = route.ID
		}
	}
	proxy := httputil.NewSingleHostReverseProxy(upstream)
	originalDirector := proxy.Director
	proxy.Director = func(request *http.Request) {
		request.Header.Del("Forwarded")
		request.Header.Del("X-Forwarded-For")
		request.Header.Del("X-Forwarded-Host")
		request.Header.Del("X-Forwarded-Proto")
		request.Header.Del("X-Real-IP")
		request.Header.Del("CF-Connecting-IP")
		request.Header.Del("True-Client-IP")
		originalDirector(request)
		request.Host = policy.Hostname
		request.Header.Set("X-Forwarded-Host", policy.Hostname)
		request.Header.Set("X-Forwarded-Proto", "https")
		request.Header.Del("X-Plntir-Route-ID")
	}
	proxy.ErrorHandler = func(writer http.ResponseWriter, request *http.Request, err error) {
		logger.Error("Fleet upstream unavailable", "error", err)
		http.Error(writer, "service unavailable", http.StatusBadGateway)
	}
	return &ingressGate{hostname: policy.Hostname, routes: routes, proxy: proxy, logger: logger}
}

func (gate *ingressGate) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if request.URL.Path == "/healthz" && localRequest(request) {
		writer.Header().Set("Cache-Control", "no-store")
		writer.WriteHeader(http.StatusNoContent)
		return
	}
	reason := "route"
	if !validRequestHost(request.Host, gate.hostname) {
		reason = "host"
	} else if !canonicalRequestPath(request) {
		reason = "path_encoding"
	} else if routeID, ok := gate.routes[routeKey{method: request.Method, path: request.URL.Path}]; ok {
		started := time.Now()
		gate.proxy.ServeHTTP(writer, request)
		gate.logger.Info(
			"Fleet device request",
			"route_id", routeID,
			"method", request.Method,
			"duration_ms", time.Since(started).Milliseconds(),
		)
		return
	}
	digest := sha256.Sum256([]byte(requestURIPath(request.RequestURI)))
	loggedMethod := request.Method
	if !logMethodPattern.MatchString(loggedMethod) {
		loggedMethod = "other"
	}
	gate.logger.Warn(
		"Fleet device request denied",
		"reason", reason,
		"method", loggedMethod,
		"path_sha256", hex.EncodeToString(digest[:]),
	)
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	http.Error(writer, "not found", http.StatusNotFound)
}

func validRequestHost(value, expected string) bool {
	if value == "" {
		return false
	}
	host := value
	if parsed, _, err := net.SplitHostPort(value); err == nil {
		host = parsed
	} else if strings.Contains(value, ":") {
		return false
	}
	return strings.EqualFold(host, expected)
}

func requestURIPath(requestURI string) string {
	if index := strings.IndexByte(requestURI, '?'); index >= 0 {
		return requestURI[:index]
	}
	return requestURI
}

func canonicalRequestPath(request *http.Request) bool {
	rawPath := requestURIPath(request.RequestURI)
	if request.URL.RawPath != "" || strings.Contains(rawPath, "%") || strings.Contains(rawPath, "\\") {
		return false
	}
	return rawPath == request.URL.Path && canonicalPolicyPath(rawPath)
}

func localRequest(request *http.Request) bool {
	host, _, err := net.SplitHostPort(request.RemoteAddr)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func validatedUpstream(raw string) (*url.URL, error) {
	upstream, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("parse upstream: %w", err)
	}
	if upstream.Scheme != "http" || upstream.Host != "fleet:8080" || upstream.User != nil || upstream.Path != "" || upstream.RawQuery != "" || upstream.Fragment != "" {
		return nil, errors.New("upstream must be exactly the internal http://fleet:8080 origin")
	}
	return upstream, nil
}

func healthcheck() error {
	client := &http.Client{Timeout: 2 * time.Second}
	request, err := http.NewRequest(http.MethodGet, "http://127.0.0.1:8080/healthz", nil)
	if err != nil {
		return err
	}
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		return fmt.Errorf("health endpoint returned %s", response.Status)
	}
	return nil
}

func main() {
	if len(os.Args) == 2 && os.Args[1] == "healthcheck" {
		if err := healthcheck(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	if len(os.Args) != 1 {
		fmt.Fprintln(os.Stderr, "usage: plntir-fleet-ingress [healthcheck]")
		os.Exit(64)
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	policy, err := parsePolicy(embeddedPolicy)
	if err != nil {
		logger.Error("invalid embedded ingress policy", "error", err)
		os.Exit(78)
	}
	upstreamValue := os.Getenv("PLNTIR_FLEET_UPSTREAM")
	if upstreamValue == "" {
		upstreamValue = defaultUpstream
	}
	upstream, err := validatedUpstream(upstreamValue)
	if err != nil {
		logger.Error("invalid Fleet upstream", "error", err)
		os.Exit(78)
	}
	listenAddress := os.Getenv("PLNTIR_LISTEN_ADDRESS")
	if listenAddress == "" {
		listenAddress = defaultListen
	}
	if listenAddress != defaultListen {
		logger.Error("invalid listen address", "expected", defaultListen)
		os.Exit(78)
	}
	server := &http.Server{
		Addr:              listenAddress,
		Handler:           newIngressGate(policy, upstream, logger),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       90 * time.Second,
		MaxHeaderBytes:    64 << 10,
	}
	shutdownContext, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go func() {
		<-shutdownContext.Done()
		context, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := server.Shutdown(context); err != nil {
			logger.Error("Fleet ingress shutdown failed", "error", err)
		}
	}()
	logger.Info("Fleet device ingress listening", "address", listenAddress, "policy", expectedTag)
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		logger.Error("Fleet ingress stopped", "error", err)
		os.Exit(1)
	}
}
