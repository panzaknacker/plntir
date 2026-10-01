package wazuhintegrity

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	anchorPath     = "/internal/v1/wazuh/hash-anchor"
	projectionPath = "/internal/v1/wazuh/health"
)

var (
	ErrAnchorConflict     = errors.New("a different Wazuh anchor already exists for this UTC date")
	ErrProjectionConflict = errors.New("the Core rejected the Wazuh projection sequence")
	endpointHostPattern   = regexp.MustCompile(`^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
)

type httpDoer interface {
	Do(*http.Request) (*http.Response, error)
}

type AnchorHTTPSink struct {
	Client   httpDoer
	Endpoint string
}

func (sink AnchorHTTPSink) PublishAnchor(ctx context.Context, anchor DailyAnchor) error {
	endpoint, err := exactEndpoint(sink.Endpoint, anchorPath)
	if err != nil || sink.Client == nil {
		return errors.New("Wazuh anchor HTTPS sink is not sealed")
	}
	body, err := anchor.Marshal()
	if err != nil {
		return err
	}
	status, err := postCanonicalJSON(ctx, sink.Client, endpoint, body)
	if err != nil {
		return fmt.Errorf("publish daily Wazuh hash anchor: %w", err)
	}
	switch status {
	case http.StatusCreated, http.StatusNoContent:
		return nil
	case http.StatusConflict:
		return ErrAnchorConflict
	default:
		return fmt.Errorf("publish daily Wazuh hash anchor: unexpected HTTP status %d", status)
	}
}

type ProjectionHTTPSink struct {
	Client     httpDoer
	Endpoint   string
	PrivateKey ed25519.PrivateKey
}

func (sink ProjectionHTTPSink) PublishHealth(ctx context.Context, projection HealthProjection) error {
	endpoint, err := exactEndpoint(sink.Endpoint, projectionPath)
	if err != nil || sink.Client == nil || len(sink.PrivateKey) != ed25519.PrivateKeySize {
		return errors.New("Wazuh projection HTTPS sink is not sealed")
	}
	envelope, err := SignProjection(projection, sink.PrivateKey)
	if err != nil {
		return err
	}
	body, err := json.Marshal(envelope)
	if err != nil {
		return err
	}
	body = append(body, '\n')
	status, err := postCanonicalJSON(ctx, sink.Client, endpoint, body)
	if err != nil {
		return fmt.Errorf("publish sanitized Wazuh health: %w", err)
	}
	switch status {
	case http.StatusCreated, http.StatusNoContent:
		return nil
	case http.StatusConflict:
		return ErrProjectionConflict
	default:
		return fmt.Errorf("publish sanitized Wazuh health: unexpected HTTP status %d", status)
	}
}

func postCanonicalJSON(ctx context.Context, client httpDoer, endpoint *url.URL, body []byte) (int, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), bytes.NewReader(body))
	if err != nil {
		return 0, err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Cache-Control", "no-store")
	request.Header.Set("User-Agent", "plntir-wazuh-integrity/1")
	response, err := client.Do(request)
	if err != nil {
		return 0, err
	}
	if response == nil {
		return 0, errors.New("HTTP client returned no response")
	}
	if response.Body != nil {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4<<10))
		if err := response.Body.Close(); err != nil {
			return 0, err
		}
	}
	return response.StatusCode, nil
}

func exactEndpoint(raw, requiredPath string) (*url.URL, error) {
	if len(raw) < 12 || len(raw) > 2048 || !strings.HasPrefix(raw, "https://") {
		return nil, errors.New("endpoint must be a bounded HTTPS URL")
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "https" || parsed.Opaque != "" || parsed.User != nil ||
		parsed.RawPath != "" || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" ||
		parsed.Path != requiredPath || parsed.Host == "" || parsed.String() != raw {
		return nil, errors.New("endpoint URL is not exact")
	}
	hostname := parsed.Hostname()
	if hostname != strings.ToLower(hostname) || len(hostname) > 253 || net.ParseIP(hostname) != nil || !endpointHostPattern.MatchString(hostname) {
		return nil, errors.New("endpoint hostname is invalid")
	}
	if port := parsed.Port(); port != "" {
		number, convertErr := strconv.Atoi(port)
		if convertErr != nil || number < 1 || number > 65535 || parsed.Host != net.JoinHostPort(hostname, port) {
			return nil, errors.New("endpoint port is invalid")
		}
	} else if parsed.Host != hostname {
		return nil, errors.New("endpoint authority is noncanonical")
	}
	return parsed, nil
}

type MTLSRelayClientOptions struct {
	ProxyURL    string
	ServerName  string
	RootCAs     *x509.CertPool
	Certificate tls.Certificate
	Timeout     time.Duration
	Now         func() time.Time
}

func NewMTLSRelayClient(options MTLSRelayClientOptions) (*http.Client, error) {
	if !validTLSServerName(options.ServerName) || options.RootCAs == nil || len(options.RootCAs.Subjects()) == 0 ||
		len(options.Certificate.Certificate) == 0 || options.Certificate.PrivateKey == nil {
		return nil, errors.New("mTLS relay client identity or trust roots are missing")
	}
	now := time.Now().UTC()
	if options.Now != nil {
		now = options.Now().UTC()
	}
	leaf, err := x509.ParseCertificate(options.Certificate.Certificate[0])
	if err != nil || now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) || leaf.IsCA || !allowsClientAuthentication(leaf) {
		return nil, errors.New("mTLS relay client certificate is invalid, expired, or not client-auth capable")
	}
	tlsConfiguration := &tls.Config{
		Certificates: []tls.Certificate{options.Certificate},
		MinVersion:   tls.VersionTLS13,
		RootCAs:      options.RootCAs,
		ServerName:   options.ServerName,
	}
	return newRelayHTTPClient(options.ProxyURL, tlsConfiguration, options.Timeout)
}

func newAWSRelayHTTPClient(proxyURL string) (*http.Client, error) {
	roots, err := x509.SystemCertPool()
	if err != nil || roots == nil || len(roots.Subjects()) == 0 {
		return nil, errors.New("system TLS trust store is unavailable")
	}
	return newRelayHTTPClient(proxyURL, &tls.Config{
		MinVersion: tls.VersionTLS12,
		RootCAs:    roots,
	}, 30*time.Second)
}

func newRelayHTTPClient(rawProxyURL string, tlsConfiguration *tls.Config, timeout time.Duration) (*http.Client, error) {
	proxy, err := exactRelayProxy(rawProxyURL)
	if err != nil || tlsConfiguration == nil {
		return nil, errors.New("relay HTTP client requires the exact private proxy and TLS configuration")
	}
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	if timeout < time.Second || timeout > time.Minute {
		return nil, errors.New("relay HTTP client timeout must be between one and sixty seconds")
	}
	dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	transport := &http.Transport{
		Proxy:                 http.ProxyURL(proxy),
		DialContext:           dialer.DialContext,
		ForceAttemptHTTP2:     true,
		DisableCompression:    true,
		MaxIdleConns:          8,
		MaxIdleConnsPerHost:   2,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 15 * time.Second,
		ExpectContinueTimeout: time.Second,
		TLSClientConfig:       tlsConfiguration.Clone(),
	}
	return &http.Client{
		Transport: transport,
		Timeout:   timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("redirects are forbidden for Wazuh transports")
		},
	}, nil
}

func exactRelayProxy(raw string) (*url.URL, error) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "http" || parsed.Opaque != "" || parsed.User != nil ||
		parsed.Path != "" || parsed.RawPath != "" || parsed.RawQuery != "" || parsed.ForceQuery ||
		parsed.Fragment != "" || parsed.Port() != "3128" || parsed.String() != raw {
		return nil, errors.New("relay proxy must be an exact HTTP URL on port 3128")
	}
	ip := net.ParseIP(parsed.Hostname())
	if ip == nil || ip.To4() == nil || !ip.IsPrivate() || parsed.Host != net.JoinHostPort(ip.String(), "3128") {
		return nil, errors.New("relay proxy must use one canonical private IPv4 address")
	}
	return parsed, nil
}

func validTLSServerName(value string) bool {
	return value == strings.ToLower(value) && len(value) <= 253 && net.ParseIP(value) == nil && endpointHostPattern.MatchString(value)
}

func allowsClientAuthentication(certificate *x509.Certificate) bool {
	for _, usage := range certificate.ExtKeyUsage {
		if usage == x509.ExtKeyUsageAny || usage == x509.ExtKeyUsageClientAuth {
			return true
		}
	}
	return false
}
