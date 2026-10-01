package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

type Config struct {
	SchemaVersion            int      `json:"schema_version"`
	Mode                     string   `json:"mode"`
	Listen                   string   `json:"listen"`
	AllowedHosts             []string `json:"allowed_hosts"`
	DatabasePath             string   `json:"database_path"`
	LegacyStatusPath         string   `json:"legacy_status_path"`
	CloudflareAccessIssuer   string   `json:"cloudflare_access_issuer"`
	CloudflareAccessAudience string   `json:"cloudflare_access_audience"`
	Path                     string   `json:"-"`
}

func Load(path string) (Config, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return Config{}, err
	}
	info, err := os.Lstat(abs)
	if err != nil {
		return Config{}, fmt.Errorf("stat config: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o022 != 0 {
		return Config{}, errors.New("config must be a regular non-symlink file without group/world write permissions")
	}
	file, err := os.Open(abs)
	if err != nil {
		return Config{}, err
	}
	defer file.Close()
	decoder := json.NewDecoder(io.LimitReader(file, 1<<20))
	decoder.DisallowUnknownFields()
	var result Config
	if err := decoder.Decode(&result); err != nil {
		return Config{}, fmt.Errorf("decode config: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return Config{}, errors.New("config contains trailing JSON data")
	}
	result.Path = abs
	base := filepath.Dir(abs)
	for _, target := range []*string{&result.DatabasePath, &result.LegacyStatusPath} {
		if *target != "" && !filepath.IsAbs(*target) {
			*target = filepath.Clean(filepath.Join(base, *target))
		}
	}
	if err := result.Validate(); err != nil {
		return Config{}, err
	}
	return result, nil
}

func (c Config) Validate() error {
	if c.SchemaVersion != 1 {
		return fmt.Errorf("unsupported config schema %d", c.SchemaVersion)
	}
	if c.Mode != "shadow" {
		return errors.New("this build is fail-closed to shadow mode; active mode is not sealed")
	}
	host, port, err := net.SplitHostPort(c.Listen)
	if err != nil || port == "" {
		return errors.New("listen must be an explicit host and port")
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	if ip == nil || !ip.IsLoopback() {
		return errors.New("shadow Core must listen on an explicit loopback address")
	}
	if len(c.AllowedHosts) == 0 {
		return errors.New("at least one allowed host is required")
	}
	for _, allowed := range c.AllowedHosts {
		if allowed == "" || strings.ContainsAny(allowed, "\r\n/\\") {
			return fmt.Errorf("invalid allowed host %q", allowed)
		}
	}
	if !filepath.IsAbs(c.DatabasePath) || !filepath.IsAbs(c.LegacyStatusPath) {
		return errors.New("database_path and legacy_status_path must be absolute")
	}
	issuer, err := url.Parse(c.CloudflareAccessIssuer)
	if err != nil || issuer.Scheme != "https" || issuer.Path != "" || issuer.RawQuery != "" || issuer.Fragment != "" ||
		!strings.HasSuffix(strings.ToLower(issuer.Hostname()), ".cloudflareaccess.com") {
		return errors.New("cloudflare_access_issuer must be an HTTPS .cloudflareaccess.com origin")
	}
	if c.CloudflareAccessAudience == "" || len(c.CloudflareAccessAudience) > 256 {
		return errors.New("cloudflare_access_audience is required")
	}
	return nil
}

func (c Config) HostAllowed(host string) bool {
	for _, allowed := range c.AllowedHosts {
		if strings.EqualFold(host, allowed) {
			return true
		}
	}
	return false
}
