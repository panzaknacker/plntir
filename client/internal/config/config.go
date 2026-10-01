package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const envConfig = "PLNTIRCTL_CONFIG"

const (
	CollectorModeLegacy   = "legacy-script"
	CollectorModeObserver = "observer-command"
)

var userPattern = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

// Config contains only connection metadata. private-key material is never read
// into the application; the system ssh client receives the path directly.
type Config struct {
	Host                  string `json:"host"`
	Port                  int    `json:"port"`
	User                  string `json:"user"`
	IdentityFile          string `json:"identity_file"`
	KnownHostsFile        string `json:"known_hosts_file"`
	RefreshSeconds        int    `json:"refresh_seconds"`
	ConnectTimeoutSeconds int    `json:"connect_timeout_seconds"`
	Timezone              string `json:"timezone"`
	CollectorMode         string `json:"collector_mode"`

	Path string `json:"-"`
}

func Load(requestedPath string) (Config, error) {
	path, err := locate(requestedPath)
	if err != nil {
		return Config{}, err
	}

	f, err := os.Open(path)
	if err != nil {
		return Config{}, fmt.Errorf("open config %q: %w", path, err)
	}
	defer f.Close()

	cfg := Config{
		Port:                  22,
		RefreshSeconds:        10,
		ConnectTimeoutSeconds: 12,
		Timezone:              "UTC",
		CollectorMode:         CollectorModeObserver,
		Path:                  path,
	}
	decoder := json.NewDecoder(f)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&cfg); err != nil {
		return Config{}, fmt.Errorf("decode config %q: %w", path, err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return Config{}, fmt.Errorf("decode config %q: trailing JSON data", path)
	}

	base := filepath.Dir(path)
	cfg.IdentityFile = resolvePath(base, cfg.IdentityFile)
	cfg.KnownHostsFile = resolvePath(base, cfg.KnownHostsFile)
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func (c Config) Validate() error {
	if !validHost(c.Host) {
		return fmt.Errorf("invalid SSH host %q", c.Host)
	}
	if !userPattern.MatchString(c.User) || strings.HasPrefix(c.User, "-") {
		return fmt.Errorf("invalid SSH user %q", c.User)
	}
	if c.Port < 1 || c.Port > 65535 {
		return fmt.Errorf("invalid SSH port %d", c.Port)
	}
	if c.RefreshSeconds < 2 || c.RefreshSeconds > 3600 {
		return fmt.Errorf("refresh_seconds must be between 2 and 3600")
	}
	if c.ConnectTimeoutSeconds < 1 || c.ConnectTimeoutSeconds > 120 {
		return fmt.Errorf("connect_timeout_seconds must be between 1 and 120")
	}
	switch c.CollectorMode {
	case CollectorModeLegacy, CollectorModeObserver:
	default:
		return fmt.Errorf("invalid collector_mode %q; use %q or %q", c.CollectorMode, CollectorModeLegacy, CollectorModeObserver)
	}
	if _, err := time.LoadLocation(c.Timezone); err != nil {
		return fmt.Errorf("invalid timezone %q: %w", c.Timezone, err)
	}
	if err := validateIdentity(c.IdentityFile); err != nil {
		return err
	}
	if err := validateRegularFile("known_hosts", c.KnownHostsFile); err != nil {
		return err
	}
	return nil
}

func (c Config) Target() string {
	host := c.Host
	if ip := net.ParseIP(host); ip != nil && strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	return c.User + "@" + host
}

func (c Config) RefreshInterval() time.Duration {
	return time.Duration(c.RefreshSeconds) * time.Second
}

func (c Config) Location() (*time.Location, error) {
	return time.LoadLocation(c.Timezone)
}

func locate(requested string) (string, error) {
	if requested != "" {
		return absolute(requested)
	}
	if fromEnv := os.Getenv(envConfig); fromEnv != "" {
		return absolute(fromEnv)
	}

	candidates := []string{
		"config/plntir-console.json",
		"../config/plntir-console.json",
	}
	if executable, err := os.Executable(); err == nil {
		candidates = append(candidates, filepath.Join(filepath.Dir(executable), "..", "config", "plntir-console.json"))
	}
	for _, candidate := range candidates {
		path, err := absolute(candidate)
		if err != nil {
			continue
		}
		if info, err := os.Stat(path); err == nil && info.Mode().IsRegular() {
			return path, nil
		}
	}
	return "", errors.New("dashboard config not found; pass --config or set PLNTIRCTL_CONFIG")
}

func absolute(path string) (string, error) {
	expanded := path
	if path == "~" || strings.HasPrefix(path, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		expanded = filepath.Join(home, strings.TrimPrefix(path, "~/"))
	}
	abs, err := filepath.Abs(expanded)
	if err != nil {
		return "", err
	}
	return filepath.Clean(abs), nil
}

func resolvePath(base, path string) string {
	if filepath.IsAbs(path) {
		return filepath.Clean(path)
	}
	return filepath.Clean(filepath.Join(base, path))
}

func validHost(host string) bool {
	if host == "" || strings.HasPrefix(host, "-") || strings.ContainsAny(host, " \t\r\n/@") {
		return false
	}
	if net.ParseIP(host) != nil {
		return true
	}
	if len(host) > 253 {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return false
		}
		for _, r := range label {
			if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != '-' {
				return false
			}
		}
	}
	return true
}

func validateIdentity(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("stat identity_file %q: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("identity_file %q is not a regular file", path)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("identity_file %q permissions are %04o; require 0600 or stricter", path, info.Mode().Perm())
	}
	return nil
}

func validateRegularFile(name, path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("stat %s %q: %w", name, path, err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%s %q is not a regular file", name, path)
	}
	return nil
}
