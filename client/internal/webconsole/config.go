package webconsole

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
)

const defaultMeshCIDR = "100.96.0.0/12"

type Config struct {
	Listen                string   `json:"listen"`
	AllowedMeshCIDR       string   `json:"allowed_mesh_cidr"`
	AllowedHosts          []string `json:"allowed_hosts"`
	TLSCertFile           string   `json:"tls_cert_file"`
	TLSKeyFile            string   `json:"tls_key_file"`
	AuthFile              string   `json:"auth_file"`
	StatusCommand         []string `json:"status_command"`
	ActionCommand         []string `json:"action_command"`
	MonitorRoot           string   `json:"monitor_root"`
	RetrievedRoot         string   `json:"retrieved_root"`
	AuditFile             string   `json:"audit_file"`
	ManagedHome           string   `json:"managed_home"`
	RefreshSeconds        int      `json:"refresh_seconds"`
	SessionMinutes        int      `json:"session_minutes"`
	PrivateSessionMinutes int      `json:"private_session_minutes"`
	MaxResponseBytes      int64    `json:"max_response_bytes"`

	Path    string     `json:"-"`
	MeshNet *net.IPNet `json:"-"`
}

func LoadConfig(path string) (Config, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return Config{}, err
	}
	info, err := os.Lstat(abs)
	if err != nil {
		return Config{}, fmt.Errorf("stat web config: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o137 != 0 {
		return Config{}, errors.New("web config must be a regular non-symlink file with no execute, group-write, or world permissions")
	}
	file, err := os.Open(abs)
	if err != nil {
		return Config{}, fmt.Errorf("open web config: %w", err)
	}
	defer file.Close()

	cfg := Config{
		AllowedMeshCIDR:       defaultMeshCIDR,
		RefreshSeconds:        10,
		SessionMinutes:        480,
		PrivateSessionMinutes: 10,
		MaxResponseBytes:      8 << 20,
		Path:                  abs,
	}
	decoder := json.NewDecoder(file)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&cfg); err != nil {
		return Config{}, fmt.Errorf("decode web config: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return Config{}, errors.New("decode web config: trailing JSON data")
	}
	base := filepath.Dir(abs)
	for _, target := range []*string{
		&cfg.TLSCertFile,
		&cfg.TLSKeyFile,
		&cfg.AuthFile,
		&cfg.MonitorRoot,
		&cfg.RetrievedRoot,
		&cfg.AuditFile,
	} {
		if *target != "" && !filepath.IsAbs(*target) {
			*target = filepath.Clean(filepath.Join(base, *target))
		}
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func (c *Config) Validate() error {
	host, port, err := net.SplitHostPort(c.Listen)
	if err != nil || host == "" || port == "" {
		return fmt.Errorf("listen must be an explicit IP and port: %q", c.Listen)
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	if ip == nil || ip.IsUnspecified() || ip.IsLoopback() || ip.IsMulticast() {
		return errors.New("listen must use the control node's explicit Mesh IP")
	}
	_, meshNet, err := net.ParseCIDR(c.AllowedMeshCIDR)
	if err != nil {
		return fmt.Errorf("invalid allowed_mesh_cidr: %w", err)
	}
	if !meshNet.Contains(ip) {
		return fmt.Errorf("listen IP %s is outside allowed mesh CIDR %s", ip, meshNet)
	}
	c.MeshNet = meshNet
	if len(c.AllowedHosts) == 0 {
		c.AllowedHosts = []string{c.Listen}
	}
	for _, allowed := range c.AllowedHosts {
		if allowed == "" || strings.ContainsAny(allowed, "\r\n/\\") {
			return fmt.Errorf("invalid allowed host %q", allowed)
		}
	}
	for name, path := range map[string]string{
		"tls_cert_file": c.TLSCertFile,
		"auth_file":     c.AuthFile,
	} {
		if err := requireRegularFile(name, path); err != nil {
			return err
		}
	}
	if err := requireSecretFile("tls_key_file", c.TLSKeyFile); err != nil {
		return err
	}
	if err := requireDirectory("monitor_root", c.MonitorRoot); err != nil {
		return err
	}
	if err := requireDirectory("retrieved_root", c.RetrievedRoot); err != nil {
		return err
	}
	if !filepath.IsAbs(c.AuditFile) || filepath.Base(c.AuditFile) == "." {
		return errors.New("audit_file must be an absolute file path")
	}
	if !strings.HasPrefix(c.ManagedHome, "/Users/") || filepath.Clean(c.ManagedHome) != c.ManagedHome {
		return errors.New("managed_home must be a clean path below /Users")
	}
	if err := validateCommand("status_command", c.StatusCommand); err != nil {
		return err
	}
	if err := validateCommand("action_command", c.ActionCommand); err != nil {
		return err
	}
	if c.RefreshSeconds < 2 || c.RefreshSeconds > 3600 {
		return errors.New("refresh_seconds must be between 2 and 3600")
	}
	if c.SessionMinutes < 5 || c.SessionMinutes > 1440 {
		return errors.New("session_minutes must be between 5 and 1440")
	}
	if c.PrivateSessionMinutes < 1 || c.PrivateSessionMinutes > 30 {
		return errors.New("private_session_minutes must be between 1 and 30")
	}
	if c.MaxResponseBytes < 1<<20 || c.MaxResponseBytes > 64<<20 {
		return errors.New("max_response_bytes must be between 1 MiB and 64 MiB")
	}
	return nil
}

func validateCommand(name string, command []string) error {
	if len(command) == 0 || !filepath.IsAbs(command[0]) {
		return fmt.Errorf("%s must start with an absolute executable path", name)
	}
	for _, argument := range command {
		if argument == "" || strings.ContainsRune(argument, '\x00') {
			return fmt.Errorf("%s contains an empty or invalid argument", name)
		}
	}
	return nil
}

func requireRegularFile(name, path string) error {
	if !filepath.IsAbs(path) {
		return fmt.Errorf("%s must be absolute", name)
	}
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("stat %s: %w", name, err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s must be a regular non-symlink file", name)
	}
	return nil
}

func requireSecretFile(name, path string) error {
	if err := requireRegularFile(name, path); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode().Perm()&0o137 != 0 {
		return fmt.Errorf("%s must have no execute, group-write, or world permissions", name)
	}
	return nil
}

func requireDirectory(name, path string) error {
	if !filepath.IsAbs(path) {
		return fmt.Errorf("%s must be absolute", name)
	}
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("stat %s: %w", name, err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s must be a non-symlink directory", name)
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

func (c Config) LocalMeshAddressPresent() bool {
	listenHost, _, err := net.SplitHostPort(c.Listen)
	if err != nil {
		return false
	}
	want := net.ParseIP(strings.Trim(listenHost, "[]"))
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		return false
	}
	for _, address := range addresses {
		var candidate net.IP
		switch value := address.(type) {
		case *net.IPNet:
			candidate = value.IP
		case *net.IPAddr:
			candidate = value.IP
		}
		if candidate != nil && candidate.Equal(want) {
			return true
		}
	}
	return false
}
