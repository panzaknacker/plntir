package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadResolvesPathsAndAcceptsPrivateIdentity(t *testing.T) {
	directory := t.TempDir()
	identity := filepath.Join(directory, "operator.pem")
	knownHosts := filepath.Join(directory, "known_hosts")
	writeTestFile(t, identity, "test-key", 0o600)
	writeTestFile(t, knownHosts, "example ssh-ed25519 AAAA", 0o640)
	configPath := filepath.Join(directory, "plntir-console.json")
	writeTestFile(t, configPath, `{
  "host":"127.0.0.1",
  "port":22,
  "user":"observer",
  "identity_file":"operator.pem",
  "known_hosts_file":"known_hosts",
  "refresh_seconds":10,
  "connect_timeout_seconds":5,
  "timezone":"Europe/Berlin"
}`, 0o640)

	cfg, err := Load(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.IdentityFile != identity {
		t.Fatalf("identity path = %q, want %q", cfg.IdentityFile, identity)
	}
	if cfg.KnownHostsFile != knownHosts {
		t.Fatalf("known_hosts path = %q, want %q", cfg.KnownHostsFile, knownHosts)
	}
	if cfg.Target() != "observer@127.0.0.1" {
		t.Fatalf("target = %q", cfg.Target())
	}
	if cfg.CollectorMode != CollectorModeObserver {
		t.Fatalf("collector mode = %q", cfg.CollectorMode)
	}
}

func TestLoadRejectsBroadIdentityPermissions(t *testing.T) {
	directory := t.TempDir()
	writeTestFile(t, filepath.Join(directory, "operator.pem"), "test-key", 0o644)
	writeTestFile(t, filepath.Join(directory, "known_hosts"), "host-key", 0o640)
	configPath := filepath.Join(directory, "plntir-console.json")
	writeTestFile(t, configPath, `{
  "host":"127.0.0.1",
  "user":"observer",
  "identity_file":"operator.pem",
  "known_hosts_file":"known_hosts"
}`, 0o640)

	_, err := Load(configPath)
	if err == nil || !strings.Contains(err.Error(), "require 0600") {
		t.Fatalf("expected private-key permission error, got %v", err)
	}
}

func TestValidateRejectsArgumentInjection(t *testing.T) {
	cfg := Config{
		Host:                  "-oProxyCommand=evil",
		Port:                  22,
		User:                  "admin",
		IdentityFile:          "/does/not/matter",
		KnownHostsFile:        "/does/not/matter",
		RefreshSeconds:        10,
		ConnectTimeoutSeconds: 5,
		Timezone:              "UTC",
	}
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "invalid SSH host") {
		t.Fatalf("expected invalid-host error, got %v", err)
	}
}

func TestLoadRejectsUnknownFields(t *testing.T) {
	directory := t.TempDir()
	configPath := filepath.Join(directory, "plntir-console.json")
	writeTestFile(t, configPath, `{"host":"127.0.0.1","surprise":true}`, 0o640)
	_, err := Load(configPath)
	if err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("expected unknown-field error, got %v", err)
	}
}

func TestLoadRejectsUnknownCollectorMode(t *testing.T) {
	directory := t.TempDir()
	writeTestFile(t, filepath.Join(directory, "operator.pem"), "test-key", 0o600)
	writeTestFile(t, filepath.Join(directory, "known_hosts"), "host-key", 0o640)
	configPath := filepath.Join(directory, "plntir-console.json")
	writeTestFile(t, configPath, `{
  "host":"127.0.0.1",
  "user":"observer",
  "identity_file":"operator.pem",
  "known_hosts_file":"known_hosts",
  "collector_mode":"shell"
}`, 0o640)

	_, err := Load(configPath)
	if err == nil || !strings.Contains(err.Error(), "invalid collector_mode") {
		t.Fatalf("expected invalid collector mode error, got %v", err)
	}
}

func writeTestFile(t *testing.T, path, content string, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}
