package webconsole

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadConfigRejectsWeakConfigAndTLSKeyPermissions(t *testing.T) {
	configPath, tlsKey := writeTestConfig(t)
	if _, err := LoadConfig(configPath); err != nil {
		t.Fatalf("valid config failed: %v", err)
	}
	if err := os.Chmod(configPath, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(configPath); err == nil {
		t.Fatal("world-readable web config was accepted")
	}
	if err := os.Chmod(configPath, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(tlsKey, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(configPath); err == nil {
		t.Fatal("world-readable TLS key was accepted")
	}
}

func TestLoadConfigRejectsSymlink(t *testing.T) {
	configPath, _ := writeTestConfig(t)
	link := filepath.Join(t.TempDir(), "web.json")
	if err := os.Symlink(configPath, link); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(link); err == nil {
		t.Fatal("symlinked web config was accepted")
	}
}

func writeTestConfig(t *testing.T) (string, string) {
	t.Helper()
	root := t.TempDir()
	monitor := filepath.Join(root, "monitor")
	retrieved := filepath.Join(root, "retrieved")
	if err := os.Mkdir(monitor, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(retrieved, 0o700); err != nil {
		t.Fatal(err)
	}
	cert := filepath.Join(root, "tls.crt")
	key := filepath.Join(root, "tls.key")
	auth := filepath.Join(root, "auth.json")
	if err := os.WriteFile(cert, []byte("certificate"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(key, []byte("private key"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(auth, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	config := map[string]any{
		"listen":                  "100.101.0.5:8443",
		"allowed_mesh_cidr":       defaultMeshCIDR,
		"allowed_hosts":           []string{"100.101.0.5:8443"},
		"tls_cert_file":           cert,
		"tls_key_file":            key,
		"auth_file":               auth,
		"status_command":          []string{"/usr/bin/false"},
		"action_command":          []string{"/usr/bin/false"},
		"monitor_root":            monitor,
		"retrieved_root":          retrieved,
		"audit_file":              filepath.Join(root, "audit.jsonl"),
		"managed_home":            "/Users/managed",
		"refresh_seconds":         10,
		"session_minutes":         60,
		"private_session_minutes": 10,
		"max_response_bytes":      1 << 20,
	}
	contents, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(root, "web.json")
	if err := os.WriteFile(configPath, contents, 0o600); err != nil {
		t.Fatal(err)
	}
	return configPath, key
}
