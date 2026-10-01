package webconsole

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPasswordHashAndVerifier(t *testing.T) {
	password := []byte("correct horse battery staple")
	hash, err := HashPassword(password, minimumIterations)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(hash, string(password)) {
		t.Fatal("password hash contains plaintext password")
	}
	directory := t.TempDir()
	path := filepath.Join(directory, "auth.json")
	auth := AuthFile{SchemaVersion: 1, Username: "operator", PasswordHash: hash}
	contents, err := json.Marshal(auth)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatal(err)
	}
	verifier, err := LoadPasswordVerifier(path)
	if err != nil {
		t.Fatal(err)
	}
	if !verifier.Verify("operator", []byte("correct horse battery staple")) {
		t.Fatal("correct password was rejected")
	}
	if verifier.Verify("operator", []byte("correct horse battery stapler")) {
		t.Fatal("wrong password was accepted")
	}
	if verifier.Verify("another-user", []byte("correct horse battery staple")) {
		t.Fatal("wrong username was accepted")
	}
}

func TestAuthFileRejectsWritableSecret(t *testing.T) {
	path := filepath.Join(t.TempDir(), "auth.json")
	hash, err := HashPassword([]byte("another secure dashboard password"), minimumIterations)
	if err != nil {
		t.Fatal(err)
	}
	contents, err := json.Marshal(AuthFile{SchemaVersion: 1, Username: "operator", PasswordHash: hash})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o666); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPasswordVerifier(path); err == nil {
		t.Fatal("group/world-writable auth file was accepted")
	}
}

func TestAuthFileRejectsWorldReadableSecret(t *testing.T) {
	path := filepath.Join(t.TempDir(), "auth.json")
	hash, err := HashPassword([]byte("another secure dashboard password"), minimumIterations)
	if err != nil {
		t.Fatal(err)
	}
	contents, err := json.Marshal(AuthFile{SchemaVersion: 1, Username: "operator", PasswordHash: hash})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPasswordVerifier(path); err == nil {
		t.Fatal("world-readable auth file was accepted")
	}
}

func TestAuthFileRejectsTrailingJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "auth.json")
	hash, err := HashPassword([]byte("another secure dashboard password"), minimumIterations)
	if err != nil {
		t.Fatal(err)
	}
	contents, err := json.Marshal(AuthFile{SchemaVersion: 1, Username: "operator", PasswordHash: hash})
	if err != nil {
		t.Fatal(err)
	}
	contents = append(contents, []byte(` {"extra":true}`)...)
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPasswordVerifier(path); err == nil {
		t.Fatal("auth file with trailing JSON was accepted")
	}
}

func TestHashPasswordLengthPolicy(t *testing.T) {
	if _, err := HashPassword([]byte("too-short"), minimumIterations); err == nil {
		t.Fatal("short password was accepted")
	}
}
