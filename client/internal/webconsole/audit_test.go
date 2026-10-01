package webconsole

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAuditReadReturnsNewestRecordsFirst(t *testing.T) {
	log, err := NewAuditLog(filepath.Join(t.TempDir(), "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	for _, event := range []string{"first", "second", "third"} {
		if err := log.Write(event, "operator", "100.101.0.10", true, nil); err != nil {
			t.Fatal(err)
		}
	}
	records, err := log.Read(2)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 2 || records[0].Event != "third" || records[1].Event != "second" {
		t.Fatalf("unexpected audit order: %#v", records)
	}
	if _, err := log.Read(0); err == nil {
		t.Fatal("invalid audit limit was accepted")
	}
}

func TestAuditRejectsWeakPermissions(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "audit.jsonl")
	if err := os.WriteFile(path, []byte(""), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := NewAuditLog(path); err == nil {
		t.Fatal("group-readable audit log was accepted")
	}
}
