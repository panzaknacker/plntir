package lambdapack

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"os"
	"path/filepath"
	"testing"
)

func TestPackIsDeterministicExecutableBootstrap(t *testing.T) {
	directory := t.TempDir()
	input := filepath.Join(directory, "handler")
	if err := os.WriteFile(input, []byte("synthetic-lambda-binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	first := filepath.Join(directory, "first.zip")
	second := filepath.Join(directory, "second.zip")
	if err := Pack(input, first); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(input, fixedZIPTime.AddDate(20, 0, 0), fixedZIPTime.AddDate(20, 0, 0)); err != nil {
		t.Fatal(err)
	}
	if err := Pack(input, second); err != nil {
		t.Fatal(err)
	}
	firstBytes, _ := os.ReadFile(first)
	secondBytes, _ := os.ReadFile(second)
	if sha256.Sum256(firstBytes) != sha256.Sum256(secondBytes) {
		t.Fatal("Lambda package changed with source mtime")
	}
	reader, err := zip.OpenReader(first)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	if len(reader.File) != 1 || reader.File[0].Name != "bootstrap" || reader.File[0].Mode().Perm() != 0o755 {
		t.Fatalf("unsafe Lambda ZIP layout: %+v", reader.File)
	}
	entry, err := reader.File[0].Open()
	if err != nil {
		t.Fatal(err)
	}
	defer entry.Close()
	contents := new(bytes.Buffer)
	if _, err := contents.ReadFrom(entry); err != nil || contents.String() != "synthetic-lambda-binary" {
		t.Fatalf("wrong Lambda ZIP content: %q %v", contents.String(), err)
	}
}

func TestPackRejectsSymlinkInput(t *testing.T) {
	directory := t.TempDir()
	realPath := filepath.Join(directory, "real")
	if err := os.WriteFile(realPath, []byte("binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	symlink := filepath.Join(directory, "link")
	if err := os.Symlink(realPath, symlink); err != nil {
		t.Fatal(err)
	}
	if err := Pack(symlink, filepath.Join(directory, "out.zip")); err == nil {
		t.Fatal("symlink Lambda input was accepted")
	}
}

func TestPackRejectsNonExecutableInput(t *testing.T) {
	directory := t.TempDir()
	input := filepath.Join(directory, "not-executable")
	if err := os.WriteFile(input, []byte("not-a-lambda-binary"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Pack(input, filepath.Join(directory, "out.zip")); err == nil {
		t.Fatal("non-executable Lambda input was accepted")
	}
}
