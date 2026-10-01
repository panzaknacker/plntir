package archive

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestStateStoreIsAtomicStrictAndPrivate(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "file"), []byte("content"))
	plan, err := BuildPlan(root, PlanOptions{ChunkBytes: 32, CreatedAt: testNow, TestOnlyAllowSmallChunks: true})
	if err != nil {
		t.Fatal(err)
	}
	state, err := NewArchiveState("mac-1", "archive-1", "key-1", plan, testEnvelopes(), [NoncePrefixBytes]byte{1, 2, 3, 4}, testNow)
	if err != nil {
		t.Fatal(err)
	}
	stateDirectory := privateTempDir(t)
	store := StateStore{Path: filepath.Join(stateDirectory, "resume.json")}
	if err := store.Save(state); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(store.Path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("state mode is %o", info.Mode().Perm())
	}
	loaded, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if loaded.PlanDigestSHA256 != plan.DigestSHA256 || loaded.NextNonceCounter != 1 {
		t.Fatal("loaded state differs")
	}
	content, err := os.ReadFile(store.Path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(content, bytes.Repeat([]byte("raw-secret-key-material!"), 2)) || bytes.Contains(content, []byte("https://")) {
		t.Fatal("state contains raw key material or a bearer URL")
	}
	content = bytes.TrimSpace(content)
	content = append(content[:len(content)-1], []byte(",\"unexpected\":true}\n")...)
	if err := os.WriteFile(store.Path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(); err == nil {
		t.Fatal("unknown state field was accepted")
	}
}

func TestStateStoreRejectsSymlinksAndLoosePermissions(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "file"), []byte("content"))
	plan, err := BuildPlan(root, PlanOptions{ChunkBytes: 32, CreatedAt: testNow, TestOnlyAllowSmallChunks: true})
	if err != nil {
		t.Fatal(err)
	}
	state, err := NewArchiveState("mac-1", "archive-1", "key-1", plan, testEnvelopes(), [NoncePrefixBytes]byte{1, 2, 3, 4}, testNow)
	if err != nil {
		t.Fatal(err)
	}
	directory := privateTempDir(t)
	target := filepath.Join(directory, "target")
	mustWrite(t, target, []byte("do not replace"))
	link := filepath.Join(directory, "resume.json")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := (StateStore{Path: link}).Save(state); err == nil {
		t.Fatal("symlink state target was replaced")
	}
	loose := filepath.Join(directory, "loose.json")
	mustWrite(t, loose, []byte("{}"))
	if err := os.Chmod(loose, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := (StateStore{Path: loose}).Save(state); err == nil {
		t.Fatal("loosely permissioned existing state was replaced")
	}
}
