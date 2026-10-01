package archive

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPlanStoreCreatesOnceAndDetectsTampering(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "file"), []byte("content"))
	plan, err := BuildPlan(root, PlanOptions{ChunkBytes: 32, CreatedAt: testNow, TestOnlyAllowSmallChunks: true})
	if err != nil {
		t.Fatal(err)
	}
	store := PlanStore{Path: filepath.Join(privateTempDir(t), "plan.json")}
	if err := store.Create(plan); err != nil {
		t.Fatal(err)
	}
	if err := store.Create(plan); err == nil {
		t.Fatal("immutable plan store allowed replacement")
	}
	loaded, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if loaded.DigestSHA256 != plan.DigestSHA256 {
		t.Fatal("loaded plan differs")
	}
	info, err := os.Stat(store.Path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("plan mode is %o", info.Mode().Perm())
	}
	content, err := os.ReadFile(store.Path)
	if err != nil {
		t.Fatal(err)
	}
	for index := range content {
		if content[index] == 'c' {
			content[index] = 'd'
			break
		}
	}
	if err := os.WriteFile(store.Path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(); err == nil {
		t.Fatal("tampered immutable plan was accepted")
	}
}
