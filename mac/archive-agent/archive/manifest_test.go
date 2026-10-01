package archive

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestBuildPlanExcludesCachesAndNeverFollowsSymlinks(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	mustMkdirAll(t, filepath.Join(root, "Library", "Caches"))
	mustMkdirAll(t, filepath.Join(root, ".Trash"))
	mustMkdirAll(t, filepath.Join(root, "Documents"))
	mustWrite(t, filepath.Join(root, "Documents", "report.txt"), []byte("hello world"))
	mustWrite(t, filepath.Join(root, "Library", "Caches", "skip.bin"), []byte("cache"))
	mustWrite(t, filepath.Join(root, ".Trash", "deleted"), []byte("trash"))
	mustWrite(t, filepath.Join(root, "cloud-item.icloud"), []byte{})
	outside := filepath.Join(t.TempDir(), "outside-secret")
	mustWrite(t, outside, []byte("must not be read"))
	if err := os.Symlink(outside, filepath.Join(root, "Documents", "outside-link")); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mkfifo(filepath.Join(root, "live.pipe"), 0o600); err != nil {
		t.Fatal(err)
	}
	plan, err := BuildPlan(root, PlanOptions{ChunkBytes: 4, CreatedAt: testNow, TestOnlyAllowSmallChunks: true})
	if err != nil {
		t.Fatal(err)
	}
	if plan.LogicalBytes != int64(len("hello world")) || len(plan.Work) != 3 {
		t.Fatalf("unexpected plan totals: bytes=%d work=%d", plan.LogicalBytes, len(plan.Work))
	}
	entries := map[string]Entry{}
	for _, entry := range plan.Entries {
		entries[entry.Path] = entry
	}
	if entries["Documents/outside-link"].Type != EntrySymlink || entries["Documents/outside-link"].LinkTarget != outside {
		t.Fatal("symlink metadata was not archived without following")
	}
	for _, forbidden := range []string{"Library/Caches/skip.bin", ".Trash/deleted", "cloud-item.icloud", "live.pipe"} {
		if _, exists := entries[forbidden]; exists {
			t.Fatalf("excluded path %q entered archive", forbidden)
		}
	}
	reasons := map[string]string{}
	for _, excluded := range plan.Excluded {
		reasons[excluded.Path] = excluded.Reason
	}
	for path, reason := range map[string]string{"Library/Caches": "cache", ".Trash": "trash", "cloud-item.icloud": "icloud_not_local", "live.pipe": "unsupported_special_file"} {
		if reasons[path] != reason {
			t.Fatalf("exclusion %q=%q, want %q", path, reasons[path], reason)
		}
	}
	if err := plan.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestIncrementalPlanReusesOnlyExactIdentity(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "mail.db"), []byte("persistent mail database"))
	first, err := BuildPlan(root, PlanOptions{ChunkBytes: 8, CreatedAt: testNow, TestOnlyAllowSmallChunks: true})
	if err != nil {
		t.Fatal(err)
	}
	old := first.Entries[0]
	for index, work := range first.Work {
		old.Objects = append(old.Objects, ObjectRef{
			ObjectID:        "object-" + strings.Repeat("x", index+1),
			DeviceID:        "mac-1",
			ArchiveID:       "archive-old",
			ArchiveKeyID:    "key-old",
			WorkID:          work.ID,
			Offset:          work.Offset,
			PlaintextBytes:  work.Length,
			CiphertextBytes: work.Length + 256,
			NonceCounter:    uint64(index + 1),
			CiphertextHash:  strings.Repeat("a", 64),
		})
	}
	second, err := BuildPlan(root, PlanOptions{
		ChunkBytes:               8,
		CreatedAt:                testNow.Add(time.Hour),
		TestOnlyAllowSmallChunks: true,
		Previous:                 PreviousSnapshot{SnapshotID: "snapshot-1", Root: root, Entries: map[string]Entry{"mail.db": old}, KeyEnvelopes: map[string]KeyEnvelopes{"key-old": testEnvelopes()}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(second.Work) != 0 || len(second.Entries) != 1 || !second.Entries[0].Reused {
		t.Fatalf("exact unchanged file was not reused: %+v", second)
	}
	mustWrite(t, filepath.Join(root, "mail.db"), []byte("different mail database!"))
	changed := testNow.Add(2 * time.Hour)
	if err := os.Chtimes(filepath.Join(root, "mail.db"), changed, changed); err != nil {
		t.Fatal(err)
	}
	third, err := BuildPlan(root, PlanOptions{ChunkBytes: 8, CreatedAt: testNow.Add(3 * time.Hour), TestOnlyAllowSmallChunks: true, Previous: PreviousSnapshot{SnapshotID: "snapshot-1", Root: root, Entries: map[string]Entry{"mail.db": old}, KeyEnvelopes: map[string]KeyEnvelopes{"key-old": testEnvelopes()}}})
	if err != nil {
		t.Fatal(err)
	}
	if len(third.Work) == 0 || third.Entries[0].Reused {
		t.Fatal("changed file incorrectly reused old objects")
	}
}

func TestReadWorkRejectsMutationAndSymlinkSwap(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	file := filepath.Join(root, "settings.json")
	mustWrite(t, file, []byte("original"))
	plan, err := BuildPlan(root, PlanOptions{ChunkBytes: 32, CreatedAt: testNow, TestOnlyAllowSmallChunks: true})
	if err != nil {
		t.Fatal(err)
	}
	changed := testNow.Add(time.Hour)
	if err := os.Chtimes(file, changed, changed); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadWorkPlaintext(root, plan.Work[0]); err == nil {
		t.Fatal("mutated source identity was accepted")
	}
	secondRoot := t.TempDir()
	secondFile := filepath.Join(secondRoot, "settings.json")
	mustWrite(t, secondFile, []byte("original"))
	secondPlan, err := BuildPlan(secondRoot, PlanOptions{ChunkBytes: 32, CreatedAt: testNow, TestOnlyAllowSmallChunks: true})
	if err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "outside")
	mustWrite(t, outside, []byte("outside!"))
	if err := os.Remove(secondFile); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, secondFile); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadWorkPlaintext(secondRoot, secondPlan.Work[0]); err == nil {
		t.Fatal("symlink swap was followed")
	}
}

func TestMaterializedSnapshotFeedsNextIncrementalPlan(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "configuration"), []byte("stable configuration"))
	plan, err := BuildPlan(root, PlanOptions{ChunkBytes: 8, CreatedAt: testNow, TestOnlyAllowSmallChunks: true})
	if err != nil {
		t.Fatal(err)
	}
	state, err := NewArchiveState("mac-1", "archive-1", "key-1", plan, testEnvelopes(), [NoncePrefixBytes]byte{1, 2, 3, 4}, testNow)
	if err != nil {
		t.Fatal(err)
	}
	for index, work := range plan.Work {
		state.Confirmed[work.ID] = ObjectRef{ObjectID: "object-" + strings.Repeat("x", index+1), DeviceID: state.DeviceID, ArchiveID: state.ArchiveID, ArchiveKeyID: state.ArchiveKeyID, WorkID: work.ID, Offset: work.Offset, PlaintextBytes: work.Length, CiphertextBytes: work.Length + 128, NonceCounter: uint64(index + 1), CiphertextHash: strings.Repeat("c", 64)}
	}
	state.NextNonceCounter = uint64(len(plan.Work) + 1)
	manifest, err := MaterializeSnapshot(plan, state, testNow.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if err := manifest.Validate(); err != nil {
		t.Fatal(err)
	}
	next, err := BuildPlan(root, PlanOptions{ChunkBytes: 8, CreatedAt: testNow.Add(24 * time.Hour), TestOnlyAllowSmallChunks: true, Previous: manifest.Previous()})
	if err != nil {
		t.Fatal(err)
	}
	if len(next.Work) != 0 || !next.Entries[0].Reused || next.PreviousSnapshotID != manifest.SnapshotID {
		t.Fatal("materialized snapshot was not reusable by the next plan")
	}
}

func mustMkdirAll(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(path, 0o700); err != nil {
		t.Fatal(err)
	}
}

func mustWrite(t *testing.T, path string, value []byte) {
	t.Helper()
	if err := os.WriteFile(path, value, 0o600); err != nil {
		t.Fatal(err)
	}
}
