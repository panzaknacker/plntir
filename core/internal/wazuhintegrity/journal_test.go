package wazuhintegrity

import (
	"crypto/sha256"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func newJournalRoot(t *testing.T) string {
	t.Helper()
	root := filepath.Join(t.TempDir(), "journal")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	return root
}

func TestJournalAppendsPrivateDurableChain(t *testing.T) {
	root := newJournalRoot(t)
	journal, err := OpenJournal(root, time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	first, err := journal.Append(alertAtLevel(10), time.Date(2026, 9, 4, 12, 0, 1, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	firstHash, _ := first.Record.Hash()
	second, err := journal.Append(alertAtLevel(13), time.Date(2026, 9, 4, 12, 0, 2, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if second.Record.PreviousHash != first.Record.EntryHash || firstHash == [sha256.Size]byte{} {
		t.Fatal("journal records are not chained")
	}
	for _, path := range []string{journalStatePath(root), first.Path, second.Path} {
		info, err := os.Lstat(path)
		if err != nil || info.Mode().Perm() != 0o600 || !info.Mode().IsRegular() {
			t.Fatalf("journal file permissions are unsafe for %s: %v %#o", path, err, info.Mode().Perm())
		}
	}
	reopened, err := OpenJournal(root, time.Date(2026, 9, 4, 12, 1, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if reopened.State().LastSequence != 2 || reopened.State().ChainHash != second.Record.EntryHash {
		t.Fatalf("journal state was not durable: %#v", reopened.State())
	}
}

func TestJournalRecoversRecordWrittenBeforeStateCommit(t *testing.T) {
	root := newJournalRoot(t)
	journal, _ := OpenJournal(root, time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC))
	_, _ = journal.Append(alertAtLevel(10), time.Date(2026, 9, 4, 12, 0, 1, 0, time.UTC))
	stateAfterFirst, err := os.ReadFile(journalStatePath(root))
	if err != nil {
		t.Fatal(err)
	}
	second, err := journal.Append(alertAtLevel(11), time.Date(2026, 9, 4, 12, 0, 2, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(journalStatePath(root), stateAfterFirst, 0o600); err != nil {
		t.Fatal(err)
	}
	recovered, err := OpenJournal(root, time.Date(2026, 9, 4, 12, 0, 3, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if recovered.State().LastSequence != 2 || recovered.State().ChainHash != second.Record.EntryHash {
		t.Fatalf("orphan record was not recovered: %#v", recovered.State())
	}
}

func TestJournalRejectsTamperedPendingRecord(t *testing.T) {
	root := newJournalRoot(t)
	journal, _ := OpenJournal(root, time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC))
	item, _ := journal.Append(alertAtLevel(13), time.Date(2026, 9, 4, 12, 0, 1, 0, time.UTC))
	body, _ := os.ReadFile(item.Path)
	body[len(body)-2] ^= 1
	if err := os.WriteFile(item.Path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenJournal(root, time.Date(2026, 9, 4, 12, 0, 2, 0, time.UTC)); err == nil {
		t.Fatal("tampered journal reopened")
	}
}

func TestJournalSerializesConcurrentAppends(t *testing.T) {
	root := newJournalRoot(t)
	journal, err := OpenJournal(root, time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	var group sync.WaitGroup
	errors := make(chan error, 32)
	for index := 0; index < 32; index++ {
		group.Add(1)
		go func(offset int) {
			defer group.Done()
			_, err := journal.Append(alertAtLevel(10), time.Date(2026, 9, 4, 12, 0, offset+1, 0, time.UTC))
			errors <- err
		}(index)
	}
	group.Wait()
	close(errors)
	for err := range errors {
		if err != nil {
			t.Fatal(err)
		}
	}
	items, err := journal.Pending()
	if err != nil || len(items) != 32 || journal.State().LastSequence != 32 {
		t.Fatalf("concurrent journal lost records: items=%d state=%#v err=%v", len(items), journal.State(), err)
	}
	for index, item := range items {
		if item.Record.Sequence != uint64(index+1) {
			t.Fatalf("non-contiguous sequence at %d: %d", index, item.Record.Sequence)
		}
	}
}

func TestJournalNeverFollowsPrivateStateSymlink(t *testing.T) {
	root := newJournalRoot(t)
	target := filepath.Join(t.TempDir(), "target")
	if err := os.WriteFile(target, []byte("do not read"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, journalStatePath(root)); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenJournal(root, time.Now()); err == nil {
		t.Fatal("journal followed a state symlink")
	}
}
