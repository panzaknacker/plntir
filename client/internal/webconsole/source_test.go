package webconsole

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestManagedPathTokenBoundary(t *testing.T) {
	source := NewCommandSource(Config{ManagedHome: "/Users/managed"})
	for _, accepted := range []string{
		"/Users/managed",
		"/Users/managed/Documents/report.txt",
		"/Users/managed/Library/Safari/History.db",
	} {
		clean, token, err := source.pathToken(accepted)
		if err != nil || clean == "" || token == "" {
			t.Fatalf("accepted path %q failed: %v", accepted, err)
		}
	}
	for _, rejected := range []string{
		"/Users/managed-other/file",
		"/Users/managed/../../etc/passwd",
		"relative/path",
		"/Users/managed/file\nnext",
	} {
		if _, _, err := source.pathToken(rejected); err == nil {
			t.Fatalf("unsafe path %q was accepted", rejected)
		}
	}
}

func TestOpenArchiveRejectsTraversalAndSymlink(t *testing.T) {
	root := t.TempDir()
	inside := filepath.Join(root, "2026-08-30")
	if err := os.Mkdir(inside, 0o700); err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(inside, "sample.tar.gz")
	if err := os.WriteFile(archive, []byte("archive"), 0o600); err != nil {
		t.Fatal(err)
	}
	source := NewCommandSource(Config{RetrievedRoot: root})
	file, _, err := source.OpenArchive("2026-08-30/sample.tar.gz")
	if err != nil {
		t.Fatal(err)
	}
	file.Close()
	if _, _, err := source.OpenArchive("../sample.tar.gz"); err == nil {
		t.Fatal("archive traversal was accepted")
	}
	outside := filepath.Join(t.TempDir(), "outside.tar.gz")
	if err := os.WriteFile(outside, []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(inside, "link.tar.gz")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	if _, _, err := source.OpenArchive("2026-08-30/link.tar.gz"); err == nil {
		t.Fatal("archive symlink escape was accepted")
	}
}

func TestCommandCancellationTerminatesProcessGroupGracefully(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "running")
	source := NewCommandSource(Config{MaxResponseBytes: 1 << 20})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	script := `trap 'rm -f -- "$1"' EXIT
trap 'exit 143' HUP INT TERM
: >"$1"
/bin/sleep 30 &
wait $!`
	go func() {
		_, err := source.run(
			ctx,
			30*time.Second,
			[]string{"/bin/bash", "-c", script, "plntir-cancel-test"},
			[]string{marker},
		)
		done <- err
	}()

	readyDeadline := time.Now().Add(2 * time.Second)
	for {
		if _, err := os.Stat(marker); err == nil {
			break
		} else if !errors.Is(err, os.ErrNotExist) {
			t.Fatal(err)
		}
		if time.Now().After(readyDeadline) {
			t.Fatal("child command did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}

	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancelled command error = %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("cancelled process group did not exit")
	}
	if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("cancellation cleanup marker stat = %v", err)
	}
}
