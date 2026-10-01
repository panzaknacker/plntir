package archive

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

type staticProbe struct {
	snapshot PolicySnapshot
	err      error
}

func (probe staticProbe) Snapshot(context.Context) (PolicySnapshot, error) {
	return probe.snapshot, probe.err
}

type recordingGrants struct {
	now   time.Time
	calls []UploadGrantRequest
}

func (grants *recordingGrants) Grant(_ context.Context, request UploadGrantRequest) (UploadGrant, error) {
	grants.calls = append(grants.calls, request)
	return UploadGrant{
		ObjectID:  request.ObjectID,
		Method:    "PUT",
		URL:       "https://archive-objects.invalid/" + request.ObjectID,
		ExpiresAt: grants.now.Add(4 * time.Minute),
		RequiredHeaders: map[string]string{
			"Content-Type":                "application/octet-stream",
			"Content-Length":              strconv.FormatInt(request.ContentLength, 10),
			"x-amz-checksum-sha256":       request.ChecksumSHA256,
			"x-amz-meta-plntir-object-id": request.ObjectID,
			"x-amz-meta-plntir-work-id":   request.WorkID,
		},
	}, nil
}

type recordingObjects struct {
	failures int
	calls    []PutRequest
}

func (objects *recordingObjects) Put(_ context.Context, request PutRequest) error {
	copyOfRequest := request
	copyOfRequest.Body = append([]byte(nil), request.Body...)
	objects.calls = append(objects.calls, copyOfRequest)
	if objects.failures > 0 {
		objects.failures--
		return errors.New("simulated network loss")
	}
	return nil
}

func TestRunnerResumesExactCiphertextAfterNetworkLoss(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "Mail.db"), []byte("one immutable chunk"))
	plan, err := BuildPlan(root, PlanOptions{ChunkBytes: 64, CreatedAt: testNow, TestOnlyAllowSmallChunks: true})
	if err != nil {
		t.Fatal(err)
	}
	key := bytes.Repeat([]byte{0x62}, DEKBytes)
	state, err := NewArchiveState("mac-1", "archive-1", "key-1", plan, testEnvelopes(), [NoncePrefixBytes]byte{4, 3, 2, 1}, testNow)
	if err != nil {
		t.Fatal(err)
	}
	store := StateStore{Path: filepath.Join(privateTempDir(t), "resume.json")}
	if err := store.Save(state); err != nil {
		t.Fatal(err)
	}
	grants := &recordingGrants{now: testNow}
	objects := &recordingObjects{failures: 1}
	runner := Runner{
		Plan:    plan,
		Store:   store,
		Wrapper: fakeKMS{key: key},
		Probe:   staticProbe{snapshot: readyPolicy()},
		Grants:  grants,
		Objects: objects,
		Now:     func() time.Time { return testNow },
		Random:  bytes.NewReader(bytes.Repeat([]byte{0x44}, 32)),
	}
	if _, err := runner.Step(context.Background()); err == nil {
		t.Fatal("simulated network failure did not surface")
	}
	pendingState, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if pendingState.Pending == nil || pendingState.NextNonceCounter != 2 || len(pendingState.Confirmed) != 0 {
		t.Fatalf("reservation was not durable before upload: %+v", pendingState)
	}
	stateBytes, err := os.ReadFile(store.Path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(stateBytes, []byte("https://")) || bytes.Contains(stateBytes, key) {
		t.Fatal("durable resume state contains a URL or raw DEK")
	}
	result, err := runner.Step(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !result.Resumed || !result.Complete {
		t.Fatalf("unexpected resumed result: %+v", result)
	}
	if len(grants.calls) != 2 || grants.calls[0] != grants.calls[1] {
		t.Fatalf("retry grant changed: %+v", grants.calls)
	}
	if len(objects.calls) != 2 || !bytes.Equal(objects.calls[0].Body, objects.calls[1].Body) {
		t.Fatal("retry did not reconstruct byte-identical ciphertext")
	}
	decoded, err := DecodeCipherChunk(objects.calls[1].Body)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := OpenChunk(key, [NoncePrefixBytes]byte{4, 3, 2, 1}, ChunkAAD{DeviceID: "mac-1", ArchiveID: "archive-1", WorkID: result.WorkID, ObjectID: result.ObjectID}, decoded)
	if err != nil || string(opened) != "one immutable chunk" {
		t.Fatalf("uploaded object did not restore: %q, %v", opened, err)
	}
	finalState, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if finalState.Pending != nil || len(finalState.Confirmed) != 1 || finalState.NextNonceCounter != 2 {
		t.Fatalf("unexpected final resume state: %+v", finalState)
	}
}

func TestRunnerFailsClosedBeforeNetworkOnMeteredLink(t *testing.T) {
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
	store := StateStore{Path: filepath.Join(privateTempDir(t), "resume.json")}
	if err := store.Save(state); err != nil {
		t.Fatal(err)
	}
	probe := readyPolicy()
	probe.Network = NetworkMetered
	grants := &recordingGrants{now: testNow}
	objects := &recordingObjects{}
	runner := Runner{Plan: plan, Store: store, Wrapper: fakeKMS{key: bytes.Repeat([]byte{1}, DEKBytes)}, Probe: staticProbe{snapshot: probe}, Grants: grants, Objects: objects, Now: func() time.Time { return testNow }}
	if _, err := runner.Step(context.Background()); !errors.Is(err, ErrPolicyPaused) {
		t.Fatalf("got %v, want policy pause", err)
	}
	if len(grants.calls) != 0 || len(objects.calls) != 0 {
		t.Fatal("metered-link pause performed network work")
	}
}
