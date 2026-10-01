package archive

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"testing"
	"time"
)

type memoryObjectFetcher map[string][]byte

func (fetcher memoryObjectFetcher) Fetch(_ context.Context, objectID string) ([]byte, error) {
	value, exists := fetcher[objectID]
	if !exists {
		return nil, fmt.Errorf("unknown object")
	}
	return append([]byte(nil), value...), nil
}

func TestFullFileRestoreUsesOnlyOfflinePrivateKey(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	original := []byte("mail-browser-configuration-and-hidden-application-state")
	mustWrite(t, filepath.Join(root, "LibraryState.bin"), original)
	plan, err := BuildPlan(root, PlanOptions{ChunkBytes: 9, CreatedAt: testNow, TestOnlyAllowSmallChunks: true})
	if err != nil {
		t.Fatal(err)
	}
	key := bytes.Repeat([]byte{0x73}, DEKBytes)
	t.Logf("Prepared synthetic file: %d bytes, %d planned chunks", len(original), len(plan.Work))
	wrapContext := WrapContext{DeviceID: "mac-offline", ArchiveKeyID: "key-offline"}
	envelopes, err := WrapArchiveDEK(context.Background(), fakeKMS{key: key}, &privateKey.PublicKey, wrapContext, key, nil)
	if err != nil {
		t.Fatal(err)
	}
	state, err := NewArchiveState(wrapContext.DeviceID, "archive-offline", wrapContext.ArchiveKeyID, plan, envelopes, [NoncePrefixBytes]byte{8, 6, 7, 5}, testNow)
	if err != nil {
		t.Fatal(err)
	}
	objects := memoryObjectFetcher{}
	for index, work := range plan.Work {
		plaintext, err := ReadWorkPlaintext(root, work)
		if err != nil {
			t.Fatal(err)
		}
		objectID := fmt.Sprintf("offline-object-%d", index)
		counter := uint64(index + 1)
		chunk, err := SealChunk(key, [NoncePrefixBytes]byte{8, 6, 7, 5}, counter, ChunkAAD{DeviceID: state.DeviceID, ArchiveID: state.ArchiveID, WorkID: work.ID, ObjectID: objectID}, plaintext)
		Zero(plaintext)
		if err != nil {
			t.Fatal(err)
		}
		record, err := EncodeCipherChunk(chunk)
		if err != nil {
			t.Fatal(err)
		}
		hash := sha256.Sum256(record)
		objects[objectID] = record
		state.Confirmed[work.ID] = ObjectRef{ObjectID: objectID, DeviceID: state.DeviceID, ArchiveID: state.ArchiveID, ArchiveKeyID: state.ArchiveKeyID, WorkID: work.ID, Offset: work.Offset, PlaintextBytes: work.Length, CiphertextBytes: int64(len(record)), NonceCounter: counter, CiphertextHash: hex.EncodeToString(hash[:])}
	}
	state.NextNonceCounter = uint64(len(plan.Work) + 1)
	manifest, err := MaterializeSnapshot(plan, state, testNow.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	var restored bytes.Buffer
	t.Logf("Encrypted %d chunks and materialized the archive manifest; storage and KMS are local test doubles", len(objects))
	if err := RestoreFileOffline(context.Background(), privateKey, manifest, "LibraryState.bin", objects, &restored); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(restored.Bytes(), original) {
		t.Fatal("offline-restored file differs from source")
	}
	t.Log("PASS: restore with the temporary offline key returned exactly the original bytes")
	firstObject := manifest.Entries[0].Objects[0].ObjectID
	objects[firstObject][len(objects[firstObject])-1] ^= 1
	if err := RestoreFileOffline(context.Background(), privateKey, manifest, "LibraryState.bin", objects, &bytes.Buffer{}); err == nil {
		t.Fatal("offline restore accepted a tampered ciphertext object")
	}
	t.Log("PASS: changing one ciphertext byte caused restore to reject the archive")
}
