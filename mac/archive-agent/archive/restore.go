package archive

import (
	"context"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
)

type OfflineObjectFetcher interface {
	Fetch(context.Context, string) ([]byte, error)
}

func RestoreFileOffline(ctx context.Context, privateKey *rsa.PrivateKey, manifest SnapshotManifest, relativePath string, fetcher OfflineObjectFetcher, output io.Writer) error {
	if privateKey == nil || fetcher == nil || output == nil {
		return errors.New("offline restore dependencies are incomplete")
	}
	if err := manifest.Validate(); err != nil {
		return err
	}
	if err := validateRelativePath(relativePath); err != nil {
		return err
	}
	var selected *Entry
	for index := range manifest.Entries {
		if manifest.Entries[index].Path == relativePath {
			selected = &manifest.Entries[index]
			break
		}
	}
	if selected == nil || selected.Type != EntryRegular {
		return errors.New("offline restore path is not a regular archived file")
	}
	for _, object := range selected.Objects {
		record, err := fetcher.Fetch(ctx, object.ObjectID)
		if err != nil {
			return fmt.Errorf("fetch encrypted archive object %q: %w", object.ObjectID, err)
		}
		payloadHash := sha256.Sum256(record)
		if hex.EncodeToString(payloadHash[:]) != object.CiphertextHash || int64(len(record)) != object.CiphertextBytes {
			return fmt.Errorf("encrypted archive object %q does not match its manifest", object.ObjectID)
		}
		chunk, err := DecodeCipherChunk(record)
		if err != nil {
			return fmt.Errorf("decode encrypted archive object %q: %w", object.ObjectID, err)
		}
		if chunk.Counter != object.NonceCounter || int64(len(chunk.Ciphertext)-GCMTagBytes) != object.PlaintextBytes {
			return fmt.Errorf("encrypted archive object %q has inconsistent range metadata", object.ObjectID)
		}
		envelopes, exists := manifest.KeyEnvelopes[object.ArchiveKeyID]
		if !exists {
			return fmt.Errorf("offline key envelope %q is missing", object.ArchiveKeyID)
		}
		key, err := UnwrapOffline(privateKey, WrapContext{DeviceID: object.DeviceID, ArchiveKeyID: object.ArchiveKeyID}, envelopes)
		if err != nil {
			return fmt.Errorf("unwrap offline archive key %q: %w", object.ArchiveKeyID, err)
		}
		var prefix [NoncePrefixBytes]byte
		copy(prefix[:], chunk.Nonce[:NoncePrefixBytes])
		plaintext, openErr := OpenChunk(key, prefix, ChunkAAD{DeviceID: object.DeviceID, ArchiveID: object.ArchiveID, WorkID: object.WorkID, ObjectID: object.ObjectID}, chunk)
		Zero(key)
		if openErr != nil {
			return fmt.Errorf("authenticate encrypted archive object %q: %w", object.ObjectID, openErr)
		}
		written, writeErr := output.Write(plaintext)
		Zero(plaintext)
		if writeErr != nil {
			return writeErr
		}
		if written != int(object.PlaintextBytes) {
			return io.ErrShortWrite
		}
	}
	return nil
}
